//! A SYSTEM-owned local pipe. The requester's token, obtained by pipe
//! impersonation, is checked before a typed account request is dispatched.

use super::{config::Config, security::Descriptor};
use crate::service::{
    Kind, Service,
    guests::{Account, Request},
};
use anyhow::{Context as _, ensure};
use serde::{Serialize, de::DeserializeOwned};
use std::os::windows::io::AsHandle as _;
use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    os::windows::{
        fs::OpenOptionsExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE},
    Security::{RevertToSelf, TOKEN_QUERY},
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_READ_DATA, FILE_WRITE_DATA, PIPE_ACCESS_DUPLEX},
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
        },
        Threading::{GetCurrentThread, OpenThreadToken},
    },
};

#[derive(serde::Serialize, serde::Deserialize)]
struct Reply {
    accounts: Vec<Account>,
    error: Option<String>,
}

fn name(config: &Config) -> String {
    format!(r"\\.\pipe\{}-guests", config.name)
}

pub(crate) fn ask(service: &Service, request: &Request) -> anyhow::Result<Vec<Account>> {
    let config = Config::new(service)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut pipe = loop {
        let opened = OpenOptions::new()
            .access_mode(FILE_READ_DATA | FILE_WRITE_DATA | 0x20000 | 0x100000)
            // SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION: identification
            // never gives a substituted server authority to act as the owner.
            .custom_flags(0x00100000 | 0x00010000)
            .open(name(&config));
        match opened {
            Ok(pipe) => break pipe,
            Err(error) if error.raw_os_error() == Some(231) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error).context("the guardian's account channel is not running"),
        }
    };
    ensure!(
        fastctx_platform::object_owner_sid(pipe.as_handle())? == "S-1-5-18",
        "the guardian channel is not owned by SYSTEM"
    );
    pipe.write_all(&[1])?;
    send(&mut pipe, request)?;
    let reply: Reply = receive(&mut pipe)?;
    pipe.write_all(&[1])?;
    if let Some(error) = reply.error {
        anyhow::bail!("{error}");
    }
    Ok(reply.accounts)
}

pub(super) fn start(config: Config) -> anyhow::Result<()> {
    if config.kind != Kind::Node {
        return Ok(());
    }
    let pipe = create(&config)?;
    std::thread::Builder::new().name("guardian accounts".into()).spawn(move || {
        let mut pipe = pipe;
        loop {
            let connected = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), ptr::null_mut()) } != 0
                || std::io::Error::last_os_error().raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32);
            if !connected {
                eprintln!("fastctx guest channel connect: {}", std::io::Error::last_os_error());
                return;
            }
            let result = (|| {
                let mut hello = [0];
                read_exact(&mut pipe, &mut hello)?;
                ensure!(hello == [1], "unknown guardian account channel");
                let peer = peer(&pipe)?;
                let owner = config.target.as_ref().map(|target| target.sid.as_str()).unwrap_or("S-1-5-18");
                ensure!(peer == owner || peer == "S-1-5-18", "this account does not own the guardian");
                let request: Request = receive(&mut pipe)?;
                super::guests::manager(&config)?.handle(&request)
            })();
            let reply = match result {
                Ok(accounts) => Reply { accounts, error: None },
                Err(error) => Reply { accounts: vec![], error: Some(format!("{error:#}")) },
            };
            if let Err(error) = send(&mut pipe, &reply) {
                eprintln!("fastctx guest channel reply: {error:#}");
            }
            // An acknowledgement prevents DisconnectNamedPipe from discarding
            // a reply the client has not consumed yet.
            let mut receipt = [0];
            let _ = read_exact(&mut pipe, &mut receipt);
            // Retain the first instance for the entire service lifetime, so a
            // client can never claim the pipe name between requests.
            unsafe {
                DisconnectNamedPipe(pipe.as_raw_handle());
            }
        }
    })?;
    Ok(())
}

fn create(config: &Config) -> anyhow::Result<File> {
    let owner = config.target.as_ref().map(|target| target.sid.as_str()).unwrap_or("S-1-5-18");
    // FILE_CREATE_PIPE_INSTANCE is deliberately absent from the owner's access.
    let descriptor = Descriptor::new(&format!("O:SYG:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;{owner})"))?;
    let name: Vec<u16> = name(config).encode_utf16().chain([0]).collect();
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            60000,
            &descriptor.attributes(),
        )
    };
    ensure!(handle != INVALID_HANDLE_VALUE, "creating the guest account pipe: {}", std::io::Error::last_os_error());
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn peer(pipe: &File) -> anyhow::Result<String> {
    ensure!(
        unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } != 0,
        "identifying the guardian caller: {}",
        std::io::Error::last_os_error()
    );
    let identity = (|| {
        let mut token = ptr::null_mut();
        ensure!(
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0,
            "opening the guardian caller's token: {}",
            std::io::Error::last_os_error()
        );
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        Ok(fastctx_platform::token_user_sid(token.as_handle())?)
    })();
    // A failed revert may never leave privileged code running as a client.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    identity
}

fn read_exact(pipe: &mut File, mut bytes: &mut [u8]) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !bytes.is_empty() {
        let mut available = 0;
        ensure!(
            unsafe {
                PeekNamedPipe(
                    pipe.as_raw_handle(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &mut available,
                    ptr::null_mut(),
                )
            } != 0,
            "reading the guardian account pipe: {}",
            std::io::Error::last_os_error()
        );
        if available == 0 {
            ensure!(Instant::now() < deadline, "the guardian account request timed out");
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let size = bytes.len().min(available as usize);
        let (head, tail) = bytes.split_at_mut(size);
        pipe.read_exact(head)?;
        bytes = tail;
    }
    Ok(())
}

fn receive<T: DeserializeOwned>(pipe: &mut File) -> anyhow::Result<T> {
    let mut size = [0; 4];
    read_exact(pipe, &mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size <= 65536, "guardian message exceeds its limit");
    let mut bytes = vec![0; size];
    read_exact(pipe, &mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn send(pipe: &mut File, value: &impl Serialize) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 65532, "guardian message exceeds its limit");
    pipe.write_all(&(bytes.len() as u32).to_be_bytes())?;
    pipe.write_all(&bytes)?;
    Ok(())
}
