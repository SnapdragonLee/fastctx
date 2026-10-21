//! A bounded request on a root-owned socket, authenticated in both directions.

use std::io::{Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context as _, ensure};
use serde::{Deserialize, Serialize};

use super::config::Config;

#[derive(Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Status,
    Guests { action: crate::service::guests::Request },
    Adopt,
    Restart { digest: String },
}

#[derive(Serialize, Deserialize)]
pub(super) struct Reply {
    pub digest: Option<String>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<crate::service::guests::Account>,
}

pub(super) fn ask(config: &Config, request: &Request) -> anyhow::Result<Reply> {
    let mut stream = UnixStream::connect(config.socket()).context("the guardian is not running")?;
    configure(&stream)?;
    // 2026-10-20: a substituted socket must not impersonate the privileged service.
    ensure!(peer_uid(&stream)? == 0, "the guardian channel is not owned by root");
    send(&mut stream, request)?;
    let reply: Reply = receive(&mut stream)?;
    if let Some(error) = &reply.error {
        anyhow::bail!("{error}");
    }
    Ok(reply)
}

pub(super) fn configure(stream: &UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))
}

pub(super) fn send(stream: &mut UnixStream, value: &impl Serialize) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 64 * 1024, "guardian message exceeds its limit");
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

pub(super) fn receive<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> anyhow::Result<T> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size <= 64 * 1024, "guardian message exceeds its limit");
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
        // SAFETY: getsockopt writes precisely the supplied credentials buffer.
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut credentials).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of_val(&credentials) {
            return Err(std::io::Error::other("incomplete peer credentials"));
        }
        Ok(credentials.uid)
    }
    #[cfg(target_os = "macos")]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: getpeereid obtains credentials from the connected socket, not its payload.
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(uid)
    }
}
