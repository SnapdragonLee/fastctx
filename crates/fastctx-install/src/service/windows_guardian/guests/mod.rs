//! Ordinary hidden Windows users, with no retained login credential and no interactive,
//! remote-interactive, or network logon. Only the guardian performs S4U batch logon.

use std::os::windows::io::AsHandle as _;
mod account;
mod processes;

use super::config::Config;
use crate::service::{
    Kind,
    guests::{Identity, Manager, Record},
};
pub(crate) use account::{create, existing, name_used, set_active, verify};
use anyhow::ensure;
use std::fs;

pub(super) fn manager(config: &Config) -> anyhow::Result<Manager> {
    ensure!(config.kind == Kind::Node, "a hub cannot own guest accounts");
    Ok(Manager {
        root: config.root()?,
        homes: fastctx_platform::protected_directory::program_data()?.join("fastctx-guests"),
        registration: config.name.clone(),
        owner: Identity::Windows {
            sid: config.target.as_ref().map(|target| target.sid.clone()).unwrap_or_else(|| "S-1-5-18".into()),
        },
    })
}

pub(crate) fn prepare(manager: &Manager) -> anyhow::Result<()> {
    ensure!(fastctx_platform::elevation::is_elevated()?, "guest administration requires administrator rights");
    fastctx_platform::protected_directory::ensure(
        &manager.root.join("guests"),
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
    )?;
    fastctx_platform::protected_directory::ensure(
        &manager.homes,
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FX;;;BU)",
    )?;
    Ok(())
}

pub(crate) fn sid(record: &Record) -> anyhow::Result<&str> {
    match &record.identity {
        Some(Identity::Windows { sid })
            if sid.starts_with("S-1-5-21-")
                && sid.bytes().all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S') =>
        {
            Ok(sid)
        }
        _ => anyhow::bail!("the guest has no local Windows identity"),
    }
}

pub(crate) fn prepare_home(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    let sid = sid(record)?;
    fastctx_platform::protected_directory::ensure(
        &manager.home(record),
        &format!("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FRFX;;;{sid})"),
    )?;
    Ok(())
}

pub(crate) fn room(manager: &Manager, record: &Record, room: &fastctx_types::ResidentId) -> anyhow::Result<()> {
    use std::os::windows::fs::MetadataExt as _;
    prepare_home(manager, record)?;
    let sid = sid(record)?;
    let path = manager.home(record).join(room.as_str());
    if !path.try_exists()? {
        fastctx_platform::protected_directory::ensure(
            &path,
            &format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"),
        )?;
    }
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_dir()
            && metadata.file_attributes() & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "the guest room is not a plain directory"
    );
    use std::os::windows::fs::OpenOptionsExt as _;
    let file = fs::OpenOptions::new()
        .access_mode(0x20000)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    ensure!(fastctx_platform::file_owner_sid(file.as_handle())? == sid, "the guest room has another owner");
    Ok(())
}

pub(crate) fn stop(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    verify(manager, record)?;
    let sid = sid(record)?;
    processes::terminate(sid)?;
    let scheduled = super::task::delete_for_guest(sid);
    let killed = processes::terminate(sid);
    scheduled?;
    killed
}

pub(crate) fn delete(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    if existing(manager, record)?.is_some() {
        account::delete(record)?;
    }
    account::delete_hidden(record)?;
    // Profiles are removed by SID, never by a client-supplied path.
    if let Some(Identity::Windows { sid }) = &record.identity {
        let text = super::child::wide(std::ffi::OsStr::new(sid))?;
        if unsafe { windows_sys::Win32::UI::Shell::DeleteProfileW(text.as_ptr(), std::ptr::null(), std::ptr::null()) }
            == 0
        {
            let error = std::io::Error::last_os_error();
            ensure!(matches!(error.raw_os_error(), Some(2 | 3)), "removing guest profile: {error}");
        }
    }
    Ok(())
}

pub(super) fn retire(config: &Config) -> anyhow::Result<()> {
    if config.kind == Kind::Node && config.root()?.try_exists()? {
        super::account::enable_guest_administration()?;
        manager(config)?.handle(&crate::service::guests::Request::Retire)?;
    }
    Ok(())
}

pub(super) fn maintain(config: Config) {
    if config.kind != Kind::Node {
        return;
    }
    std::thread::spawn(move || {
        let mut previous = None;
        loop {
            let error = manager(&config).and_then(|manager| manager.maintain()).err().map(|error| format!("{error:#}"));
            if error != previous {
                if let Some(error) = &error {
                    eprintln!("fastctx guardian guest maintenance: {error}");
                }
                previous = error;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
}
