//! Unix account checks and filesystem ownership, shared by both native managers.

#[cfg(target_os = "linux")]
use super::linux as system;
#[cfg(target_os = "macos")]
use super::macos as system;
use super::{Identity, Manager, Record};
use anyhow::{Context as _, ensure};
use std::{
    ffi::{CStr, CString, OsStr},
    fs,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
        process::CommandExt as _,
    },
    path::Path,
    process::Command,
};

pub(crate) fn prepare(manager: &Manager) -> anyhow::Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "guest administration requires root");
    directory(&manager.root.join("guests"), 0, 0, 0o700)?;
    directory(&manager.homes, 0, 0, 0o755)
}

pub(crate) fn create(manager: &Manager, record: &Record) -> anyhow::Result<Identity> {
    if let Some(identity) = existing(manager, record)? {
        return Ok(identity);
    }
    system::create(manager, record)?;
    existing(manager, record)?.context("the system did not create the guest account")
}

pub(crate) fn existing(manager: &Manager, record: &Record) -> anyhow::Result<Option<Identity>> {
    let name = CString::new(record.name.as_str())?;
    let mut storage = vec![0 as libc::c_char; 65536];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: the caller owns all output buffers until their fields are copied.
    let code = unsafe { libc::getpwnam_r(name.as_ptr(), &mut entry, storage.as_mut_ptr(), storage.len(), &mut found) };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code).into());
    }
    if found.is_null() {
        return Ok(None);
    }
    let text = |pointer: *const libc::c_char| -> &[u8] {
        if pointer.is_null() { b"" } else { unsafe { CStr::from_ptr(pointer) }.to_bytes() }
    };
    if record.identity.is_none() && text(entry.pw_gecos) != record.mark.as_bytes() {
        return Err(super::NameOccupied.into());
    }
    let identity = Identity::Unix { uid: entry.pw_uid, gid: entry.pw_gid };
    ensure!(
        entry.pw_uid != 0 && entry.pw_gid != 0 && identity != manager.owner,
        "a guest must be an ordinary separate account"
    );
    if let Identity::Unix { uid, gid } = manager.owner {
        ensure!(entry.pw_uid != uid && entry.pw_gid != gid, "a guest cannot share the node owner's identity or group");
    }
    ensure!(text(entry.pw_gecos) == record.mark.as_bytes(), "{} was not created by this guardian", record.name);
    ensure!(text(entry.pw_dir) == manager.home(record).as_os_str().as_bytes(), "the guest account's home has changed");
    ensure!(text(entry.pw_shell) == system::SHELL.as_bytes(), "the guest account's login shell has changed");
    ensure!(
        record.identity.as_ref().is_none_or(|saved| saved == &identity),
        "the guest account's system identity has changed"
    );
    let account = fastctx_platform::unix_account::lookup(entry.pw_uid)?.context("guest account disappeared")?;
    let groups = crate::service::unix_owner::groups(&account)?;
    ensure!(
        groups.iter().all(|gid| *gid == entry.pw_gid || cfg!(target_os = "macos") && [12, 61].contains(gid)),
        "the guest has acquired another group's rights"
    );
    Ok(Some(identity))
}

pub(crate) fn verify(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    ensure!(existing(manager, record)?.is_some(), "the guest account no longer exists");
    Ok(())
}

pub(crate) fn ids(record: &Record) -> anyhow::Result<(u32, u32)> {
    match record.identity {
        Some(Identity::Unix { uid, gid }) if uid != 0 && gid != 0 => Ok((uid, gid)),
        _ => anyhow::bail!("the guest has no ordinary Unix identity"),
    }
}

pub(crate) fn prepare_home(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    let (_, gid) = ids(record)?;
    // The account cannot install ~/.ssh/authorized_keys or replace its rooms.
    // Each room, which becomes HOME for work, belongs wholly to the guest.
    directory(&manager.home(record), 0, gid, 0o750)
}

pub(crate) fn room(manager: &Manager, record: &Record, room: &fastctx_types::ResidentId) -> anyhow::Result<()> {
    prepare_home(manager, record)?;
    let (uid, gid) = ids(record)?;
    let path = manager.home(record).join(room.as_str());
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(metadata.is_dir() && metadata.uid() == uid, "guest room is not its own directory");
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => directory(&path, uid, gid, 0o700),
        Err(error) => Err(error.into()),
    }
}

fn directory(path: &Path, uid: u32, gid: u32, mode: u32) -> anyhow::Result<()> {
    let created = match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    if created {
        let name = CString::new(path.as_os_str().as_bytes())?;
        // The parent is root-owned and not writable by clients.
        if unsafe { libc::chown(name.as_ptr(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.gid() == gid && metadata.mode() & 0o777 == mode,
        "{} is not the protected guest directory",
        path.display()
    );
    Ok(())
}

pub(crate) fn set_active(manager: &Manager, record: &Record, active: bool) -> anyhow::Result<()> {
    verify(manager, record)?;
    system::set_active(record, active)
}

pub(crate) fn stop(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    verify(manager, record)?;
    signal(record, libc::SIGSTOP)?;
    signal(record, libc::SIGKILL)?;
    // A frozen user manager cannot acknowledge a scheduler shutdown. End it
    // first, then remove restart sources and any process they already queued.
    // Locking remains durable if a scheduler refuses cleanup.
    let schedules = system::schedules(record);
    let killed = signal(record, libc::SIGKILL);
    schedules?;
    killed
}

pub(crate) fn delete(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    if existing(manager, record)?.is_some() {
        system::delete(record)?;
    }
    #[cfg(target_os = "macos")]
    system::delete(record)?;
    system::delete_group(record)
}

fn signal(record: &Record, signal: i32) -> anyhow::Result<()> {
    let mut command = command("/usr/bin/true");
    identity(&mut command, record)?;
    // SAFETY: only async-signal-safe operations after fork. Identity is already
    // dropped by the previous pre_exec hook, so the kernel protects other users.
    unsafe {
        command.pre_exec(move || {
            if libc::kill(-1, signal) != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
            Ok(())
        });
    }
    checked(&mut command)?;
    Ok(())
}

pub(crate) fn identity(command: &mut Command, record: &Record) -> anyhow::Result<()> {
    let (uid, gid) = ids(record)?;
    // SAFETY: no allocation, lock, or filesystem lookup occurs in the child.
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            fastctx_platform::close_on_exec_from(3)
        });
    }
    Ok(())
}

pub(crate) fn command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear().env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").env("LANG", "C").env("HOME", "/").current_dir("/");
    command
}

pub(crate) fn checked(command: &mut Command) -> anyhow::Result<String> {
    let output = crate::program::service_answer(command)?;
    ensure!(
        output.status.success(),
        "{} failed: {}{}",
        command.get_program().to_string_lossy(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

pub(crate) fn cron_and_at(record: &Record) -> anyhow::Result<()> {
    let cron = Path::new("/usr/bin/crontab");
    if cron.exists() {
        let found = crate::program::service_answer(command(cron).args(["-u", &record.name, "-l"]))?;
        if found.status.success() {
            checked(command(cron).args(["-u", &record.name, "-r"]))?;
        } else {
            let message = String::from_utf8_lossy(&found.stderr);
            ensure!(message.contains("no crontab for"), "cannot inspect the guest crontab: {message}");
        }
    }
    let atq = Path::new("/usr/bin/atq");
    if atq.exists() {
        let mut list = command(atq);
        identity(&mut list, record)?;
        let pending = checked(&mut list)?;
        for line in pending.lines().filter(|line| !line.trim().is_empty()) {
            let id = line.split_whitespace().next().context("atq returned no job id")?;
            ensure!(id.bytes().all(|byte| byte.is_ascii_digit()), "atq returned an invalid job id");
            let mut remove = command("/usr/bin/atrm");
            remove.arg(id);
            identity(&mut remove, record)?;
            checked(&mut remove)?;
        }
    }
    Ok(())
}

pub(crate) fn name_used(name: &str) -> anyhow::Result<bool> {
    let name = CString::new(name)?;
    let mut storage = vec![0 as libc::c_char; 65536];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let code = unsafe { libc::getpwnam_r(name.as_ptr(), &mut entry, storage.as_mut_ptr(), storage.len(), &mut found) };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code).into());
    }
    if !found.is_null() {
        return Ok(true);
    }
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut group_found = std::ptr::null_mut();
    let code =
        unsafe { libc::getgrnam_r(name.as_ptr(), &mut group, storage.as_mut_ptr(), storage.len(), &mut group_found) };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code).into());
    }
    Ok(!group_found.is_null())
}
