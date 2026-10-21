//! Linux system users have a locked password, an expired login, and a private
//! group. Activation permits only the guardian's direct credential switch.

use super::{
    Manager, Record,
    unix::{checked, command},
};
use anyhow::ensure;
pub(super) const SHELL: &str = "/usr/sbin/nologin";

pub(super) fn create(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    checked(
        command("/usr/sbin/useradd")
            .args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--no-log-init",
                "--shell",
                SHELL,
                "--password",
                "!",
                "--expiredate",
                "1",
                "--comment",
                &record.mark,
                "--home-dir",
            ])
            .arg(manager.home(record))
            .arg(&record.name),
    )?;
    Ok(())
}

pub(super) fn set_active(record: &Record, active: bool) -> anyhow::Result<()> {
    checked(command("/usr/sbin/usermod").args(["--expiredate", if active { "" } else { "1" }, &record.name]))?;
    Ok(())
}

pub(super) fn schedules(record: &Record) -> anyhow::Result<()> {
    let (uid, _) = super::unix::ids(record)?;
    let linger = std::path::Path::new("/var/lib/systemd/linger").join(&record.name);
    if linger.try_exists()? {
        checked(command("/usr/bin/loginctl").args(["disable-linger", &record.name]))?;
    }
    // Stop the per-user manager and timers even when the guest daemonized out
    // of its original job. A missing user manager needs no special treatment.
    let unit = format!("user@{uid}.service");
    checked(command("/usr/bin/systemctl").args(["--system", "stop", &unit]))?;
    super::unix::cron_and_at(record)
}

pub(super) fn delete(record: &Record) -> anyhow::Result<()> {
    checked(command("/usr/sbin/userdel").arg(&record.name))?;
    Ok(())
}

pub(super) fn delete_group(record: &Record) -> anyhow::Result<()> {
    let name = std::ffi::CString::new(record.name.as_str())?;
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut storage = vec![0 as libc::c_char; 65536];
    let mut found = std::ptr::null_mut();
    let code = unsafe { libc::getgrnam_r(name.as_ptr(), &mut entry, storage.as_mut_ptr(), storage.len(), &mut found) };
    ensure!(code == 0, "cannot inspect the guest group: {}", std::io::Error::from_raw_os_error(code));
    if found.is_null() {
        return Ok(());
    }
    let (_, gid) = super::unix::ids(record)?;
    ensure!(
        entry.gr_gid == gid && (entry.gr_mem.is_null() || unsafe { *entry.gr_mem }.is_null()),
        "the guest group now belongs to someone else"
    );
    checked(command("/usr/sbin/groupdel").arg(&record.name))?;
    Ok(())
}
