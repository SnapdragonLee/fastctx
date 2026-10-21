//! File operations belonging to the node always run after dropping root's identity.

use super::{Service, checked};
use anyhow::Context as _;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

pub(super) fn marker(service: &Service, present: bool) -> anyhow::Result<()> {
    let account = fastctx_platform::unix_account::lookup(service.uid)?.context("node owner does not exist")?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["guardian", "marker", "--dir"])
        .arg(&service.directory)
        .arg(if present { "--present" } else { "--absent" })
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", account.home)
        .env("FASTCTX_HOME", &service.directory);
    let (uid, gid) = (account.uid, account.gid);
    // 2026-10-20: root's supplementary groups must not cross into the user's file helper.
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) == -1 || libc::setgid(gid) == -1 || libc::setuid(uid) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    checked(&mut command)?;
    Ok(())
}

/// Resolves supplementary groups before fork, where NSS may allocate or acquire locks.
pub(super) fn groups(account: &fastctx_platform::unix_account::Account) -> anyhow::Result<Vec<libc::gid_t>> {
    let name = std::ffi::CString::new(account.name.as_encoded_bytes())?;
    let mut groups = vec![account.gid; 16];
    loop {
        let mut count = i32::try_from(groups.len())?;
        // SAFETY: the name and group buffer outlive the lookup; count is their actual capacity.
        let result =
            unsafe { libc::getgrouplist(name.as_ptr(), account.gid as _, groups.as_mut_ptr().cast(), &mut count) };
        if result >= 0 {
            groups.truncate(usize::try_from(count)?);
            return Ok(groups);
        }
        anyhow::ensure!(count > 0 && count as usize > groups.len(), "the account's groups could not be resolved");
        groups.resize(count as usize, account.gid);
    }
}
