//! Hidden local directory-service accounts, outside the interactive UID range.

use super::{
    Manager, Record,
    unix::{checked, command},
};
use anyhow::{Context as _, ensure};
use std::{collections::BTreeSet, path::Path};
pub(super) const SHELL: &str = "/usr/bin/false";

fn attribute(path: &str, name: &str) -> anyhow::Result<Option<String>> {
    let output = crate::program::service_answer(command("/usr/bin/dscl").args([".", "-read", path, name]))?;
    if !output.status.success() {
        let message = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        ensure!(
            message.contains("eDSRecordNotFound") || message.contains("eDSAttributeNotFound"),
            "cannot read directory-service attribute: {message}"
        );
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout)?;
    Ok(Some(text.split_once(':').context("dscl returned no attribute value")?.1.trim().into()))
}

fn set(path: &str, name: &str, value: &str) -> anyhow::Result<()> {
    checked(command("/usr/bin/dscl").args([".", "-create", path, name, value]))?;
    Ok(())
}

pub(super) fn create(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    let parent = manager.root.parent().context("guardian root has no parent")?;
    let _allocation = fastctx_platform::FileLock::acquire(&parent.join("accounts.lock"))?;
    let user = format!("/Users/{}", record.name);
    let group = format!("/Groups/{}", record.name);
    for path in [&user, &group] {
        let found = crate::program::service_answer(command("/usr/bin/dscl").args([".", "-read", path]))?;
        if found.status.success() {
            ensure!(
                attribute(path, "RealName")?.as_deref() == Some(record.mark.as_str()),
                "a pre-existing directory-service record has another owner"
            );
        } else {
            let message =
                format!("{}{}", String::from_utf8_lossy(&found.stdout), String::from_utf8_lossy(&found.stderr));
            ensure!(message.contains("eDSRecordNotFound"), "cannot inspect a directory-service record: {message}");
            // The first create publishes ownership before an identity exists.
            set(path, "RealName", &record.mark)?;
        }
    }
    let gid = match attribute(&group, "PrimaryGroupID")? {
        Some(gid) => gid.parse::<u32>()?,
        None => {
            let mut occupied = BTreeSet::new();
            for (kind, field) in [("/Users", "UniqueID"), ("/Groups", "PrimaryGroupID")] {
                let entries = checked(command("/usr/bin/dscl").args([".", "-list", kind, field]))?;
                for line in entries.lines() {
                    if let Some(id) = line.split_whitespace().last().and_then(|id| id.parse::<u32>().ok()) {
                        occupied.insert(id);
                    }
                }
            }
            let id = (200..500).rev().find(|id| !occupied.contains(id)).context("the system account range is full")?;
            set(&group, "PrimaryGroupID", &id.to_string())?;
            id
        }
    };
    ensure!((200..500).contains(&gid), "the guest is outside the system account range");
    set(&group, "Password", "*")?;
    set(&user, "IsHidden", "1")?;
    set(&user, "UserShell", SHELL)?;
    set(&user, "Password", "*")?;
    set(&user, "AuthenticationAuthority", ";DisabledUser;")?;
    set(&user, "NFSHomeDirectory", manager.home(record).to_str().context("the system guest home is not UTF-8")?)?;
    set(&user, "PrimaryGroupID", &gid.to_string())?;
    set(&user, "UniqueID", &gid.to_string())?;
    Ok(())
}

pub(super) fn set_active(record: &Record, active: bool) -> anyhow::Result<()> {
    set(
        &format!("/Users/{}", record.name),
        "AuthenticationAuthority",
        if active { ";basic;" } else { ";DisabledUser;" },
    )
}

pub(super) fn schedules(record: &Record) -> anyhow::Result<()> {
    let (uid, _) = super::unix::ids(record)?;
    let domain = format!("user/{uid}");
    let found = crate::program::service_answer(command("/bin/launchctl").args(["print", &domain]))?;
    if found.status.success() {
        checked(command("/bin/launchctl").args(["bootout", &domain]))?;
    } else {
        let message = String::from_utf8_lossy(&found.stderr);
        ensure!(
            message.contains("Could not find domain") || message.contains("No such process"),
            "cannot inspect the guest launch domain: {message}"
        );
    }
    super::unix::cron_and_at(record)
}

pub(super) fn delete(record: &Record) -> anyhow::Result<()> {
    let path = format!("/Users/{}", record.name);
    if let Some(mark) = attribute(&path, "RealName")? {
        ensure!(mark == record.mark, "the guest directory-service record now belongs to someone else");
        checked(command("/usr/bin/dscl").args([".", "-delete", &path]))?;
    }
    Ok(())
}

pub(super) fn delete_group(record: &Record) -> anyhow::Result<()> {
    let path = format!("/Groups/{}", record.name);
    if let Some(mark) = attribute(&path, "RealName")? {
        ensure!(mark == record.mark, "the guest group now belongs to someone else");
        checked(command(Path::new("/usr/bin/dscl")).args([".", "-delete", &path]))?;
    }
    Ok(())
}
