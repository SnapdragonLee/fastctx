//! Native account APIs. The durable random description proves ownership even
//! when a crash occurs between NetUserAdd and recording the assigned SID.

use super::super::child::wide;
use crate::service::guests::{Identity, Manager, Record};
use anyhow::{Context as _, ensure};
use std::{ffi::OsStr, io, ptr};
use windows_sys::Win32::NetworkManagement::NetManagement::*;
const HIDDEN: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

fn check(code: u32) -> anyhow::Result<()> {
    ensure!(code == NERR_Success, "Windows account operation: {}", io::Error::from_raw_os_error(code as i32));
    Ok(())
}

pub(crate) fn existing(manager: &Manager, record: &Record) -> anyhow::Result<Option<Identity>> {
    let name = wide(OsStr::new(&record.name))?;
    let mut raw = ptr::null_mut();
    let code = unsafe { NetUserGetInfo(ptr::null(), name.as_ptr(), 1, &mut raw) };
    if code == NERR_UserNotFound {
        return Ok(None);
    }
    check(code)?;
    let result = (|| {
        let info = unsafe { &*raw.cast::<USER_INFO_1>() };
        let comment = if info.usri1_comment.is_null() {
            String::new()
        } else {
            let size = (0..).take_while(|&i| unsafe { *info.usri1_comment.add(i) } != 0).count();
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(info.usri1_comment, size) })
        };
        if record.identity.is_none() && comment != record.mark {
            return Err(crate::service::guests::NameOccupied.into());
        }
        // The creation marker recovers an interrupted NetUserAdd. Once saved,
        // the non-reusable SID is authoritative; editable profile text must not
        // let a guest prevent withdrawal of its already-recorded identity.
        ensure!(
            (record.identity.is_some() || comment == record.mark) && info.usri1_priv == USER_PRIV_USER,
            "this Windows account is not an ordinary guest created by the guardian"
        );
        let sid = super::super::managed::sid_of(&name)?;
        let identity = Identity::Windows { sid };
        ensure!(identity != manager.owner, "a guest cannot be the node owner");
        ensure!(record.identity.as_ref().is_none_or(|saved| saved == &identity), "the guest SID has changed");
        Ok(Some(identity))
    })();
    unsafe {
        NetApiBufferFree(raw.cast());
    }
    result
}

pub(crate) fn create(manager: &Manager, record: &Record) -> anyhow::Result<Identity> {
    if let Some(identity) = existing(manager, record)? {
        return Ok(identity);
    }
    windows_registry::LOCAL_MACHINE.create(HIDDEN)?.set_u32(&record.name, 0)?;
    let mut name = wide(OsStr::new(&record.name))?;
    let mut comment = wide(OsStr::new(&record.mark))?;
    // A blank password can be a usable credential for LogonUser's local batch
    // logon. S4U needs no password, so generate one that is never retained.
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy)?;
    let mut password: Vec<u16> = "G1!a".encode_utf16().collect();
    for byte in &mut entropy {
        password.push(u16::from(b"0123456789abcdef"[(*byte >> 4) as usize]));
        password.push(u16::from(b"0123456789abcdef"[(*byte & 15) as usize]));
        // SAFETY: a live initialized element, erased without dead-store removal.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    password.push(0);
    let info = USER_INFO_1 {
        usri1_name: name.as_mut_ptr(),
        usri1_password: password.as_mut_ptr(),
        usri1_priv: USER_PRIV_USER,
        usri1_comment: comment.as_mut_ptr(),
        usri1_flags: UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_CANT_CHANGE | UF_DONT_EXPIRE_PASSWD,
        ..Default::default()
    };
    let code = unsafe { NetUserAdd(ptr::null(), 1, (&raw const info).cast(), ptr::null_mut()) };
    for unit in &mut password {
        // SAFETY: the native call has returned and no longer reads this buffer.
        unsafe {
            std::ptr::write_volatile(unit, 0);
        }
    }
    check(code)?;
    existing(manager, record)?.context("Windows did not create the guest account")
}

pub(crate) fn verify(manager: &Manager, record: &Record) -> anyhow::Result<()> {
    ensure!(existing(manager, record)?.is_some(), "the guest account no longer exists");
    let name = wide(OsStr::new(&record.name))?;
    let allowed = fastctx_platform::account_name("S-1-5-32-545")?;
    let mut groups = ptr::null_mut();
    let (mut count, mut total) = (0, 0);
    check(unsafe {
        NetUserGetLocalGroups(
            ptr::null(),
            name.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut groups,
            MAX_PREFERRED_LENGTH,
            &mut count,
            &mut total,
        )
    })?;
    let result = (|| {
        if count != 0 {
            for group in unsafe { std::slice::from_raw_parts(groups.cast::<LOCALGROUP_USERS_INFO_0>(), count as usize) }
            {
                let size = (0..).take_while(|&i| unsafe { *group.lgrui0_name.add(i) } != 0).count();
                let group = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(group.lgrui0_name, size) });
                ensure!(group.eq_ignore_ascii_case(&allowed), "the guest has acquired another local group's rights");
            }
        }
        Ok(())
    })();
    unsafe {
        NetApiBufferFree(groups.cast());
    }
    result
}

pub(crate) fn set_active(manager: &Manager, record: &Record, active: bool) -> anyhow::Result<()> {
    verify(manager, record)?;
    let sid = super::sid(record)?;
    let group = wide(OsStr::new(&fastctx_platform::account_name("S-1-5-32-545")?))?;
    let member = wide(OsStr::new(&record.name))?;
    let info = LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname: member.as_ptr().cast_mut() };
    let code = unsafe { NetLocalGroupAddMembers(ptr::null(), group.as_ptr(), 3, (&raw const info).cast(), 1) };
    if code != windows_sys::Win32::Foundation::ERROR_MEMBER_IN_ALIAS {
        check(code)?;
    }
    super::super::policy::guest(sid)?;
    windows_registry::LOCAL_MACHINE.create(HIDDEN)?.set_u32(&record.name, 0)?;
    let name = wide(OsStr::new(&record.name))?;
    let info = USER_INFO_1008 {
        usri1008_flags: UF_SCRIPT
            | UF_NORMAL_ACCOUNT
            | UF_PASSWD_CANT_CHANGE
            | UF_DONT_EXPIRE_PASSWD
            | if active { 0 } else { UF_ACCOUNTDISABLE },
    };
    check(unsafe { NetUserSetInfo(ptr::null(), name.as_ptr(), 1008, (&raw const info).cast(), ptr::null_mut()) })
}

pub(crate) fn delete(record: &Record) -> anyhow::Result<()> {
    let name = wide(OsStr::new(&record.name))?;
    super::super::policy::delete_guest(super::sid(record)?)?;
    let code = unsafe { NetUserDel(ptr::null(), name.as_ptr()) };
    if code != NERR_UserNotFound {
        check(code)?;
    }
    Ok(())
}

pub(super) fn delete_hidden(record: &Record) -> anyhow::Result<()> {
    if let Err(error) = windows_registry::LOCAL_MACHINE.create(HIDDEN)?.remove_value(&record.name) {
        ensure!(error.code().0 == 0x80070002u32 as i32, "removing the hidden guest entry: {error}");
    }
    Ok(())
}

pub(crate) fn name_used(name: &str) -> anyhow::Result<bool> {
    let name = wide(OsStr::new(name))?;
    let mut raw = ptr::null_mut();
    let code = unsafe { NetUserGetInfo(ptr::null(), name.as_ptr(), 0, &mut raw) };
    if code == NERR_UserNotFound {
        let code = unsafe { NetLocalGroupGetInfo(ptr::null(), name.as_ptr(), 0, &mut raw) };
        if code == NERR_GroupNotFound {
            return Ok(false);
        }
        check(code)?;
    } else {
        check(code)?;
    }
    unsafe {
        NetApiBufferFree(raw.cast());
    }
    Ok(true)
}
