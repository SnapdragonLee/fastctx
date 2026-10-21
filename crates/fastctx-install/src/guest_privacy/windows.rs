use anyhow::ensure;
use std::os::windows::io::AsHandle as _;
use std::{
    fs::{File, OpenOptions},
    os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        SetSecurityInfo,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
        GetAce, GetAclInformation, GetSecurityDescriptorDacl, INHERIT_ONLY_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT},
};

fn directory(path: &Path, edit: bool) -> anyhow::Result<File> {
    use std::os::windows::fs::MetadataExt as _;
    let file = OpenOptions::new()
        .access_mode(0x20000 | if edit { 0x40000 } else { 0 })
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_dir() && metadata.file_attributes() & 0x400 == 0, "the path is not a plain directory");
    let owner = fastctx_platform::file_owner_sid(file.as_handle())?;
    ensure!(
        owner == fastctx_platform::current_user_sid()?
            || owner == "S-1-5-32-544" && fastctx_platform::elevation::is_elevated()?,
        "the directory belongs to another system user"
    );
    Ok(file)
}

pub(super) fn harden(path: &Path) -> anyhow::Result<()> {
    let file = directory(path, true)?;
    let owner = fastctx_platform::current_user_sid()?;
    let text: Vec<u16> = format!("D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)").encode_utf16().chain([0]).collect();
    let mut descriptor = ptr::null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, ptr::null_mut())
        } != 0,
        "cannot prepare the private directory access list"
    );
    let result = (|| {
        let (mut present, mut defaulted, mut acl) = (0, 0, ptr::null_mut());
        ensure!(
            unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } != 0
                && present != 0,
            "private directory access list is missing"
        );
        let code = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null_mut(),
            )
        };
        ensure!(code == 0, "making the directory private: {}", std::io::Error::from_raw_os_error(code as i32));
        Ok(())
    })();
    unsafe {
        LocalFree(descriptor);
    }
    result
}

pub(super) fn owner_only(path: &Path) -> anyhow::Result<bool> {
    let file = directory(path, false)?;
    let owner = fastctx_platform::current_user_sid()?;
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    ensure!(code == 0, "reading home directory permissions: {}", std::io::Error::from_raw_os_error(code as i32));
    let result = (|| {
        if acl.is_null() {
            return Ok(false);
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        ensure!(
            unsafe {
                GetAclInformation(acl, (&raw mut info).cast(), std::mem::size_of_val(&info) as u32, AclSizeInformation)
            } != 0,
            "cannot read the home directory access list"
        );
        for index in 0..info.AceCount {
            let mut entry = ptr::null_mut();
            ensure!(unsafe { GetAce(acl, index, &mut entry) } != 0, "cannot read a home directory permission");
            let header = unsafe { &*entry.cast::<ACE_HEADER>() };
            if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
                continue;
            }
            // Deny entries grant nobody access. Other allow forms are not an
            // owner-only access list and are reported without guessing rights.
            if header.AceType == 1 {
                continue;
            }
            if header.AceType != 0 {
                return Ok(false);
            }
            let ace = unsafe { &*entry.cast::<ACCESS_ALLOWED_ACE>() };
            let mut text = ptr::null_mut();
            ensure!(
                unsafe { ConvertSidToStringSidW((&raw const ace.SidStart).cast_mut().cast(), &mut text) } != 0,
                "cannot read a home directory trustee"
            );
            let size = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
            let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, size) });
            unsafe {
                LocalFree(text.cast());
            }
            if sid != owner && !["S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"].contains(&sid.as_str()) {
                return Ok(false);
            }
        }
        Ok(true)
    })();
    unsafe {
        LocalFree(descriptor);
    }
    result
}
