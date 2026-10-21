use anyhow::ensure;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd as _;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

fn directory(path: &Path) -> anyhow::Result<File> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
    ensure!(file.metadata()?.uid() == unsafe { libc::geteuid() }, "the directory belongs to another system user");
    Ok(file)
}

pub(super) fn harden(path: &Path) -> anyhow::Result<()> {
    let file = directory(path)?;
    #[cfg(target_os = "macos")]
    unsafe {
        // Darwin mode bits do not mask extended ACL grants.
        let acl = acl_init(0);
        if acl.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = acl_set_fd_np(file.as_raw_fd(), acl, 0x100);
        let error = std::io::Error::last_os_error();
        acl_free(acl);
        if result != 0 {
            return Err(error.into());
        }
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(super) fn owner_only(path: &Path) -> anyhow::Result<bool> {
    let file = directory(path)?;
    #[cfg(target_os = "macos")]
    unsafe {
        let acl = acl_get_fd_np(file.as_raw_fd(), 0x100);
        if acl.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let checked = (|| {
            for index in 0.. {
                let mut entry = std::ptr::null_mut();
                if acl_get_entry(acl, index, &mut entry) != 0 {
                    let error = std::io::Error::last_os_error();
                    ensure!(error.raw_os_error() == Some(libc::EINVAL), "reading the directory's access list: {error}");
                    return Ok(true);
                }
                let mut tag = 0;
                ensure!(acl_get_tag_type(entry, &mut tag) == 0, "reading an ACL entry type failed");
                if tag != 0x200 {
                    return Ok(false);
                }
            }
            unreachable!()
        })();
        acl_free(acl);
        if !checked? {
            return Ok(false);
        }
    }
    // POSIX ACL named users and groups are masked by the group permission bits.
    Ok(file.metadata()?.mode() & 0o077 == 0)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_init(count: i32) -> *mut std::ffi::c_void;
    fn acl_set_fd_np(fd: i32, acl: *mut std::ffi::c_void, kind: u32) -> i32;
    fn acl_get_fd_np(fd: i32, kind: u32) -> *mut std::ffi::c_void;
    fn acl_get_entry(acl: *mut std::ffi::c_void, which: i32, entry: *mut *mut std::ffi::c_void) -> i32;
    fn acl_get_tag_type(entry: *mut std::ffi::c_void, tag: *mut u32) -> i32;
    fn acl_free(acl: *mut std::ffi::c_void) -> i32;
}
