//! Stop every process with the guest SID, including detached and scheduled work.
//! An open process handle pins identity across the check and termination.

use anyhow::ensure;
use std::os::windows::io::AsHandle as _;
use std::{
    io,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    Security::TOKEN_QUERY,
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
        },
        Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
            TerminateProcess, WaitForSingleObject,
        },
    },
};

pub(super) fn terminate(sid: &str) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut killed = false;
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        ensure!(raw != INVALID_HANDLE_VALUE, "enumerating processes: {}", io::Error::last_os_error());
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
        while found != 0 {
            if entry.th32ProcessID != 0 {
                let raw = unsafe {
                    OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                        0,
                        entry.th32ProcessID,
                    )
                };
                if !raw.is_null() {
                    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
                    let mut token = ptr::null_mut();
                    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } != 0 {
                        let token = unsafe { OwnedHandle::from_raw_handle(token) };
                        if fastctx_platform::token_user_sid(token.as_handle())? == sid {
                            killed = true;
                            if unsafe { TerminateProcess(process.as_raw_handle(), 1) } == 0 {
                                ensure!(
                                    unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } == WAIT_OBJECT_0,
                                    "terminating a guest process: {}",
                                    io::Error::last_os_error()
                                );
                            }
                            ensure!(
                                unsafe { WaitForSingleObject(process.as_raw_handle(), 5000) } == WAIT_OBJECT_0,
                                "a guest process did not exit"
                            );
                        }
                    } else {
                        let error = io::Error::last_os_error();
                        ensure!(
                            unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } == WAIT_OBJECT_0,
                            "identifying a process during guest withdrawal: {error}"
                        );
                    }
                } else {
                    let error = io::Error::last_os_error();
                    ensure!(
                        matches!(error.raw_os_error(), Some(code) if code == ERROR_INVALID_PARAMETER as i32 || code == ERROR_ACCESS_DENIED as i32),
                        "opening a process: {error}"
                    );
                }
            }
            found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
        }
        ensure!(
            io::Error::last_os_error().raw_os_error() == Some(ERROR_NO_MORE_FILES as i32),
            "process enumeration ended unexpectedly"
        );
        if !killed {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "guest processes keep restarting during withdrawal");
    }
}
