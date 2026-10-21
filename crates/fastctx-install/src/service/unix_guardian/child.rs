//! Node identity is dropped before exec; only its two lifetime descriptors survive.

use super::{super::Kind, config::Config};
use anyhow::Context as _;
use fastctx_platform::service_channel::{ServiceCommand, ServiceEvent};
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

pub(super) struct Child {
    pub process: std::process::Child,
    _control: Option<File>,
}

pub(super) fn spawn(config: &Config) -> anyhow::Result<Child> {
    let account = fastctx_platform::unix_account::lookup(config.uid)?.context("guardian owner no longer exists")?;
    let groups = super::super::unix_owner::groups(&account)?;
    // 2026-10-20: even a root-owned node uses the protected image, never a user path.
    let program = config.image();
    let mut command = Command::new(program);
    command
        .args(config.service().arguments_for_guardian())
        .env_clear()
        .env("HOME", &account.home)
        .env("USER", &account.name)
        .env("LOGNAME", &account.name)
        .env("SHELL", &account.shell)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .env("FASTCTX_HOME", &config.directory)
        .stdin(Stdio::null());
    let pipes = if config.kind == Kind::Node {
        let (control, reader) = UnixStream::pair()?;
        let (events, writer) = UnixStream::pair()?;
        command.args([
            "--supervised",
            "--supervisor-control",
            &reader.as_raw_fd().to_string(),
            "--supervisor-events",
            &writer.as_raw_fd().to_string(),
            "--service-identity",
            "interactive",
        ]);
        Some((control, reader, events, writer))
    } else {
        None
    };
    let descriptors = pipes.as_ref().map(|(_, reader, _, writer)| (reader.as_raw_fd(), writer.as_raw_fd()));
    let (uid, gid) = (account.uid, account.gid);
    // SAFETY: these operations run in the forked child before exec. No Rust lock is acquired.
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            fastctx_platform::close_on_exec_from(3)?;
            if let Some((reader, writer)) = descriptors {
                for fd in [reader, writer] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            Ok(())
        });
    }
    let process = command.spawn().context("starting the guardian's registered child")?;
    let control = if let Some((control, reader, mut events, writer)) = pipes {
        drop((reader, writer));
        let mut activation = control.try_clone()?;
        std::thread::spawn(move || {
            if matches!(ServiceEvent::read(&mut events), Ok(Some(ServiceEvent::Prepared))) {
                if ServiceCommand::Activate.write(&mut activation).is_err() {
                    return;
                }
                while let Ok(Some(_)) = ServiceEvent::read(&mut events) {}
            }
        });
        // SAFETY: ownership is transferred exactly once from the stream to File.
        Some(unsafe { File::from_raw_fd(control.into_raw_fd()) })
    } else {
        None
    };
    Ok(Child { process, _control: control })
}
