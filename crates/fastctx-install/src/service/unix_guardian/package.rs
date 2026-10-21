//! Debian's one root installation enrolls each desktop user through OS credentials.
//! No account, executable or service name is accepted from the enrolling client.

use super::super::{Service, checked};
use super::{channel, config};
use anyhow::{Context as _, ensure};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;

const UNIT: &str = "fastctx-guardian-enrollment.service";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    #[serde(with = "config::native_path")]
    directory: PathBuf,
}

fn root() -> PathBuf {
    config::base().join("package")
}
fn socket() -> PathBuf {
    config::socket_base().join("enroll.sock")
}

pub(crate) fn install() -> anyhow::Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "the package installation requires root");
    config::prepare_directory(config::base())?;
    config::prepare_directory(&root())?;
    let image = root().join("fastctx");
    fastctx_platform::publish(
        &image,
        &fs::read(std::env::current_exe()?)?,
        fastctx_platform::Permissions::KeepExisting,
    )?;
    fs::set_permissions(&image, fs::Permissions::from_mode(0o755))?;
    let unit = format!(
        "# fastctx guardian enrollment v1\n[Unit]\nDescription=Fastctx guardian enrollment\nStartLimitIntervalSec=0\n\n[Service]\nExecStart={} guardian package-serve\nUser=root\nRestart=always\nRestartSec=1\n\n[Install]\nWantedBy=multi-user.target\n",
        image.display()
    );
    fastctx_platform::publish(
        &PathBuf::from("/etc/systemd/system").join(UNIT),
        unit.as_bytes(),
        fastctx_platform::Permissions::KeepExisting,
    )?;
    let watchdog = super::super::linux_watchdog::Watchdog::new(UNIT, "# fastctx guardian enrollment v1\n");
    watchdog.write(UNIT, super::super::linux::manager_version()?)?;
    super::super::linux::systemctl(&["daemon-reload"])?;
    super::super::linux::systemctl(&["enable", UNIT])?;
    super::super::linux::systemctl(&["restart", UNIT])?;
    watchdog.start()?;
    super::super::linux::upgrade_installed()?;
    Ok(())
}

pub(crate) fn uninstall() -> anyhow::Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "the package removal requires root");
    let unit = PathBuf::from("/etc/systemd/system").join(UNIT);
    if !unit.exists() {
        return Ok(());
    }
    super::super::linux::systemctl(&["disable", UNIT])?;
    let watchdog = super::super::linux_watchdog::Watchdog::new(UNIT, "# fastctx guardian enrollment v1\n");
    watchdog.stop()?;
    super::super::linux::systemctl(&["stop", UNIT])?;
    watchdog.delete()?;
    fs::remove_file(unit)?;
    super::super::linux::systemctl(&["daemon-reload"])?;
    match fs::remove_file(socket()) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    fs::remove_file(root().join("fastctx"))?;
    fs::remove_dir(root())?;
    Ok(())
}

pub(crate) fn enroll(service: &Service) -> anyhow::Result<bool> {
    let mut stream = match UnixStream::connect(socket()) {
        Ok(stream) => stream,
        Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => {
            return Ok(false);
        }
        Err(error) => return Err(error.into()),
    };
    channel::configure(&stream)?;
    ensure!(channel::peer_uid(&stream)? == 0, "the enrollment service is not root");
    channel::send(&mut stream, &Enrollment { directory: service.directory.clone() })?;
    let reply: channel::Reply = channel::receive(&mut stream)?;
    if let Some(error) = reply.error {
        anyhow::bail!("{error}");
    }
    Ok(true)
}

pub(crate) fn serve() -> anyhow::Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "the enrollment service must run as root");
    config::check_directory(&root())?;
    config::prepare_directory(config::socket_base())?;
    match fs::remove_file(socket()) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let listener = UnixListener::bind(socket())?;
    fs::set_permissions(socket(), fs::Permissions::from_mode(0o666))?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        channel::configure(&stream)?;
        let result = (|| {
            let uid = channel::peer_uid(&stream)?;
            let owner =
                fastctx_platform::unix_account::lookup(uid)?.context("the enrolling account no longer exists")?;
            // 2026-10-20: generated guest accounts cannot enroll a second privileged broker.
            ensure!(!owner.name.to_string_lossy().starts_with("fxg"), "guest accounts cannot enroll a World");
            let enrollment: Enrollment = channel::receive(&mut stream)?;
            ensure!(enrollment.directory.is_absolute(), "the World directory must be absolute");
            let directory = fs::canonicalize(enrollment.directory)?;
            ensure!(fs::metadata(&directory)?.uid() == uid, "the World directory belongs to another account");
            // A fixed protected program registers a service for the authenticated UID alone.
            checked(
                Command::new(root().join("fastctx"))
                    .args(["guardian", "install", "--uid", &uid.to_string(), "--dir"])
                    .arg(directory)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            )?;
            Ok::<_, anyhow::Error>(())
        })();
        let reply =
            channel::Reply { digest: None, error: result.err().map(|error| format!("{error:#}")), accounts: vec![] };
        if let Err(error) = channel::send(&mut stream, &reply) {
            eprintln!("enrollment reply failed: {error:#}");
        }
    }
    Ok(())
}
