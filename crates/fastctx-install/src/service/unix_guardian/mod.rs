//! Privileged Unix guardians. Their public socket accepts maintenance only.

mod channel;
mod child;
mod config;
mod guests;
pub(crate) use guests::retire as retire_guests;
#[cfg(target_os = "macos")]
mod launchd;
#[cfg(target_os = "linux")]
pub(crate) mod package;
mod runtime;

use super::Service;
use anyhow::ensure;
use config::Config;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

pub(crate) fn prepare(service: &Service) -> anyhow::Result<PathBuf> {
    let config = Config::new(service)?;
    config.prepare()?;
    let _lock = fastctx_platform::FileLock::acquire(&config.root().join("manager.lock"))?;
    let bytes = fs::read(std::env::current_exe()?)?;
    fastctx_platform::publish(&config.image(), &bytes, fastctx_platform::Permissions::KeepExisting)?;
    fs::set_permissions(config.image(), fs::Permissions::from_mode(0o755))?;
    fastctx_platform::publish(
        &config.root().join("version.json"),
        &serde_json::to_vec(env!("CARGO_PKG_VERSION"))?,
        fastctx_platform::Permissions::KeepExisting,
    )?;
    prepare_assets(&config)?;
    let _guests = fastctx_platform::FileLock::acquire(&config.root().join("guests.lock"))?;
    match fs::remove_file(config.root().join("guests-retired")) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    Ok(config.image())
}

pub(crate) fn installed(service: &Service) -> anyhow::Result<bool> {
    let config = Config::new(service)?;
    if !config.root().try_exists()? {
        return Ok(false);
    }
    Config::read(&config.name)?;
    Ok(true)
}

pub(crate) fn guests(
    service: &Service,
    request: &super::guests::Request,
) -> anyhow::Result<Vec<super::guests::Account>> {
    Ok(channel::ask(&Config::new(service)?, &channel::Request::Guests { action: request.clone() })?.accounts)
}

pub(crate) fn current(service: &Service, digest: &str) -> anyhow::Result<bool> {
    if !installed(service)? {
        return Ok(true);
    }
    let config = Config::new(service)?;
    Ok(channel::ask(&config, &channel::Request::Status)?.digest.as_deref() == Some(digest) && staged(service, digest)?)
}

pub(crate) fn staged(service: &Service, digest: &str) -> anyhow::Result<bool> {
    if !installed(service)? {
        return Ok(true);
    }
    Ok(crate::renewal::digest(&Config::new(service)?.image())? == digest)
}

pub(crate) fn adopt(service: &Service, digest: &str) -> anyhow::Result<bool> {
    if !installed(service)? {
        return Ok(false);
    }
    Ok(channel::ask(&Config::new(service)?, &channel::Request::Adopt)?.digest.as_deref() == Some(digest))
}

pub(crate) fn restart(service: &Service, digest: &str) -> anyhow::Result<()> {
    channel::ask(&Config::new(service)?, &channel::Request::Restart { digest: digest.into() })?;
    Ok(())
}

pub(crate) fn replace(service: &Service, digest: &str) -> anyhow::Result<()> {
    ensure!(crate::renewal::build()?.digest == digest, "approved guardian image differs");
    prepare(service)?;
    Ok(())
}

pub(crate) fn artifacts(service: &Service) -> anyhow::Result<Vec<PathBuf>> {
    Ok(vec![Config::new(service)?.root()])
}

pub(crate) fn registration(name: &str) -> anyhow::Result<Option<Service>> {
    config::validate_name(name)?;
    if !config::base().join(name).try_exists()? {
        return Ok(None);
    }
    Ok(Some(Config::read(name)?.service()))
}

pub fn run(name: &str) -> anyhow::Result<()> {
    runtime::run(name)
}

#[cfg(target_os = "macos")]
pub(crate) use launchd::{install, status as launchd_status, uninstall};

#[derive(serde::Serialize, serde::Deserialize)]
struct Running {
    process: fastctx_types::ProcessIdentity,
    digest: String,
    child: Option<fastctx_types::ProcessIdentity>,
}

pub(crate) fn running(service: &Service) -> anyhow::Result<bool> {
    let config = Config::new(service)?;
    let value: Option<Running> = crate::renewal::read_json(&config.root().join("running.json"))?;
    Ok(value.map(|value| fastctx_platform::is_alive(&value.process)).transpose()?.unwrap_or(false))
}

#[cfg(target_os = "linux")]
pub(crate) fn child_pid(service: &Service) -> anyhow::Result<u64> {
    let config = Config::new(service)?;
    let value: Option<Running> = crate::renewal::read_json(&config.root().join("running.json"))?;
    if let Some(value) = value
        && fastctx_platform::is_alive(&value.process)?
        && let Some(child) = value.child
        && fastctx_platform::is_alive(&child)?
    {
        return Ok(child.pid.into());
    }
    Ok(0)
}

pub(crate) fn forget(service: &Service) -> anyhow::Result<()> {
    let config = Config::new(service)?;
    if !config.root().try_exists()? {
        return Ok(());
    }
    Config::read(&config.name)?;
    retire_guests(service)?;
    for directory in ["guests", "homes"] {
        match fs::remove_dir(config.root().join(directory)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    for file in [
        "guests.lock",
        "guests-retired",
        "guests.log",
        "guests.log.1",
        "config.json",
        "fastctx",
        "version.json",
        "running.json",
        "running.lock",
        "manager.lock",
        "guardian.log",
        "guardian.log.1",
        "service.log",
        "rg",
        "LICENSE-APACHE",
        "NOTICE",
        "THIRD_PARTY_LICENSES.md",
        "prelude.bash",
        "state.bash",
    ] {
        match fs::remove_file(config.root().join(file)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    match fs::remove_file(config.socket()) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    fs::remove_dir(config.root())?;
    Ok(())
}

pub(crate) fn is_program(root: &std::path::Path, program: &std::path::Path) -> anyhow::Result<bool> {
    let base = match fs::canonicalize(config::base()) {
        Ok(base) => base,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let current = fs::canonicalize(program)?;
    if !current.starts_with(base) {
        return Ok(false);
    }
    let service = Service::new(super::Kind::Node, crate::executable::installed_path(root), root).normalized()?;
    if !installed(&service)? {
        return Ok(false);
    }
    Ok(current == fs::canonicalize(Config::new(&service)?.image())?)
}

fn prepare_assets(config: &Config) -> anyhow::Result<()> {
    super::checked(
        std::process::Command::new(config.image())
            .args(["guardian", "prepare-assets"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
    )?;
    Ok(())
}
