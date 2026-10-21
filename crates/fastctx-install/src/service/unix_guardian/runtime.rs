//! A small root service: authenticated maintenance and an explicitly owned child.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt as _;
use std::process::Command;
use std::time::Duration;

use super::super::Kind;
use super::{
    channel::{self, Reply, Request},
    config::{self, Config},
};
use anyhow::{Context as _, ensure};
use fastctx_platform::{FileLock, Permissions, publish};

pub(super) fn run(name: &str) -> anyhow::Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "the guardian must run as root");
    let config = Config::read(name)?;
    let _lease = FileLock::acquire(&config.root().join("running.lock"))?;
    config::prepare_directory(config::socket_base())?;
    match fs::remove_file(config.socket()) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let listener = UnixListener::bind(config.socket())?;
    // Only OS peer credentials authorize a call; the socket's path conveys no authority.
    fs::set_permissions(config.socket(), fs::Permissions::from_mode(0o666))?;
    let log = fastctx_platform::rolling_log::RollingLog::open(&config.root().join("guardian.log"))?;
    let mut child = if cfg!(target_os = "linux") || config.kind == Kind::Hub || config.uid == 0 {
        Some(super::child::spawn(&config)?)
    } else {
        None
    };
    record(&config, child.as_ref())?;
    super::guests::maintain(&config);
    listener.set_nonblocking(true)?;
    loop {
        if let Some(process) = &mut child
            && let Some(status) = process.process.try_wait()?
        {
            log.write(format!("child exited {status}; restoring it\n").as_bytes())?;
            child = Some(super::child::spawn(&config)?);
            record(&config, child.as_ref())?;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                channel::configure(&stream)?;
                let result = (|| {
                    let peer = channel::peer_uid(&stream)?;
                    // 2026-10-20: a guest cannot act as the node by supplying an owner UID.
                    ensure!(peer == config.requester || peer == 0, "this account does not own the guardian");
                    let request: Request = channel::receive(&mut stream)?;
                    match request {
                        Request::Status => Ok((Some(crate::renewal::build()?.digest), false, vec![])),
                        Request::Guests { action } => {
                            Ok((None, false, super::guests::manager(&config)?.handle(&action)?))
                        }
                        Request::Adopt => {
                            let digest = adopt(&config)?;
                            log.write(format!("adopted signed release image {digest}\n").as_bytes())?;
                            Ok((Some(digest), false, vec![]))
                        }
                        Request::Restart { digest } => {
                            ensure!(
                                crate::renewal::digest(&config.image())? == digest,
                                "the requested guardian image is not staged"
                            );
                            Ok((Some(digest), true, vec![]))
                        }
                    }
                })();
                let (reply, restart) = match result {
                    Ok((digest, restart, accounts)) => (Reply { digest, error: None, accounts }, restart),
                    Err(error) => (Reply { digest: None, error: Some(format!("{error:#}")), accounts: vec![] }, false),
                };
                if let Err(error) = channel::send(&mut stream, &reply) {
                    log.write(format!("reply failed: {error:#}\n").as_bytes())?;
                }
                if restart {
                    if let Some(mut process) = child.take() {
                        process.process.kill()?;
                        process.process.wait()?;
                    }
                    // The fixed image and arguments are read only from the protected registration.
                    let error = Command::new(config.image())
                        .args(["guardian", "serve", "--name", &config.name])
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                        .exec();
                    return Err(error.into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn adopt(config: &Config) -> anyhow::Result<String> {
    let _lock = FileLock::acquire(&config.root().join("manager.lock"))?;
    let bytes = fs::read(&config.executable)?;
    let signature = fs::read_to_string(crate::renewal::signature_of(&config.executable))
        .context("the World program has no official signature; an administrator must install it")?;
    let version = fastctx_update::verify::signed_version(&signature).context("the signature names no release")?;
    fastctx_update::verify::bytes(&bytes, &signature, &version).map_err(anyhow::Error::msg)?;
    let previous: Option<String> = crate::renewal::read_json(&config.root().join("version.json"))?;
    let previous = previous.as_deref().unwrap_or(env!("CARGO_PKG_VERSION"));
    ensure!(
        fastctx_types::update::release(&version) > fastctx_types::update::release(previous)
            && fastctx_types::update::release(&version) > fastctx_types::update::release(env!("CARGO_PKG_VERSION")),
        "{version} is not newer than this guardian's {previous}"
    );
    // The verified bytes are the bytes published; the user path is never opened again.
    publish(&config.image(), &bytes, Permissions::KeepExisting)?;
    fs::set_permissions(config.image(), fs::Permissions::from_mode(0o755))?;
    super::prepare_assets(config)?;
    publish(&config.root().join("version.json"), &serde_json::to_vec(&version)?, Permissions::KeepExisting)?;
    Ok(crate::renewal::digest(&config.image())?)
}

fn record(config: &Config, child: Option<&super::child::Child>) -> anyhow::Result<()> {
    publish(
        &config.root().join("running.json"),
        &serde_json::to_vec(&super::Running {
            process: fastctx_platform::current_identity()?,
            digest: crate::renewal::build()?.digest,
            child: child.map(|child| fastctx_platform::identity_of(child.process.id())).transpose()?.flatten(),
        })?,
        Permissions::KeepExisting,
    )?;
    Ok(())
}
