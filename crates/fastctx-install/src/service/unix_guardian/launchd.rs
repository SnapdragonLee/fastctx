//! A LaunchDaemon beside the user's LaunchAgent; it never enters their keychain session.

use super::{
    super::{Service, checked},
    config::Config,
};
use anyhow::ensure;
use fastctx_platform::{Permissions, publish};
use std::path::PathBuf;
use std::process::Command;

fn path(config: &Config) -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(format!("{}.guardian.plist", config.name))
}
fn target(config: &Config) -> String {
    format!("system/{}.guardian", config.name)
}
fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub(crate) fn install(service: &Service) -> anyhow::Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "installing a guardian requires root");
    let config = Config::new(service)?;
    let changed = super::installed(service)? && !super::staged(service, &crate::renewal::build()?.digest)?;
    let image = super::prepare(service)?;
    let text = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n\
        <key>Label</key><string>{}.guardian</string>\n\
        <key>ProgramArguments</key><array><string>{}</string><string>guardian</string><string>serve</string><string>--name</string><string>{}</string></array>\n\
        <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n\
        <key>ThrottleInterval</key><integer>1</integer>\n\
        <key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>\n\
        </dict></plist>\n",
        config.name,
        escape(&image.to_string_lossy()),
        config.name,
        escape(&config.root().join("service.log").to_string_lossy()),
        escape(&config.root().join("service.log").to_string_lossy())
    );
    let path = path(&config);
    let unchanged = std::fs::read(&path).ok().as_deref() == Some(text.as_bytes());
    let loaded = Command::new("/bin/launchctl").args(["print", &target(&config)]).output()?.status.success();
    if loaded && (changed || !unchanged) {
        checked(Command::new("/bin/launchctl").args(["bootout", &target(&config)]))?;
    }
    publish(&path, text.as_bytes(), Permissions::KeepExisting)?;
    if !loaded || changed || !unchanged {
        checked(Command::new("/bin/launchctl").args(["bootstrap", "system"]).arg(&path))?;
    }
    checked(Command::new("/bin/launchctl").args(["enable", &target(&config)]))?;
    checked(Command::new("/bin/launchctl").args(["kickstart", &target(&config)]))?;
    Ok(())
}

pub(crate) fn uninstall(service: &Service) -> anyhow::Result<()> {
    super::retire_guests(service)?;
    let config = Config::new(service)?;
    if !path(&config).exists() {
        return Ok(());
    }
    let loaded = Command::new("/bin/launchctl").args(["print", &target(&config)]).output()?.status.success();
    if loaded {
        checked(Command::new("/bin/launchctl").args(["bootout", &target(&config)]))?;
    }
    std::fs::remove_file(path(&config))?;
    Ok(())
}

pub(crate) fn status(service: &Service) -> anyhow::Result<super::super::Status> {
    let config = Config::new(service)?;
    let output = Command::new("/bin/launchctl").args(["print", &target(&config)]).output()?;
    Ok(super::super::Status {
        name: format!("{}.guardian", config.name),
        installed: path(&config).exists(),
        enabled: path(&config).exists(),
        state: if output.status.success() { "running" } else { "not loaded" }.into(),
        last_exit: None,
        logs: config.root().join("guardian.log").display().to_string(),
        recovery: None,
    })
}
