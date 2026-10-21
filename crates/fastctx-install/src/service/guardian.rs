//! Installing or inspecting the privileged part without changing the user's session.

use super::{Kind, Service};
pub use fastctx_types::stats::Guardian as Status;

pub fn status(service: &Service) -> Status {
    let result = inspect(service);
    match result {
        Ok((installed, running)) => {
            Status { installed, running, reason: None, install: (!installed).then(|| install_command(service)) }
        }
        Err(error) => Status {
            installed: false,
            running: false,
            reason: Some(format!("{error:#}")),
            install: Some(install_command(service)),
        },
    }
}

fn inspect(service: &Service) -> anyhow::Result<(bool, bool)> {
    #[cfg(windows)]
    {
        let status = service.status()?;
        Ok((status.installed, status.state.eq_ignore_ascii_case("running")))
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let normalized = service.normalized()?;
        let installed = super::unix_guardian::installed(&normalized)?;
        Ok((installed, installed && super::unix_guardian::running(&normalized)?))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = service;
        Ok((false, false))
    }
}

pub fn install_command(service: &Service) -> String {
    format!(
        "{}fastctx guardian install --dir {}",
        if cfg!(unix) { "sudo " } else { "" },
        fastctx_platform::shell_quote::path(&service.directory)
    )
}

/// Installs the root/SYSTEM service. The caller already holds administrator rights.
pub fn install(service: &Service) -> anyhow::Result<()> {
    anyhow::ensure!(service.kind == Kind::Node, "install a node guardian for a World directory");
    anyhow::ensure!(fastctx_platform::elevation::is_elevated()?, "installing a guardian requires administrator rights");
    #[cfg(target_os = "macos")]
    {
        if service.uid == 0 {
            service.install()?;
        } else {
            super::unix_guardian::install(&service.normalized()?)?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        service.install()?;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    for directory in super::registered_hubs(&service.directory)? {
        let hub = Service::new(Kind::Hub, &service.executable, directory);
        if hub.status()?.installed {
            hub.install()?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn serve(name: &str) -> anyhow::Result<()> {
    super::unix_guardian::run(name)
}

#[cfg(target_os = "linux")]
pub fn package_install() -> anyhow::Result<()> {
    super::unix_guardian::package::install()
}
#[cfg(target_os = "linux")]
pub fn package_uninstall() -> anyhow::Result<()> {
    super::unix_guardian::package::uninstall()
}
#[cfg(target_os = "linux")]
pub fn package_serve() -> anyhow::Result<()> {
    super::unix_guardian::package::serve()
}

/// Whether this caller is the protected program installed for its own World.
/// This permits a supervised Unix node and its tools to retain that exact image.
pub fn is_program(root: &std::path::Path, program: &std::path::Path) -> anyhow::Result<bool> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        super::unix_guardian::is_program(root, program)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (root, program);
        Ok(false)
    }
}
