//! The one-time privileged installation, including headless upgrades.

use clap::{Args, Subcommand};
use fastctx_install::service::{Kind, Service, guardian};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum Guardian {
    /// Install the system guardian once, as administrator or with sudo.
    Install(Owner),
    /// Inspect this World's guardian without starting or installing anything.
    Status(Owner),
    #[command(hide = true)]
    Guests(Owner),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(hide = true)]
    PrepareAssets,
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    PackageInstall,
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    PackageUninstall,
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    PackageServe,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(hide = true)]
    Marker {
        #[arg(long, value_parser = crate::paths::parser())]
        dir: PathBuf,
        #[arg(long, conflicts_with = "absent")]
        present: bool,
        #[arg(long, required_unless_present = "present")]
        absent: bool,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        name: String,
    },
}

#[derive(Args)]
pub struct Owner {
    /// Ask the operating system for administrator approval at the screen.
    #[arg(long)]
    graphical: bool,
    #[arg(long, value_parser = crate::paths::parser())]
    dir: Option<PathBuf>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(long)]
    uid: Option<u32>,
    #[cfg(windows)]
    #[arg(long)]
    user_sid: Option<String>,
}

pub fn run(command: Guardian) -> anyhow::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if matches!(command, Guardian::PrepareAssets) {
        use std::os::unix::fs::PermissionsExt as _;
        anyhow::ensure!(fastctx_platform::elevation::is_elevated()?, "preparing a protected image requires root");
        let executable = std::env::current_exe()?;
        let directory = executable.parent().ok_or_else(|| anyhow::anyhow!("the image has no parent"))?;
        fastctx_ripgrep::place(directory)?;
        fastctx_hands::run::shell::ensure_prelude(directory)?;
        std::fs::set_permissions(directory.join("rg"), std::fs::Permissions::from_mode(0o755))?;
        for name in ["prelude.bash", "state.bash"] {
            std::fs::set_permissions(directory.join(name), std::fs::Permissions::from_mode(0o644))?;
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    match command {
        Guardian::PackageInstall => return guardian::package_install(),
        Guardian::PackageUninstall => return guardian::package_uninstall(),
        Guardian::PackageServe => return guardian::package_serve(),
        _ => {}
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Guardian::Serve { name } = &command {
        return guardian::serve(name);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Guardian::Marker { dir, present, .. } = &command {
        let world = fastctx_types::layout::WorldDir::under(dir);
        if *present {
            fastctx_platform::ensure_private_dir(world.path())?;
            fastctx_platform::publish(&world.node_service(), b"", fastctx_platform::Permissions::Private)?;
        } else {
            match std::fs::remove_file(world.node_service()) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
                _ => {}
            }
        }
        return Ok(());
    }
    let install = matches!(command, Guardian::Install(_));
    let guests = matches!(command, Guardian::Guests(_));
    let owner = match command {
        Guardian::Install(owner) | Guardian::Status(owner) | Guardian::Guests(owner) => owner,
        #[cfg(target_os = "linux")]
        Guardian::PackageInstall | Guardian::PackageUninstall | Guardian::PackageServe => unreachable!(),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Guardian::Serve { .. } | Guardian::Marker { .. } | Guardian::PrepareAssets => unreachable!(),
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let uid = owner
        .uid
        .or_else(|| std::env::var("SUDO_UID").ok().and_then(|uid| uid.parse().ok()))
        .unwrap_or(fastctx_platform::user_id().unwrap_or(0));
    let directory = match owner.dir {
        Some(directory) => directory,
        None => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                if std::env::var_os("FASTCTX_HOME").is_some() {
                    fastctx_platform::fastctx_root()?
                } else {
                    let account = fastctx_platform::unix_account::lookup(uid)?
                        .ok_or_else(|| anyhow::anyhow!("user {uid} has no account record"))?;
                    fastctx_platform::fastctx_root_in(std::path::Path::new(&account.home))
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                fastctx_platform::fastctx_root()?
            }
        }
    };
    let service = Service::new(Kind::Node, fastctx_install::executable::installed_path(&directory), &directory);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let service = Service { uid, ..service };
    #[cfg(windows)]
    let service = Service { user_sid: owner.user_sid, ..service };
    if guests {
        use std::io::Read as _;
        let mut bytes = Vec::new();
        std::io::stdin().take(65537).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 65536, "guardian request exceeds its limit");
        let request = serde_json::from_slice(&bytes)?;
        let accounts = fastctx_install::service::guests::call(&service, &request)?;
        println!("{}", serde_json::to_string(&accounts)?);
        return Ok(());
    }
    if install {
        install_here(&service, owner.graphical)?;
    }
    println!("{}", serde_json::to_string_pretty(&guardian::status(&service))?);
    Ok(())
}

/// An explicit local action requests one system dialog; headless installs use sudo.
pub(crate) fn install_here(service: &Service, graphical: bool) -> anyhow::Result<()> {
    if fastctx_platform::elevation::is_elevated()? {
        return guardian::install(service);
    }
    anyhow::ensure!(
        graphical,
        "installing the guardian requires administrator rights: {}",
        guardian::install_command(service)
    );
    let program = std::env::current_exe()?;
    let mut args: Vec<std::ffi::OsString> =
        vec!["guardian".into(), "install".into(), "--dir".into(), service.directory.clone().into_os_string()];
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    args.extend(["--uid".into(), service.uid.to_string().into()]);
    #[cfg(windows)]
    args.extend([
        "--user-sid".into(),
        service.user_sid.clone().unwrap_or(fastctx_platform::current_user_sid()?).into(),
    ]);
    #[cfg(target_os = "linux")]
    let code = std::process::Command::new("pkexec").arg(&program).args(&args).status()?.code().unwrap_or(1) as u32;
    #[cfg(any(windows, target_os = "macos"))]
    let code = fastctx_platform::elevation::run_elevated(&program, &args)?;
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let code = {
        let _ = (program, args);
        1
    };
    anyhow::ensure!(code == 0, "installing the guardian failed (exit {code})");
    Ok(())
}
