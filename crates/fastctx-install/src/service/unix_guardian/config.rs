//! Root-owned launch descriptions. No client chooses a privileged executable.

use std::fs;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, ensure};
use serde::{Deserialize, Serialize};

use super::super::{Kind, Service};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Config {
    pub name: String,
    pub kind: Kind,
    pub uid: u32,
    pub requester: u32,
    #[serde(with = "native_path")]
    pub executable: PathBuf,
    #[serde(with = "native_path")]
    pub directory: PathBuf,
}

pub(super) fn base() -> &'static Path {
    if cfg!(target_os = "macos") {
        Path::new("/var/db/fastctx-guardians")
    } else {
        Path::new("/var/lib/fastctx-guardians")
    }
}

pub(super) fn validate_name(name: &str) -> anyhow::Result<()> {
    ensure!(
        name.starts_with("fastctx-service-")
            && name.len() <= 96
            && name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "invalid guardian registration"
    );
    Ok(())
}

impl Config {
    pub fn new(service: &Service) -> anyhow::Result<Self> {
        let name = service.id(&service.uid.to_le_bytes());
        validate_name(&name)?;
        let requester = if service.kind == Kind::Hub { fs::metadata(&service.directory)?.uid() } else { service.uid };
        Ok(Self {
            name,
            kind: service.kind,
            uid: service.uid,
            requester,
            executable: service.executable.clone(),
            directory: service.directory.clone(),
        })
    }

    pub fn root(&self) -> PathBuf {
        base().join(&self.name)
    }
    pub fn image(&self) -> PathBuf {
        self.root().join("fastctx")
    }
    pub fn socket(&self) -> PathBuf {
        // Darwin's sockaddr_un holds 104 bytes; the protected directory's name is longer.
        let digest = self.name.rsplit('-').next().expect("validated name");
        socket_base().join(format!("{}.sock", &digest[..32]))
    }

    pub fn service(&self) -> Service {
        Service { uid: self.uid, ..Service::new(self.kind, &self.executable, &self.directory) }
    }

    pub fn read(name: &str) -> anyhow::Result<Self> {
        validate_name(name)?;
        check_directory(base())?;
        let root = base().join(name);
        check_directory(&root)?;
        let file = root.join("config.json");
        let metadata = fs::symlink_metadata(&file)?;
        ensure!(
            metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "guardian configuration is not protected"
        );
        let value: Self = serde_json::from_slice(&fs::read(&file)?)?;
        ensure!(
            value.name == name && value.service().id(&value.uid.to_le_bytes()) == name,
            "guardian configuration does not match its registration"
        );
        ensure!(value.executable.is_absolute() && value.directory.is_absolute(), "guardian paths must be absolute");
        ensure!(value.kind != Kind::Hub || value.uid == 0, "a hub must run as root");
        Ok(value)
    }

    pub fn prepare(&self) -> anyhow::Result<()> {
        ensure!(unsafe { libc::geteuid() } == 0, "installing a guardian requires root");
        prepare_directory(base())?;
        prepare_directory(&self.root())?;
        prepare_directory(socket_base())?;
        fastctx_platform::publish(
            &self.root().join("config.json"),
            &serde_json::to_vec(self)?,
            fastctx_platform::Permissions::KeepExisting,
        )?;
        fs::set_permissions(self.root().join("config.json"), fs::Permissions::from_mode(0o644))?;
        Ok(())
    }
}

pub(super) fn socket_base() -> &'static Path {
    if cfg!(target_os = "macos") {
        Path::new("/var/run/fastctx-guardians")
    } else {
        Path::new("/run/fastctx-guardians")
    }
}

pub(super) fn check_directory(path: &Path) -> anyhow::Result<()> {
    // 2026-10-20: never repair a pre-existing attacker-owned directory in place.
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "{} is not a protected system directory",
        path.display()
    );
    Ok(())
}

pub(super) fn prepare_directory(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            prepare_directory(parent)?;
        }
        // /var on Darwin is a system-owned link; canonicalize the trusted parent.
        check_directory(&fs::canonicalize(parent).context("resolving guardian parent")?)?;
    }
    match fs::DirBuilder::new().mode(0o755).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    check_directory(path)
}

pub(super) mod native_path {
    use serde::{Deserialize as _, Serialize as _};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Path, PathBuf};

    pub fn serialize<S: serde::Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
        path.as_os_str().as_bytes().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
        Ok(std::ffi::OsString::from_vec(Vec::<u8>::deserialize(deserializer)?).into())
    }
}
