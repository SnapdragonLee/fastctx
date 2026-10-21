//! The node protects its own state before the first guest exists. The user's
//! home is inspected separately and changed only by an explicit user call.

use anyhow::Context as _;
use fastctx_platform::{FileLock, Permissions, publish};
use std::path::Path;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as native;
#[cfg(windows)]
use windows as native;

pub const MARKER: &str = "guest-accounts.json";

/// Serializes with integration changes so a new login cannot miss the first
/// account's privacy pass. This writes no model configuration or credentials.
pub fn prepare(root: &Path) -> anyhow::Result<()> {
    harden(root)?;
    let _lock = FileLock::acquire(&root.join("apply.lock"))?;
    let mut places = crate::apply::Places::here()?;
    places.root = root.into();
    places.world = fastctx_types::layout::WorldDir::under(root).path().into();
    for integration in crate::apply::integrations(&places)? {
        if integration.home.try_exists()? {
            harden(&integration.home)?;
        }
    }
    publish(&root.join(MARKER), b"{}", Permissions::Private)?;
    Ok(())
}

/// Called inside apply's lock before it first touches the selected logins.
pub(crate) fn integrating(places: &crate::apply::Places, hosts: crate::apply::Hosts) -> anyhow::Result<()> {
    if !places.root.join(MARKER).try_exists()? {
        return Ok(());
    }
    for path in
        [hosts.codex.then_some(&places.codex_home), hosts.claude.then_some(&places.claude_home)].into_iter().flatten()
    {
        if !path.try_exists()? {
            fastctx_platform::ensure_private_dir(path)?;
        }
        harden(path)?;
    }
    Ok(())
}

pub fn harden(path: &Path) -> anyhow::Result<()> {
    let path = std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;
    native::harden(&path).with_context(|| format!("making {} private", path.display()))
}

pub fn home(harden_home: bool) -> anyhow::Result<fastctx_types::stats::HomePrivacy> {
    #[cfg(windows)]
    if fastctx_platform::current_user_sid()? == "S-1-5-18" {
        return Ok(fastctx_types::stats::HomePrivacy {
            directory: None,
            owner_only: None,
            reason: Some("this node runs as SYSTEM and has no owner's home".into()),
        });
    }
    let path = std::fs::canonicalize(fastctx_platform::user_home()?)?;
    if harden_home {
        harden(&path)?;
    }
    let owner_only = native::owner_only(&path)?;
    Ok(fastctx_types::stats::HomePrivacy {
        directory: Some(path),
        owner_only: Some(owner_only),
        reason: (!owner_only).then(|| "the home directory grants permissions to other accounts or groups".into()),
    })
}
