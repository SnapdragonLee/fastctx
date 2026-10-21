//! Accounts owned by one guardian. Clients name World accounts and conversations,
//! never an operating-system identity, privileged command, or filesystem path.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod manager;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

#[cfg(windows)]
use super::windows::guests as native;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) use manager::{Manager, Record};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use unix as native;

pub use fastctx_types::guest::{Account, AccountState, Identity, Principal, Request, Room};

/// Makes one authenticated local request. It never installs a service or falls
/// back to the node's own identity when the guardian is absent or unavailable.
pub fn call(service: &super::Service, request: &Request) -> anyhow::Result<Vec<Account>> {
    anyhow::ensure!(service.kind == super::Kind::Node, "a hub cannot own guest accounts");
    let service = service.normalized()?;
    if matches!(request, Request::Ensure { .. }) {
        crate::guest_privacy::prepare(&service.directory)?;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        super::unix_guardian::guests(&service, request)
    }
    #[cfg(windows)]
    {
        super::windows::guest_channel::ask(&service, request)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (service, request);
        anyhow::bail!("this platform cannot create guest accounts")
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[derive(Debug, thiserror::Error)]
#[error("the system account name is already in use")]
pub(crate) struct NameOccupied;
