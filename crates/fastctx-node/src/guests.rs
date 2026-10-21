//! The node translates live assistance into account lifetime. Guardian IO is
//! outside the node's resident, disk, and directory-view locks.

mod grants;
mod retirements;

use crate::Node;
use fastctx_install::service::{
    Kind, Service,
    guests::{self, Request, Room},
};
use fastctx_types::{
    MachineName,
    access::{Acting, Purpose},
    ipc::Failure,
    remote::{RemoteCall, RemoteReply},
    stats::HomePrivacy,
};
use std::sync::Arc;

fn service(node: &Node) -> Service {
    Service::new(Kind::Node, fastctx_install::executable::installed_path(&node.root), &node.root)
}

pub(crate) fn start(node: &Arc<Node>) {
    retirements::start(node);
    let weak = Arc::downgrade(node);
    let mut views = node.views.subscribe();
    tokio::spawn(async move {
        let mut previous = None;
        loop {
            let Some(node) = weak.upgrade() else { return };
            let result = tokio::task::spawn_blocking(move || reconcile(&node)).await;
            let error = match result {
                Ok(result) => result.err().map(|error| format!("{error:#}")),
                Err(error) => Some(error.to_string()),
            };
            if error != previous {
                if let Some(error) = &error
                    && let Some(node) = weak.upgrade()
                {
                    node.log.line(format_args!("guest account reconciliation: {error}"));
                }
                previous = error;
            }
            tokio::select! {
                changed = views.changed() => { if changed.is_err() { return; } }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        }
    });
}

fn reconcile(node: &Node) -> anyhow::Result<()> {
    let service = service(node);
    if !node.root.join(fastctx_install::guest_privacy::MARKER).try_exists()? {
        return Ok(());
    }
    let accounts = guests::call(&service, &Request::List)?;
    let logins = grants::Logins::read(node);
    let mut trouble = None;
    for account in accounts {
        let grant = match &logins {
            Ok(logins) => logins.grant(node, &account.account),
            Err(error) => Err(anyhow::anyhow!("reading integrated logins: {error:#}")),
        };
        let grant = match grant {
            Ok(grant) => grant,
            Err(error) => {
                trouble.get_or_insert(error);
                grants::Grant::Ended
            }
        };
        match grant {
            grants::Grant::Ended if account.state != guests::AccountState::Locked => {
                if let Err(error) = guests::call(&service, &Request::Lock { account: account.account }) {
                    trouble.get_or_insert(error);
                }
            }
            grants::Grant::Live { principal, until }
                if account.state == guests::AccountState::Locked
                    || account.active && (account.until != until || account.account.account != principal.account) =>
            {
                let changed = fastctx_install::guest_privacy::prepare(&node.root)
                    .and_then(|()| guests::call(&service, &Request::Activate { account: principal, until }));
                if let Err(error) = changed {
                    trouble.get_or_insert(error);
                }
            }
            _ => {}
        }
    }
    if let Some(error) = trouble {
        return Err(error);
    }
    Ok(())
}

pub(crate) async fn delete_room(node: &Arc<Node>, room: Room) -> Result<(), Failure> {
    // A World without any created accounts needs no guardian for deletion.
    if !node
        .root
        .join(fastctx_install::guest_privacy::MARKER)
        .try_exists()
        .map_err(|error| Failure::new(error.to_string()))?
    {
        return Ok(());
    }
    let service = service(node);
    tokio::task::spawn_blocking(move || guests::call(&service, &Request::DeleteRoom { room }))
        .await
        .map_err(|error| Failure::new(error.to_string()))?
        .map_err(|error| Failure::new(format!("deleting the guest room: {error:#}")))?;
    Ok(())
}

pub(crate) async fn privacy(
    node: &Arc<Node>,
    acting: &Acting,
    machine: Option<MachineName>,
    harden: bool,
) -> Result<HomePrivacy, Failure> {
    if let Some(target) = machine.filter(|machine| !node.is_me(machine)) {
        return match node
            .call(acting, &(&target).into(), Purpose::Hands, RemoteCall::HomePrivacy { harden })
            .await
            .map_err(|error| Failure::new(error.to_string()))??
        {
            RemoteReply::HomePrivacy(privacy) => Ok(privacy),
            _ => Err(Failure::new(format!("{target} did not return home directory permissions"))),
        };
    }
    node.works_here(acting).map_err(Failure::not_run)?;
    privacy_here(harden).await
}

pub(crate) async fn privacy_here(harden: bool) -> Result<HomePrivacy, Failure> {
    tokio::task::spawn_blocking(move || fastctx_install::guest_privacy::home(harden))
        .await
        .map_err(|error| Failure::new(error.to_string()))?
        .map_err(|error| Failure::new(format!("home directory permissions: {error:#}")))
}

/// Capture stable identities before the account can be renamed or deleted.
pub(crate) fn principals(node: &Node, acting: &Acting) -> Result<Vec<fastctx_types::guest::Principal>, Failure> {
    let Acting::Accounts { accounts } = acting else {
        return Ok(Vec::new());
    };
    let mut principals = Vec::new();
    for account in accounts {
        let link =
            node.link_of(&account.hub).ok_or_else(|| Failure::not_run("this machine left the account's network"))?;
        let view = link.view();
        if !view.guest_accounts {
            continue;
        }
        let found = view
            .account(&account.account)
            .filter(|account| !account.locked)
            .ok_or_else(|| Failure::not_run("the account this conversation works for no longer exists or is locked"))?;
        let id =
            found.id.clone().ok_or_else(|| Failure::not_run("the hub has not supplied a stable account identifier"))?;
        principals.push(fastctx_types::guest::Principal {
            hub: account.hub.clone(),
            id,
            account: account.account.clone(),
        });
    }
    Ok(principals)
}
