//! Explicit account-deletion notifications are retained locally before work
//! begins. Leaving a network does not manufacture such a notification.

use crate::Node;
use anyhow::{Context as _, ensure};
use fastctx_install::service::guests::{self, Request, Room};
use fastctx_types::guest::Principal;
use std::{
    collections::{BTreeSet, HashMap},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) fn start(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    let mut views = node.views.subscribe();
    tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        let mut active = HashMap::new();
        let mut retries: HashMap<PathBuf, (Instant, Duration, String)> = HashMap::new();
        let mut scan_error = None;
        loop {
            let Some(node) = weak.upgrade() else {
                return;
            };
            let scan_node = node.clone();
            let pending = tokio::task::spawn_blocking(move || collect(&scan_node)).await;
            match pending {
                Ok(Ok(pending)) => {
                    scan_error = None;
                    for (path, principal) in pending {
                        if active.contains_key(&path)
                            || retries.get(&path).is_some_and(|(after, _, _)| *after > Instant::now())
                        {
                            continue;
                        }
                        let key = path.clone();
                        let node = node.clone();
                        let task = tasks.spawn(async move {
                            let result = finish(&node, &path, &principal).await;
                            (path, result)
                        });
                        active.insert(key, task.id());
                    }
                }
                error => {
                    let error = match error {
                        Ok(Err(error)) => format!("{error:#}"),
                        Err(error) => error.to_string(),
                        _ => unreachable!(),
                    };
                    if scan_error.as_ref() != Some(&error) {
                        node.log.line(format_args!("reading guest account deletion intents: {error}"));
                        scan_error = Some(error);
                    }
                }
            }
            tokio::select! {
                changed = views.changed() => { if changed.is_err() { return; } }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Some(Ok((path, Ok(())))) => { active.remove(&path); retries.remove(&path); }
                        Some(Ok((path, Err(error)))) => {
                            active.remove(&path);
                            let message = format!("{error:#}");
                            let delay = retries.get(&path).map_or(Duration::from_secs(2), |(_, delay, _)| (*delay * 2).min(Duration::from_secs(60)));
                            if retries.get(&path).is_none_or(|(_, _, old)| *old != message) {
                                node.log.line(format_args!("finishing {}: {message}", path.display()));
                            }
                            retries.insert(path, (Instant::now() + delay, delay, message));
                        }
                        Some(Err(error)) => {
                            node.log.line(format_args!("guest account deletion task failed: {error}"));
                            if let Some(path) = active.iter().find_map(|(path, id)| (*id == error.id()).then(|| path.clone())) {
                                active.remove(&path);
                            }
                        }
                        None => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    });
}

fn directory(node: &Node) -> PathBuf {
    node.world.path().join("guest-account-deletions")
}

fn collect(node: &Node) -> anyhow::Result<Vec<(PathBuf, Principal)>> {
    let directory = directory(node);
    for link in node.links() {
        let view = link.view();
        if !view.guest_accounts {
            continue;
        }
        for principal in &view.deleted_guest_accounts {
            // 2026-10-20: a hub can retire only identities in its own namespace.
            ensure!(principal.hub == *link.hub(), "a hub tried to delete another hub's guest identity");
            crate::here::retire_account(node, principal);
            fastctx_platform::ensure_private_dir(&directory)?;
            let path = directory.join(format!("{}-{}.json", principal.hub, principal.id));
            match fastctx_platform::publish_new(
                &path,
                &serde_json::to_vec(principal)?,
                fastctx_platform::Permissions::Private,
            ) {
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                result => result?,
            }
        }
    }
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut pending = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let principal: Principal = serde_json::from_slice(&std::fs::read(&path)?)?;
        ensure!(
            path.file_name().and_then(|name| name.to_str())
                == Some(format!("{}-{}.json", principal.hub, principal.id).as_str()),
            "guest deletion intent does not match its identity"
        );
        crate::here::retire_account(node, &principal);
        pending.push((path, principal));
    }
    Ok(pending)
}

async fn native(node: &Node, request: Request) -> anyhow::Result<Vec<guests::Account>> {
    let service = super::service(node);
    tokio::task::spawn_blocking(move || guests::call(&service, &request)).await?
}

async fn finish(node: &Arc<Node>, path: &std::path::Path, principal: &Principal) -> anyhow::Result<()> {
    let _handoff = node.handoff.call().context("the node is handing over")?;
    let has_accounts = node.root.join(fastctx_install::guest_privacy::MARKER).try_exists()?;
    if has_accounts {
        native(node, Request::Lock { account: principal.clone() }).await?;
    }
    ensure!(
        !crate::here::retire_account(node, principal),
        "a conversation of the deleted account is still being started"
    );
    let mut rooms = BTreeSet::new();
    if has_accounts {
        for account in native(node, Request::List).await? {
            if account.account.same_person(principal) {
                rooms.extend(account.rooms);
            }
        }
    }
    for resident in node.residents.everyone() {
        if resident.about.principals.iter().any(|known| known.same_person(principal)) {
            rooms.insert(Room { resident: resident.id.clone(), machine: None });
        }
    }
    for room in rooms {
        crate::forget::retired_guest(node, principal, &room).await.map_err(anyhow::Error::msg)?;
        if has_accounts {
            super::delete_room(node, room).await.map_err(|error| anyhow::anyhow!(error.message))?;
        }
    }
    if has_accounts {
        native(node, Request::Delete { account: principal.clone() }).await?;
    }
    let link =
        node.link_of(&principal.hub).context("the account's hub is unavailable; its cleanup receipt is retained")?;
    link.guest_accounts_deleted(vec![principal.id.clone()]).await.map_err(anyhow::Error::msg)?;
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    node.log.line(format_args!("deleted the conversations and local account of {} on {}", principal.id, principal.hub));
    Ok(())
}
