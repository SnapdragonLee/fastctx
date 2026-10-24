//! A stop follows the exact inputs it was requested for, across restarts.
//! Once a consuming turn is known, only that turn may receive the stop.

use crate::Node;
use fastctx_types::{NoticeId, ResidentId, ipc::Failure};
use std::{io, sync::Arc, time::Duration};

#[derive(Default)]
pub(crate) struct Stops;

fn marker(node: &Node, resident: &ResidentId, input: &NoticeId) -> std::path::PathBuf {
    node.world.conversation(resident).book("input-stops").join(input.as_str())
}

/// The user's intent is separate from the host's interrupted outcome.
/// Keeping it before the stop also lets a delayed terminal report classify it.
pub(crate) fn mark_turn(node: &Node, resident: &ResidentId, turn: &str) -> io::Result<()> {
    let key = crate::speech::fixed_id("stopped", &[turn]);
    let path = node.world.conversation(resident).book("user-stops").join(key.as_str());
    fastctx_platform::ensure_private_dir(path.parent().expect("user stop directory"))?;
    fastctx_platform::publish(&path, b"", fastctx_platform::Permissions::Private)
}

pub(crate) fn requested_turn(node: &Node, resident: &ResidentId, turn: &str) -> io::Result<bool> {
    let key = crate::speech::fixed_id("stopped", &[turn]);
    node.world.conversation(resident).book("user-stops").join(key.as_str()).try_exists()
}

impl Stops {
    /// The record lock and the turn check cover either ordering with `started`:
    /// a turn already entered is stopped directly; otherwise its inputs carry it.
    pub(crate) fn coming(&self, node: &Node, resident: &ResidentId, coming: Vec<NoticeId>) -> io::Result<bool> {
        let _transaction = crate::resident_storage::lock();
        if coming.is_empty() || node.residents.now(resident).is_some_and(|now| now.turn.is_some()) {
            return Ok(false);
        }
        for input in coming {
            let path = marker(node, resident, &input);
            fastctx_platform::ensure_private_dir(path.parent().expect("stop directory"))?;
            fastctx_platform::publish(&path, b"", fastctx_platform::Permissions::Private)?;
        }
        Ok(true)
    }

    pub(crate) fn started<'a>(
        &self,
        node: &Node,
        resident: &ResidentId,
        words: impl IntoIterator<Item = &'a NoticeId>,
    ) -> io::Result<bool> {
        let _transaction = crate::resident_storage::lock();
        for input in words {
            if marker(node, resident, input).try_exists()? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Stop delivery is independent of the report consumer and never blocks it.
pub(crate) fn deliver(node: &Arc<Node>, resident: &ResidentId, turn: &str, inputs: Vec<NoticeId>) {
    let (node, resident, turn) = (node.clone(), resident.clone(), turn.to_string());
    tokio::spawn(async move {
        let mut problem = None;
        loop {
            if node.residents.about(&resident).is_none() {
                return;
            }
            match apply(&node, &resident, &turn, &inputs).await {
                Ok(()) => return,
                Err(error) => {
                    if problem.as_ref() != Some(&error.message) {
                        node.log.line(format_args!("stopping {resident}'s consuming turn {turn}; retrying: {error}"));
                        problem = Some(error.message);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

async fn apply(node: &Arc<Node>, resident: &ResidentId, turn: &str, inputs: &[NoticeId]) -> Result<(), Failure> {
    if !node.stops.started(node, resident, inputs).map_err(failure)? {
        return Ok(());
    }
    let directory = node.world.conversation(resident);
    if crate::delivery::terminal(&directory, turn).map_err(failure)?.is_none() {
        let speaking = node.residents.speaking(resident).ok_or_else(crate::authorization::no_subject)?;
        let guard = speaking.lock().await;
        if node.residents.now(resident).and_then(|now| now.turn).as_deref() != Some(turn) {
            return Err(Failure::new("the consuming turn has not become current or settled yet"));
        }
        mark_turn(node, resident, turn).map_err(failure)?;
        node.interrupts.raise(&fastctx_types::Address { machine: node.machine(), resident: resident.clone() });
        drop(guard);
        let (about, _) = node.residents.about(resident).ok_or_else(crate::authorization::no_subject)?;
        let session = about.session.as_deref().ok_or_else(|| Failure::new("the consuming session is unknown"))?;
        match about.host.agent.as_str() {
            "codex" => node.codex.of(node, &about)?.interrupt_turn(session, turn).await.map_err(Failure::new)?,
            "claude" => fastctx_hosts::claude::exchange::stop(
                &fastctx_hosts::claude::exchange::sessions(node.world.path()).join(session),
                turn,
            )
            .map_err(failure)?,
            _ => return Err(Failure::new("the consuming host has no stop entrance")),
        }
    }
    for input in inputs {
        match std::fs::remove_file(marker(node, resident, input)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(failure(error)),
            _ => {}
        }
    }
    Ok(())
}

/// A node may have stopped after binding a turn and before sending its stop.
pub(crate) fn recover(node: &Arc<Node>) {
    for resident in node.residents.everyone().filter(|resident| resident.removed.is_none()) {
        let directory = node.world.conversation(&resident.id);
        let paths = match std::fs::read_dir(directory.book("input-stops")) {
            Ok(paths) => paths,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                node.log.line(format_args!("recovering input stops: {error}"));
                continue;
            }
        };
        for path in paths {
            let result = (|| -> io::Result<()> {
                let path = path?.path();
                let Some(input) =
                    path.file_name().and_then(|name| name.to_str()).and_then(|name| name.parse::<NoticeId>().ok())
                else {
                    return Ok(());
                };
                if let Some(turn) = crate::delivery::input_turn(&directory, &input)? {
                    deliver(node, &resident.id, &turn, vec![input]);
                }
                Ok(())
            })();
            if let Err(error) = result {
                node.log.line(format_args!("recovering {}'s input stop: {error}", resident.id));
            }
        }
    }
}

fn failure(error: impl std::fmt::Display) -> Failure {
    Failure::new(format!("keeping a stop for its input: {error}"))
}
