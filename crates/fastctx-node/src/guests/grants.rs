//! Effective assistance includes the login still being integrated locally.
//! An initial, not-yet-received directory is not evidence of withdrawal.

use crate::Node;
use fastctx_install::apply::{self, Host, Integration};
use fastctx_types::guest::Principal;

pub(super) enum Grant {
    Unknown,
    Ended,
    Live { principal: Principal, until: Option<jiff::Timestamp> },
}

pub(super) struct Logins {
    context: crate::logins::Context,
    integrated: Vec<Integration>,
}

impl Logins {
    pub fn read(node: &Node) -> anyhow::Result<Self> {
        let context = crate::logins::Context::of(node).map_err(|error| anyhow::anyhow!(error.message))?;
        let integrated = apply::integrations(&context.places)?;
        Ok(Self { context, integrated })
    }

    pub fn grant(&self, node: &Node, principal: &Principal) -> anyhow::Result<Grant> {
        let Some(link) = node.link_of(&principal.hub) else {
            return Ok(Grant::Ended);
        };
        if matches!(link.status(), fastctx_net::link::Status::Stopped { .. }) {
            return Ok(Grant::Ended);
        }
        let view = link.view();
        let Some(here) = view.me() else {
            return Ok(Grant::Unknown);
        };
        let Some(owner) = here.home.as_ref().and_then(|owner| view.account(owner)).filter(|owner| !owner.locked) else {
            return Ok(Grant::Ended);
        };
        if owner.level == fastctx_types::accounts::Level::Visitor || here.managed {
            return Ok(Grant::Ended);
        }
        let Some(account) =
            view.accounts.iter().find(|account| account.id.as_ref() == Some(&principal.id) && !account.locked)
        else {
            return Ok(Grant::Ended);
        };
        let current = Principal { hub: principal.hub.clone(), id: principal.id.clone(), account: account.name.clone() };
        let mut deadline = None;
        for assist in view.assisting(&account.name, &view.me) {
            let host = match assist.agent.as_str() {
                "codex" => Host::Codex,
                "claude" => Host::Claude,
                _ => continue,
            };
            let home = assist.home.as_deref().unwrap_or_else(|| self.context.default_of(assist.agent.as_str()));
            if !self.integrated.iter().any(|login| login.host == host && crate::homes::same_dir(&login.home, home)) {
                continue;
            }
            match std::fs::metadata(home) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            }
            match assist.until {
                None => return Ok(Grant::Live { principal: current, until: None }),
                Some(until) => deadline = Some(deadline.map_or(until, |previous: jiff::Timestamp| previous.max(until))),
            }
        }
        Ok(match deadline {
            Some(until) => Grant::Live { principal: current, until: Some(until) },
            None => Grant::Ended,
        })
    }
}
