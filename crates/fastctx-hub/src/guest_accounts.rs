//! Account deletion is an explicit durable fact, delivered only to machines
//! that hosted its assistance. A cut directory omitting a name proves nothing.

use fastctx_net::{directory::Directory, sign::PublicKey};
use fastctx_types::{
    AccountName, MachineName,
    access::HubId,
    guest::{AccountId, Principal},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct History {
    #[serde(default)]
    hosts: BTreeMap<AccountId, BTreeSet<PublicKey>>,
    #[serde(default)]
    deleted: BTreeMap<AccountId, Deleted>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Deleted {
    principal: Principal,
    waiting: BTreeSet<PublicKey>,
}

impl History {
    /// Remember hosts while the grant exists, including a migration's existing
    /// grants. Names may change; the machine key and account id do not.
    pub fn observe(&mut self, directory: &Directory) -> bool {
        let mut changed = false;
        for assist in &directory.assists {
            if let (Some(id), Some(machine)) = (
                directory.account(&assist.account).and_then(|account| account.id.as_ref()),
                directory.member(&assist.machine),
            ) {
                changed |= self.hosts.entry(id.clone()).or_default().insert(machine.key);
            }
        }
        changed
    }

    pub fn retire(&mut self, hub: &HubId, directory: &Directory, name: &AccountName) -> Result<(), String> {
        self.observe(directory);
        let account = directory.account(name).ok_or("the account being deleted no longer exists")?;
        let id = account.id.clone().ok_or("the account has no stable identifier")?;
        let waiting = self.hosts.remove(&id).unwrap_or_default();
        if !waiting.is_empty() {
            let principal = Principal { hub: hub.clone(), id: id.clone(), account: name.clone() };
            self.deleted.insert(id, Deleted { principal, waiting });
        }
        Ok(())
    }

    pub fn pending(&self, key: &PublicKey) -> Vec<Principal> {
        self.deleted
            .values()
            .filter(|deleted| deleted.waiting.contains(key))
            .map(|deleted| deleted.principal.clone())
            .collect()
    }

    fn settled(&mut self, key: &PublicKey, ids: &[AccountId]) {
        for id in ids {
            if let Some(deleted) = self.deleted.get_mut(id) {
                deleted.waiting.remove(key);
            }
        }
        self.deleted.retain(|_, deleted| !deleted.waiting.is_empty());
    }
}

pub(crate) fn settled(hub: &crate::Hub, machine: &MachineName, ids: &[AccountId]) -> Result<(), String> {
    let mut store = hub.store();
    let key = store.book.directory.member(machine).ok_or("this machine left the hub")?.key;
    let before = store.book.guest_accounts.clone();
    store.book.guest_accounts.settled(&key, ids);
    if let Err(error) = store.save_book() {
        store.book.guest_accounts = before;
        return Err(format!("keeping account cleanup acknowledgements: {error}"));
    }
    drop(store);
    hub.changed();
    Ok(())
}
