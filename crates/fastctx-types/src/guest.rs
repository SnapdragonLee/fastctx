//! Stable identities used by the machine's guest-account ledger. Account names
//! remain presentation and routing labels; changing them never changes a person.

use crate::{AccountName, MachineName, ResidentId, access::HubId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountId(String);

impl AccountId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(format!("a-{}", bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AccountId {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 34
            && value.starts_with("a-")
            && value[2..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err("invalid stable account id".into())
        }
    }
}
impl From<AccountId> for String {
    fn from(value: AccountId) -> Self {
        value.0
    }
}
impl std::str::FromStr for AccountId {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}
impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub hub: HubId,
    pub id: AccountId,
    pub account: AccountName,
}

impl Principal {
    /// The durable identity, independent of the account's current name.
    pub fn same_person(&self, other: &Self) -> bool {
        self.hub == other.hub && self.id == other.id
    }
}

/// The durable authorization transition, including incomplete native work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Creating,
    Activating,
    Active,
    Locking,
    Locked,
    Deleting,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Ensure { account: Principal, room: Room, until: Option<jiff::Timestamp> },
    Activate { account: Principal, until: Option<jiff::Timestamp> },
    Lock { account: Principal },
    DeleteRoom { room: Room },
    Delete { account: Principal },
    List,
    Retire,
}

/// A conversation here, or one arriving from the named remote machine. A bare
/// resident id is unique only on its originating machine, not across the World.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Room {
    pub resident: ResidentId,
    #[serde(default)]
    pub machine: Option<MachineName>,
}

/// The native identity is returned as a fact; no request may select one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum Identity {
    Unix { uid: u32, gid: u32 },
    Windows { sid: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub account: Principal,
    pub name: String,
    pub identity: Option<Identity>,
    pub state: AccountState,
    pub problem: Option<String>,
    pub directory: PathBuf,
    pub rooms: Vec<Room>,
    pub active: bool,
    pub until: Option<jiff::Timestamp>,
}
