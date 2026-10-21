//! Durable account intents outlive the guardian and its node. Native ownership
//! is checked before every account mutation; records disappear last.

use super::{Account, Identity, Request, Room, native};
use anyhow::{Context as _, ensure};
use fastctx_platform::{FileLock, Permissions, publish};
use fastctx_types::guest::Principal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use super::AccountState as State;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Record {
    pub account: Principal,
    pub name: String,
    pub mark: String,
    pub identity: Option<Identity>,
    pub rooms: BTreeSet<Room>,
    pub removing: BTreeSet<Room>,
    pub state: State,
    pub until: Option<jiff::Timestamp>,
    #[serde(default)]
    pub problem: Option<String>,
    #[serde(default)]
    retry_after: Option<jiff::Timestamp>,
    #[serde(default)]
    failures: u32,
}

pub(crate) struct Manager {
    pub root: PathBuf,
    pub homes: PathBuf,
    pub registration: String,
    pub owner: Identity,
}

impl Manager {
    fn records(&self) -> PathBuf {
        self.root.join("guests")
    }
    fn path(&self, name: &str) -> PathBuf {
        self.records().join(format!("{name}.json"))
    }
    pub fn home(&self, record: &Record) -> PathBuf {
        self.homes.join(&record.name)
    }

    pub fn handle(&self, request: &Request) -> anyhow::Result<Vec<Account>> {
        native::prepare(self)?;
        let _lock = FileLock::acquire(&self.root.join("guests.lock"))?;
        let result = self.dispatch(request);
        if let Err(error) = &result {
            let account = match request {
                Request::Ensure { account, .. }
                | Request::Activate { account, .. }
                | Request::Lock { account }
                | Request::Delete { account } => Some(account),
                _ => None,
            };
            if let Some(account) = account
                && let Some(mut record) = self.read(&self.key(account)?)?
            {
                record.problem = Some(format!("{error:#}"));
                self.save(&record)?;
            }
        }
        result
    }

    fn dispatch(&self, request: &Request) -> anyhow::Result<Vec<Account>> {
        if matches!(request, Request::Ensure { .. } | Request::Activate { .. }) {
            ensure!(!self.root.join("guests-retired").try_exists()?, "the guardian is being uninstalled");
        }
        match request {
            Request::Ensure { account, room, until } => {
                live(*until)?;
                ensure!(
                    room.resident.as_str().len() <= 255,
                    "the conversation id exceeds the system directory name limit"
                );
                let key = self.key(account)?;
                let mut record = match self.read(&key)? {
                    Some(record) => record,
                    None => {
                        let mut nonce = [0; 16];
                        getrandom::fill(&mut nonce)?;
                        let nonce = nonce.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
                        let record = Record {
                            account: account.clone(),
                            name: self.available_name(&key)?,
                            mark: format!("Fastctx guest {nonce}"),
                            identity: None,
                            rooms: BTreeSet::from([room.clone()]),
                            removing: BTreeSet::new(),
                            state: State::Creating,
                            until: *until,
                            problem: None,
                            retry_after: None,
                            failures: 0,
                        };
                        self.save(&record)?;
                        record
                    }
                };
                ensure!(record.account.same_person(account), "guest account name collision");
                ensure!(record.state != State::Deleting, "the guest account is being deleted");
                record.account = account.clone();
                self.complete_creation(&mut record)?;
                native::verify(self, &record)?;
                ensure!(
                    !record.rooms.iter().any(|known| known.resident == room.resident && known != room),
                    "two conversations from different machines have the same id; their rooms cannot be combined"
                );
                ensure!(!record.removing.contains(room), "the guest room is being deleted");
                record.rooms.insert(room.clone());
                // Persist ownership before the directory appears. Recovery completes it.
                self.save(&record)?;
                native::room(self, &record, &room.resident)?;
                self.activate(&mut record, *until)?;
                Ok(vec![self.about(&record)?])
            }
            Request::Activate { account, until } => {
                live(*until)?;
                if let Some(mut record) = self.read(&self.key(account)?)? {
                    ensure!(record.account.same_person(account), "guest account name collision");
                    record.account = account.clone();
                    self.activate(&mut record, *until)?;
                    Ok(vec![self.about(&record)?])
                } else {
                    Ok(vec![])
                }
            }
            Request::Lock { account } => {
                if let Some(mut record) = self.read(&self.key(account)?)? {
                    ensure!(record.account.same_person(account), "guest account name collision");
                    if record.state == State::Creating || record.state == State::Deleting {
                        record.state = State::Deleting;
                        self.save(&record)?;
                        self.finish(&mut record)?;
                    } else {
                        self.lock(&mut record)?;
                    }
                }
                Ok(vec![])
            }
            Request::Delete { account } => {
                if let Some(mut record) = self.read(&self.key(account)?)? {
                    ensure!(record.account.same_person(account), "guest account identity differs");
                    record.state = State::Deleting;
                    self.save(&record)?;
                    self.finish(&mut record)?;
                }
                Ok(vec![])
            }
            Request::DeleteRoom { room } => {
                for mut record in self.all()? {
                    if !record.rooms.contains(room) {
                        continue;
                    }
                    if record.rooms.len() == 1 {
                        record.state = State::Deleting;
                    } else {
                        record.removing.insert(room.clone());
                    }
                    self.save(&record)?;
                    self.finish(&mut record)?;
                }
                Ok(vec![])
            }
            Request::List => self.all()?.iter().map(|record| self.about(record)).collect(),
            Request::Retire => {
                publish(&self.root.join("guests-retired"), b"", Permissions::KeepExisting)?;
                self.recover()?;
                Ok(vec![])
            }
        }
    }

    /// Also runs without a node: expiry and interrupted withdrawals cannot be
    /// postponed indefinitely by a disconnected or restarting owner process.
    pub fn maintain(&self) -> anyhow::Result<()> {
        if !self.records().try_exists()? {
            return Ok(());
        }
        let _lock = FileLock::acquire(&self.root.join("guests.lock"))?;
        self.recover()
    }

    fn recover(&self) -> anyhow::Result<()> {
        let retired = self.root.join("guests-retired").try_exists()?;
        let mut problems = Vec::new();
        for mut record in self.all()? {
            if retired {
                record.state = State::Deleting;
                self.save(&record)?;
            }
            let expired = record.until.is_some_and(|until| until <= jiff::Timestamp::now());
            if !retired && !expired && record.retry_after.is_some_and(|after| after > jiff::Timestamp::now()) {
                continue;
            }
            let result = self.finish(&mut record);
            let problem = result.err().map(|error| format!("{error:#}"));
            if self.path(&self.key(&record.account)?).try_exists()? {
                let had_problem = record.problem.is_some();
                record.problem = problem.clone();
                if problem.is_some() {
                    record.failures = record.failures.saturating_add(1);
                    let delay = 2_i64.pow(record.failures.min(6)).min(60);
                    record.retry_after =
                        Some(jiff::Timestamp::now().checked_add(jiff::SignedDuration::from_secs(delay))?);
                    self.save(&record)?;
                } else if had_problem {
                    record.failures = 0;
                    record.retry_after = None;
                    self.save(&record)?;
                }
            }
            if let Some(problem) = problem {
                problems.push(format!("{}: {problem}", record.name));
            }
        }
        problems.sort();
        ensure!(problems.is_empty(), "{}", problems.join("; "));
        Ok(())
    }

    fn finish(&self, record: &mut Record) -> anyhow::Result<()> {
        if record.state == State::Deleting {
            // Creation may have reached the OS before its identity was persisted.
            if record.identity.is_none() {
                record.identity = match native::existing(self, record) {
                    Ok(identity) => identity,
                    Err(error) if error.is::<super::NameOccupied>() => {
                        // The candidate was taken before this creation finished;
                        // neither that account nor its home belongs to this intent.
                        fs::remove_file(self.path(&self.key(&record.account)?))?;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                self.save(record)?;
            }
            if native::existing(self, record)?.is_some() {
                self.quiesce(record)?;
            }
            let home = self.home(record);
            // Remove data before releasing the UID/GID for native reuse.
            delete_directory(&home)?;
            native::delete(self, record)?;
            self.audit(&format!("deleted guest {}", record.name))?;
            fs::remove_file(self.path(&self.key(&record.account)?))?;
            return Ok(());
        }
        self.complete_creation(record)?;
        native::verify(self, record)?;
        if record.state == State::Locking || record.until.is_some_and(|until| until <= jiff::Timestamp::now()) {
            self.lock(record)?;
        }
        if record.state == State::Activating {
            native::set_active(self, record, true)?;
            record.state = State::Active;
            self.save(record)?;
        }
        for room in record.removing.clone() {
            delete_directory(&self.home(record).join(room.resident.as_str()))?;
            record.rooms.remove(&room);
            record.removing.remove(&room);
            self.save(record)?;
        }
        for room in &record.rooms {
            native::room(self, record, &room.resident)?;
        }
        Ok(())
    }

    fn complete_creation(&self, record: &mut Record) -> anyhow::Result<()> {
        if record.state != State::Creating {
            return Ok(());
        }
        loop {
            match native::create(self, record) {
                Ok(identity) => {
                    record.identity = Some(identity);
                    break;
                }
                Err(error) if record.identity.is_none() && error.is::<super::NameOccupied>() => {
                    record.name = self.available_name(&self.key(&record.account)?)?;
                    self.save(record)?;
                }
                Err(error) => return Err(error),
            }
        }
        self.save(record)?;
        native::prepare_home(self, record)?;
        native::set_active(self, record, false)?;
        record.state = State::Locked;
        self.save(record)?;
        self.audit(&format!("created guest {} for {} on {}", record.name, record.account.account, record.account.hub))
    }

    fn activate(&self, record: &mut Record, until: Option<jiff::Timestamp>) -> anyhow::Result<()> {
        ensure!(record.state != State::Deleting, "the guest account is being deleted");
        if record.state == State::Locking {
            self.lock(record)?;
        }
        self.complete_creation(record)?;
        native::verify(self, record)?;
        live(until)?;
        let was_active = record.state == State::Active;
        // Authorization is committed before the native account is enabled.
        record.state = State::Activating;
        record.until = until;
        self.save(record)?;
        native::set_active(self, record, true)?;
        record.state = State::Active;
        record.problem = None;
        record.failures = 0;
        record.retry_after = None;
        self.save(record)?;
        if !was_active {
            self.audit(&format!("unlocked guest {}", record.name))?;
        }
        Ok(())
    }

    fn lock(&self, record: &mut Record) -> anyhow::Result<()> {
        if record.state == State::Locked {
            return Ok(());
        }
        record.state = State::Locking;
        self.save(record)?;
        self.quiesce(record)?;
        record.state = State::Locked;
        record.until = None;
        record.problem = None;
        record.failures = 0;
        record.retry_after = None;
        self.save(record)?;
        self.audit(&format!("locked guest {} and removed its processes and schedules", record.name))
    }

    fn quiesce(&self, record: &Record) -> anyhow::Result<()> {
        // 2026-10-20: a read-only account database must not prevent terminating
        // already running guest processes; an incomplete lock remains durable.
        let disabled = native::set_active(self, record, false);
        let stopped = native::stop(self, record);
        match (disabled, stopped) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(disable), Err(stop)) => anyhow::bail!("locking the account: {disable:#}; stopping it: {stop:#}"),
        }
    }

    fn key(&self, account: &Principal) -> anyhow::Result<String> {
        let bytes = serde_json::to_vec(&(&self.registration, &account.hub, &account.id))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn available_name(&self, key: &str) -> anyhow::Result<String> {
        for attempt in 0u64.. {
            let digest = if attempt == 0 {
                key.to_string()
            } else {
                format!("{:x}", Sha256::digest(format!("{key}:{attempt}")))
            };
            let name = format!("fxg{}", &digest[..16]);
            if !native::name_used(&name)? && !self.homes.join(&name).try_exists()? {
                return Ok(name);
            }
        }
        unreachable!()
    }

    fn read(&self, key: &str) -> anyhow::Result<Option<Record>> {
        let bytes = match fs::read(self.path(key)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let record: Record = serde_json::from_slice(&bytes)?;
        ensure!(self.key(&record.account)? == key, "guest record does not match its stable identity");
        ensure!(
            record.name.len() == 19
                && record.name.starts_with("fxg")
                && record.name[3..].bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid guest system name"
        );
        ensure!(record.mark.starts_with("Fastctx guest ") && record.mark.len() == 46, "invalid guest ownership marker");
        Ok(Some(record))
    }

    fn all(&self) -> anyhow::Result<Vec<Record>> {
        let entries = match fs::read_dir(self.records()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(error.into()),
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| anyhow::anyhow!("invalid guest record filename"))?;
            if name.starts_with(".fastctx-") && name.ends_with(".tmp") {
                // A publication interrupted before rename never became a record.
                fs::remove_file(entry.path())?;
                continue;
            }
            let name = name.strip_suffix(".json").context("unexpected file in guest records")?;
            ensure!(
                name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid guest record filename"
            );
            if let Some(record) = self.read(name)? {
                records.push(record);
            }
        }
        Ok(records)
    }

    fn save(&self, record: &Record) -> anyhow::Result<()> {
        publish(&self.path(&self.key(&record.account)?), &serde_json::to_vec(record)?, Permissions::KeepExisting)?;
        Ok(())
    }

    fn about(&self, record: &Record) -> anyhow::Result<Account> {
        Ok(Account {
            account: record.account.clone(),
            name: record.name.clone(),
            identity: record.identity.clone(),
            state: record.state.clone(),
            problem: record.problem.clone(),
            directory: self.home(record),
            rooms: record.rooms.iter().cloned().collect(),
            active: record.state == State::Active,
            until: record.until,
        })
    }

    fn audit(&self, message: &str) -> anyhow::Result<()> {
        fastctx_platform::rolling_log::RollingLog::open(&self.root.join("guests.log"))?
            .write(format!("{} {message}\n", jiff::Timestamp::now()).as_bytes())?;
        Ok(())
    }
}

fn live(until: Option<jiff::Timestamp>) -> anyhow::Result<()> {
    ensure!(until.is_none_or(|until| until > jiff::Timestamp::now()), "this assistance has expired");
    Ok(())
}

fn delete_directory(path: &Path) -> anyhow::Result<()> {
    // Rust's recursive removal does not traverse symbolic links or junctions.
    match fs::remove_dir_all(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}
