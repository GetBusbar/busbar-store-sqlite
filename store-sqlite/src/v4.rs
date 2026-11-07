// SPDX-License-Identifier: Apache-2.0
//! Native SQLite implementation of the primitive persistence contract.
//! Receipt collection waits 24 monotonic hours after observing durable retirement;
//! reopening resets that grace period. Backend qualification remains configuration-specific.
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::v4::backend::{Backend, Committed};
use busbar_contract::abi::sdk::store::v4::retirement::Horizon;
use busbar_contract::abi::sdk::store::{Op, Step};
use busbar_contract::persistence::{control, *};
use busbar_contract::Secret;
use rusqlite::{params, Connection, TransactionBehavior};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::Instant;

busbar_contract::own_seal!(Own);
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["db_path"]"#),
]);
busbar_contract::store_v4_door!(SqliteV4, "busbar-store-sqlite", env!("CARGO_PKG_VERSION"), 64,
    extensions: EXTENSIONS,
    settings_schema: busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("settings.schema.json")),
    migrate: busbar_contract::abi::sdk::migrate::Migrator<crate::settings::SettingsMigration>,
);
type Value = Secret<Vec<u8>, Own>;
pub(crate) const DDL: &str = "CREATE TABLE meta(key TEXT PRIMARY KEY NOT NULL,value BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE records(namespace BLOB NOT NULL CHECK(typeof(namespace)='blob' AND length(namespace)=16),key BLOB NOT NULL CHECK(typeof(key)='blob'),value BLOB NOT NULL CHECK(typeof(value)='blob'),PRIMARY KEY(namespace,key)) WITHOUT ROWID;
CREATE TABLE receipts(writer BLOB NOT NULL CHECK(typeof(writer)='blob' AND length(writer)=16),operation BLOB NOT NULL CHECK(typeof(operation)='blob' AND length(operation)=16),fingerprint BLOB NOT NULL CHECK(typeof(fingerprint)='blob' AND length(fingerprint)=32),execution_epoch BLOB NOT NULL CHECK(typeof(execution_epoch)='blob' AND length(execution_epoch)=8),observed BLOB NOT NULL CHECK(typeof(observed)='blob' AND length(observed)=8),result BLOB NOT NULL CHECK(typeof(result)='blob'),PRIMARY KEY(writer,operation)) WITHOUT ROWID;";
struct SqliteV4 {
    owner: Own,
    budget: usize,
    info: Mutex<BackendInfo>,
    enabled: AtomicBool,
    settings: Vec<u8>,
    native: Mutex<crate::legacy::native::Session>,
    connection: Mutex<Connection>,
    horizons: Mutex<HashMap<[u8; 16], Horizon>>,
}
fn sql<T>(r: rusqlite::Result<T>) -> Result<T, Failure> {
    r.map_err(|_| Failure::Unavailable)
}
fn protected(v: &[u8]) -> Result<Value, Failure> {
    let mut out = zeroize::Zeroizing::new(Vec::new());
    out.try_reserve_exact(v.len())
        .map_err(|_| Failure::Overloaded)?;
    out.extend_from_slice(v);
    Ok(Secret::held(std::mem::take(&mut *out)))
}
fn reserve<T>(n: usize) -> Result<Vec<T>, Failure> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Failure::Overloaded)?;
    Ok(v)
}
fn random() -> Result<[u8; 16], String> {
    loop {
        let mut v = [0; 16];
        getrandom::fill(&mut v).map_err(|_| "OS entropy unavailable")?;
        if v != [0; 16] {
            return Ok(v);
        }
    }
}
fn get(c: &Connection, ns: [u8; 16], key: &[u8]) -> Result<Option<Value>, Failure> {
    let mut statement = sql(c.prepare("SELECT value FROM records WHERE namespace=?1 AND key=?2"))?;
    let mut rows = sql(statement.query(params![ns.as_slice(), key]))?;
    let Some(row) = sql(rows.next())? else {
        return Ok(None);
    };
    let value = row
        .get_ref(0)
        .map_err(|_| Failure::Corrupt)?
        .as_blob()
        .map_err(|_| Failure::Corrupt)?;
    protected(value).map(Some)
}
fn generation(c: &Connection, ns: [u8; 16], own: &Own) -> Result<u64, Failure> {
    let Some(v) = get(c, control::GENERATION_NAMESPACE.0, &ns)? else {
        return Ok(0);
    };
    let n = u64::from_le_bytes(
        v.expose_own(own)
            .as_slice()
            .try_into()
            .map_err(|_| Failure::Corrupt)?,
    );
    if n == 0 {
        Err(Failure::Corrupt)
    } else {
        Ok(n)
    }
}
fn put(c: &Connection, ns: [u8; 16], key: &[u8], v: &[u8]) -> Result<(), Failure> {
    sql(c.execute("INSERT INTO records VALUES(?1,?2,?3) ON CONFLICT(namespace,key) DO UPDATE SET value=excluded.value",params![ns.as_slice(),key,v])).map(drop)
}
impl SqliteV4 {
    fn connect_now(&self) -> Result<(), String> {
        if self.enabled.load(Ordering::Acquire) {
            return Ok(());
        }
        let native = self
            .native
            .lock()
            .map_err(|_| "SQLite session unavailable")?;
        if !native.may_write() {
            return Err("SQLite writable authority required".into());
        }
        if matches!(
            native.inspection,
            crate::legacy::native::Inspection::InProgress(crate::legacy::native::Upgrade {
                phase: 2,
                ..
            })
        ) {
            let (connection, upgrade) = native
                .selected()
                .map_err(|_| "SQLite selected target unavailable")?;
            *self
                .connection
                .lock()
                .map_err(|_| "SQLite session unavailable")? = connection;
            *self.info.lock().map_err(|_| "SQLite session unavailable")? = BackendInfo {
                dataset: DatasetId(upgrade.target),
                atomic_domain: upgrade.atomic_domain,
                clock_authority: upgrade.clock_authority,
                physical_version: 1,
                durability: Durability::Local,
            };
            self.enabled.store(true, Ordering::Release);
            return Ok(());
        }
        if !matches!(
            native.inspection,
            crate::legacy::native::Inspection::Empty | crate::legacy::native::Inspection::Current
        ) {
            return Err("SQLite upgrade must complete before ordinary open".into());
        }
        let (connection, info) = open_current(
            &self.settings,
            matches!(native.inspection, crate::legacy::native::Inspection::Empty),
        )?;
        *self
            .connection
            .lock()
            .map_err(|_| "SQLite session unavailable")? = connection;
        *self.info.lock().map_err(|_| "SQLite session unavailable")? = info;
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }
    fn connect_binding(&self, binding: &lifecycle::OpenBinding) -> Result<(), String> {
        {
            let native = self
                .native
                .lock()
                .map_err(|_| "SQLite session unavailable")?;
            match binding {
                lifecycle::OpenBinding::Empty
                    if matches!(native.inspection, crate::legacy::native::Inspection::Empty) => {}
                lifecycle::OpenBinding::Current {
                    source,
                    admission_marker_digest,
                } => {
                    let marker = native
                        .admission()
                        .map_err(|_| "SQLite admission unavailable")?
                        .ok_or("SQLite admission marker required")?;
                    if native.view().map_err(|_| "SQLite source unavailable")?.0 != *source
                        || busbar_contract::persistence::archive::digest(&marker)
                            != *admission_marker_digest
                    {
                        return Err("SQLite prepared identity changed".into());
                    }
                }
                lifecycle::OpenBinding::Recovery(expected) => {
                    native
                        .check(expected.upgrade)
                        .map_err(|_| "SQLite recovery authority unavailable")?;
                    if native
                        .ready()
                        .map_err(|_| "SQLite recovery selector unavailable")?
                        != *expected
                    {
                        return Err("SQLite recovery selector changed".into());
                    }
                    let (connection, upgrade) = native
                        .selected()
                        .map_err(|_| "SQLite recovery target unavailable")?;
                    *self
                        .connection
                        .lock()
                        .map_err(|_| "SQLite session unavailable")? = connection;
                    *self.info.lock().map_err(|_| "SQLite session unavailable")? = BackendInfo {
                        dataset: DatasetId(upgrade.target),
                        atomic_domain: upgrade.atomic_domain,
                        clock_authority: upgrade.clock_authority,
                        physical_version: 1,
                        durability: Durability::Local,
                    };
                    self.enabled.store(true, Ordering::Release);
                    return Ok(());
                }
                _ => return Err("SQLite open binding refused".into()),
            }
        }
        self.connect_now()
    }
    fn facts(&self) -> BackendInfo {
        *self
            .info
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn bootstrap_now(
        &self,
        request: &lifecycle::Request<Own>,
    ) -> Result<lifecycle::Response<Own>, lifecycle::Error> {
        bootstrap::run(self, request)
    }
    fn collect_receipts(&self, c: &mut Connection, now: Instant) -> Result<(), Failure> {
        let tx = sql(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut horizons = self.horizons.lock().map_err(|_| Failure::Unavailable)?;
        let mut statement = sql(tx.prepare("SELECT key,value FROM records WHERE namespace=?1"))?;
        let mut rows = sql(statement.query([control::NAMESPACE.0.as_slice()]))?;
        let mut floors = reserve(0)?;
        while let Some(row) = sql(rows.next())? {
            let key = row
                .get_ref(0)
                .map_err(|_| Failure::Corrupt)?
                .as_blob()
                .map_err(|_| Failure::Corrupt)?;
            let Some(control::Key::Writer(writer)) = control::Key::decode(key) else {
                continue;
            };
            let value = row
                .get_ref(1)
                .map_err(|_| Failure::Corrupt)?
                .as_blob()
                .map_err(|_| Failure::Corrupt)?;
            let retired = control::Writer::decode(value)
                .ok_or(Failure::Corrupt)?
                .retired_through;
            horizons.try_reserve(1).map_err(|_| Failure::Overloaded)?;
            let floor = horizons
                .entry(writer)
                .or_insert_with(|| Horizon::new(retired, now))
                .observe(retired, now)?;
            if floor > 0 {
                floors.try_reserve(1).map_err(|_| Failure::Overloaded)?;
                floors.push((writer, floor));
            }
        }
        drop(rows);
        drop(statement);
        for (writer, floor) in floors {
            let mut statement =
                sql(tx.prepare("SELECT operation,execution_epoch FROM receipts WHERE writer=?1"))?;
            let mut rows = sql(statement.query([writer.as_slice()]))?;
            let mut operations = reserve(0)?;
            while let Some(row) = sql(rows.next())? {
                let epoch = row
                    .get_ref(1)
                    .map_err(|_| Failure::Corrupt)?
                    .as_blob()
                    .map_err(|_| Failure::Corrupt)?;
                let epoch = u64::from_le_bytes(epoch.try_into().map_err(|_| Failure::Corrupt)?);
                if epoch <= floor {
                    let operation: [u8; 16] = row
                        .get_ref(0)
                        .map_err(|_| Failure::Corrupt)?
                        .as_blob()
                        .map_err(|_| Failure::Corrupt)?
                        .try_into()
                        .map_err(|_| Failure::Corrupt)?;
                    operations.try_reserve(1).map_err(|_| Failure::Overloaded)?;
                    operations.push(operation);
                }
            }
            drop(rows);
            drop(statement);
            for operation in operations {
                sql(tx.execute(
                    "DELETE FROM receipts WHERE writer=?1 AND operation=?2",
                    params![writer.as_slice(), operation.as_slice()],
                ))?;
            }
        }
        tx.commit().map_err(|_| Failure::Unknown)
    }
    fn dataset(&self, d: DatasetId) -> Result<(), Failure> {
        if d == self.facts().dataset {
            Ok(())
        } else {
            Err(Failure::Refused)
        }
    }
    fn guard(&self) -> Result<std::sync::MutexGuard<'_, Connection>, Failure> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(Failure::Refused);
        }
        {
            let native = self.native.lock().map_err(|_| Failure::Unavailable)?;
            if let crate::legacy::native::Inspection::InProgress(upgrade) = &native.inspection {
                if upgrade.phase < 2 {
                    native
                        .check(upgrade.upgrade)
                        .map_err(|_| Failure::Refused)?;
                }
            }
        }
        self.connection.lock().map_err(|_| Failure::Unavailable)
    }
    // The first SELECT establishes the SQLite snapshot and samples SQLite's clock
    // together. Never sample an external clock then queue for a native transaction.
    fn observation(&self, c: &Connection) -> Result<ClockObservation, Failure> {
        let now: i64 = sql(c.query_row(
            "SELECT unixepoch(),value FROM meta WHERE key='dataset'",
            [],
            |r| r.get(0),
        ))?;
        Ok(ClockObservation {
            authority: self.facts().clock_authority,
            unix_seconds: u64::try_from(now).map_err(|_| Failure::Corrupt)?,
        })
    }
    fn read_now(&self, r: &Read) -> Result<ReadResult<Own>, Failure> {
        self.dataset(r.dataset)?;
        let mut c = self.guard()?;
        let tx = sql(c.transaction())?;
        let observed_at = self.observation(&tx)?;
        if r.time.is_some_and(|t| !t.permits(observed_at.unix_seconds)) {
            return Ok(ReadResult::TimeGuardFailed { observed_at });
        }
        let mut values = reserve(r.addresses.len())?;
        for a in &r.addresses {
            values.push(get(&tx, a.namespace, &a.key)?)
        }
        Ok(ReadResult::Values {
            observed_at,
            values,
        })
    }
    fn scan_now(&self, r: &Scan) -> Result<Page<Own>, Failure> {
        self.dataset(r.dataset)?;
        if r.max_items == 0
            || r.max_bytes == 0
            || (!r.allow_change && r.after.is_some() && r.generation.is_none())
        {
            return Err(Failure::Refused);
        }
        let mut c = self.guard()?;
        let tx = sql(c.transaction())?;
        let g = generation(&tx, r.namespace.0, &self.owner)?;
        if !r.allow_change && r.generation.is_some_and(|v| v != g) {
            return Err(Failure::StaleScan);
        }
        let mut stmt=sql(tx.prepare("SELECT key,value FROM records WHERE namespace=?1 AND substr(key,1,?2)=?3 AND (?4 IS NULL OR key>?4) ORDER BY key"))?;
        let mut cursor = sql(stmt.query(params![
            r.namespace.0.as_slice(),
            r.prefix.len() as i64,
            &r.prefix,
            r.after
        ]))?;
        let mut rows = reserve(r.max_items.min(256))?;
        let mut used = 0;
        let mut more = false;
        while let Some(row) = sql(cursor.next())? {
            let key = row
                .get_ref(0)
                .map_err(|_| Failure::Corrupt)?
                .as_blob()
                .map_err(|_| Failure::Corrupt)?;
            let v = row
                .get_ref(1)
                .map_err(|_| Failure::Corrupt)?
                .as_blob()
                .map_err(|_| Failure::Corrupt)?;
            let n = key.len().checked_add(v.len()).ok_or(Failure::Overloaded)?;
            if rows.len() == r.max_items || n > r.max_bytes - used {
                more = true;
                break;
            }
            rows.try_reserve(1).map_err(|_| Failure::Overloaded)?;
            let mut k = reserve(key.len())?;
            k.extend_from_slice(key);
            rows.push((
                Address {
                    namespace: r.namespace.0,
                    key: k,
                },
                protected(v)?,
            ));
            used += n;
        }
        if more && rows.is_empty() {
            return Err(Failure::Refused);
        }
        let next = if more {
            Some(rows.last().ok_or(Failure::Corrupt)?.0.key.clone())
        } else {
            None
        };
        Ok(Page {
            generation: g,
            rows,
            next,
        })
    }
    fn commit_now(&self, p: &PreparedCandidate<Own>) -> Result<Committed<Own>, Failure> {
        let r = p.candidate();
        let mut c = self.guard()?;
        let tx = sql(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        // Replay precedes dataset, clock, fence and predicate validation.
        let prior = {
            let mut statement=sql(tx.prepare("SELECT fingerprint,observed,result,execution_epoch FROM receipts WHERE writer=?1 AND operation=?2"))?;
            let mut rows =
                sql(statement.query(params![r.id.writer.as_slice(), r.id.operation.as_slice()]))?;
            if let Some(row) = sql(rows.next())? {
                let blob = |i| {
                    row.get_ref(i)
                        .map_err(|_| Failure::Corrupt)?
                        .as_blob()
                        .map_err(|_| Failure::Corrupt)
                };
                let fp: [u8; 32] = blob(0)?.try_into().map_err(|_| Failure::Corrupt)?;
                let time = u64::from_le_bytes(blob(1)?.try_into().map_err(|_| Failure::Corrupt)?);
                let epoch = u64::from_le_bytes(blob(3)?.try_into().map_err(|_| Failure::Corrupt)?);
                if epoch == 0 {
                    return Err(Failure::Corrupt);
                }
                Some((fp == p.fingerprint(), time, protected(blob(2)?)?))
            } else {
                None
            }
        };
        if let Some((same, time, result)) = prior {
            return Ok(Committed {
                observed_at: ClockObservation {
                    authority: self.facts().clock_authority,
                    unix_seconds: time,
                },
                decision: if same {
                    Decision::Applied(result)
                } else {
                    Decision::OpIdConflict
                },
            });
        }
        self.dataset(r.id.dataset)?;
        let observed_at = self.observation(&tx)?;
        let answer = |decision| {
            Ok(Committed {
                observed_at,
                decision,
            })
        };
        let empty: bool = sql(tx.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM records) AND NOT EXISTS(SELECT 1 FROM receipts)",
            [],
            |row| row.get(0),
        ))?;
        let fresh = empty && control::initialization(r, self.facts().dataset);
        if !fresh {
            let root = get(&tx, control::NAMESPACE.0, control::DATASET_KEY)?;
            let writer = get(&tx, control::NAMESPACE.0, &control::writer_key(r.id.writer))?;
            // Present malformed authority is corruption, never missing authority.
            let root = root
                .as_ref()
                .map(|v| {
                    control::Dataset::decode(v.expose_own(&self.owner)).ok_or(Failure::Corrupt)
                })
                .transpose()?;
            let writer = writer
                .as_ref()
                .map(|v| control::Writer::decode(v.expose_own(&self.owner)).ok_or(Failure::Corrupt))
                .transpose()?;
            if root.is_some_and(|v| v.id != self.facts().dataset) {
                return Err(Failure::Corrupt);
            }
            if !root.is_some_and(|v| v.writer_epoch == r.id.writer_epoch)
                || !writer.is_some_and(|v| v.admits(r.id.execution_epoch))
            {
                return answer(Decision::ExpiredUnknown);
            }
        }
        if r.time.is_some_and(|t| !t.permits(observed_at.unix_seconds)) {
            return answer(Decision::TimeGuardFailed { observed_at });
        }
        for pred in &r.predicates {
            let old = get(&tx, pred.address.namespace, &pred.address.key)?;
            let matches = match (&pred.expected, old.as_ref()) {
                (ExpectedValue::Absent, None) => true,
                (ExpectedValue::Exact(a), Some(b)) => a == b,
                _ => false,
            };
            if !matches {
                return answer(Decision::ConditionConflict);
            }
        }
        let mut namespaces = reserve(r.mutations.len())?;
        for m in &r.mutations {
            let (ns, key, value) = match m {
                Mutation::Put { address, value } => {
                    (address.namespace, Some(address.key.as_slice()), Some(value))
                }
                Mutation::Delete(a) => (a.namespace, Some(a.key.as_slice()), None),
                Mutation::DeleteRange { namespace, .. } => (namespace.0, None, None),
            };
            if ns == control::GENERATION_NAMESPACE.0 {
                return Err(Failure::Refused);
            }
            if ns == control::NAMESPACE.0 && !fresh {
                let key = key.ok_or(Failure::Refused)?;
                let value = value.ok_or(Failure::Refused)?;
                let known = control::Key::decode(key).ok_or(Failure::Refused)?;
                if !r
                    .predicates
                    .iter()
                    .any(|p| p.address.namespace == ns && p.address.key == key)
                {
                    return Err(Failure::Refused);
                }
                let old = get(&tx, ns, key)?;
                control::replacement(
                    known,
                    self.facts().dataset,
                    old.as_ref().map(|v| v.expose_own(&self.owner).as_slice()),
                    value.expose_own(&self.owner),
                )?;
            }
            namespaces.push(ns);
        }
        namespaces.sort_unstable();
        namespaces.dedup();
        // Check generation overflow before any effects. Store u64 as exact LE BLOB.
        let mut advances = reserve(namespaces.len())?;
        for ns in namespaces {
            advances.push((
                ns,
                generation(&tx, ns, &self.owner)?
                    .checked_add(1)
                    .ok_or(Failure::Refused)?,
            ))
        }
        let returned = protected(r.result.expose_own(&self.owner))?;
        for m in &r.mutations {
            match m {
                Mutation::Put { address, value } => put(
                    &tx,
                    address.namespace,
                    &address.key,
                    value.expose_own(&self.owner),
                )
                .map_err(|_| Failure::Unknown)?,
                Mutation::Delete(a) => {
                    sql(tx.execute(
                        "DELETE FROM records WHERE namespace=?1 AND key=?2",
                        params![a.namespace.as_slice(), &a.key],
                    ))
                    .map_err(|_| Failure::Unknown)?;
                }
                Mutation::DeleteRange {
                    namespace,
                    prefix,
                    exact_key_length,
                } => {
                    // SQLite cannot hold a key with a byte length above i64::MAX.
                    if let Ok(length) = i64::try_from(*exact_key_length) {
                        sql(tx.execute("DELETE FROM records WHERE namespace=?1 AND substr(key,1,?2)=?3 AND length(key)=?4",params![namespace.0.as_slice(),prefix.len() as i64,prefix,length])).map_err(|_| Failure::Unknown)?;
                    }
                }
            }
        }
        for (ns, n) in advances {
            put(&tx, control::GENERATION_NAMESPACE.0, &ns, &n.to_le_bytes())
                .map_err(|_| Failure::Unknown)?
        }
        sql(tx.execute(
            "INSERT INTO receipts VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                r.id.writer.as_slice(),
                r.id.operation.as_slice(),
                p.fingerprint().as_slice(),
                r.id.execution_epoch.to_le_bytes().as_slice(),
                observed_at.unix_seconds.to_le_bytes().as_slice(),
                r.result.expose_own(&self.owner).as_slice()
            ],
        ))
        .map_err(|_| Failure::Unknown)?;
        // A COMMIT error can be ambiguous. Never turn it into a false refusal.
        tx.commit().map_err(|_| Failure::Unknown)?;
        // Maintenance cannot erase the definitive successful business receipt.
        let _ = self.collect_receipts(&mut c, Instant::now());
        answer(Decision::Applied(returned))
    }
}
fn settings(input: &[u8]) -> Result<(crate::settings::Settings, usize), String> {
    let mut config: serde_json::Value = if input.trim_ascii().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(input).map_err(|e| e.to_string())?
    };
    let budget = if let Some(value) = config
        .as_object_mut()
        .and_then(|v| v.remove("input_budget_bytes"))
    {
        value
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("input_budget_bytes must be a positive usize")?
    } else {
        usize::MAX
    };
    Ok((
        crate::settings::Settings::parse(&config.to_string())?,
        budget,
    ))
}
fn open_current(s: &[u8], require_empty: bool) -> Result<(Connection, BackendInfo), String> {
    let (s, _budget) = settings(s)?;
    // Do not run schema migrations or journal PRAGMAs before inspection.
    // Inspect existing files read-only, honoring committed WAL state. SQLite may
    // use locking sidecars; this performs no data/schema/journal changes. The
    // same classification is repeated under the writer transaction below.
    if std::fs::metadata(&s.db_path).is_ok_and(|m| m.len() > 0) {
        let inspect =
            Connection::open_with_flags(&s.db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| e.to_string())?;
        if !crate::legacy::native::uninitialized(&inspect)
            .map_err(|_| "SQLite inspection unavailable")?
            && !crate::legacy::native::current_schema(&inspect)
                .map_err(|_| "SQLite current schema unavailable")?
        {
            return Err("not a canonical SQLite dataset; native preparation required".into());
        }
    }
    #[cfg(unix)]
    if s.db_path != ":memory:" {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&s.db_path)
        {
            Ok(file) => drop(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("SQLite file creation unavailable".into()),
        }
    }
    let mut c = Connection::open(&s.db_path).map_err(|e| e.to_string())?;
    c.busy_timeout(std::time::Duration::from_millis(s.busy_timeout_ms as u64))
        .map_err(|e| e.to_string())?;
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let schema: Vec<(String, String)> = tx
        .prepare("SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .and_then(|mut st| st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect())
        .map_err(|e| e.to_string())?;
    let ids = if schema.is_empty() {
        if !crate::legacy::native::uninitialized(&tx)
            .map_err(|_| "SQLite inspection unavailable")?
        {
            return Err("SQLite empty source changed".into());
        }
        let ids = [random()?, random()?, random()?];
        tx.execute_batch(DDL).map_err(|e| e.to_string())?;
        for (key, v) in [
            ("dataset", ids[0].as_slice()),
            ("atomic_domain", ids[1].as_slice()),
            ("clock_authority", ids[2].as_slice()),
            ("physical_format", &1u32.to_le_bytes()),
        ] {
            tx.execute("INSERT INTO meta VALUES(?1,?2)", params![key, v])
                .map_err(|e| e.to_string())?;
        }
        ids
    } else {
        if !crate::legacy::native::current_schema(&tx)
            .map_err(|_| "SQLite current schema unavailable")?
        {
            return Err("not a canonical SQLite dataset; native preparation required".into());
        }
        let mut ids = [[0; 16]; 3];
        for (i, k) in ["dataset", "atomic_domain", "clock_authority"]
            .iter()
            .enumerate()
        {
            let v: Vec<u8> = tx
                .query_row("SELECT value FROM meta WHERE key=?1", [k], |r| r.get(0))
                .map_err(|_| "missing v4 identity")?;
            ids[i] = v.try_into().map_err(|_| "bad v4 identity")?;
            if ids[i] == [0; 16] {
                return Err("zero v4 identity".into());
            }
        }
        let format: Vec<u8> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='physical_format'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "missing physical format")?;
        if format != 1u32.to_le_bytes() {
            return Err("unknown physical format".into());
        }
        ids
    };
    crate::legacy::native::install_empty_origin(&tx)
        .map_err(|_| "SQLite empty-origin barrier unavailable")?;
    if require_empty
        && !crate::legacy::native::whole_empty(&tx)
            .map_err(|_| "SQLite empty inspection unavailable")?
    {
        return Err("SQLite empty source changed".into());
    }
    tx.commit().map_err(|e| e.to_string())?;
    let memory: bool = c
        .query_row(
            "SELECT file = '' FROM pragma_database_list WHERE name='main'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let mode: String = c
        .query_row(
            if memory {
                "PRAGMA journal_mode=MEMORY"
            } else {
                "PRAGMA journal_mode=WAL"
            },
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    c.execute_batch("PRAGMA synchronous=FULL")
        .map_err(|e| e.to_string())?;
    let sync: i64 = c
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if sync != 2 || (!memory && mode != "wal") || (memory && mode != "memory") {
        return Err("SQLite durability configuration not effective".into());
    }
    Ok((
        c,
        BackendInfo {
            dataset: DatasetId(ids[0]),
            atomic_domain: ids[1],
            clock_authority: ids[2],
            physical_version: 1,
            durability: if memory {
                Durability::Ephemeral
            } else {
                Durability::Local
            },
        },
    ))
}

impl Backend for SqliteV4 {
    type Owner = Own;
    fn owner(&self) -> &Own {
        &self.owner
    }
    // An explicit instance setting may narrow host admission. Absent that setting,
    // the address-space ceiling applies; this is not a lower protocol byte cap.
    fn input_budget(&self) -> usize {
        self.budget
    }
    fn validate(s: &[u8]) -> Result<(), String> {
        settings(s).map(drop)
    }
    fn open(s: &[u8], _: &[&[u8]], _: Option<Host>) -> Result<Self, String> {
        let (settings, budget) = settings(s)?;
        let native = crate::legacy::native::Session::inspect(
            std::path::Path::new(&settings.db_path),
            settings.busy_timeout_ms as u64,
            64 * 1024 * 1024,
        )
        .map_err(|e| format!("SQLite preparation refused ({e:?})"))?;
        Ok(Self {
            owner: Own::here(),
            budget,
            settings: {
                let mut value: serde_json::Value =
                    serde_json::from_slice(s).unwrap_or_else(|_| serde_json::json!({}));
                if !value.is_object() {
                    value = serde_json::json!({});
                }
                value["db_path"] = serde_json::Value::String(
                    native
                        .database_name()
                        .to_str()
                        .ok_or("SQLite path unsupported")?
                        .to_owned(),
                );
                serde_json::to_vec(&value).map_err(|_| "SQLite settings unavailable")?
            },
            native: Mutex::new(native),
            enabled: AtomicBool::new(false),
            connection: Mutex::new(
                Connection::open_in_memory().map_err(|_| "SQLite preparation unavailable")?,
            ),
            horizons: Mutex::new(HashMap::new()),
            info: Mutex::new(BackendInfo {
                dataset: DatasetId([0; 16]),
                atomic_domain: [0; 16],
                clock_authority: [0; 16],
                physical_version: 1,
                durability: Durability::Ephemeral,
            }),
        })
    }
    fn connect(&self, _: &mut Op<'_>) -> Step<Result<(), String>> {
        Step::Ready(self.connect_now())
    }

    fn connect_prepared(
        &self,
        _: &mut Op<'_>,
        binding: &lifecycle::OpenBinding,
    ) -> Step<Result<(), String>> {
        Step::Ready(self.connect_binding(binding))
    }
    fn bootstrap(
        &self,
        _: &mut Op<'_>,
        request: &lifecycle::Request<Own>,
    ) -> Step<Result<lifecycle::Response<Own>, lifecycle::Error>> {
        Step::Ready(self.bootstrap_now(request))
    }
    fn info(&self) -> BackendInfo {
        self.facts()
    }
    fn read(&self, _: &mut Op<'_>, r: &Read) -> Step<Result<ReadResult<Own>, Failure>> {
        Step::Ready(self.read_now(r))
    }
    fn scan(&self, _: &mut Op<'_>, r: &Scan) -> Step<Result<Page<Own>, Failure>> {
        Step::Ready(self.scan_now(r))
    }
    fn commit(
        &self,
        _: &mut Op<'_>,
        r: &PreparedCandidate<Own>,
    ) -> Step<Result<Committed<Own>, Failure>> {
        Step::Ready(self.commit_now(r))
    }
    fn clock(&self, _: &mut Op<'_>, d: DatasetId) -> Step<Result<ClockObservation, Failure>> {
        Step::Ready(self.dataset(d).and_then(|()| {
            let c = self.guard()?;
            self.observation(&c)
        }))
    }
}
#[cfg(test)]
#[path = "tests/v4_tests.rs"]
mod tests;

#[path = "v4_lifecycle.rs"]
mod bootstrap;
