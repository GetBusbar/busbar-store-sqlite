// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in SQLite backend for busbar's durable governance store. Implements
//! `busbar_contract::records::RecordStore` over embedded rusqlite connections: one mutex-guarded
//! writer, plus a small pool of `query_only` readers so a long billing report or retention sweep
//! never blocks the hot-path usage flush (WAL readers are unaffected by an in-flight writer).
//!
//! [`door::door`] answers the store v3 table over [`SqliteStore`] through the contract's store SDK:
//! the base op set is the [`RecordStore`] implementation below, the v3 additions are in `v3`. A
//! build that links this crate registers `door`; the `busbar-store-sqlite-plugin` cdylib exports it.

#![forbid(unsafe_code)]

use busbar_contract::abi::sdk::store::{column, fork};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    PlaneDisposition, PlaneRecordRef, PlaneSelector, RecordStore, RecordStoreError,
    RecordStoreResult, Retention, SecretForm, UsageDelta, UsageLedger, VirtualKey, UNIT_CACHE_READ,
    UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// rusqlite error -> `RecordStoreError` (the contract crate stays storage-free, so the `From` impl
/// behind `?` cannot live there): write `<rusqlite call>.store()?`.
trait IntoStoreResult<T> {
    fn store(self) -> RecordStoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, rusqlite::Error> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| RecordStoreError(e.to_string()))
    }
}

/// Store schema version, kept in `PRAGMA user_version`. A file older than v6 is refused: no
/// release ever wrote one. v6 -> v14 upgrades in place:
/// - v10: kind-tagged `plane_records` / `plane_tokens`; `keys` gains `scope_grants`,
///   `idp_subject`, `binding_mode`, `minted_by`, `idp_provider`; `usage_metering` gains
///   `priced_from_ms` in its key (existing rows copied at 0); open usage units get their own tables.
///   The v6 `mcp_calls` table is left unread: its body is a digest stream no backend can rebuild.
/// - v11-v13: the store v3 state (`store_ops`, `schema_records`).
/// - v14: `credentials` is rebuilt so a revoked row may hold no secret (revoke destroys it); a row
///   revoked under an older build loses the secret it kept.
///
/// A file stamped by a later build is refused.
const SCHEMA_VERSION: i64 = 14;

/// The oldest schema any release wrote.
const FIRST_RELEASED_SCHEMA: i64 = 6;

/// The `credentials` table, under `$head` (`IF NOT EXISTS credentials` in [`SCHEMA`], the scratch
/// name in the v14 rebuild), so the two cannot drift.
macro_rules! credentials_ddl {
    ($head:literal) => {
        concat!(
            "CREATE TABLE ",
            $head,
            " (
    id            TEXT NOT NULL PRIMARY KEY,
    key_id        TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    kind          TEXT NOT NULL,
    -- 0 or 1: two rows per (key_id, kind) allow overlap-window rotation.
    slot          INTEGER NOT NULL,
    public_id     TEXT NOT NULL,
    secret        TEXT,
    secret_form   TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    revoked_at    INTEGER,
    revoke_reason TEXT,
    revision      INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT cred_kind CHECK (kind IN ('sigv4')),
    CONSTRAINT cred_slot CHECK (slot IN (0,1)),
    CONSTRAINT cred_form CHECK (secret_form IN ('none','recoverable','digest')),
    CONSTRAINT cred_form_null CHECK ((secret_form='none') = (secret IS NULL)),
    -- A revoked row has had its secret destroyed.
    CONSTRAINT cred_sigv4_recov CHECK (kind <> 'sigv4' OR secret_form = 'recoverable' OR revoked_at IS NOT NULL),
    CONSTRAINT cred_revoked_bare CHECK (revoked_at IS NULL OR secret IS NULL),
    CONSTRAINT cred_secret_fmt CHECK (secret IS NULL OR secret GLOB 'v1:?*:?*'),
    CONSTRAINT cred_reason_ord CHECK (revoke_reason IS NULL OR revoked_at IS NOT NULL),
    CONSTRAINT cred_expiry_after CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;"
        )
    };
}

const SCHEMA: &str = concat!("
CREATE TABLE IF NOT EXISTS store_meta (
    k TEXT NOT NULL PRIMARY KEY,
    v TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS store_revision (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
    revision INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE IF NOT EXISTS keys (
    id              TEXT NOT NULL PRIMARY KEY,
    name            TEXT NOT NULL,
    key_group       TEXT,
    -- NULL = the pool grant was omitted at mint = all pools; a JSON array (even '[]') = exhaustive.
    allowed_pools   TEXT,
    labels          TEXT NOT NULL DEFAULT '{}',
    enabled         INTEGER NOT NULL DEFAULT 1,
    -- Rotation fingerprint, compared post-resolution, never looked up by: deliberately not UNIQUE.
    generation_hash TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    expires_at      INTEGER,
    deleted_at      INTEGER,
    revision        INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT keys_enabled_bool CHECK (enabled IN (0,1)),
    CONSTRAINT keys_pools_json CHECK (allowed_pools IS NULL OR (json_valid(allowed_pools) AND json_type(allowed_pools)='array')),
    CONSTRAINT keys_labels_json CHECK (json_valid(labels) AND json_type(labels)='object' AND length(labels)<=4096),
    -- Both tombstone flags must change in the SAME UPDATE (SQLite has no deferred CHECK).
    CONSTRAINT keys_tombstone_off CHECK (deleted_at IS NULL OR enabled = 0),
    CONSTRAINT keys_expiry_after CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;
CREATE INDEX IF NOT EXISTS keys_revision_idx ON keys (revision);
CREATE INDEX IF NOT EXISTS keys_group_live_idx ON keys (key_group) WHERE deleted_at IS NULL;

-- Only for auth verified by ROW LOOKUP from a wire-supplied public identifier (today: sigv4).
",
    credentials_ddl!("IF NOT EXISTS credentials"),
    "
CREATE UNIQUE INDEX IF NOT EXISTS cred_public_id_uq ON credentials (kind, public_id);
CREATE UNIQUE INDEX IF NOT EXISTS cred_slot_uq ON credentials (key_id, kind, slot);
CREATE INDEX IF NOT EXISTS cred_revision_idx ON credentials (revision);

-- No FK to keys: a revocation must be insertable even if the key row is gone.
CREATE TABLE IF NOT EXISTS denylist (
    sub        TEXT NOT NULL PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;

-- window_start leads the PK: write locality and a contiguous prefix for the retention sweep.
CREATE TABLE IF NOT EXISTS usage_windows (
    window_start       INTEGER NOT NULL,
    bucket_id          TEXT NOT NULL,
    model              TEXT NOT NULL,
    requests           INTEGER NOT NULL DEFAULT 0,
    billable_requests  INTEGER NOT NULL DEFAULT 0,
    tokens_input       INTEGER NOT NULL DEFAULT 0,
    tokens_output      INTEGER NOT NULL DEFAULT 0,
    tokens_cache_read  INTEGER NOT NULL DEFAULT 0,
    tokens_cache_write INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (window_start, bucket_id, model)
) STRICT, WITHOUT ROWID;

-- Durable billing ledger. `priced_from_ms` is the start of the rate-card entry the cell accrued
-- under (0 = the opening card): a card edit mid-day splits the day's cell.
CREATE TABLE IF NOT EXISTS usage_metering (
    bucket             TEXT NOT NULL,
    key_id             TEXT NOT NULL,
    provider           TEXT NOT NULL,
    model              TEXT NOT NULL,
    key_group_at_use   TEXT NOT NULL DEFAULT '',
    pricing_version    TEXT NOT NULL DEFAULT '',
    requests           INTEGER NOT NULL DEFAULT 0,
    billable_requests  INTEGER NOT NULL DEFAULT 0,
    tokens_input       INTEGER NOT NULL DEFAULT 0,
    tokens_output      INTEGER NOT NULL DEFAULT 0,
    tokens_cache_read  INTEGER NOT NULL DEFAULT 0,
    tokens_cache_write INTEGER NOT NULL DEFAULT 0,
    priced_from_ms     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS um_key_bucket_idx ON usage_metering (key_id, bucket);

-- The open usage units (every one the four reserved token columns do not hold), one row per unit
-- so an accrual is an atomic `count = count + delta`.
CREATE TABLE IF NOT EXISTS usage_window_units (
    window_start INTEGER NOT NULL,
    bucket_id    TEXT NOT NULL,
    model        TEXT NOT NULL,
    unit         TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (window_start, bucket_id, model, unit)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS usage_metering_units (
    bucket         TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    provider       TEXT NOT NULL,
    model          TEXT NOT NULL,
    priced_from_ms INTEGER NOT NULL DEFAULT 0,
    unit           TEXT NOT NULL,
    count          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms, unit)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS audit_log (
    seq       INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    action    TEXT NOT NULL,
    resource  TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    principal TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS audit_resource_seq_idx ON audit_log (resource, seq);

-- Every plane's durable records, tagged by `kind`. The store never decodes `body`; everything it
-- keys, orders or sweeps on is a typed sidecar column. `identity` is the record's `parent` when it
-- has one (a chain position is `(kind, parent, seq)`), else its own `id` at `seq` 0.
CREATE TABLE IF NOT EXISTS plane_records (
    kind        TEXT NOT NULL,
    identity    TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    id          TEXT NOT NULL,
    parent      TEXT,
    ts          INTEGER NOT NULL,
    disposition TEXT NOT NULL,
    body        BLOB NOT NULL,
    CONSTRAINT plane_disposition CHECK (disposition IN ('active','terminal')),
    PRIMARY KEY (kind, identity, seq)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS plane_records_kind_ts_idx ON plane_records (kind, ts);
CREATE INDEX IF NOT EXISTS plane_records_kind_parent_idx ON plane_records (kind, parent, seq);

-- The single-use token ledger, shared by every node on the file; swept past one validity window.
CREATE TABLE IF NOT EXISTS plane_tokens (
    kind       TEXT NOT NULL,
    token      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (kind, token)
) STRICT, WITHOUT ROWID;

-- The durable `op_id` dedupe log: an applied op's body (`Dedupe::body_hex`; an older build's
-- `{:?}` form still replays) in the same transaction as its effect. `answer` is a constant.
CREATE TABLE IF NOT EXISTS store_ops (
    op_id       BLOB NOT NULL PRIMARY KEY,
    body        TEXT NOT NULL,
    answer      TEXT NOT NULL,
    recorded_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS store_ops_recorded_idx ON store_ops (recorded_at);

-- A plane's kernel-held records, by `(schema, key)`.
CREATE TABLE IF NOT EXISTS schema_records (
    schema     TEXT NOT NULL,
    record_key BLOB NOT NULL,
    value      BLOB NOT NULL,
    PRIMARY KEY (schema, record_key)
) STRICT, WITHOUT ROWID;

-- Integrity triggers that survive opening the file with the sqlite3 CLI (foreign_keys defaults OFF).
CREATE TRIGGER IF NOT EXISTS keys_guard_hard_delete BEFORE DELETE ON keys FOR EACH ROW
  WHEN EXISTS (SELECT 1 FROM usage_metering WHERE key_id = OLD.id)
  BEGIN SELECT RAISE(ABORT, 'keys: hard DELETE would orphan usage_metering rows; use the tombstone path (Store::delete_key)'); END;
CREATE TRIGGER IF NOT EXISTS keys_cascade_credentials AFTER DELETE ON keys FOR EACH ROW
  BEGIN DELETE FROM credentials WHERE key_id = OLD.id; END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
-- An appended chain record (one filed at its parent: identity = parent) is never rewritten; an
-- upserted record that names a parent lives at its own id and is rewritten by its next upsert.
-- No no-delete counterpart: these rows have a retention sweep, and bounded retention is not an
-- integrity claim.
CREATE TRIGGER IF NOT EXISTS plane_records_chain_no_update BEFORE UPDATE ON plane_records
  WHEN OLD.parent IS NOT NULL AND OLD.identity = OLD.parent
  BEGIN SELECT RAISE(ABORT, 'plane_records: an appended chain record is never rewritten'); END;
");

/// True for any SQLite path spelling that opens a private in-memory database: `:memory:`, or a
/// `file:` URI whose path is `:memory:` or whose query carries `mode=memory`. A path that merely
/// contains those characters elsewhere is a real file. Pragma selection and `SqliteStore::open`'s
/// single-connection routing both use this one check.
fn is_memory_path(path: &str) -> bool {
    if path == ":memory:" {
        return true;
    }
    let Some(uri) = path.strip_prefix("file:") else {
        return false;
    };
    let uri = uri.split('#').next().unwrap_or_default();
    let (file, query) = uri.split_once('?').unwrap_or((uri, ""));
    file == ":memory:" || query.split('&').any(|param| param == "mode=memory")
}

/// Apply the fixed pragma set, `busy_timeout` FIRST (switching a file into WAL itself briefly
/// acquires the database, so the timeout must already be set). `is_writer` gates the writer-only
/// pragmas and `query_only` (readers only; `SQLITE_OPEN_READ_ONLY` cannot create the `-wal`/`-shm`
/// files on a fresh database).
fn apply_pragmas(
    conn: &Connection,
    path: &str,
    busy_timeout_ms: i64,
    is_writer: bool,
) -> RecordStoreResult<()> {
    conn.pragma_update(None, "busy_timeout", busy_timeout_ms)
        .store()?;
    let is_memory = is_memory_path(path);
    if !is_memory {
        conn.pragma_update(None, "journal_mode", "WAL").store()?;
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .store()?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(RecordStoreError(format!(
                "sqlite: failed to enable WAL mode on {path} (got journal_mode={mode}); refusing to \
                 continue on a rollback-journal database, which would make every read block on the writer"
            )));
        }
    }
    conn.pragma_update(None, "foreign_keys", "ON").store()?;
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .store()?;
    if fk != 1 {
        return Err(RecordStoreError(
            "sqlite: foreign_keys could not be enabled (SQLITE_OMIT_FOREIGN_KEY build, or the pragma \
             was issued inside a transaction) — refusing to start without FK enforcement backing the \
             credentials->keys CASCADE".to_string(),
        ));
    }
    conn.pragma_update(None, "synchronous", "NORMAL").store()?;
    conn.pragma_update(None, "temp_store", "MEMORY").store()?;
    conn.pragma_update(None, "cache_size", if is_writer { -65536 } else { -16384 })
        .store()?;
    // No mmap on a path that looks like a network filesystem (best effort, not an fs-type probe).
    let mmap = if path.contains("//") && !path.starts_with(':') {
        0
    } else {
        268_435_456
    };
    conn.pragma_update(None, "mmap_size", mmap).store()?;
    conn.pragma_update(None, "secure_delete", "FAST").store()?;
    conn.pragma_update(None, "trusted_schema", "OFF").store()?;
    conn.pragma_update(None, "recursive_triggers", "OFF")
        .store()?;
    if is_writer && !is_memory {
        conn.pragma_update(None, "journal_size_limit", 67_108_864i64)
            .store()?;
        conn.pragma_update(None, "wal_autocheckpoint", 2000i64)
            .store()?;
    }
    if !is_writer {
        conn.pragma_update(None, "query_only", "ON").store()?;
    }
    Ok(())
}

/// Every row of `sql`, mapped by `f`.
fn query_all<T>(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
    f: impl FnMut(&rusqlite::Row) -> rusqlite::Result<T>,
) -> RecordStoreResult<Vec<T>> {
    conn.prepare_cached(sql)
        .store()?
        .query_map(params, f)
        .store()?
        .collect::<Result<Vec<_>, _>>()
        .store()
}

/// The one row of `sql` mapped by `f`, if any (statement cached per connection).
fn query_one<T>(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
    f: impl FnOnce(&rusqlite::Row) -> rusqlite::Result<T>,
) -> RecordStoreResult<Option<T>> {
    conn.prepare_cached(sql)
        .store()?
        .query_row(params, f)
        .optional()
        .store()
}

/// Execute `sql` through the connection's statement cache; the rows changed.
fn exec(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> RecordStoreResult<usize> {
    conn.prepare_cached(sql).store()?.execute(params).store()
}

/// Embedded SQLite `Store` backend. One mutex-guarded writer connection (all mutations, `BEGIN
/// IMMEDIATE`, never `DEFERRED`: every write here is read-then-write and `DEFERRED`'s upgrade can
/// return `SQLITE_BUSY_SNAPSHOT`, which bypasses the busy handler) plus a small round-robin pool of
/// `query_only` reader connections.
pub struct SqliteStore {
    writer: Mutex<Connection>,
    /// The writer's current `synchronous` mode (FULL = true), so the PRAGMA is issued only on a
    /// change. Read and written only under the `writer` lock.
    writer_full: AtomicBool,
    /// Ops recorded since open, pacing the `store_ops` retention sweep.
    ops_recorded: AtomicU64,
    readers: Vec<Mutex<Connection>>,
    next_reader: AtomicUsize,
    path: String,
}

/// Create a missing database file 0600 (it holds recoverable secrets) so SQLite, which gives the
/// `-wal`/`-shm` files the main file's mode, never creates it with the umask. An existing file is
/// left alone, and so is any failure to create (SQLite reports it on open).
#[cfg(unix)]
fn create_private(path: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    if !path.starts_with("file:") {
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);
    }
}

#[cfg(not(unix))]
fn create_private(_: &str) {}

impl SqliteStore {
    pub fn open(path: &str, busy_timeout_ms: i64) -> RecordStoreResult<Self> {
        // A `:memory:` spelling opens a NEW private database per connection, so a writer plus N
        // readers would be N+1 mutually invisible databases: route to the single-connection path.
        if is_memory_path(path) {
            return Self::open_in_memory();
        }
        Self::open_with_readers(
            path,
            busy_timeout_ms,
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .clamp(4, 8),
        )
    }

    fn open_with_readers(
        path: &str,
        busy_timeout_ms: i64,
        n_readers: usize,
    ) -> RecordStoreResult<Self> {
        create_private(path);
        let writer_conn = Connection::open(path).store()?;
        apply_pragmas(&writer_conn, path, busy_timeout_ms, true)?;
        let mut readers = Vec::with_capacity(n_readers);
        for _ in 0..n_readers {
            let r = Connection::open(path).store()?;
            apply_pragmas(&r, path, busy_timeout_ms, false)?;
            readers.push(Mutex::new(r));
        }
        let store = Self {
            writer: Mutex::new(writer_conn),
            writer_full: AtomicBool::new(false),
            ops_recorded: AtomicU64::new(0),
            readers,
            next_reader: AtomicUsize::new(0),
            path: path.to_string(),
        };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory store with one connection for both roles (a separate reader pool would see a
    /// different empty database).
    pub fn open_in_memory() -> RecordStoreResult<Self> {
        let conn = Connection::open_in_memory().store()?;
        apply_pragmas(&conn, ":memory:", 5000, true)?;
        let store = Self {
            writer: Mutex::new(conn),
            writer_full: AtomicBool::new(false),
            ops_recorded: AtomicU64::new(0),
            readers: Vec::new(),
            next_reader: AtomicUsize::new(0),
            path: ":memory:".to_string(),
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock_writer(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.writer.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The filesystem path (or `:memory:`) this store was opened against.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// An idle reader connection (round-robin start), else wait on one; the writer when no pool exists (`:memory:`).
    fn lock_reader(&self) -> std::sync::MutexGuard<'_, Connection> {
        if self.readers.is_empty() {
            return self.lock_writer();
        }
        let n = self.readers.len();
        let start = self.next_reader.fetch_add(1, Ordering::Relaxed) % n;
        for k in 0..n {
            match self.readers[(start + k) % n].try_lock() {
                Ok(g) => return g,
                Err(std::sync::TryLockError::Poisoned(p)) => return p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
        }
        self.readers[start]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Run `f` in one `BEGIN IMMEDIATE` transaction on the writer, committing when it returns `Ok`.
    /// `full` escalates to `synchronous=FULL` for the transaction (mint, revoke, rotate, delete,
    /// the metering flush, audit, every plane write: a power cut must not hand back the old state).
    fn write<T>(
        &self,
        full: bool,
        f: impl FnOnce(&Transaction<'_>) -> RecordStoreResult<T>,
    ) -> RecordStoreResult<T> {
        let mut conn = self.lock_writer();
        // SQLite refuses to change `synchronous` inside a transaction, so the mode is set BEFORE
        // the transaction opens, and only when it differs from the connection's current one.
        if self.writer_full.load(Ordering::Relaxed) != full {
            conn.pragma_update(None, "synchronous", if full { "FULL" } else { "NORMAL" })
                .store()?;
            self.writer_full.store(full, Ordering::Relaxed);
        }
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        let out = f(&tx)?;
        tx.commit().store()?;
        Ok(out)
    }

    fn migrate(&self) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        // One transaction over the upgrade and the version stamp. The version is read
        // INSIDE it: every one-time step below is gated on it, and a value read before the lock is
        // stale the moment another process opening the file commits its own migration.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        let version: i64 = tx
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .store()?;
        if version > SCHEMA_VERSION {
            return Err(RecordStoreError(format!(
                "sqlite: database schema v{version} is newer than this build (v{SCHEMA_VERSION}); \
                 refusing to open"
            )));
        }
        if version != 0 && version < FIRST_RELEASED_SCHEMA {
            return Err(RecordStoreError(format!(
                "sqlite: database schema v{version} predates v{FIRST_RELEASED_SCHEMA}, the oldest \
                 released schema; refusing to open"
            )));
        }
        // v10: `usage_metering` gains `priced_from_ms` in its key. Keyed on the column's absence so
        // a re-run is a no-op, and run BEFORE `SCHEMA` so its `IF NOT EXISTS` finds the rebuilt table.
        if table_exists(&tx, "usage_metering")?
            && !column_exists(&tx, "usage_metering", "priced_from_ms")?
        {
            rebuild_usage_metering_for_v10(&tx)?;
        }
        // v14: `credentials` gains the revoked-row CHECKs, which SQLite cannot add in place. Run
        // BEFORE `SCHEMA` so its `IF NOT EXISTS` finds the rebuilt table.
        if version != 0 && version < 14 && table_exists(&tx, "credentials")? {
            rebuild_credentials_for_v14(&tx)?;
        }
        // The chain trigger's condition narrowed to appended records (upsert-by-id): a file opened
        // by an older build holds the old one, and `SCHEMA` creates it only if it is absent.
        tx.execute_batch("DROP TRIGGER IF EXISTS plane_records_chain_no_update;")
            .store()?;
        tx.execute_batch(SCHEMA).store()?;
        tx.execute(
            "INSERT INTO store_revision (id, revision) VALUES (0, 0) ON CONFLICT(id) DO NOTHING",
            [],
        )
        .store()?;
        add_v10_key_columns(&tx)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    /// Bump the store-global revision counter, inside the same `BEGIN IMMEDIATE` transaction as the
    /// mutation it stamps (`RETURNING` hands the value back in one round trip).
    fn bump_revision(tx: &rusqlite::Transaction) -> RecordStoreResult<i64> {
        query_one(
            tx,
            "UPDATE store_revision SET revision = revision + 1 WHERE id = 0 RETURNING revision",
            [],
            |r| r.get(0),
        )?
        .ok_or_else(|| RecordStoreError("store_revision row missing".into()))
    }
}

/// `col + delta` in SQL, saturating at `i64::MAX` (a REAL result would be refused by STRICT INTEGER).
macro_rules! sat_add {
    ($col:literal, $delta:literal) => {
        concat!(
            "CASE WHEN ",
            $delta,
            " > 0 AND ",
            $col,
            " > 9223372036854775807 - ",
            $delta,
            " THEN 9223372036854775807 ELSE ",
            $col,
            " + ",
            $delta,
            " END"
        )
    };
}

/// The four RESERVED usage units, in the order of the `usage_windows` token columns that hold them.
/// Every other unit name is an OPEN unit and lives in `usage_window_units`.
const RESERVED_COLUMNS: [&str; 4] = [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE];

/// The OPEN (non-reserved) entries of a name-keyed usage map.
fn open_units<V>(units: &BTreeMap<String, V>) -> impl Iterator<Item = (&String, &V)> {
    units
        .iter()
        .filter(|(k, _)| !RESERVED_COLUMNS.contains(&k.as_str()))
}

fn table_exists(tx: &rusqlite::Connection, table: &str) -> RecordStoreResult<bool> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |r| r.get(0),
    )
    .store()
}

fn column_exists(tx: &rusqlite::Connection, table: &str, column: &str) -> RecordStoreResult<bool> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name=?2)",
        params![table, column],
        |r| r.get(0),
    )
    .store()
}

/// Rebuild a pre-v10 `usage_metering` with `priced_from_ms` in its primary key, the one change SQLite
/// cannot make in place. Every row is copied at `priced_from_ms = 0`, the opening card's instant.
/// The column list must stay identical to [`SCHEMA`]'s (`a_real_v6_database_from_the_released_plugin_opens_and_upgrades_losslessly`).
/// The trigger naming `usage_metering` is dropped first because `ALTER TABLE ... RENAME` re-parses
/// every trigger; `SCHEMA` recreates it right after.
fn rebuild_usage_metering_for_v10(tx: &rusqlite::Connection) -> RecordStoreResult<()> {
    tx.execute_batch(
        "DROP TRIGGER IF EXISTS keys_guard_hard_delete;
         CREATE TABLE usage_metering_v10 (
             bucket             TEXT NOT NULL,
             key_id             TEXT NOT NULL,
             provider           TEXT NOT NULL,
             model              TEXT NOT NULL,
             key_group_at_use   TEXT NOT NULL DEFAULT '',
             pricing_version    TEXT NOT NULL DEFAULT '',
             requests           INTEGER NOT NULL DEFAULT 0,
             billable_requests  INTEGER NOT NULL DEFAULT 0,
             tokens_input       INTEGER NOT NULL DEFAULT 0,
             tokens_output      INTEGER NOT NULL DEFAULT 0,
             tokens_cache_read  INTEGER NOT NULL DEFAULT 0,
             tokens_cache_write INTEGER NOT NULL DEFAULT 0,
             priced_from_ms     INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms)
         ) STRICT, WITHOUT ROWID;
         INSERT INTO usage_metering_v10 (bucket, key_id, provider, model, key_group_at_use,
             pricing_version, requests, billable_requests, tokens_input, tokens_output,
             tokens_cache_read, tokens_cache_write, priced_from_ms)
           SELECT bucket, key_id, provider, model, key_group_at_use, pricing_version, requests,
             billable_requests, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, 0
           FROM usage_metering;
         DROP TABLE usage_metering;
         ALTER TABLE usage_metering_v10 RENAME TO usage_metering;",
    )
    .store()
}

/// Rebuild a pre-v14 `credentials` with the v14 CHECKs, copying every row; a row revoked under an
/// older build keeps its metadata and loses the secret it held. The trigger naming `credentials`
/// is dropped first because `ALTER TABLE ... RENAME` re-parses every trigger; `SCHEMA` recreates
/// it and the indexes right after.
fn rebuild_credentials_for_v14(tx: &rusqlite::Connection) -> RecordStoreResult<()> {
    tx.execute_batch(concat!(
        "DROP TRIGGER IF EXISTS keys_cascade_credentials;",
        credentials_ddl!("credentials_v14"),
        "INSERT INTO credentials_v14 (id, key_id, kind, slot, public_id, secret, secret_form,
             created_at, updated_at, expires_at, revoked_at, revoke_reason, revision)
           SELECT id, key_id, kind, slot, public_id,
             CASE WHEN revoked_at IS NULL THEN secret END,
             CASE WHEN revoked_at IS NULL THEN secret_form ELSE 'none' END,
             created_at, updated_at, expires_at, revoked_at, revoke_reason, revision
           FROM credentials;
         DROP TABLE credentials;
         ALTER TABLE credentials_v14 RENAME TO credentials;"
    ))
    .store()
}

/// The v10 `keys` columns: nullable `ADD COLUMN`s, so a pre-v10 row reads back exactly as before
/// (no non-pool scope grant, `None` for the attribution fields).
fn add_v10_key_columns(tx: &rusqlite::Connection) -> RecordStoreResult<()> {
    const COLUMNS: [(&str, &str); 5] = [
        (
            "scope_grants",
            "TEXT CONSTRAINT keys_scope_grants_json CHECK (scope_grants IS NULL OR \
             (json_valid(scope_grants) AND json_type(scope_grants)='object'))",
        ),
        ("idp_subject", "TEXT"),
        ("binding_mode", "TEXT"),
        ("minted_by", "TEXT"),
        ("idp_provider", "TEXT"),
    ];
    for (name, decl) in COLUMNS {
        if !column_exists(tx, "keys", name)? {
            tx.execute_batch(&format!("ALTER TABLE keys ADD COLUMN {name} {decl}"))
                .store()?;
        }
    }
    Ok(())
}

fn row_to_key(r: &rusqlite::Row) -> rusqlite::Result<VirtualKey> {
    Ok(VirtualKey {
        id: r.get(0)?,
        generation_hash: r.get(1)?,
        name: r.get(2)?,
        allowed_scopes: column::scopes_from_columns(r.get(3)?, r.get(11)?),
        enabled: r.get::<_, i64>(4)? != 0,
        created_at: r.get::<_, i64>(5)? as u64,
        group: r.get(6)?,
        labels: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default(),
        expires_at: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        deleted_at: r.get::<_, Option<i64>>(9)?.map(|v| v as u64),
        revision: column::read_u64(r.get(10)?),
        idp_subject: r.get(12)?,
        binding_mode: r.get(13)?,
        minted_by: r.get(14)?,
        idp_provider: r.get(15)?,
    })
}

macro_rules! key_cols {
    () => {
        "id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,\
         expires_at,deleted_at,revision,scope_grants,idp_subject,binding_mode,minted_by,idp_provider"
    };
}

fn secret_form_to_str(f: SecretForm) -> &'static str {
    match f {
        SecretForm::None => "none",
        SecretForm::Recoverable => "recoverable",
        SecretForm::Digest => "digest",
    }
}
fn secret_form_from_str(s: &str) -> SecretForm {
    match s {
        "recoverable" => SecretForm::Recoverable,
        "digest" => SecretForm::Digest,
        _ => SecretForm::None,
    }
}

fn row_to_cred_meta(r: &rusqlite::Row) -> rusqlite::Result<CredentialMeta> {
    Ok(CredentialMeta {
        id: r.get(0)?,
        key_id: r.get(1)?,
        kind: r.get(2)?,
        slot: r.get::<_, i64>(3)? as u8,
        public_id: r.get(4)?,
        secret_form: secret_form_from_str(&r.get::<_, String>(5)?),
        created_at: r.get::<_, i64>(6)? as u64,
        updated_at: r.get::<_, i64>(7)? as u64,
        expires_at: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        revoked_at: r.get::<_, Option<i64>>(9)?.map(|v| v as u64),
        revoke_reason: r.get(10)?,
        revision: column::read_u64(r.get(11)?),
    })
}
const CRED_META_COLS: &str =
    "id,key_id,kind,slot,public_id,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision";

/// The meta columns, then `secret`.
fn row_to_cred_secret(r: &rusqlite::Row) -> rusqlite::Result<CredentialSecret> {
    Ok(CredentialSecret {
        meta: row_to_cred_meta(r)?,
        secret: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
    })
}

/// The `keys_labels_json` CHECK's ceiling on the serialized labels, in characters (`length()`).
const MAX_LABELS_CHARS: usize = 4096;

fn put_key_inner(
    conn: &rusqlite::Connection,
    key: &VirtualKey,
    revision: i64,
    method: &str,
) -> RecordStoreResult<()> {
    let labels = serde_json::to_string(&key.labels).unwrap_or_else(|_| "{}".to_string());
    let chars = labels.chars().count();
    if chars > MAX_LABELS_CHARS {
        return Err(RecordStoreError(format!(
            "{method}: labels of key {} are {chars} characters, over the {MAX_LABELS_CHARS}-character limit",
            key.id
        )));
    }
    // `?6` (created_at) seeds `updated_at` on INSERT, but the ON CONFLICT branch stamps `?12`, the
    // mutation time, like every other mutation path here. The `WHERE` on that branch is the
    // TOMBSTONE PRECONDITION: a live-shaped write must not overwrite a tombstoned row, which would
    // reissue an id the contract says is never reissued. It is in the statement, not a prior SELECT,
    // so the test and the write are atomic against a concurrent `delete_key`. A write that CARRIES
    // a tombstone is unaffected. When the guard bites, `execute` reports 0 rows.
    let (allowed_pools, scope_grants) = column::scope_columns(key.allowed_scopes.as_deref());
    let affected = conn.execute(
        "INSERT INTO keys (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,updated_at,revision,
                           scope_grants,idp_subject,binding_mode,minted_by,idp_provider)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?6,?11,?13,?14,?15,?16,?17)
         ON CONFLICT(id) DO UPDATE SET
            generation_hash=excluded.generation_hash, name=excluded.name, allowed_pools=excluded.allowed_pools,
            enabled=excluded.enabled, key_group=excluded.key_group, labels=excluded.labels,
            expires_at=excluded.expires_at, deleted_at=excluded.deleted_at, updated_at=?12, revision=?11,
            scope_grants=excluded.scope_grants, idp_subject=excluded.idp_subject,
            binding_mode=excluded.binding_mode, minted_by=excluded.minted_by, idp_provider=excluded.idp_provider
         WHERE excluded.deleted_at IS NOT NULL OR keys.deleted_at IS NULL",
        params![
            key.id,
            key.generation_hash,
            key.name,
            allowed_pools,
            key.enabled as i64,
            key.created_at as i64,
            key.group,
            labels,
            key.expires_at.map(|v| v as i64),
            key.deleted_at.map(|v| v as i64),
            revision,
            now_secs(),
            scope_grants,
            key.idp_subject,
            key.binding_mode,
            key.minted_by,
            key.idp_provider,
        ],
    )
    .store()?;
    if affected == 0 {
        return Err(RecordStoreError(format!(
            "put_key: '{}' is tombstoned and its id is never reissued; refusing to clear the \
             tombstone",
            key.id
        )));
    }
    Ok(())
}

const CRED_SECRET_COLS: &str = "id,key_id,kind,slot,public_id,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision,secret";

/// [`RecordStore::add_usage`]'s writes, inside the caller's transaction (the trait method's own, or
/// a store v3 slot's, where the `op_id` record shares it).
fn add_usage_in(
    tx: &Connection,
    bucket_id: &str,
    window_start: u64,
    delta: &UsageDelta,
) -> RecordStoreResult<()> {
    // `requests` / `billable_requests` accumulate unconditionally on the `model=''` sentinel row,
    // whether or not the delta reached any model (a rejected request adds to `requests` alone).
    // `prepare_cached`: this fires once per admitted request, the hottest write path in the crate.
    tx.prepare_cached(concat!(
        "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests)
         VALUES (?1,?2,'',MAX(0,?3),MAX(0,?4))
         ON CONFLICT(window_start, bucket_id, model) DO UPDATE SET
            requests = MAX(0, ",
        sat_add!("requests", "?3"),
        "),
            billable_requests = MAX(0, ",
        sat_add!("billable_requests", "?4"),
        ")"
    ))
    .store()?
    .execute(params![
        window_start as i64,
        bucket_id,
        delta.requests,
        delta.billable_requests
    ])
    .store()?;
    for m in &delta.models {
        let d = |unit: &str| m.usage_units.get(unit).copied().unwrap_or(0);
        tx.prepare_cached(concat!(
            "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests,
                 tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
             VALUES (?1,?2,?3,0,0,MAX(0,?4),MAX(0,?5),MAX(0,?6),MAX(0,?7))
             ON CONFLICT(window_start, bucket_id, model) DO UPDATE SET
                tokens_input       = MAX(0, ", sat_add!("tokens_input", "?4"), "),
                tokens_output      = MAX(0, ", sat_add!("tokens_output", "?5"), "),
                tokens_cache_read  = MAX(0, ", sat_add!("tokens_cache_read", "?6"), "),
                tokens_cache_write = MAX(0, ", sat_add!("tokens_cache_write", "?7"), ")"
        ))
        .store()?
        .execute(params![
            window_start as i64,
            bucket_id,
            m.model,
            d(UNIT_INPUT),
            d(UNIT_OUTPUT),
            d(UNIT_CACHE_READ),
            d(UNIT_CACHE_WRITE),
        ])
        .store()?;
        // Every open unit accumulates the same way, floored at 0 (a refund never drives a counter negative).
        for (unit, d) in open_units(&m.usage_units) {
            tx.prepare_cached(concat!(
                "INSERT INTO usage_window_units (window_start, bucket_id, model, unit, count)
                 VALUES (?1,?2,?3,?4,MAX(0,?5))
                 ON CONFLICT(window_start, bucket_id, model, unit) DO UPDATE SET
                    count = MAX(0, ",
                sat_add!("count", "?5"),
                ")"
            ))
            .store()?
            .execute(params![window_start as i64, bucket_id, m.model, unit, d])
            .store()?;
        }
    }
    Ok(())
}

/// [`RecordStore::add_metering`]'s writes, inside the caller's transaction.
fn add_metering_in(tx: &Connection, d: &MeteringDelta) -> RecordStoreResult<()> {
    // Refused rather than clamped: `priced_from_ms` is part of the cell's KEY, so a clamped value
    // would merge this accrual into a different card's cell.
    let priced_from = column::storable_i64("add_metering", "priced_from_ms", d.priced_from_ms)?;
    exec(
        tx,
        concat!("INSERT INTO usage_metering (bucket, key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version,
             tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, requests, billable_requests)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(bucket, key_id, provider, model, priced_from_ms) DO UPDATE SET
             tokens_input       = ", sat_add!("tokens_input", "excluded.tokens_input"), ",
             tokens_output      = ", sat_add!("tokens_output", "excluded.tokens_output"), ",
             tokens_cache_read  = ", sat_add!("tokens_cache_read", "excluded.tokens_cache_read"), ",
             tokens_cache_write = ", sat_add!("tokens_cache_write", "excluded.tokens_cache_write"), ",
             requests           = ", sat_add!("requests", "excluded.requests"), ",
             billable_requests  = ", sat_add!("billable_requests", "excluded.billable_requests")),
        params![
            d.bucket as i64,
            d.key_id,
            d.provider,
            d.model,
            priced_from,
            d.key_group_at_use,
            d.pricing_version,
            column::clamp(d.tokens_input),
            column::clamp(d.tokens_output),
            column::clamp(d.tokens_cache_read),
            column::clamp(d.tokens_cache_write),
            column::clamp(d.requests),
            column::clamp(d.billable_requests),
        ],
    )?;
    for (unit, count) in &d.usage_units {
        exec(
            tx,
            concat!("INSERT INTO usage_metering_units (bucket, key_id, provider, model, priced_from_ms, unit, count)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(bucket, key_id, provider, model, priced_from_ms, unit) DO UPDATE SET
                 count = ", sat_add!("count", "excluded.count")),
            params![
                d.bucket as i64,
                d.key_id,
                d.provider,
                d.model,
                priced_from,
                unit,
                column::clamp(*count),
            ],
        )?;
    }
    Ok(())
}

/// [`RecordStore::append_audit`]'s write and fork check, inside the caller's transaction.
fn append_audit_in(tx: &Connection, entry: &AuditRecord) -> RecordStoreResult<()> {
    // A `seq` / `ts` past `i64::MAX` would wrap negative and read back clamped to 0, so an identical
    // retry would compare unequal and be reported as a forked chain. Rejected outright.
    let seq = column::storable_i64("append_audit", "seq", entry.seq)?;
    let ts = column::storable_i64("append_audit", "ts", entry.ts)?;
    let affected = exec(
        tx,
        "INSERT INTO audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(seq) DO NOTHING",
        params![
            seq,
            ts,
            entry.action,
            entry.resource,
            entry.outcome,
            entry.principal,
            entry.prev_hash,
            entry.hash,
        ],
    )?;
    // A collision is EITHER the write-through retrying (identical: Ok) or two records claiming one
    // chain position (a forked or tampered log, the thing an audit store must report).
    if affected == 0 {
        let stored = query_one(
            tx,
            "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash \
             FROM audit_log WHERE seq=?1",
            params![seq],
            row_to_audit,
        )?;
        if stored.as_ref() != Some(entry) {
            return Err(fork::audit_fork(entry.seq));
        }
    }
    Ok(())
}

/// [`RecordStore::append_plane_record`]'s occupancy check and insert, inside the caller's transaction.
fn append_plane_record_in(tx: &Connection, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
    let seq = column::storable_i64("append_plane_record", "seq", record.seq)?;
    let row = PlaneRow::of(
        record,
        record.parent.unwrap_or(record.id),
        seq,
        "append_plane_record",
    )?;
    let existing: Option<StoredPlaneRow> = query_one(
        tx,
        "SELECT id, parent, ts, disposition, body FROM plane_records \
         WHERE kind=?1 AND identity=?2 AND seq=?3",
        params![record.kind, row.identity, row.seq],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    if let Some((id, parent, ts, disposition, body)) = existing {
        // Identical is the write-through retrying (success); different is a forked chain (an error,
        // as in `append_audit`). The message names the position and echoes no stored content.
        if id == record.id
            && parent.as_deref() == record.parent
            && ts == row.ts
            && disposition == row.disposition
            && body == record.body
        {
            return Ok(());
        }
        return Err(fork::chain_fork(record.kind, &row.identity, record.seq));
    }
    exec(
        tx,
        "INSERT INTO plane_records (kind, identity, seq, id, parent, ts, disposition, body) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        row.params(&record),
    )?;
    Ok(())
}

impl RecordStore for SqliteStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.write(true, |tx| {
            put_key_inner(tx, key, Self::bump_revision(tx)?, "put_key")
        })
    }

    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        query_one(
            &self.lock_reader(),
            concat!("SELECT ", key_cols!(), " FROM keys WHERE id=?1"),
            params![id],
            row_to_key,
        )
    }

    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        let sql = concat!("SELECT ", key_cols!(), " FROM keys ORDER BY created_at, id");
        query_all(&self.lock_reader(), sql, [], row_to_key)
    }

    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        let sql = concat!(
            "SELECT ",
            key_cols!(),
            " FROM keys WHERE revision > ?1 OR revision = 0 ORDER BY revision, id"
        );
        query_all(&self.lock_reader(), sql, params![since as i64], row_to_key)
    }

    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.write(true, |tx| {
            let already_deleted: Option<i64> = tx
                .query_row(
                    "SELECT deleted_at FROM keys WHERE id=?1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()
                .store()?
                .flatten();
            if already_deleted.is_some() {
                return Ok(());
            }
            let rev = Self::bump_revision(tx)?;
            let now = now_secs();
            // Explicit DELETE, not only the FK CASCADE, which does not depend on every caller
            // having set `PRAGMA foreign_keys`.
            tx.execute("DELETE FROM credentials WHERE key_id=?1", params![id])
                .store()?;
            // `enabled=0` and `deleted_at` in the SAME statement, or `keys_tombstone_off` fires.
            let changed = tx
                .execute(
                    "UPDATE keys SET enabled=0, deleted_at=?2, updated_at=?2, revision=?3 WHERE id=?1",
                    params![id, now, rev],
                )
                .store()?;
            if changed == 0 {
                return Err(RecordStoreError(format!("delete_key: no such key {id}")));
            }
            Ok(())
        })
    }

    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.write(true, |tx| {
            put_credential_inner(tx, secret, Self::bump_revision, "put_credential")
        })
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        const OP: &str = "put_key_with_credential";
        self.write(true, |tx| {
            // Refused before anything is written: the key is not minted, no revision is spent.
            if key.deleted_at.is_some() {
                return Err(RecordStoreError(format!(
                    "{OP}: key '{}' is tombstoned; a credential is never minted onto it",
                    key.id
                )));
            }
            let stored_tombstone: Option<bool> = tx
                .query_row(
                    "SELECT deleted_at IS NOT NULL FROM keys WHERE id=?1",
                    params![key.id],
                    |r| r.get(0),
                )
                .optional()
                .store()?;
            if stored_tombstone == Some(true) {
                return Err(RecordStoreError(format!(
                    "{OP}: '{}' is tombstoned and its id is never reissued",
                    key.id
                )));
            }
            if secret.meta.key_id != key.id {
                return Err(RecordStoreError(format!(
                    "{OP}: the credential names key '{}', not the key '{}' being minted with it",
                    secret.meta.key_id, key.id
                )));
            }
            let rev = Self::bump_revision(tx)?;
            put_key_inner(tx, key, rev, OP)?;
            put_credential_inner(tx, secret, |_| Ok(rev), OP)
        })
    }

    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        let sql =
            format!("SELECT {CRED_META_COLS} FROM credentials WHERE key_id=?1 ORDER BY kind, slot");
        query_all(&self.lock_reader(), &sql, params![key_id], row_to_cred_meta)
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.write(true, |tx| {
            // Read in the same transaction as the write, or a concurrent insert could make the
            // answer a lie. Unknown is an error and already revoked is Ok (idempotent): collapsing
            // them would tell an operator responding to a leak that a live credential is dead.
            let revoked: Option<bool> = tx
                .query_row(
                    "SELECT revoked_at IS NOT NULL FROM credentials WHERE id=?1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()
                .store()?;
            match revoked {
                None => Err(RecordStoreError(format!(
                    "revoke_credential: unknown id '{id}'"
                ))),
                Some(true) => Ok(()),
                Some(false) => {
                    let rev = Self::bump_revision(tx)?;
                    // The secret is destroyed with the revocation: it must not outlive its use.
                    tx.execute(
                        "UPDATE credentials SET secret=NULL, secret_form='none', revoked_at=?2,
                             revoke_reason=?3, updated_at=?2, revision=?4 WHERE id=?1",
                        params![id, now_secs(), reason, rev],
                    )
                    .store()
                    .map(drop)
                }
            }
        })
    }

    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        let sql = format!(
            "SELECT {CRED_SECRET_COLS} FROM credentials WHERE revision > ?1 OR revision = 0 \
             ORDER BY revision, id"
        );
        query_all(
            &self.lock_reader(),
            &sql,
            params![since as i64],
            row_to_cred_secret,
        )
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        let conn = self.lock_reader();
        // One deferred read transaction: every SELECT sees the same WAL snapshot (rolled back on drop).
        let _snapshot = conn.unchecked_transaction().store()?;
        // `requests` / `billable_requests` live ONLY on the `model=''` sentinel row, so there is one
        // source of truth however many put/add_usage calls interleaved. Never written reads (0, 0).
        let (requests, billable_requests): (i64, i64) = query_one(
            &conn,
            "SELECT requests, billable_requests FROM usage_windows WHERE window_start=?1 AND bucket_id=?2 AND model=''",
            params![window_start as i64, bucket_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .unwrap_or((0, 0));
        let ws = window_start as i64;
        let at = params![ws, bucket_id];
        let mut models = query_all(
            &conn,
            "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
             FROM usage_windows WHERE window_start=?1 AND bucket_id=?2 AND model != '' ORDER BY model",
            at,
            |r| {
                let mut units = BTreeMap::new();
                for (i, unit) in RESERVED_COLUMNS.iter().enumerate() {
                    let v = column::read_u64(r.get(i + 1)?);
                    // A zero reads as absent, as `ModelTokens` itself reads an absent key.
                    if v != 0 {
                        units.insert(unit.to_string(), v);
                    }
                }
                Ok(ModelTokens {
                    model: r.get(0)?,
                    usage_units: units,
                })
            },
        )?;
        let opens = query_all(
            &conn,
            "SELECT model, unit, count FROM usage_window_units
             WHERE window_start=?1 AND bucket_id=?2 ORDER BY model, unit",
            at,
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    column::read_u64(r.get(2)?),
                ))
            },
        )?;
        for (model, unit, count) in opens {
            // Sparse, as the reserved units are: a zero count reads as absent.
            if count == 0 {
                continue;
            }
            // An open-unit row is written beside its model's row, so the model is already listed;
            // the fallback only keeps an out-of-band edit readable.
            let at = match models.iter().position(|m| m.model == model) {
                Some(at) => at,
                None => {
                    models.push(ModelTokens {
                        model,
                        ..Default::default()
                    });
                    models.len() - 1
                }
            };
            models[at].usage_units.insert(unit, count);
        }
        Ok(UsageLedger {
            requests: column::read_u64(requests),
            billable_requests: column::read_u64(billable_requests),
            models,
        })
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        self.write(false, |tx| {
            for table in ["usage_windows", "usage_window_units"] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE window_start=?1 AND bucket_id=?2"),
                    params![window_start as i64, bucket_id],
                )
                .store()?;
            }
            // The counts ALWAYS live on the `model=''` sentinel row; per-model rows carry tokens only.
            tx.execute(
                "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests) VALUES (?1,?2,'',?3,?4)",
                params![
                    window_start as i64,
                    bucket_id,
                    column::clamp(ledger.requests),
                    column::clamp(ledger.billable_requests)
                ],
            )
            .store()?;
            for m in &ledger.models {
                tx.execute(
                    "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests,
                         tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                     VALUES (?1,?2,?3,0,0,?4,?5,?6,?7)",
                    params![
                        window_start as i64, bucket_id, m.model,
                        column::clamp(m.tier(UNIT_INPUT)),
                        column::clamp(m.tier(UNIT_OUTPUT)),
                        column::clamp(m.tier(UNIT_CACHE_READ)),
                        column::clamp(m.tier(UNIT_CACHE_WRITE)),
                    ],
                ).store()?;
                for (unit, count) in open_units(&m.usage_units) {
                    tx.execute(
                        "INSERT INTO usage_window_units (window_start, bucket_id, model, unit, count)
                         VALUES (?1,?2,?3,?4,?5)",
                        params![window_start as i64, bucket_id, m.model, unit, column::clamp(*count)],
                    )
                    .store()?;
                }
            }
            Ok(())
        })
    }

    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.write(false, |tx| add_usage_in(tx, bucket_id, window_start, delta))
    }

    fn add_metering(&self, d: &MeteringDelta) -> RecordStoreResult<()> {
        self.write(true, |tx| add_metering_in(tx, d))
    }

    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        let conn = self.lock_reader();
        let _snapshot = conn.unchecked_transaction().store()?;
        let u = column::read_u64;
        let mut rows = query_all(
            &conn,
            "SELECT key_id, model, provider, tokens_input, tokens_output, tokens_cache_read,
                tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version,
                priced_from_ms
             FROM usage_metering WHERE bucket = ?1",
            params![bucket.to_string()],
            |r| {
                Ok(MeteringRow {
                    key_id: r.get(0)?,
                    model: r.get(1)?,
                    provider: r.get(2)?,
                    tokens_input: u(r.get(3)?),
                    tokens_output: u(r.get(4)?),
                    tokens_cache_read: u(r.get(5)?),
                    tokens_cache_write: u(r.get(6)?),
                    requests: u(r.get(7)?),
                    billable_requests: u(r.get(8)?),
                    key_group_at_use: r.get(9)?,
                    pricing_version: r.get(10)?,
                    priced_from_ms: u(r.get(11)?),
                    usage_units: Default::default(),
                })
            },
        )?;
        let units = query_all(
            &conn,
            "SELECT key_id, provider, model, priced_from_ms, unit, count
             FROM usage_metering_units WHERE bucket = ?1",
            params![bucket.to_string()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    u(r.get(3)?),
                    r.get::<_, String>(4)?,
                    u(r.get(5)?),
                ))
            },
        )?;
        let mut index: std::collections::HashMap<(String, String, String, u64), usize> =
            std::collections::HashMap::with_capacity(rows.len());
        for (i, m) in rows.iter().enumerate() {
            index
                .entry((
                    m.key_id.clone(),
                    m.provider.clone(),
                    m.model.clone(),
                    m.priced_from_ms,
                ))
                .or_insert(i);
        }
        for (key_id, provider, model, priced_from_ms, unit, count) in units {
            if let Some(&i) = index.get(&(key_id, provider, model, priced_from_ms)) {
                rows[i].usage_units.insert(unit, count);
            }
        }
        Ok(rows)
    }

    /// FULL sync: a hard crash must lose ~0 entries, which `synchronous=NORMAL` does not give under WAL.
    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        self.write(true, |tx| append_audit_in(tx, entry))
    }

    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        query_all(
            &self.lock_reader(),
            "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log ORDER BY seq",
            [],
            row_to_audit,
        )
    }

    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        let mut rows = query_all(
            &self.lock_reader(),
            "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log ORDER BY seq DESC LIMIT ?1",
            [column::clamp(limit)],
            row_to_audit,
        )?;
        rows.reverse();
        Ok(rows)
    }

    /// FULL sync, like every revocation path: a denial lost to a power cut makes the token valid
    /// again on reboot with no error ever reported.
    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.write(true, |tx| {
            tx.execute(
                "INSERT INTO denylist (sub, reason, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(sub) DO NOTHING",
                params![sub, reason, now_secs()],
            )
            .store()
            .map(drop)
        })
    }

    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        query_all(&self.lock_reader(), "SELECT sub FROM denylist", [], |r| {
            r.get(0)
        })
    }

    // The neutral kind-tagged plane-record verbs: one table, `plane_records`, for every kind. The
    // store never decodes a `body`; identity, ordering and retention read only the typed sidecar
    // columns. Every write is FULL sync: a transition, a quarantine, a capability or a chain record
    // handed back by a power cut is worse than a slow commit.

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        // Keyed on the record's own id, parent or not: the contract upserts by `(kind, id)`.
        let row = PlaneRow::of(record, record.id, UPSERT_SEQ, "upsert_plane_record")?;
        self.write(true, |tx| {
            tx.execute(
                "INSERT INTO plane_records (kind, identity, seq, id, parent, ts, disposition, body) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                 ON CONFLICT(kind, identity, seq) DO UPDATE SET \
                    id=excluded.id, parent=excluded.parent, ts=excluded.ts, \
                    disposition=excluded.disposition, body=excluded.body",
                row.params(&record),
            )
            .store()
            .map(drop)
        })
    }

    /// An upserted record lives at `(kind, id, 0)`. No caller-scoping filter: authorization stays
    /// engine-side, or an unauthorized reader bypasses it by configuring a different backend.
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        query_one(
            &self.lock_reader(),
            "SELECT body FROM plane_records WHERE kind=?1 AND identity=?2 AND seq=?3",
            params![kind, id, UPSERT_SEQ],
            |r| r.get::<_, Vec<u8>>(0),
        )
    }

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.write(true, |tx| append_plane_record_in(tx, record))
    }

    /// Unfiltered beyond the selector, terminal rows included (boot rehydrate wants the active
    /// rows, the retention sweep the terminal ones). Oldest-first by `seq`.
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let conn = self.lock_reader();
        match selector {
            PlaneSelector::All => query_all(
                &conn,
                "SELECT body FROM plane_records WHERE kind=?1 ORDER BY seq, identity",
                [kind],
                |r| r.get(0),
            ),
            PlaneSelector::Parent(parent) => query_all(
                &conn,
                "SELECT body FROM plane_records WHERE kind=?1 AND parent=?2 ORDER BY seq",
                params![kind, parent],
                |r| r.get(0),
            ),
        }
    }

    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        query_all(
            &self.lock_reader(),
            "SELECT DISTINCT parent FROM plane_records \
             WHERE kind=?1 AND parent IS NOT NULL ORDER BY parent",
            [kind],
            |r| r.get(0),
        )
    }

    /// The age-only entry: `task` drops only its TERMINAL rows, every other kind every older row. A
    /// caller that carries the rule calls `purge_plane_records`.
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        let retention = if kind == "task" {
            Retention::TerminalOnly
        } else {
            Retention::Age
        };
        self.purge_plane_records(kind, before, retention)
    }

    /// STRICTLY older than the cutoff, by the rule the call carries (never one inferred from the
    /// kind's name): `TerminalOnly` drops only TERMINAL rows (an interrupted task waiting on a human
    /// sits still longest), `Age` every older row; under either, a purged task takes its
    /// `task_event` chain with it, and the count is the task rows. `before` is clamped, not refused: a cutoff past what SQLite holds means "everything older
    /// than the end of time".
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        let before = column::clamp(before);
        let terminal_only = retention == Retention::TerminalOnly;
        self.write(false, |tx| {
            let predicate = if terminal_only {
                "kind=?1 AND ts < ?2 AND disposition='terminal'"
            } else {
                "kind=?1 AND ts < ?2"
            };
            if kind == "task" {
                tx.execute(
                    &format!(
                        "DELETE FROM plane_records WHERE kind='task_event' AND parent IN \
                         (SELECT identity FROM plane_records WHERE {predicate})"
                    ),
                    params![kind, before],
                )
                .store()?;
            }
            let removed = tx
                .execute(
                    &format!("DELETE FROM plane_records WHERE {predicate}"),
                    params![kind, before],
                )
                .store()?;
            Ok(removed as u64)
        })
    }

    /// Absent is a no-op; every `seq` under the identity goes, so a chain is never left partial.
    /// A task takes its `task_event` chain with it.
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.write(true, |tx| {
            if kind == "task" {
                tx.execute(
                    "DELETE FROM plane_records WHERE kind='task_event' AND parent=?1",
                    params![id],
                )
                .store()?;
            }
            tx.execute(
                "DELETE FROM plane_records WHERE kind=?1 AND identity=?2",
                params![kind, id],
            )
            .store()
            .map(drop)
        })
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // `now` is REFUSED, not clamped: clamped to `i64::MAX` it would sweep the entire ledger and
        // report the insert as a first redemption, reopening every spent grant. `expires_at` alone
        // saturates: minting claims pass `u64::MAX` for "never expires", and the column is only
        // compared against `now` by the sweep, so `i64::MAX` is the same answer.
        let expires = column::clamp(expires_at);
        let now_i = column::storable_i64("redeem_plane_token", "now", now)?;
        // One transaction over the sweep and the test-and-set: two redemptions of one grant, from two
        // threads or two nodes on one file, serialise instead of both being told they were first.
        self.write(true, |tx| {
            // STRICTLY less-than, so an entry expiring exactly at `now` is kept (fail closed).
            tx.execute("DELETE FROM plane_tokens WHERE expires_at < ?1", [now_i])
                .store()?;
            // 1 row inserted means this call recorded the redemption, read off what the database did.
            let inserted = tx
                .execute(
                    "INSERT INTO plane_tokens (kind, token, expires_at) VALUES (?1,?2,?3) \
                     ON CONFLICT(kind, token) DO NOTHING",
                    params![kind, token, expires],
                )
                .store()?;
            Ok(inserted == 1)
        })
    }

    /// Multi-use and SPENDS NOTHING: a plain read of the `(kind, token)` upserted record, live while
    /// present, still `active`, and `now` not past `expires_at`. Fail closed on every uncertain answer.
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        if now > expires_at {
            return Ok(false);
        }
        let disposition: Option<String> = query_one(
            &self.lock_reader(),
            "SELECT disposition FROM plane_records WHERE kind=?1 AND identity=?2 AND seq=?3",
            params![kind, token, UPSERT_SEQ],
            |r| r.get(0),
        )?;
        Ok(disposition.as_deref() == Some(DISPOSITION_ACTIVE))
    }
}

/// The `seq` an upserted record lives at: the contract upserts by `(kind, id)`.
const UPSERT_SEQ: i64 = 0;

/// A stored plane row's `(id, parent, ts, disposition, body)`, as the append verb's fork check reads it.
type StoredPlaneRow = (String, Option<String>, i64, String, Vec<u8>);

const DISPOSITION_ACTIVE: &str = "active";
const DISPOSITION_TERMINAL: &str = "terminal";

/// A plane record's storable sidecar columns, range-checked once for every verb that writes one.
struct PlaneRow {
    identity: String,
    seq: i64,
    ts: i64,
    disposition: &'static str,
}

impl PlaneRow {
    /// Refused rather than mangled: a `u64` past `i64::MAX` would wrap negative and read back
    /// clamped, so a wrapped `seq` reorders a chain and a wrapped `ts` changes what retention does.
    /// `identity` is where the row lives: an appended record's chain (its parent, else its id), an
    /// upserted record's own id.
    fn of(
        record: PlaneRecordRef<'_>,
        identity: &str,
        seq: i64,
        method: &str,
    ) -> RecordStoreResult<Self> {
        Ok(Self {
            identity: identity.to_string(),
            seq,
            ts: column::storable_i64(method, "ts", record.ts)?,
            disposition: match record.disposition {
                PlaneDisposition::Active => DISPOSITION_ACTIVE,
                PlaneDisposition::Terminal => DISPOSITION_TERMINAL,
            },
        })
    }

    fn params<'a>(&'a self, record: &'a PlaneRecordRef<'a>) -> [&'a dyn rusqlite::ToSql; 8] {
        [
            &record.kind,
            &self.identity,
            &self.seq,
            &record.id,
            &record.parent,
            &self.ts,
            &self.disposition,
            &record.body,
        ]
    }
}

fn put_credential_inner(
    tx: &rusqlite::Transaction,
    secret: &CredentialSecret,
    revision: impl FnOnce(&rusqlite::Transaction) -> RecordStoreResult<i64>,
    method: &str,
) -> RecordStoreResult<()> {
    let m = &secret.meta;
    // The owning key must EXIST and be LIVE, checked in the caller's transaction: the FK covers only
    // "no such row", a tombstone is still a row, and a caller-side check is the gap a concurrent
    // `delete_key` lands in.
    let owner_live: Option<bool> = tx
        .query_row(
            "SELECT deleted_at IS NULL FROM keys WHERE id=?1",
            params![m.key_id],
            |r| r.get(0),
        )
        .optional()
        .store()?;
    match owner_live {
        None => {
            return Err(RecordStoreError(format!(
                "put_credential: owning key '{}' does not exist",
                m.key_id
            )))
        }
        Some(false) => {
            return Err(RecordStoreError(format!(
            "put_credential: owning key '{}' is tombstoned; a revoked key takes no new credential",
            m.key_id
        )))
        }
        Some(true) => {}
    }
    let live_slot = |kind: &str, key_id: &str, slot: u8| {
        RecordStoreError(format!(
            "{method}: slot {slot} for key '{key_id}' kind '{kind}' holds a live credential; \
             revoke it first"
        ))
    };
    let by_id: Option<CredentialSecret> = query_one(
        tx,
        &format!("SELECT {CRED_SECRET_COLS} FROM credentials WHERE id=?1"),
        params![m.id],
        row_to_cred_secret,
    )?;
    if let Some(stored) = by_id {
        let sm = &stored.meta;
        if sm.revoked_at.is_some() {
            return Err(RecordStoreError(format!(
                "{method}: credential '{}' is revoked; a revoked credential is never re-minted",
                m.id
            )));
        }
        // A live credential re-put identically (revision aside) is the retry of a write that
        // landed: Ok, nothing written.
        let mut same = secret.clone();
        same.meta.revision = sm.revision;
        if same == stored {
            return Ok(());
        }
        return Err(live_slot(&sm.kind, &sm.key_id, sm.slot));
    }
    // A LIVE occupant of the slot must fail rather than silently destroy a working credential
    // mid-overlap-window; a REVOKED one is replaced by the upsert below.
    let occupant: Option<(String, bool)> = query_one(
        tx,
        "SELECT id, revoked_at IS NULL FROM credentials WHERE key_id=?1 AND kind=?2 AND slot=?3",
        params![m.key_id, m.kind, m.slot as i64],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if matches!(occupant, Some((_, true))) {
        return Err(live_slot(&m.kind, &m.key_id, m.slot));
    }
    let taken: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM credentials WHERE kind=?1 AND public_id=?2 \
             AND NOT (key_id=?3 AND slot=?4))",
            params![m.kind, m.public_id, m.key_id, m.slot as i64],
            |r| r.get(0),
        )
        .store()?;
    if taken {
        return Err(RecordStoreError(format!(
            "put_credential: public_id {} is already taken for kind {}",
            m.public_id, m.kind
        )));
    }
    let revision = revision(tx)?;
    // `updated_at` is its own parameter (?11), not a second use of `created_at`'s.
    tx.execute(
        "INSERT INTO credentials (id,key_id,kind,slot,public_id,secret,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?11,?9,NULL,NULL,?10)
         ON CONFLICT(key_id,kind,slot) DO UPDATE SET
            id=excluded.id, public_id=excluded.public_id, secret=excluded.secret, secret_form=excluded.secret_form,
            created_at=excluded.created_at, updated_at=excluded.updated_at, expires_at=excluded.expires_at,
            revoked_at=NULL, revoke_reason=NULL, revision=excluded.revision",
        params![
            m.id, m.key_id, m.kind, m.slot as i64, m.public_id, secret.secret,
            secret_form_to_str(m.secret_form), m.created_at as i64, m.expires_at.map(|v| v as i64), revision,
            m.updated_at as i64,
        ],
    )
    .store()?;
    Ok(())
}

fn row_to_audit(r: &rusqlite::Row) -> rusqlite::Result<AuditRecord> {
    Ok(AuditRecord {
        seq: column::read_u64(r.get(0)?),
        ts: column::read_u64(r.get(1)?),
        action: r.get(2)?,
        resource: r.get(3)?,
        outcome: r.get(4)?,
        principal: r.get(5)?,
        prev_hash: r.get(6)?,
        hash: r.get(7)?,
    })
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The settings parser and the store v3 table over [`SqliteStore`] (`door::door`).
pub mod door;
mod v3;

#[cfg(test)]
mod tests;
