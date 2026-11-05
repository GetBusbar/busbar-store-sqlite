// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in SQLite backend for busbar's durable governance store. Implements
//! `busbar_contract::records::RecordStore` over embedded rusqlite connections: one mutex-guarded
//! writer, plus a small pool of `query_only` readers so a long read (a billing report, a hydrate)
//! and the hot-path usage flush never wait on each other (WAL readers are unaffected by an
//! in-flight writer). Retention sweeps are writes: they take the writer like every other write.
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

/// Reserved kernel ticket records carry their absolute expiry in ts (governance::tickets).
const TICKET_RECORD_KIND: &str = "ticket";

/// The A2A task record kind: its age-only retention drops only TERMINAL rows, and it owns a chain.
const TASK_RECORD_KIND: &str = "task";

/// A task's provenance chain, filed at the task's id: purged and deleted with its task.
const TASK_EVENT_RECORD_KIND: &str = "task_event";

/// Store schema version, kept in `PRAGMA user_version`. A file older than v6 is refused: no
/// release ever wrote one. A v6 file (the v1.0.x releases) upgrades in place to v7 in ONE
/// transaction, through the steps below. Their `_v10`/`_v15`/`_v16`/`_v17` names are the
/// development steps they were written as, consolidated into v7; no file is ever stamped with them.
/// - `keys` gains `scope_grants`, `idp_subject`, `binding_mode`, `minted_by`, `idp_provider`;
///   `usage_metering` gains `priced_from_ms` in its key (existing rows copied at 0); open usage
///   units get their own tables; kind-tagged `plane_records` / `plane_tokens`; the store v3 state
///   (`store_ops`, `schema_records`), `plane_tokens` indexed by expiry. The v6 `mcp_calls` table is
///   left unread: its body is a digest stream no backend can rebuild.
/// - `credentials` is rebuilt so a revoked row may hold no secret (revoke destroys it); a row
///   revoked under an older build loses the secret it kept. Credential expiry compares the unsigned
///   timestamps preserved by the INTEGER bit codec: a legacy row whose expiry precedes creation in
///   that order refuses the entire migration.
/// - The same unsigned expiry order applies to keys, preserving their full-width codec. An
///   incompatible legacy key refuses the entire migration.
/// - Metering cells and their units are keyed by the recorded group and price version.
///
/// v8 converts quantity columns and exact JSON ledgers to checked micro-units in one
/// transaction. Request counters remain unscaled. v9 promotes every row into exact i128 JSON
/// authority and rebuilds signed INTEGER mirrors from that authority. The version fences older
/// writers/readers from wide quantities. A file stamped by a later build is refused.
const SCHEMA_VERSION: i64 = 9;

macro_rules! unsigned_expiry_order {
    () => {
        "expires_at IS NULL OR (created_at >= 0 AND expires_at < 0) OR \
         (((created_at < 0) = (expires_at < 0)) AND expires_at > created_at)"
    };
}

/// The oldest schema any release wrote.
const FIRST_RELEASED_SCHEMA: i64 = 6;

/// The `credentials` table, under `$head` (`IF NOT EXISTS credentials` in [`SCHEMA`], the scratch
/// name in the v15 rebuild), so the two cannot drift.
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
    CONSTRAINT cred_expiry_after CHECK (",
            unsigned_expiry_order!(),
            ")
) STRICT;"
        )
    };
}

/// The base key columns are followed by the nullable v10 columns through one shared helper.
macro_rules! keys_ddl {
    ($head:literal) => {
        concat!(
            "CREATE TABLE ",
            $head,
            " (
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
    CONSTRAINT keys_expiry_after CHECK (",
            unsigned_expiry_order!(),
            ")
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

",
    keys_ddl!("IF NOT EXISTS keys"),
    "
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
    PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS um_key_bucket_idx ON usage_metering (key_id, bucket);

-- Whole exact raw rows. The legacy INTEGER tables remain the low-count mirror; every writer
-- replaces or updates this authority in the same transaction. No derived money is stored.
CREATE TABLE IF NOT EXISTS usage_window_exact (
    window_start INTEGER NOT NULL,
    bucket_id TEXT NOT NULL,
    ledger BLOB NOT NULL,
    PRIMARY KEY (window_start, bucket_id)
) STRICT, WITHOUT ROWID;

-- Full-width accumulated metering counts, written atomically with the signed-column mirror.
-- The identity is the same dated billing cell as usage_metering; old databases promote lazily.
CREATE TABLE IF NOT EXISTS usage_metering_exact (
    bucket TEXT NOT NULL,
    key_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    priced_from_ms INTEGER NOT NULL,
    key_group_at_use TEXT NOT NULL,
    pricing_version TEXT NOT NULL,
    ledger BLOB NOT NULL,
    PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version)
) STRICT, WITHOUT ROWID;

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
    key_group_at_use TEXT NOT NULL DEFAULT '',
    pricing_version TEXT NOT NULL DEFAULT '',
    unit           TEXT NOT NULL,
    count          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version, unit)
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
-- Every redemption sweeps the lapsed receipts first; without this the sweep scans the ledger.
CREATE INDEX IF NOT EXISTS plane_tokens_expires_idx ON plane_tokens (expires_at);

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

/// How a store reads the shared clock on a connection holding its transaction or snapshot.
type Clock = fn(&Connection) -> RecordStoreResult<i64>;

/// SQLite's own Unix clock, the one every connection to the file shares.
fn sqlite_unixepoch(conn: &Connection) -> RecordStoreResult<i64> {
    conn.prepare_cached("SELECT unixepoch()")
        .store()?
        .query_row([], |r| r.get(0))
        .store()
}

/// The filesystem path a file-backed `db_path` names: the path itself, or the percent-decoded path
/// of a `file:` URI (whose authority, as SQLite requires, is empty or `localhost`). `None` for a URI
/// SQLite itself refuses or that names no file; SQLite then reports it on open.
fn file_path_of(path: &str) -> Option<String> {
    let Some(uri) = path.strip_prefix("file:") else {
        return Some(path.to_string());
    };
    let uri = uri.split('#').next().unwrap_or_default();
    let file = uri.split_once('?').map_or(uri, |(file, _)| file);
    let file = match file.strip_prefix("//") {
        Some(rest) => {
            let (authority, rest) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            if !(authority.is_empty() || authority.eq_ignore_ascii_case("localhost")) {
                return None;
            }
            rest
        }
        None => file,
    };
    let hex = |b: Option<&u8>| b.and_then(|&b| char::from(b).to_digit(16));
    let bytes = file.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
            (b'%', Some(high), Some(low)) => {
                decoded.push((high * 16 + low) as u8);
                i += 3;
            }
            (byte, _, _) => {
                decoded.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(decoded).ok().filter(|p| !p.is_empty())
}

/// Decode URI query components before interpreting options, just as SQLite does. Split the
/// raw query first so escaped `&` and `=` remain inside their component; `+` stays literal.
/// NUL cannot be safely represented in SQLite's zero-terminated option list, so refuse it.
fn uri_parameters(path: &str) -> RecordStoreResult<Vec<(String, String)>> {
    let Some(uri) = path.strip_prefix("file:") else {
        return Ok(Vec::new());
    };
    let uri = uri.split('#').next().unwrap_or_default();
    let Some((_, query)) = uri.split_once('?') else {
        return Ok(Vec::new());
    };
    let decode = |part: &str| -> RecordStoreResult<String> {
        let bytes = part.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let hex = |offset| bytes.get(offset).and_then(|b| char::from(*b).to_digit(16));
            match (bytes[i], hex(i + 1), hex(i + 2)) {
                (b'%', Some(high), Some(low)) => {
                    decoded.push((high * 16 + low) as u8);
                    i += 3;
                }
                (byte, _, _) => {
                    decoded.push(byte);
                    i += 1;
                }
            }
        }
        if decoded.contains(&0) {
            return Err(RecordStoreError(
                "sqlite: db_path URI query contains a NUL byte".into(),
            ));
        }
        String::from_utf8(decoded)
            .map_err(|_| RecordStoreError("sqlite: db_path URI query is not valid UTF-8".into()))
    };
    query
        .split('&')
        .map(|param| {
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            Ok((decode(key)?, decode(value)?))
        })
        .collect()
}

/// Refuse a file-backed `file:` URI parameter that breaks the one-writer + reader-pool design:
/// `cache=shared` puts every connection in one table-locked cache (readers fail `SQLITE_LOCKED`
/// under the writer, which no busy timeout covers), `nolock` (and `vfs=unix-none`, the same thing as
/// a VFS) drops the file locks that keep two processes from interleaving writes, and `immutable`
/// lets a reader miss committed writes.
fn refuse_unsafe_uri(path: &str) -> RecordStoreResult<()> {
    for (key, value) in uri_parameters(path)? {
        let unsafe_param = match key.as_str() {
            "cache" => value.eq_ignore_ascii_case("shared"),
            "vfs" => value == "unix-none",
            "nolock" | "immutable" => !matches!(
                value.to_ascii_lowercase().as_str(),
                "0" | "no" | "false" | "off"
            ),
            _ => false,
        };
        if unsafe_param {
            return Err(RecordStoreError(format!(
                "sqlite: db_path URI parameter `{key}={value}` is not supported: it breaks the store's \
                 single-writer locking; use a plain file path"
            )));
        }
    }
    Ok(())
}

/// True for any SQLite path spelling that opens a private in-memory database: `:memory:`, or a
/// `file:` URI whose path is `:memory:` or whose query carries `mode=memory`. A path that merely
/// contains those characters elsewhere is a real file. Pragma selection and `SqliteStore::open`'s
/// single-connection routing both use this one check.
fn is_memory_path(path: &str) -> bool {
    if path == ":memory:" {
        return true;
    }
    if !path.starts_with("file:") {
        return false;
    }
    let Ok(parameters) = uri_parameters(path) else {
        return false;
    };
    file_path_of(path).as_deref() == Some(":memory:")
        || parameters
            .iter()
            .any(|(key, value)| key == "mode" && value == "memory")
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

    // No mmap on a path that looks like a network filesystem (best effort, not an fs-type probe);
    // a `file:` URI is judged by the file it names, so `file:///var/x.db` keeps mmap.
    let file = file_path_of(path).unwrap_or_else(|| path.to_string());
    let mmap = if file.contains("//") && !file.starts_with(':') {
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
    /// The shared clock single-use tokens and ticket deadlines are judged by.
    clock: Clock,
}

/// Create a missing database file 0600 (it holds recoverable secrets) so SQLite, which gives the
/// `-wal`/`-shm` files the main file's mode, never creates it with the umask. A `file:` URI is
/// created at the file it names, unless its `mode` (`ro`, `rw`) tells SQLite never to create one:
/// a missing file then stays an open error rather than becoming a fresh, empty store. An existing
/// file is left alone, and so is any failure to create (SQLite reports it on open).
#[cfg(unix)]
fn create_private(path: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(parameters) = uri_parameters(path) else {
        return;
    };
    let mode = parameters
        .iter()
        .rev()
        .find_map(|(key, value)| (key == "mode").then_some(value.as_str()));
    if mode.is_some_and(|mode| mode != "rwc") {
        return;
    }
    if let Some(file) = file_path_of(path) {
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(file);
    }
}

#[cfg(not(unix))]
fn create_private(_: &str) {}

/// Best effort: checkpoint the whole WAL into the main file and truncate it, so the frames that
/// still hold bytes a commit just destroyed (a revoked secret, a replaced envelope, a dropped
/// table) do not outlive them in the `-wal` file. It never blocks and never fails the write it
/// follows: the busy timeout is lifted for the checkpoint, so a reader holding a snapshot leaves it
/// partial (a later scrub, or SQLite's own checkpoints, finish it). The store's busy handling is
/// only ever `busy_timeout`, restored exactly; a custom busy handler (only tests install one) is
/// cleared by the lift. An in-memory store has no WAL.
fn scrub_wal(conn: &Connection, path: &str) {
    if is_memory_path(path) {
        return;
    }
    let Ok(timeout) = conn.query_row("PRAGMA busy_timeout", [], |r| r.get::<_, i64>(0)) else {
        return;
    };
    if conn.pragma_update(None, "busy_timeout", 0).is_ok() {
        let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    }
    let _ = conn.pragma_update(None, "busy_timeout", timeout);
}

impl SqliteStore {
    pub fn open(path: &str, busy_timeout_ms: i64) -> RecordStoreResult<Self> {
        if is_memory_path(path) {
            return Self::open_in_memory();
        }
        refuse_unsafe_uri(path)?;
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
            clock: sqlite_unixepoch,
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
            clock: sqlite_unixepoch,
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock_writer(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.writer.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The shared clock, read on `conn` (which holds the caller's transaction or snapshot); a
    /// failed or pre-epoch clock is an error, so it can never authorize expiry or cleanup.
    fn shared_clock(&self, conn: &Connection) -> RecordStoreResult<i64> {
        let now = (self.clock)(conn)?;
        if now < 0 {
            return Err(RecordStoreError(
                "sqlite: shared clock precedes Unix epoch".into(),
            ));
        }
        Ok(now)
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

    /// Like [`Self::write`] for a write that destroys secret material (revoke, rewrap, key
    /// delete): once it commits, the WAL frames that still hold the old bytes are scrubbed.
    fn write_destroying_secrets<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> RecordStoreResult<T>,
    ) -> RecordStoreResult<T> {
        let out = self.write(true, f)?;
        scrub_wal(&self.lock_writer(), &self.path);
        Ok(out)
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

        let result = (|| {
            conn.pragma_update(None, "foreign_keys", "OFF").store()?;
            let disabled: i64 = conn
                .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                .store()?;
            if disabled != 0 {
                return Err(RecordStoreError(
                    "sqlite: foreign_keys could not be disabled for the schema migration".into(),
                ));
            }
            // An upgrade drops the tables it rebuilds, and `secure_delete=FAST` zeroes only freed
            // space inside live pages: a dropped table's pages (the secret a revoked legacy row
            // kept among them) would go to the freelist intact. ON zeroes them; FAST is restored.
            conn.pragma_update(None, "secure_delete", "ON").store()?;
            Self::migrate_transaction(&mut conn)
        })();
        let fast = conn.pragma_update(None, "secure_delete", "FAST").store();

        let restored = conn
            .pragma_update(None, "foreign_keys", "ON")
            .store()
            .and_then(|()| {
                let enabled: i64 = conn
                    .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                    .store()?;
                if enabled == 1 {
                    Ok(())
                } else {
                    Err(RecordStoreError(
                        "sqlite: foreign_keys could not be restored after the schema migration"
                            .into(),
                    ))
                }
            });
        let upgraded = result?;
        restored?;
        fast?;
        if upgraded {
            scrub_wal(&conn, &self.path);
        }
        Ok(())
    }

    /// The migration in one `BEGIN IMMEDIATE` transaction; whether it upgraded an older file.
    fn migrate_transaction(conn: &mut Connection) -> RecordStoreResult<bool> {
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

        if table_exists(&tx, "usage_metering")?
            && !column_exists(&tx, "usage_metering", "priced_from_ms")?
        {
            rebuild_usage_metering_for_v10(&tx)?;
        }
        if version < 7 && table_exists(&tx, "usage_metering")? {
            rebuild_metering_for_v17(&tx)?;
        }

        if version != 0 && version < 7 && table_exists(&tx, "credentials")? {
            rebuild_credentials_for_v15(&tx)?;
        }
        if version < 7 && table_exists(&tx, "keys")? {
            add_v10_key_columns(&tx)?;
            rebuild_keys_for_v16(&tx)?;
        }

        tx.execute_batch("DROP TRIGGER IF EXISTS plane_records_chain_no_update;")
            .store()?;
        tx.execute_batch(SCHEMA).store()?;
        tx.execute(
            "INSERT INTO store_revision (id, revision) VALUES (0, 0) ON CONFLICT(id) DO NOTHING",
            [],
        )
        .store()?;
        add_v10_key_columns(&tx)?;
        let broken_fk: Option<String> =
            query_one(&tx, "PRAGMA foreign_key_check", [], |row| row.get(0))?;
        if let Some(table) = broken_fk {
            return Err(RecordStoreError(format!(
                "sqlite: schema migration left a foreign key violation in '{table}'; refusing to open"
            )));
        }
        if version < 9 {
            migrate_exact_counts(&tx, version)?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .store()?;
        tx.commit().store()?;
        Ok(version != 0 && version < SCHEMA_VERSION)
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

/// A nonnegative exact quantity projected into its signed INTEGER mirror. The JSON row is
/// authoritative; this lossy projection must never be used as the next accrual's pre-state.
fn quantity_mirror(value: i128) -> i64 {
    value.clamp(0, i128::from(i64::MAX)) as i64
}

/// Existing signed mirrors contain nonnegative quantities; request counters use their own codec.
fn quantity_column(value: i64) -> i128 {
    i128::from(column::read_u64(value))
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

/// Exact rows retain the same sparse open-unit shape as the legacy column reader.
fn omit_zero_open_units(ledger: &mut UsageLedger) {
    for model in &mut ledger.models {
        model
            .usage_units
            .retain(|unit, count| *count != 0 || RESERVED_COLUMNS.contains(&unit.as_str()));
    }
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

/// Rebuild a v6 `usage_metering` with `priced_from_ms` in its primary key, the one change SQLite
/// cannot make in place. Every row is copied at `priced_from_ms = 0`, the opening card's instant.
/// The column list must stay identical to [`SCHEMA`]'s; [`rebuild_metering_for_v17`] then adds the
/// recorded group and price version to the key. The trigger naming `usage_metering` is dropped
/// first because `ALTER TABLE ... RENAME` re-parses every trigger; `SCHEMA` recreates it right
/// after.
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

/// Rebuild a v6 `credentials` with unsigned expiry order, copying every row; a row revoked under
/// an older build keeps its metadata and loses the secret it held. The trigger naming `credentials`
/// is dropped first because `ALTER TABLE ... RENAME` re-parses every trigger; `SCHEMA` recreates
/// it and the indexes right after.
fn rebuild_credentials_for_v15(tx: &rusqlite::Connection) -> RecordStoreResult<()> {
    let invalid: Option<(String, i64, i64)> = query_one(
        tx,
        concat!(
            "SELECT id, created_at, expires_at FROM credentials WHERE NOT (",
            unsigned_expiry_order!(),
            ") LIMIT 1"
        ),
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if let Some((id, created, expires)) = invalid {
        return Err(RecordStoreError(format!(
            "sqlite: credential '{id}' expires_at={} is not after created_at={} in unsigned \
             timestamp order; refusing the schema v{SCHEMA_VERSION} migration",
            expires as u64, created as u64
        )));
    }
    tx.execute_batch(concat!(
        "DROP TRIGGER IF EXISTS keys_cascade_credentials;",
        credentials_ddl!("credentials_v15"),
        "INSERT INTO credentials_v15 (id, key_id, kind, slot, public_id, secret, secret_form,
             created_at, updated_at, expires_at, revoked_at, revoke_reason, revision)
           SELECT id, key_id, kind, slot, public_id,
             CASE WHEN revoked_at IS NULL THEN secret END,
             CASE WHEN revoked_at IS NULL THEN secret_form ELSE 'none' END,
             created_at, updated_at, expires_at, revoked_at, revoke_reason, revision
           FROM credentials;
         DROP TABLE credentials;
         ALTER TABLE credentials_v15 RENAME TO credentials;"
    ))
    .store()
}

/// Replace the parent without renaming the old table: credential FK references stay `keys`.
/// The caller disabled FK actions before BEGIN and checks all FK links before COMMIT.
fn rebuild_keys_for_v16(tx: &rusqlite::Connection) -> RecordStoreResult<()> {
    let invalid: Option<(String, i64, i64)> = query_one(
        tx,
        concat!(
            "SELECT id, created_at, expires_at FROM keys WHERE NOT (",
            unsigned_expiry_order!(),
            ") LIMIT 1"
        ),
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if let Some((id, created, expires)) = invalid {
        return Err(RecordStoreError(format!(
            "sqlite: key '{id}' expires_at={} is not after created_at={} in unsigned \
             timestamp order; refusing the schema v{SCHEMA_VERSION} migration",
            expires as u64, created as u64
        )));
    }

    let objects: Vec<String> = query_all(
        tx,
        "SELECT sql FROM sqlite_master WHERE tbl_name='keys' AND type IN ('index','trigger')
         AND sql IS NOT NULL ORDER BY type,name",
        [],
        |row| row.get(0),
    )?;
    tx.execute_batch(keys_ddl!("keys_v16")).store()?;
    add_v10_key_columns_to(tx, "keys_v16")?;
    tx.execute_batch(
        "INSERT INTO keys_v16 (id,name,key_group,allowed_pools,labels,enabled,generation_hash,
             created_at,updated_at,expires_at,deleted_at,revision,scope_grants,idp_subject,
             binding_mode,minted_by,idp_provider)
         SELECT id,name,key_group,allowed_pools,labels,enabled,generation_hash,
             created_at,updated_at,expires_at,deleted_at,revision,scope_grants,idp_subject,
             binding_mode,minted_by,idp_provider FROM keys;
         DROP TABLE keys;
         ALTER TABLE keys_v16 RENAME TO keys;",
    )
    .store()?;
    for sql in objects {
        tx.execute_batch(&sql).store()?;
    }
    Ok(())
}

/// The v7 `keys` columns: nullable `ADD COLUMN`s, so a v6 row reads back exactly as before
/// (no non-pool scope grant, `None` for the attribution fields).
fn add_v10_key_columns(tx: &rusqlite::Connection) -> RecordStoreResult<()> {
    add_v10_key_columns_to(tx, "keys")
}

fn add_v10_key_columns_to(tx: &rusqlite::Connection, table: &str) -> RecordStoreResult<()> {
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
        if !column_exists(tx, table, name)? {
            tx.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {name} {decl}"))
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
        labels: serde_json::from_str(&r.get::<_, String>(7)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
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
const CRED_META_COLS: &str = "id,key_id,kind,slot,public_id,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision";

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
            "{method}: '{}' is tombstoned and its id is never reissued; refusing to clear the \
             tombstone",
            key.id
        )));
    }
    if key.deleted_at.is_some() {
        // A tombstone says every credential row for the key is destroyed, whichever verb wrote it.
        exec(
            conn,
            "DELETE FROM credentials WHERE key_id=?1",
            params![key.id],
        )?;
    }
    Ok(())
}

const CRED_SECRET_COLS: &str = "id,key_id,kind,slot,public_id,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision,secret";

/// The refusal of an ordinary write to a reserved adjustment bucket, whichever verb it came through.
const RESERVED_USAGE_REFUSAL: &str =
    "sqlite: reserved adjustment rows require atomic usage correction";

/// Promote all old quantities into exact JSON authority before projecting signed mirrors.
/// Old SQL quantities are whole units before v8; v8 mirrors already hold micro-units. JSON
/// authority carries its own scale discriminator. No multiplication runs in SQLite INTEGER
/// arithmetic, which could promote an overflow to an imprecise REAL. The enclosing transaction
/// includes every promotion and the v9 fence, so any invalid source row rolls back the upgrade.
fn migrate_exact_counts(tx: &Connection, source_version: i64) -> RecordStoreResult<()> {
    for (table, columns) in [
        (
            "usage_windows",
            &[
                "tokens_input",
                "tokens_output",
                "tokens_cache_read",
                "tokens_cache_write",
            ][..],
        ),
        ("usage_window_units", &["count"][..]),
        (
            "usage_metering",
            &[
                "tokens_input",
                "tokens_output",
                "tokens_cache_read",
                "tokens_cache_write",
            ][..],
        ),
        ("usage_metering_units", &["count"][..]),
    ] {
        let predicate = columns
            .iter()
            .map(|column| format!("{column} < 0"))
            .collect::<Vec<_>>()
            .join(" OR ");
        let invalid: bool = tx
            .query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
                [],
                |row| row.get(0),
            )
            .store()?;
        if invalid {
            return Err(RecordStoreError(format!(
                "exact count migration: {table} contains a negative quantity; nothing converted"
            )));
        }
    }
    let windows: Vec<(i64, String)> = query_all(
        tx,
        "SELECT window_start,bucket_id FROM usage_windows UNION          SELECT window_start,bucket_id FROM usage_window_units UNION          SELECT window_start,bucket_id FROM usage_window_exact",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    for (window, bucket) in windows {
        let bytes: Option<Vec<u8>> = query_one(
            tx,
            "SELECT ledger FROM usage_window_exact WHERE window_start=?1 AND bucket_id=?2",
            params![window, bucket],
            |row| row.get(0),
        )?;
        let mut ledger: UsageLedger = if let Some(bytes) = bytes {
            serde_json::from_slice(&bytes).map_err(|e| RecordStoreError(e.to_string()))?
        } else {
            let mut ledger = usage_columns_in(tx, &bucket, window as u64)?;
            if source_version < 8 {
                for model in &mut ledger.models {
                    model.scale = 0;
                }
            }
            ledger
        };
        ledger
            .normalize_scale6()
            .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
        put_usage_in(tx, &bucket, window as u64, &ledger)?;
    }
    let buckets: Vec<String> = query_all(
        tx,
        "SELECT bucket FROM usage_metering UNION SELECT bucket FROM usage_metering_units          UNION SELECT bucket FROM usage_metering_exact",
        [], |row| row.get(0),
    )?;
    for bucket in buckets {
        let bucket = bucket.parse::<i64>().map_err(|_| {
            RecordStoreError(
                "exact count migration: invalid metering bucket; nothing converted".into(),
            )
        })? as u64;
        let rows = metering_in(tx, bucket)?;
        for mut row in rows {
            if source_version < 8 && metering_exact_bytes(tx, bucket, &row)?.is_none() {
                row.scale = 0;
            }
            row.normalize_scale6()
                .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
            put_metering_in(tx, bucket, &row)?;
        }
    }
    Ok(())
}

fn refuse_reserved_usage(bucket: &str) -> RecordStoreResult<()> {
    if busbar_contract::abi::sdk::store::correction::reserved_bucket(bucket) {
        return Err(RecordStoreError(RESERVED_USAGE_REFUSAL.into()));
    }
    Ok(())
}

/// One raw row read under the caller's snapshot or writer transaction.
fn usage_in(
    conn: &Connection,
    bucket_id: &str,
    window_start: u64,
) -> RecordStoreResult<UsageLedger> {
    if let Some(bytes) = query_one(
        conn,
        "SELECT ledger FROM usage_window_exact WHERE window_start=?1 AND bucket_id=?2",
        params![window_start as i64, bucket_id],
        |row| row.get::<_, Vec<u8>>(0),
    )? {
        let mut ledger: UsageLedger = serde_json::from_slice(&bytes).map_err(|error| {
            RecordStoreError(format!(
                "sqlite: exact usage ledger of bucket '{bucket_id}' window {window_start} is \
                 unreadable: {error}"
            ))
        })?;
        ledger
            .normalize_scale6()
            .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
        omit_zero_open_units(&mut ledger);
        return Ok(ledger);
    }
    usage_columns_in(conn, bucket_id, window_start)
}

fn usage_columns_in(
    conn: &Connection,
    bucket_id: &str,
    window_start: u64,
) -> RecordStoreResult<UsageLedger> {
    let (requests, billable_requests): (i64, i64) = query_one(
            conn,
            "SELECT requests, billable_requests FROM usage_windows WHERE window_start=?1 AND bucket_id=?2 AND model=''",
            params![window_start as i64, bucket_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .unwrap_or((0, 0));
    let ws = window_start as i64;
    let at = params![ws, bucket_id];
    let mut models = query_all(
        conn,
        "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
             FROM usage_windows WHERE window_start=?1 AND bucket_id=?2
             AND (model != '' OR tokens_input != 0 OR tokens_output != 0
                  OR tokens_cache_read != 0 OR tokens_cache_write != 0) ORDER BY model",
        at,
        |r| {
            let mut units = BTreeMap::new();
            for (i, unit) in RESERVED_COLUMNS.iter().enumerate() {
                let v = quantity_column(r.get(i + 1)?);

                if v != 0 {
                    units.insert(unit.to_string(), v);
                }
            }
            Ok(ModelTokens {
                scale: 6,
                model: r.get(0)?,
                usage_units: units,
            })
        },
    )?;
    let opens = query_all(
        conn,
        "SELECT model, unit, count FROM usage_window_units
             WHERE window_start=?1 AND bucket_id=?2 ORDER BY model, unit",
        at,
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                quantity_column(r.get(2)?),
            ))
        },
    )?;
    for (model, unit, count) in opens {
        if count == 0 {
            continue;
        }

        let at = match models.iter().position(|m| m.model == model) {
            Some(at) => at,
            None => {
                models.push(ModelTokens {
                    scale: 6,
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

fn insert_usage_in(
    tx: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> RecordStoreResult<()> {
    if exec(tx, sql, params)? != 1 {
        return Err(RecordStoreError(
            "sqlite: raw usage row was not inserted".into(),
        ));
    }
    Ok(())
}

/// Replace both the signed-column mirror and the exact raw ledger under one writer authority.
fn put_usage_in(
    tx: &Connection,
    bucket_id: &str,
    window_start: u64,
    ledger: &UsageLedger,
) -> RecordStoreResult<()> {
    let mut ledger = ledger.clone();
    ledger
        .normalize_scale6()
        .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
    let ledger = &ledger;

    for sql in [
        "DELETE FROM usage_windows WHERE window_start=?1 AND bucket_id=?2",
        "DELETE FROM usage_window_units WHERE window_start=?1 AND bucket_id=?2",
        "DELETE FROM usage_window_exact WHERE window_start=?1 AND bucket_id=?2",
    ] {
        exec(tx, sql, params![window_start as i64, bucket_id])?;
    }

    insert_usage_in(
        tx,
        "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests) VALUES (?1,?2,'',?3,?4)",
        params![
            window_start as i64,
            bucket_id,
            column::clamp(ledger.requests),
            column::clamp(ledger.billable_requests)
        ],
    )?;
    for m in ledger.models.iter().filter(|model| !model.model.is_empty()) {
        insert_usage_in(
            tx,
            "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests,
                 tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
             VALUES (?1,?2,?3,0,0,?4,?5,?6,?7)",
            params![
                window_start as i64,
                bucket_id,
                m.model,
                quantity_mirror(m.tier(UNIT_INPUT)),
                quantity_mirror(m.tier(UNIT_OUTPUT)),
                quantity_mirror(m.tier(UNIT_CACHE_READ)),
                quantity_mirror(m.tier(UNIT_CACHE_WRITE)),
            ],
        )?;
        for (unit, count) in open_units(&m.usage_units) {
            insert_usage_in(
                tx,
                "INSERT INTO usage_window_units (window_start, bucket_id, model, unit, count)
                         VALUES (?1,?2,?3,?4,?5)",
                params![
                    window_start as i64,
                    bucket_id,
                    m.model,
                    unit,
                    quantity_mirror(*count)
                ],
            )?;
        }
    }
    let mut exact = ledger.clone();
    omit_zero_open_units(&mut exact);
    let bytes = serde_json::to_vec(&exact).map_err(|error| RecordStoreError(error.to_string()))?;
    let changed = exec(
        tx,
        "INSERT INTO usage_window_exact(window_start,bucket_id,ledger) VALUES (?1,?2,?3)",
        params![window_start as i64, bucket_id, bytes],
    )?;
    if changed != 1 {
        return Err(RecordStoreError(
            "sqlite: exact raw usage row was not inserted".into(),
        ));
    }
    verify_usage_in(tx, bucket_id, window_start, ledger)
}

/// Verify again after every row has been replaced: later SQL triggers may affect earlier rows.
fn verify_usage_in(
    tx: &Connection,
    bucket_id: &str,
    window_start: u64,
    ledger: &UsageLedger,
) -> RecordStoreResult<()> {
    let mut ledger = ledger.clone();
    ledger
        .normalize_scale6()
        .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
    let ledger = &ledger;

    let mut expected_ledger = ledger.clone();
    omit_zero_open_units(&mut expected_ledger);
    let expected = serde_json::to_vec(&expected_ledger)
        .map_err(|error| RecordStoreError(error.to_string()))?;
    let exact: Option<Vec<u8>> = query_one(
        tx,
        "SELECT ledger FROM usage_window_exact WHERE window_start=?1 AND bucket_id=?2",
        params![window_start as i64, bucket_id],
        |row| row.get(0),
    )?;
    let mut mirror = expected_ledger;
    mirror.requests = column::clamp(mirror.requests) as u64;
    mirror.billable_requests = column::clamp(mirror.billable_requests) as u64;
    mirror.models.retain(|model| !model.model.is_empty());
    mirror
        .models
        .sort_by(|left, right| left.model.cmp(&right.model));
    for model in &mut mirror.models {
        for count in model.usage_units.values_mut() {
            *count = i128::from(quantity_mirror(*count));
        }
        model.usage_units.retain(|_, count| *count != 0);
    }
    if exact.as_ref() != Some(&expected) || usage_columns_in(tx, bucket_id, window_start)? != mirror
    {
        return Err(RecordStoreError(
            "sqlite: exact raw usage replacement was not applied".into(),
        ));
    }
    Ok(())
}

/// A metering cell's identity, every C4 attribution field included:
/// `(key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version)`.
type CellKey = (String, String, String, u64, String, String);

fn cell_key(row: &MeteringRow) -> CellKey {
    (
        row.key_id.clone(),
        row.provider.clone(),
        row.model.clone(),
        row.priced_from_ms,
        row.key_group_at_use.clone(),
        row.pricing_version.clone(),
    )
}

/// Complete day selection read under the caller's snapshot: the column mirror, each cell replaced
/// by its exact ledger where one exists.
fn metering_in(conn: &Connection, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
    let mut rows = metering_columns_in(conn, bucket)?;
    let index: std::collections::HashMap<CellKey, usize> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| (cell_key(row), i))
        .collect();
    for bytes in query_all(
        conn,
        "SELECT ledger FROM usage_metering_exact WHERE bucket=?1",
        params![(bucket as i64).to_string()],
        |row| row.get::<_, Vec<u8>>(0),
    )? {
        let mut exact: MeteringRow = serde_json::from_slice(&bytes).map_err(|error| {
            RecordStoreError(format!(
                "sqlite: an exact metering cell of bucket {bucket} is unreadable: {error}"
            ))
        })?;
        exact
            .normalize_scale6()
            .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
        let Some(&i) = index.get(&cell_key(&exact)) else {
            return Err(RecordStoreError(format!(
                "sqlite: exact metering cell of key '{}' model '{}' in bucket {bucket} has no \
                 column mirror",
                exact.key_id, exact.model
            )));
        };
        rows[i] = exact;
    }
    Ok(rows)
}

fn metering_columns_in(conn: &Connection, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
    let u = column::read_u64;
    let mut rows = query_all(
        conn,
        "SELECT key_id, model, provider, tokens_input, tokens_output, tokens_cache_read,
                tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version,
                priced_from_ms
             FROM usage_metering WHERE bucket = ?1",
        params![(bucket as i64).to_string()],
        |r| {
            Ok(MeteringRow {
                scale: 6,
                key_id: r.get(0)?,
                model: r.get(1)?,
                provider: r.get(2)?,
                tokens_input: quantity_column(r.get(3)?),
                tokens_output: quantity_column(r.get(4)?),
                tokens_cache_read: quantity_column(r.get(5)?),
                tokens_cache_write: quantity_column(r.get(6)?),
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
        conn,
        "SELECT key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version, unit, count
             FROM usage_metering_units WHERE bucket = ?1",
        params![(bucket as i64).to_string()],
        |r| {
            Ok((
                (
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    u(r.get(3)?),
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ),
                r.get::<_, String>(6)?,
                quantity_column(r.get(7)?),
            ))
        },
    )?;
    let index: std::collections::HashMap<CellKey, usize> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| (cell_key(row), i))
        .collect();
    for (cell, unit, count) in units {
        let Some(&i) = index.get(&cell) else {
            // The upgrade refuses an open unit without its parent rather than guess attribution;
            // a read does not drop one silently either (it would under-report the cell's usage).
            return Err(RecordStoreError(format!(
                "sqlite: metering unit '{unit}' of key '{}' in bucket {bucket} has no attribution \
                 parent",
                cell.0
            )));
        };
        rows[i].usage_units.insert(unit, count);
    }
    Ok(rows)
}

/// The one column-mirror cell `cell` names, its open units included, for a cell that has no exact
/// ledger yet: a point read on the cell's primary key, never the whole bucket.
fn metering_cell_in(
    conn: &Connection,
    bucket: u64,
    priced_from: i64,
    cell: &MeteringRow,
) -> RecordStoreResult<Option<MeteringRow>> {
    let u = column::read_u64;
    let bucket = (bucket as i64).to_string();
    let at = params![
        bucket,
        cell.key_id,
        cell.provider,
        cell.model,
        priced_from,
        cell.key_group_at_use,
        cell.pricing_version
    ];
    let Some(mut row) = query_one(
        conn,
        "SELECT tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, requests,
                billable_requests
             FROM usage_metering WHERE bucket=?1 AND key_id=?2 AND provider=?3 AND model=?4
             AND priced_from_ms=?5 AND key_group_at_use=?6 AND pricing_version=?7",
        at,
        |r| {
            Ok(MeteringRow {
                scale: 6,
                tokens_input: quantity_column(r.get(0)?),
                tokens_output: quantity_column(r.get(1)?),
                tokens_cache_read: quantity_column(r.get(2)?),
                tokens_cache_write: quantity_column(r.get(3)?),
                requests: u(r.get(4)?),
                billable_requests: u(r.get(5)?),
                ..cell.clone()
            })
        },
    )?
    else {
        return Ok(None);
    };
    for (unit, count) in query_all(
        conn,
        "SELECT unit, count FROM usage_metering_units WHERE bucket=?1 AND key_id=?2 AND provider=?3
             AND model=?4 AND priced_from_ms=?5 AND key_group_at_use=?6 AND pricing_version=?7",
        at,
        |r| Ok((r.get::<_, String>(0)?, quantity_column(r.get(1)?))),
    )? {
        row.usage_units.insert(unit, count);
    }
    Ok(Some(row))
}

/// [`RecordStore::add_usage`]'s writes, inside the caller's transaction (the trait method's own, or
/// a store v3 slot's, where the `op_id` record shares it).
fn add_usage_in(
    tx: &Connection,
    bucket_id: &str,
    window_start: u64,
    delta: &UsageDelta,
) -> RecordStoreResult<()> {
    let mut delta = delta.clone();
    delta
        .normalize_scale6()
        .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
    let delta = &delta;

    refuse_reserved_usage(bucket_id)?;
    // The exact ledger is the authority for every accrual, including the first. SQLite INTEGER
    // cannot represent the public u64 counters, and its primary-key order is not first-seen order.
    let mut ledger = usage_in(tx, bucket_id, window_start)?;
    ledger
        .checked_apply_delta(delta)
        .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
    put_usage_in(tx, bucket_id, window_start, &ledger)
}

/// [`RecordStore::add_metering`]'s writes, inside the caller's transaction.
fn add_metering_in(tx: &Connection, d: &MeteringDelta) -> RecordStoreResult<()> {
    let mut d = d.clone();
    d.normalize_scale6()
        .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
    let d = &d;

    let priced_from = column::storable_i64("add_metering", "priced_from_ms", d.priced_from_ms)?;
    let mut exact = MeteringRow {
        scale: 6,
        key_id: d.key_id.clone(),
        model: d.model.clone(),
        provider: d.provider.clone(),
        tokens_input: 0,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 0,
        billable_requests: 0,
        key_group_at_use: d.key_group_at_use.clone(),
        pricing_version: d.pricing_version.clone(),
        priced_from_ms: d.priced_from_ms,
        usage_units: Default::default(),
    };
    let persisted = metering_exact_bytes(tx, d.bucket, &exact)?;
    if let Some(bytes) = persisted {
        exact = serde_json::from_slice(&bytes).map_err(|error| {
            RecordStoreError(format!(
                "sqlite: exact metering cell of key '{}' model '{}' in bucket {} is unreadable: \
                 {error}",
                d.key_id, d.model, d.bucket
            ))
        })?;
    } else if let Some(previous) = metering_cell_in(tx, d.bucket, priced_from, &exact)? {
        exact = previous;
    }
    exact
        .checked_add_delta(d)
        .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
    put_metering_in(tx, d.bucket, &exact)
}

fn metering_exact_bytes(
    conn: &Connection,
    bucket: u64,
    cell: &MeteringRow,
) -> RecordStoreResult<Option<Vec<u8>>> {
    query_one(
        conn,
        "SELECT ledger FROM usage_metering_exact WHERE bucket=?1 AND key_id=?2 AND provider=?3          AND model=?4 AND priced_from_ms=?5 AND key_group_at_use=?6 AND pricing_version=?7",
        params![(bucket as i64).to_string(), cell.key_id, cell.provider, cell.model,
            column::storable_i64("metering", "priced_from_ms", cell.priced_from_ms)?,
            cell.key_group_at_use, cell.pricing_version],
        |row| row.get(0),
    )
}

/// Replace the exact cell and every mirror from the same checked post-state. Re-adding a
/// delta to an already clamped mirror would produce the wrong value after a later refund.
fn put_metering_in(tx: &Connection, bucket: u64, row: &MeteringRow) -> RecordStoreResult<()> {
    let mut exact = row.clone();
    exact
        .normalize_scale6()
        .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
    let priced_from = column::storable_i64("metering", "priced_from_ms", exact.priced_from_ms)?;
    exec(
        tx,
        "INSERT INTO usage_metering (bucket,key_id,provider,model,priced_from_ms,key_group_at_use,pricing_version,
         tokens_input,tokens_output,tokens_cache_read,tokens_cache_write,requests,billable_requests)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(bucket,key_id,provider,model,priced_from_ms,key_group_at_use,pricing_version) DO UPDATE SET
         tokens_input=excluded.tokens_input,tokens_output=excluded.tokens_output,
         tokens_cache_read=excluded.tokens_cache_read,tokens_cache_write=excluded.tokens_cache_write,
         requests=excluded.requests,billable_requests=excluded.billable_requests",
        params![(bucket as i64).to_string(), exact.key_id, exact.provider, exact.model, priced_from,
            exact.key_group_at_use, exact.pricing_version,
            quantity_mirror(exact.tokens_input), quantity_mirror(exact.tokens_output),
            quantity_mirror(exact.tokens_cache_read), quantity_mirror(exact.tokens_cache_write),
            column::clamp(exact.requests), column::clamp(exact.billable_requests)],
    )?;
    exec(tx,
        "DELETE FROM usage_metering_units WHERE bucket=?1 AND key_id=?2 AND provider=?3 AND model=?4          AND priced_from_ms=?5 AND key_group_at_use=?6 AND pricing_version=?7",
        params![(bucket as i64).to_string(), exact.key_id, exact.provider, exact.model, priced_from,
            exact.key_group_at_use, exact.pricing_version],
    )?;
    for (unit, count) in &exact.usage_units {
        exec(tx,
            "INSERT INTO usage_metering_units (bucket,key_id,provider,model,priced_from_ms,key_group_at_use,pricing_version,unit,count)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![(bucket as i64).to_string(), exact.key_id, exact.provider, exact.model, priced_from,
                exact.key_group_at_use, exact.pricing_version, unit, quantity_mirror(*count)],
        )?;
    }
    let bytes = serde_json::to_vec(&exact).map_err(|error| RecordStoreError(error.to_string()))?;
    if exec(tx,
        "INSERT INTO usage_metering_exact (bucket,key_id,provider,model,priced_from_ms,key_group_at_use,pricing_version,ledger)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(bucket,key_id,provider,model,priced_from_ms,key_group_at_use,pricing_version)
         DO UPDATE SET ledger=excluded.ledger",
        params![(bucket as i64).to_string(), exact.key_id, exact.provider, exact.model, priced_from,
            exact.key_group_at_use, exact.pricing_version, bytes],
    )? != 1 {
        return Err(RecordStoreError("sqlite: exact metering cell was not written".into()));
    }
    let mut mirror = exact.clone();
    mirror.tokens_input = i128::from(quantity_mirror(exact.tokens_input));
    mirror.tokens_output = i128::from(quantity_mirror(exact.tokens_output));
    mirror.tokens_cache_read = i128::from(quantity_mirror(exact.tokens_cache_read));
    mirror.tokens_cache_write = i128::from(quantity_mirror(exact.tokens_cache_write));
    mirror.requests = column::clamp(exact.requests) as u64;
    mirror.billable_requests = column::clamp(exact.billable_requests) as u64;
    for count in mirror.usage_units.values_mut() {
        *count = i128::from(quantity_mirror(*count));
    }
    // The column reader starts with the supplied identity and its open map. Clear that map
    // so only persisted unit rows determine the verification result.
    let mut identity = mirror.clone();
    identity.usage_units.clear();
    if metering_exact_bytes(tx, bucket, &exact)?.as_ref() != Some(&bytes)
        || metering_cell_in(tx, bucket, priced_from, &identity)? != Some(mirror)
    {
        return Err(RecordStoreError(
            "sqlite: exact metering replacement was not applied".into(),
        ));
    }
    Ok(())
}

/// [`RecordStore::append_audit`]'s write and fork check, inside the caller's transaction.
fn append_audit_in(tx: &Connection, entry: &AuditRecord) -> RecordStoreResult<()> {
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

/// A deduped batch's refusal as the trait's error: a reused `op_id` with another body answers the
/// contract's conflict diagnostic.
fn deduped_refusal(error: busbar_contract::abi::sdk::store::OpRefused) -> RecordStoreError {
    use busbar_contract::abi::sdk::store::OpRefused;
    RecordStoreError(match error {
        OpRefused::Conflict => busbar_contract::abi::store::DIAG_OPID_CONFLICT.into(),
        OpRefused::Refused(reason) | OpRefused::Failed(reason) => reason,
    })
}

impl RecordStore for SqliteStore {
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.v3_add_usage_batch(op, cells).map_err(deduped_refusal)
    }

    fn supports_usage_batch_deduped(&self) -> bool {
        true
    }

    fn add_metering_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.v3_add_metering_batch(op, deltas)
            .map_err(deduped_refusal)
    }

    fn supports_metering_batch_deduped(&self) -> bool {
        true
    }

    fn apply_usage_correction(
        &self,
        request: &busbar_contract::abi::sdk::store::correction::Request,
    ) -> RecordStoreResult<busbar_contract::abi::sdk::store::correction::Decision> {
        self.v3_apply_usage_correction(request).map_err(|error| {
            use busbar_contract::abi::sdk::store::OpRefused;
            RecordStoreError(match error {
                OpRefused::Conflict => "usage correction operation id conflict".into(),
                OpRefused::Refused(reason) | OpRefused::Failed(reason) => reason,
            })
        })
    }

    fn supports_usage_correction(&self) -> bool {
        true
    }

    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        if key.deleted_at.is_some() {
            self.write_destroying_secrets(|tx| {
                put_key_inner(tx, key, Self::bump_revision(tx)?, "put_key")
            })
        } else {
            self.write(true, |tx| {
                put_key_inner(tx, key, Self::bump_revision(tx)?, "put_key")
            })
        }
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
        query_all(
            &self.lock_reader(),
            sql,
            params![column::clamp(since)],
            row_to_key,
        )
    }

    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.write_destroying_secrets(|tx| {
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
            tx.execute("DELETE FROM credentials WHERE key_id=?1", params![id])
                .store()?;
            let changed = tx
                .execute(
                    "UPDATE keys SET enabled=0, deleted_at=?2, updated_at=?2, revision=?3 WHERE id=?1",
                    params![id, now, rev],
                )
                .store()?;
            if changed == 0 {
                return Err(RecordStoreError(format!("delete_key: unknown id '{id}'")));
            }
            Ok(())
        })
    }

    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.write(true, |tx| {
            put_credential_inner(tx, secret, Self::bump_revision, "put_credential")
        })
    }

    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        let rewrapped = self.write(true, |tx| {
            if expected.meta.revoked_at.is_some()
                || expected.meta.secret_form != SecretForm::Recoverable
                || expected.secret == replacement
            {
                return Ok(false);
            }
            let owner_live: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM keys WHERE id=?1 AND deleted_at IS NULL)",
                    params![expected.meta.key_id],
                    |row| row.get(0),
                )
                .store()?;
            if !owner_live {
                return Ok(false);
            }
            let mut current = query_one(
                tx,
                &format!("SELECT {CRED_SECRET_COLS} FROM credentials WHERE id=?1"),
                params![expected.meta.id],
                row_to_cred_secret,
            )?;
            let matches = current.as_ref() == Some(expected);
            if let Some(current) = &mut current {
                zeroize::Zeroize::zeroize(&mut current.secret);
            }
            if !matches {
                return Ok(false);
            }
            let revision = Self::bump_revision(tx)?;
            let changed = exec(
                tx,
                "UPDATE credentials SET secret=?2, revision=?3 WHERE id=?1",
                params![expected.meta.id, replacement, revision],
            )?;
            if changed != 1 {
                return Err(RecordStoreError(
                    "credential rewrap lost its locked row".into(),
                ));
            }
            Ok(true)
        })?;
        if rewrapped {
            // The replaced envelope must not outlive the rewrap in the WAL.
            scrub_wal(&self.lock_writer(), &self.path);
        }
        Ok(rewrapped)
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        const OP: &str = "put_key_with_credential";
        self.write(true, |tx| {
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
        self.write_destroying_secrets(|tx| {
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
            params![column::clamp(since)],
            row_to_cred_secret,
        )
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        let conn = self.lock_reader();
        let _snapshot = conn.unchecked_transaction().store()?;
        usage_in(&conn, bucket_id, window_start)
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        refuse_reserved_usage(bucket_id)?;
        self.write(false, |tx| {
            put_usage_in(tx, bucket_id, window_start, ledger)
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
        metering_in(&conn, bucket)
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

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let row = PlaneRow::of(record, record.id, UPSERT_SEQ, "upsert_plane_record")?;
        self.write(true, |tx| {
            exec(
                tx,
                "INSERT INTO plane_records (kind, identity, seq, id, parent, ts, disposition, body) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                 ON CONFLICT(kind, identity, seq) DO UPDATE SET \
                    id=excluded.id, parent=excluded.parent, ts=excluded.ts, \
                    disposition=excluded.disposition, body=excluded.body",
                row.params(&record),
            )
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
        let retention = if kind == TASK_RECORD_KIND {
            Retention::TerminalOnly
        } else {
            Retention::Age
        };
        self.purge_plane_records(kind, before, retention)
    }

    /// STRICTLY older than the cutoff, by the rule the call carries (never one inferred from the
    /// kind's name): `TerminalOnly` drops only TERMINAL rows (an interrupted task waiting on a human
    /// sits still longest), `Age` every older row; under either, a purged task takes its
    /// `task_event` chain with it, and the count is the task rows. A cutoff past the signed
    /// timestamp range includes every storable timestamp, including the signed maximum.
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        let terminal_only = retention == Retention::TerminalOnly;
        self.write(false, |tx| {
            let before = if kind == TICKET_RECORD_KIND {
                before.min(self.shared_clock(tx)? as u64)
            } else {
                before
            };
            // Past the signed range every storable timestamp is older, the signed maximum
            // included, so the clamped cutoff is inclusive there. Either form is a range seek on
            // `plane_records_kind_ts_idx`.
            let older = if before > i64::MAX as u64 {
                "ts <= ?2"
            } else {
                "ts < ?2"
            };
            let before = column::clamp(before);
            let predicate = if terminal_only {
                format!("kind=?1 AND {older} AND disposition='terminal'")
            } else {
                format!("kind=?1 AND {older}")
            };
            if kind == TASK_RECORD_KIND {
                exec(
                    tx,
                    &format!(
                        "DELETE FROM plane_records WHERE kind=?3 AND parent IN \
                         (SELECT identity FROM plane_records WHERE {predicate})"
                    ),
                    params![kind, before, TASK_EVENT_RECORD_KIND],
                )?;
            }
            let removed = exec(
                tx,
                &format!("DELETE FROM plane_records WHERE {predicate}"),
                params![kind, before],
            )?;
            Ok(removed as u64)
        })
    }

    /// Absent is a no-op; every `seq` under the identity goes, so a chain is never left partial.
    /// A task takes its `task_event` chain with it.
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.write(true, |tx| {
            if kind == TASK_RECORD_KIND {
                exec(
                    tx,
                    "DELETE FROM plane_records WHERE kind=?2 AND parent=?1",
                    params![id, TASK_EVENT_RECORD_KIND],
                )?;
            }
            exec(
                tx,
                "DELETE FROM plane_records WHERE kind=?1 AND identity=?2",
                params![kind, id],
            )
            .map(drop)
        })
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        self.write(true, |tx| {
            let now_i = self.shared_clock(tx)?;
            let store_now = now_i as u64;
            if expires_at < store_now {
                return Ok(false);
            }
            let expires = column::clamp(expires_at);
            exec(
                tx,
                "DELETE FROM plane_tokens WHERE expires_at < ?1",
                [now_i],
            )?;
            let inserted = exec(
                tx,
                "INSERT INTO plane_tokens (kind, token, expires_at) VALUES (?1,?2,?3) \
                 ON CONFLICT(kind, token) DO NOTHING",
                params![kind, token, expires],
            )?;
            Ok(inserted == 1)
        })
    }

    /// Multi-use and SPENDS NOTHING: a plain read of the `(kind, token)` upserted record, live while
    /// present, still `active`, and `now` not past `expires_at`. Reserved tickets instead require
    /// their terminal record and exact deadline under the shared clock. Uncertain answers fail closed.
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        if kind == TICKET_RECORD_KIND {
            let conn = self.lock_reader();
            let _snapshot = conn.unchecked_transaction().store()?;
            let row: Option<(i64, String)> = query_one(
                &conn,
                "SELECT ts, disposition FROM plane_records WHERE kind=?1 AND identity=?2 AND seq=?3",
                params![kind, token, UPSERT_SEQ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let store_now = self.shared_clock(&conn)? as u64;
            return Ok(store_now <= expires_at
                && row.is_some_and(|(ts, disposition)| {
                    u64::try_from(ts).ok() == Some(expires_at)
                        && disposition == DISPOSITION_TERMINAL
                }));
        }
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
                "{method}: key '{}' does not exist; a credential must hang off a real key",
                m.key_id
            )));
        }
        Some(false) => {
            return Err(RecordStoreError(format!(
                "{method}: key '{}' is tombstoned; its credentials were revoked with it and are \
                 never reissued",
                m.key_id
            )));
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
    if let Some(mut stored) = by_id {
        // The stored secret is read only to compare; it is wiped before any answer, and the
        // caller's is compared in place, never copied.
        let mut meta = m.clone();
        meta.revision = stored.meta.revision;
        let identical = meta == stored.meta && secret.secret == stored.secret;
        zeroize::Zeroize::zeroize(&mut stored.secret);
        let sm = &stored.meta;
        if sm.revoked_at.is_some() {
            return Err(RecordStoreError(format!(
                "{method}: credential '{}' is revoked; a revoked credential is never re-minted",
                m.id
            )));
        }
        if identical {
            return Ok(());
        }
        return Err(live_slot(&sm.kind, &sm.key_id, sm.slot));
    }

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
            "{method}: public_id '{}' is already in use for kind '{}'",
            m.public_id, m.kind
        )));
    }
    let revision = revision(tx)?;

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

/// Preserve each old cell's recorded attribution; already-collapsed history cannot be recovered.
fn rebuild_metering_for_v17(tx: &Connection) -> RecordStoreResult<()> {
    let has_units = table_exists(tx, "usage_metering_units")?;
    if has_units {
        let orphan: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM usage_metering_units u WHERE NOT EXISTS (
                SELECT 1 FROM usage_metering m WHERE m.bucket=u.bucket AND m.key_id=u.key_id
                AND m.provider=u.provider AND m.model=u.model AND m.priced_from_ms=u.priced_from_ms))",
            [], |r| r.get(0)).store()?;
        if orphan {
            return Err(RecordStoreError(
                "sqlite: metering unit has no attribution parent; refusing migration".into(),
            ));
        }
    }
    tx.execute_batch(r#"
        DROP TRIGGER IF EXISTS keys_guard_hard_delete;
CREATE TABLE usage_metering_v17 (
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
    PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version)
) STRICT, WITHOUT ROWID;
CREATE TABLE usage_metering_units_v17 (
    bucket         TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    provider       TEXT NOT NULL,
    model          TEXT NOT NULL,
    priced_from_ms INTEGER NOT NULL DEFAULT 0,
    key_group_at_use TEXT NOT NULL DEFAULT '',
    pricing_version TEXT NOT NULL DEFAULT '',
    unit           TEXT NOT NULL,
    count          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version, unit)
) STRICT, WITHOUT ROWID;


        INSERT INTO usage_metering_v17 (bucket,key_id,provider,model,key_group_at_use,pricing_version,
            requests,billable_requests,tokens_input,tokens_output,tokens_cache_read,tokens_cache_write,priced_from_ms)
        SELECT bucket,key_id,provider,model,key_group_at_use,pricing_version,
            requests,billable_requests,tokens_input,tokens_output,tokens_cache_read,tokens_cache_write,priced_from_ms
        FROM usage_metering;
    "#).store()?;
    if has_units {
        tx.execute_batch("INSERT INTO usage_metering_units_v17
            (bucket,key_id,provider,model,priced_from_ms,key_group_at_use,pricing_version,unit,count)
            SELECT u.bucket,u.key_id,u.provider,u.model,u.priced_from_ms,m.key_group_at_use,m.pricing_version,u.unit,u.count
            FROM usage_metering_units u JOIN usage_metering m
            ON m.bucket=u.bucket AND m.key_id=u.key_id AND m.provider=u.provider
            AND m.model=u.model AND m.priced_from_ms=u.priced_from_ms;
            DROP TABLE usage_metering_units;").store()?;
    }
    tx.execute_batch(
        "DROP TABLE usage_metering;
        ALTER TABLE usage_metering_v17 RENAME TO usage_metering;
        ALTER TABLE usage_metering_units_v17 RENAME TO usage_metering_units;",
    )
    .store()?;
    Ok(())
}

#[cfg(test)]
mod tests;
