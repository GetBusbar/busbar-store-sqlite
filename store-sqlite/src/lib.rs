// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in SQLite backend for busbar's durable governance store — the default `db` plugin.
//! Implements `busbar_contract::records::RecordStore` over embedded rusqlite connections: one mutex-guarded
//! writer, plus a small pool of `query_only` readers so a long billing report or retention sweep
//! never blocks the hot-path usage flush (WAL readers are unaffected by an in-flight writer).
//! Depends only on the `busbar-contract` crate (plus rusqlite), never on the engine.
//!
//! THE DOOR: [`door::door`] answers the store v3 table (`busbar_contract::abi::store`) over
//! [`SqliteStore`] through the contract's safe store SDK — the 1.5.5 op set is the
//! [`RecordStore`] implementation below, the v3 additions are in `v3`. The crate exports no
//! symbol: a build that links it registers `door`, and the `busbar-store-sqlite-plugin` cdylib
//! exports it. No `unsafe` here at all.

#![forbid(unsafe_code)]

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    PlaneDisposition, PlaneRecordRef, PlaneSelector, RecordStore, RecordStoreError,
    RecordStoreResult, ScopeRef, SecretForm, UsageDelta, UsageLedger, VirtualKey, UNIT_CACHE_READ,
    UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// rusqlite error -> the api's backend-agnostic `RecordStoreError` (the contract crate stays storage-free,
// so the `From` impl that powers `?` cannot live there). Replace `<rusqlite call>?` with `<call>.store()?`.
trait IntoStoreResult<T> {
    fn store(self) -> RecordStoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, rusqlite::Error> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| RecordStoreError(e.to_string()))
    }
}

/// Store schema version, kept in SQLite's `PRAGMA user_version`. v5 (1.5.0, the generic-credentials
/// redesign): `virtual_keys`/`aws_credentials` are replaced by `keys` (pure principal attributes,
/// `generation_hash` is a post-resolution rotation FINGERPRINT never looked up by, not the old
/// `key_hash` lookup credential) and `credentials` (kind-polymorphic, row-looked-up admission
/// credentials — today only `kind='sigv4'`). `DELETE` is now a TOMBSTONE (`deleted_at`/`enabled=0`,
/// credentials destroyed, row KEPT for billing attribution) rather than a hard row removal.
/// `store_revision` adds a store-global monotonic counter for incremental hydration
/// (`list_keys_since`/`list_credentials_since`). `usage_windows` gains a `model` column into its PK
/// (was missing it) and leads with `window_start` (write locality + a contiguous prefix for the
/// retention sweep); `usage_metering` leads with `bucket` for the same write-locality reasoning, and
/// gains `key_group_at_use`/`pricing_version`/`billable_requests`, and renames
/// `tokens_cache_creation` -> `tokens_cache_write` to match `TierTokens`'s own naming (a drift fixed
/// core-side in this same redesign). 1.5.0 is UNRELEASED, so each bump up to and including v5 was
/// destructive (drop + recreate), never a migration: a pre-v5 dev database was recreated empty on
/// open.
///
/// v6: the FIRST real, additive (non-destructive) migration this store has ever needed — a
/// one-time backfill of `billable_requests` for any row where a v5-era write left it at 0 despite
/// a nonzero `requests` (see the `version < 6` block in `migrate`, and
/// `governance::state::hydrate_budgets` in busbar core for the boot-time bug this closes).
///
/// v7: the durable MCP TOOL-CALL LOG (`mcp_calls`). PURELY ADDITIVE and needs no backfill block —
/// the table is new, so `SCHEMA`'s own `CREATE TABLE IF NOT EXISTS` (executed unconditionally on
/// every open) is the entire migration. Nothing is dropped and no existing row is touched: a v6
/// database crossing to v7 gains an empty table and keeps everything else, which is why there is no
/// `version < 7` arm in `migrate` to match the `version < 6` one.
///
/// v8: the durable A2A TASK STORE (`tasks`, `task_events`). Additive on the same terms as v7 — two
/// new tables, no backfill, nothing dropped — so again no `version < 8` arm exists.
///
/// v9: the durable TRUST STATE (`mcp_demotions`, `spent_ask_states`) — the recorded quarantine of an
/// upstream that drifted from what the operator approved, and the ledger that makes a single-use
/// human approval single-use across a restart and across a fleet. Additive on the same terms as v7
/// and v8 — two new tables, no backfill, nothing dropped — so there is no `version < 9` arm either.
///
/// v10 (busbar 1.6.0): the store contract replaced its fourteen protocol-named methods
/// (`put_task`, `append_mcp_call`, `redeem_ask_state`, …) with eight KIND-TAGGED verbs over an opaque
/// `PlaneRecord` envelope, and three record shapes grew. The crossing is FORWARD-ONLY and keeps every
/// byte an operator already has:
/// - `plane_records` / `plane_tokens` are the new neutral tables every kind lives in (additive).
/// - the v8/v9 typed tables (`tasks`, `task_events`, `mcp_demotions`, `spent_ask_states`) are COPIED
///   into them as the exact bodies the 1.6.0 planes decode, then dropped — see
///   `migrate_legacy_plane_tables`. `mcp_calls` is the one exception: the 1.6.0 call body is a
///   framed digest stream the engine seals and no backend can reconstruct, so its rows are LEFT IN
///   PLACE, unread, rather than destroyed or forged (busbar ships no `call` migration either).
/// - `keys` gains `scope_grants` (the non-pool scope kinds, which the pool-only column used to
///   silently turn into POOL grants), `idp_subject`, `binding_mode` and `minted_by` — nullable
///   `ADD COLUMN`s, so every existing row reads back exactly as before.
/// - `usage_metering` gains `priced_from_ms` INTO ITS PRIMARY KEY (a rate-card edit splits the day's
///   cell), which SQLite can only do by rebuilding the table: every existing row is copied across at
///   `priced_from_ms = 0`, the opening card's instant, which is the reading the contract gives an
///   undated row.
/// - the open (non-reserved) usage units of both ledgers get their own tables
///   (`usage_window_units`, `usage_metering_units`); the reserved four stay in the columns they
///   always lived in, so no existing count moves.
///
/// Versions 7-9 were never released (the last release, v1.0.6, is schema v6), but a dev database at
/// any of them upgrades the same way; `tests/fixtures/` pins both a real v6 and a real v9 file.
///
/// v11 (busbar 1.6.0, the store v3 table): the state the v3 slots keep — the DURABLE `op_id` dedupe
/// log (`store_ops`, S4: a replay after a restart still answers the original), the money slots'
/// caps, drawn totals and slices (`money_caps`, `money_used`, `money_slices`), the ledger streams
/// (`journal`), the session directory (`sessions`) and a plane's kernel-held records
/// (`schema_records`). Additive on the same terms as v7-v9: new tables only, created by `SCHEMA`.
const SCHEMA_VERSION: i64 = 11;

/// The task states that are TERMINAL — used ONLY by the v10 migration, to set the `disposition`
/// sidecar on a task row copied out of the legacy typed `tasks` table (a live 1.6.0 engine sets it
/// itself on every write). Named as a closed set rather than derived by negation on purpose: an unrecognised state token — one a newer
/// engine emits and this build has never heard of — must read as NOT terminal, so a store compiled
/// before a state existed cannot delete a task it does not understand. The wrong half to guess on is
/// the deleting half.
const TERMINAL_TASK_STATES: [&str; 4] = ["completed", "failed", "canceled", "rejected"];

const SCHEMA: &str = "
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
    -- Bare string, NOT a foreign key: groups are config-defined, not persisted entities.
    key_group       TEXT,
    -- NULLABLE JSON array of bare pool-name strings: NULL = the pool grant was OMITTED at mint =
    -- ALL pools; a JSON array (including '[]') = the exhaustive grant. Matches
    -- VirtualKey::allowed_scopes: Option<Vec<ScopeRef>> (every entry kind=pool by construction
    -- today) — wire/storage shape is unchanged by the ScopeRef generalization, only the in-memory
    -- Rust type changed (C6: None vs Some([]) must never collapse into each other).
    allowed_pools   TEXT,
    labels          TEXT NOT NULL DEFAULT '{}',
    enabled         INTEGER NOT NULL DEFAULT 1,
    -- Rotation fingerprint (VirtualKey::generation_hash) — compared post-resolution against a signed
    -- token's `generation` claim, never looked up BY. Deliberately no uniqueness constraint: a
    -- UNIQUE index here would be a load-bearing lie suggesting it's a lookup key.
    generation_hash TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    expires_at      INTEGER,
    deleted_at      INTEGER,
    revision        INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT keys_enabled_bool CHECK (enabled IN (0,1)),
    CONSTRAINT keys_pools_json CHECK (allowed_pools IS NULL OR (json_valid(allowed_pools) AND json_type(allowed_pools)='array')),
    CONSTRAINT keys_labels_json CHECK (json_valid(labels) AND json_type(labels)='object' AND length(labels)<=4096),
    -- Tombstone atomicity: a key can never be deleted-but-still-enabled. Both flags MUST be set in
    -- the SAME UPDATE statement (SQLite has no deferred CHECK constraints), or this fires mid-flight.
    CONSTRAINT keys_tombstone_off CHECK (deleted_at IS NULL OR enabled = 0),
    CONSTRAINT keys_expiry_after CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;
CREATE INDEX IF NOT EXISTS keys_revision_idx ON keys (revision);
CREATE INDEX IF NOT EXISTS keys_group_live_idx ON keys (key_group) WHERE deleted_at IS NULL;

-- ONLY for auth mechanisms verified by ROW LOOKUP from a wire-supplied public identifier (today:
-- sigv4 — bearer/signed-token auth is NEVER represented here, see `keys.generation_hash`'s comment).
CREATE TABLE IF NOT EXISTS credentials (
    id            TEXT NOT NULL PRIMARY KEY,
    key_id        TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    kind          TEXT NOT NULL,
    -- 0 or 1: bounds cardinality to exactly two rows per (key_id, kind), enabling safe
    -- overlap-window rotation (mint into the free slot, hand it out, revoke the old one).
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
    CONSTRAINT cred_sigv4_recov CHECK (kind <> 'sigv4' OR secret_form = 'recoverable'),
    CONSTRAINT cred_secret_fmt CHECK (secret IS NULL OR secret GLOB 'v1:?*:?*'),
    CONSTRAINT cred_reason_ord CHECK (revoke_reason IS NULL OR revoked_at IS NOT NULL),
    CONSTRAINT cred_expiry_after CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS cred_public_id_uq ON credentials (kind, public_id);
CREATE UNIQUE INDEX IF NOT EXISTS cred_slot_uq ON credentials (key_id, kind, slot);
CREATE INDEX IF NOT EXISTS cred_revision_idx ON credentials (revision);

-- Revocation for the bearer/signed-token plane only (sigv4 revocation lives on credentials.revoked_at
-- instead). Deliberately NO FK to keys: revocation must be insertable even if the key row is gone or
-- inconsistent — it must never fail on referential integrity.
CREATE TABLE IF NOT EXISTS denylist (
    sub        TEXT NOT NULL PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;

-- Rate-limit ledger. window_start LEADS the PK: write locality for the current-window flush, and a
-- contiguous prefix range for the retention sweep (`WHERE window_start < cutoff`).
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

-- Billing ledger, durable, never auto-pruned by default. bucket LEADS the PK for the same
-- write-locality reasoning as usage_windows (writes cluster on today's bucket).
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
    -- The instant the price this cell accrued under started (v10). Part of the key: a rate-card edit
    -- mid-day SPLITS the day's cell so each half prices at the card it was earned under. 0 = the
    -- opening card, which is what every pre-v10 row reads as.
    priced_from_ms     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, key_id, provider, model, priced_from_ms)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS um_key_bucket_idx ON usage_metering (key_id, bucket);

-- The OPEN usage units (v10): every ledgered class the four reserved token columns do not hold, by
-- name (a plane's `tool_calls`, a rerank's search units, a session count, ...). One row per unit so
-- an accrual is an atomic `count = count + delta` UPSERT exactly like the columns, rather than a
-- read-modify-write of a JSON blob. The reserved four never appear here: they stay in the columns
-- they have always lived in.
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

-- THE NEUTRAL PLANE-RECORD TABLE (v10). Every durable record a plane keeps -- an A2A task and its
-- provenance chain, the MCP per-call log, a demotion, a push-callback config, and any kind a future
-- plane declares -- is one row here, tagged by `kind`. The store never decodes `body`: it is the
-- plane's own serialized row, persisted and returned verbatim. Everything the store has to key,
-- order or sweep on is a TYPED sidecar column instead, which is what lets retention honour a
-- per-kind contract without reading the body.
--
-- IDENTITY. `identity` is the record's `parent` when it has one (an appended chain position is
-- `(kind, parent, seq)`), else its own `id` at `seq` 0 (an upserted top-level record). `id` and
-- `parent` are kept verbatim beside it so nothing is lost in the keying.
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
-- The retention sweep's access path (`purge_plane_records_before` filters on kind + ts), and the
-- parent enumeration's (`list_plane_record_parents`) and a parent's scan's.
CREATE INDEX IF NOT EXISTS plane_records_kind_ts_idx ON plane_records (kind, ts);
CREATE INDEX IF NOT EXISTS plane_records_kind_parent_idx ON plane_records (kind, parent, seq);

-- THE SINGLE-USE TOKEN LEDGER (v10), for every kind (`ask` is the MCP confirm-once approval). A
-- sealed single-use grant is byte-identical on its second presentation, so only a RECORD THAT THE
-- FIRST HAPPENED tells them apart -- and one shared by every node of the deployment, not held in one
-- process's memory. Every read is a point lookup on the key (the INSERT's own conflict check), and
-- the only scan is the eviction sweep, bounded by one validity window: an entry recording a grant
-- that can no longer be presented protects nothing.
CREATE TABLE IF NOT EXISTS plane_tokens (
    kind       TEXT NOT NULL,
    token      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (kind, token)
) STRICT, WITHOUT ROWID;

-- THE STORE v3 STATE (v11). `store_ops` is the DURABLE `op_id` dedupe log (abi::store S1-S4): an
-- op that APPLIED is remembered with its value fields (`body`) and its answer for at least
-- OP_ID_RETENTION_SECS, in the same transaction as its effect, so a replay after a crash or a
-- restart answers the original and applies nothing.
CREATE TABLE IF NOT EXISTS store_ops (
    op_id       BLOB NOT NULL PRIMARY KEY,
    body        TEXT NOT NULL,
    answer      TEXT NOT NULL,
    recorded_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS store_ops_recorded_idx ON store_ops (recorded_at);

-- The money slots. A `slot` is `(bucket, pool, dimension, class_key, window_start)`, kept as its
-- JSON array so `pool`'s None and Some('') stay apart. Amounts are u64 stored bit-for-bit in the
-- signed column and compared in Rust, never in SQL.
CREATE TABLE IF NOT EXISTS money_caps (
    slot       TEXT NOT NULL PRIMARY KEY,
    cap        INTEGER NOT NULL,
    config_gen INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS money_used (
    slot TEXT NOT NULL PRIMARY KEY,
    used INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
-- AUTOINCREMENT: a slice id is never reused, so a late release of a closed slice can never land on
-- a newer one.
CREATE TABLE IF NOT EXISTS money_slices (
    slice_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    slot      TEXT NOT NULL,
    remaining INTEGER NOT NULL
) STRICT;

-- The ledger streams: `seq` counts from 1 per stream, so a stream's head is its MAX(seq).
CREATE TABLE IF NOT EXISTS journal (
    stream TEXT NOT NULL,
    seq    INTEGER NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (stream, seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS sessions (
    session   INTEGER NOT NULL PRIMARY KEY,
    node      TEXT NOT NULL,
    principal TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS sessions_principal_idx ON sessions (principal);

-- A plane's kernel-held durable records, by `(schema, key)`; a scan reads a key prefix in byte order.
CREATE TABLE IF NOT EXISTS schema_records (
    schema     TEXT NOT NULL,
    record_key BLOB NOT NULL,
    value      BLOB NOT NULL,
    PRIMARY KEY (schema, record_key)
) STRICT, WITHOUT ROWID;

-- Pragma-independent integrity triggers: survive an operator opening the file with the sqlite3 CLI
-- (where foreign_keys defaults OFF) or a build with SQLITE_OMIT_FOREIGN_KEY.
CREATE TRIGGER IF NOT EXISTS keys_guard_hard_delete BEFORE DELETE ON keys FOR EACH ROW
  WHEN EXISTS (SELECT 1 FROM usage_metering WHERE key_id = OLD.id)
  BEGIN SELECT RAISE(ABORT, 'keys: hard DELETE would orphan usage_metering rows; use the tombstone path (Store::delete_key)'); END;
CREATE TRIGGER IF NOT EXISTS keys_cascade_credentials AFTER DELETE ON keys FOR EACH ROW
  BEGIN DELETE FROM credentials WHERE key_id = OLD.id; END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
-- An APPENDED chain position (a row with a parent: a task event, a call record) is never REWRITTEN,
-- so a stored digest can never be quietly restated -- the append verb refuses a different record at
-- an occupied position, and this makes the same true for anything that opens the file directly.
-- There is deliberately NO no-delete counterpart (as audit_log has): these rows have a retention
-- sweep, and bounded retention and never-rewritten are different properties -- only the second one
-- is an integrity claim. Upserted top-level records (parent NULL) are updated in place by design.
CREATE TRIGGER IF NOT EXISTS plane_records_chain_no_update BEFORE UPDATE ON plane_records
  WHEN OLD.parent IS NOT NULL
  BEGIN SELECT RAISE(ABORT, 'plane_records: an appended chain record is never rewritten'); END;
";

/// Apply the fixed pragma set to a connection, in the documented order (`busy_timeout` FIRST:
/// switching a not-yet-WAL file into WAL mode itself briefly acquires the database, so the timeout
/// must already be configured or that acquisition is subject to SQLite's zero-second default).
/// `is_writer` gates the writer-only pragmas (`journal_size_limit`, `wal_autocheckpoint`) and
/// `query_only` (readers only — NOT `SQLITE_OPEN_READ_ONLY`, which cannot create the `-wal`/`-shm`
/// files on a fresh database and would race the writer's first open).
/// True for any SQLite path spelling that opens a private in-memory database: the bare `:memory:`
/// literal, or a URI filename using `mode=memory` (e.g. `file::memory:?cache=shared`,
/// `file:foo?mode=memory`). Every caller that needs to special-case in-memory routing (pragma
/// selection here, and `SqliteStore::open`'s single-connection routing) MUST share this check —
/// two independent, drifting definitions is exactly how `open()` missed URI spellings that
/// `apply_pragmas` already recognized (see `SqliteStore::open`'s doc comment).
fn is_memory_path(path: &str) -> bool {
    path.starts_with(":memory:")
        || path.contains("mode=memory")
        || (path.starts_with("file:") && path.contains(":memory:"))
}

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
    // Skip mmap on anything that looks like a network filesystem path convention; best-effort, not a
    // real fs-type probe (avoids a new platform-specific dependency for a defense-in-depth knob).
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

/// Run `f` with the writer connection escalated to `synchronous=FULL` for security/billing-relevant
/// transactions (mint/revoke/rotate/delete, the metering flush) — SQLite refuses to change
/// `synchronous` WHILE a transaction is active ("Safety level may not be changed inside a
/// transaction"), so the escalation happens BEFORE `f` opens its `BEGIN IMMEDIATE` and the restore
/// happens AFTER `f` returns (success or error) rather than being a value-scoped RAII guard, which
/// would either have to hold the pragma-change across the transaction (rejected by SQLite) or race
/// the transaction's own connection borrow. The restore is unconditional (`f`'s `Result` either way)
/// so an early `?` inside `f` can never leave the connection permanently paying the FULL-fsync cost.
fn with_full_sync<T>(
    conn: &mut Connection,
    f: impl FnOnce(&mut Connection) -> RecordStoreResult<T>,
) -> RecordStoreResult<T> {
    conn.pragma_update(None, "synchronous", "FULL").store()?;
    let result = f(conn);
    let _ = conn.pragma_update(None, "synchronous", "NORMAL");
    result
}

/// Embedded SQLite `Store` backend (durable; opt-in via `store.module: sqlite`). One mutex-guarded
/// writer connection (all mutations, `BEGIN IMMEDIATE` — never `DEFERRED`, since every write here is
/// read-then-write and `DEFERRED`'s upgrade-on-first-write can return `SQLITE_BUSY_SNAPSHOT`, which
/// bypasses the busy handler entirely) plus a small round-robin pool of `query_only` reader
/// connections, so a long billing report or retention sweep never blocks the hot-path usage flush.
pub struct SqliteStore {
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    next_reader: AtomicUsize,
    path: String,
}

impl SqliteStore {
    pub fn open(path: &str, busy_timeout_ms: i64) -> RecordStoreResult<Self> {
        // `:memory:` (and its URI-form spellings, e.g. `file::memory:`, `file:foo?mode=memory`) is
        // not a real file path -- SQLite opens a NEW, PRIVATE in-memory database per connection to
        // it, never a shared one. Opening a writer + N readers against it the normal way would
        // silently create N+1 isolated, mutually-invisible databases (only the writer's copy would
        // ever get `migrate()`'s schema; every reader would see "no such table"). Route to the
        // single-connection path instead, matching `open_in_memory()`'s own doc comment on exactly
        // this hazard. This makes every in-memory spelling behave correctly for EVERY caller of
        // `open()` (config-driven plugin adapters included), not just callers who already knew to
        // use `open_in_memory()` explicitly, or who happened to pass the exact `:memory:` literal —
        // `is_memory_path` is the same check `apply_pragmas` already uses, so this routing decision
        // can never drift out of sync with the pragma-selection one again.
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
            readers,
            next_reader: AtomicUsize::new(0),
            path: path.to_string(),
        };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory SQLite store, for unit tests. Single connection reused for both roles: `:memory:`
    /// is one private database per connection, so a separate reader pool would see a DIFFERENT
    /// empty database, not a read replica of the writer's data.
    pub fn open_in_memory() -> RecordStoreResult<Self> {
        let conn = Connection::open_in_memory().store()?;
        apply_pragmas(&conn, ":memory:", 5000, true)?;
        let store = Self {
            writer: Mutex::new(conn),
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

    /// The filesystem path (or `:memory:`) this store was opened against — for operator-facing
    /// diagnostics (e.g. a boot-log line naming which file governance is persisted to).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// A reader connection for read-mostly/long-running queries (billing reports, the retention
    /// sweep's SELECT half). Falls back to the writer for `:memory:` / when no reader pool exists —
    /// still correct (WAL semantics don't apply), just without the concurrency benefit.
    fn lock_reader(&self) -> std::sync::MutexGuard<'_, Connection> {
        if self.readers.is_empty() {
            return self.lock_writer();
        }
        let i = self.next_reader.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        self.readers[i].lock().unwrap_or_else(|p| p.into_inner())
    }

    fn migrate(&self) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        // ONE transaction over the drop, the recreate, and the version stamp — a crash between them
        // must not leave a half-initialised DB the re-run can't repair. BEGIN IMMEDIATE (not
        // DEFERRED): see the type-level doc for why every write transaction in this file uses it.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        // The version is read INSIDE the write transaction, never before it: every destructive or
        // one-time step below is gated on it, and a value read before BEGIN IMMEDIATE is stale the
        // moment another process opening the same file commits its own migration while this one
        // waits for the lock. Read before the lock, a second first-open of an un-migrated file
        // would take the pre-v5 drop path against the tables the first open just created.
        let version: i64 = tx
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .store()?;
        // A file stamped by a LATER build is refused, not restamped: running this build's schema
        // pass over it and stamping it back down to `SCHEMA_VERSION` would make the newer build
        // re-run its own version-gated steps against data they already migrated. The transaction
        // is dropped (rolled back) unwritten.
        if version > SCHEMA_VERSION {
            return Err(RecordStoreError(format!(
                "sqlite: database schema v{version} is newer than this build (v{SCHEMA_VERSION}); \
                 refusing to open"
            )));
        }
        // Gated on the actual pre-v5 boundary (`< 5`), NOT on `SCHEMA_VERSION` (which moves every
        // bump): every bump up to and including v5 was destructive by design (1.5.0 was
        // unreleased, so a pre-v5 dev database is simply wiped and recreated). v6+ are ADDITIVE,
        // non-destructive migrations (see the `version < 6` backfill just below) — they must
        // never fall into this drop-and-recreate path, even though `keys`/`store_meta` are named
        // in the drop list below (the list has to cover every table this schema has EVER used,
        // including its OWN current names, since a version<5 db could theoretically already carry
        // a same-named-but-incompatibly-shaped table from an even older generation — see
        // `migrate_drops_and_recreates_a_genuinely_older_schema`). Gating on `< SCHEMA_VERSION`
        // instead of `< 5` here was tried first and is WRONG: it makes a real v5 database's own
        // (correctly-shaped, live) `keys`/`store_meta` tables register as "has_legacy" on the
        // v5->v6 crossing and wipes them — confirmed by hand, reverting this gate to
        // `< SCHEMA_VERSION` reproduces exactly that data loss in
        // `migrate_v5_to_v6_backfills_billable_requests_without_wiping_data`.
        if version < 5 {
            let has_legacy: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name IN \
                     ('usage_counters','virtual_keys','aws_credentials','usage_ledger','keys','store_meta'))",
                    [],
                    |r| r.get(0),
                )
                .store()?;
            if has_legacy {
                tx.execute_batch(
                    "DROP TABLE IF EXISTS virtual_keys;
                     DROP TABLE IF EXISTS aws_credentials;
                     DROP TABLE IF EXISTS usage_counters;
                     DROP TABLE IF EXISTS usage_windows;
                     DROP TABLE IF EXISTS usage_ledger;
                     DROP TABLE IF EXISTS usage_metering;
                     DROP TABLE IF EXISTS audit_log;
                     DROP TABLE IF EXISTS denylist;
                     DROP TRIGGER IF EXISTS keys_guard_hard_delete;
                     DROP TRIGGER IF EXISTS keys_cascade_credentials;
                     DROP TRIGGER IF EXISTS audit_log_no_update;
                     DROP TRIGGER IF EXISTS audit_log_no_delete;
                     DROP TABLE IF EXISTS credentials;
                     DROP TABLE IF EXISTS keys;
                     DROP TABLE IF EXISTS store_meta;
                     DROP TABLE IF EXISTS store_revision;",
                )
                .store()?;
            }
        }
        // v10: `usage_metering` gains `priced_from_ms` in its PRIMARY KEY. Keyed on the column's
        // absence rather than on `version` so a re-run after any partial state is a no-op, and run
        // BEFORE `SCHEMA` so the `CREATE TABLE IF NOT EXISTS` below finds the rebuilt table and the
        // index/trigger `SCHEMA` (re)creates land on it.
        if table_exists(&tx, "usage_metering")?
            && !column_exists(&tx, "usage_metering", "priced_from_ms")?
        {
            rebuild_usage_metering_for_v10(&tx)?;
        }
        tx.execute_batch(SCHEMA).store()?;
        tx.execute(
            "INSERT INTO store_revision (id, revision) VALUES (0, 0) ON CONFLICT(id) DO NOTHING",
            [],
        )
        .store()?;
        // v5 -> v6, ONE-TIME durable backfill (never repeated, gated on the version crossing —
        // see governance::state::hydrate_budgets in busbar core for the bug this closes). A
        // pre-v6 row can have `billable_requests=0` for either of two reasons that look
        // IDENTICAL in the data: (a) it was written by v5 code that never split billable_requests
        // out from requests (a real legacy gap — v5 added the column but not every code path
        // populated it correctly from day one), or (b) every request in that window was
        // legitimately refunded (refund_bucket decrements billable_requests but never requests,
        // by design). Those two cases are NOT distinguishable from the stored values alone, which
        // is exactly why this must NOT be a per-boot heuristic (hydrate_budgets no longer applies
        // one after this migration ships) — it is safe to run this AS A BLANKET, UNCONDITIONAL
        // backfill exactly once, right now, only because 1.5.0 has never shipped to a real
        // customer: there is no genuine "currently, legitimately refunded to zero" row in
        // existence yet that this could incorrectly re-bill. Re-running this same UPDATE
        // unconditionally at ANY later point (once real refund data exists) would reintroduce the
        // exact bug it closes — that is why it is gated on `version < 6`, never repeated.
        if version < 6 {
            tx.execute(
                "UPDATE usage_windows SET billable_requests = requests \
                 WHERE model = '' AND billable_requests = 0 AND requests > 0",
                [],
            )
            .store()?;
            tx.execute(
                "UPDATE usage_metering SET billable_requests = requests \
                 WHERE billable_requests = 0 AND requests > 0",
                [],
            )
            .store()?;
        }
        // v10: the additive `keys` columns, then the legacy typed plane tables into the neutral
        // ones. Both are idempotent by construction (column/table existence), so they need no
        // version gate and a fresh database passes straight through them.
        add_v10_key_columns(&tx)?;
        migrate_legacy_plane_tables(&tx)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    /// Bump the store-global revision counter. MUST be called inside the same `BEGIN IMMEDIATE`
    /// transaction as the mutation it stamps — `RETURNING` hands the new value back with no second
    /// round trip, and single-writer + IMMEDIATE makes this gapless-under-commit-order for free (no
    /// sequence, no advisory lock).
    fn bump_revision(tx: &rusqlite::Transaction) -> RecordStoreResult<i64> {
        tx.query_row(
            "UPDATE store_revision SET revision = revision + 1 WHERE id = 0 RETURNING revision",
            [],
            |r| r.get(0),
        )
        .store()
    }
}

/// The four RESERVED usage units, in the order of the `usage_windows` token columns that hold them.
/// Every other unit name is an OPEN unit and lives in `usage_window_units`.
const RESERVED_COLUMNS: [&str; 4] = [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE];

/// The OPEN (non-reserved) entries of a name-keyed usage map — the ones the token columns do not hold.
fn open_units<V>(
    units: &std::collections::BTreeMap<String, V>,
) -> impl Iterator<Item = (&String, &V)> {
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

/// Rebuild a pre-v10 `usage_metering` with `priced_from_ms` in its primary key — the one change in
/// this migration SQLite cannot make in place. Every row is copied at `priced_from_ms = 0`, the
/// OPENING card's instant, which is exactly how the contract says an undated row reads (see
/// `MeteringDelta::priced_from_ms`); no count is touched.
///
/// The column list below must stay identical to `usage_metering` in [`SCHEMA`];
/// `migrated_tables_match_a_fresh_schema` holds the two together.
///
/// `keys_guard_hard_delete` names `usage_metering` in its body, and SQLite's `ALTER TABLE ... RENAME`
/// re-parses every trigger in the schema and refuses to proceed while one references a table that
/// does not exist — which is the state between the DROP and the RENAME. So the trigger is dropped
/// first; `SCHEMA`, executed immediately after this, recreates it against the rebuilt table. All of
/// it runs inside `migrate`'s single transaction: a crash anywhere leaves the v9 table intact.
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

/// The v10 `keys` columns. Nullable `ADD COLUMN`s, so a pre-v10 row reads back exactly as it did:
/// no non-pool scope grant (the pool-only column was the whole grant), and `None` for the three 1.6.0
/// attribution fields, which is what the contract says a key minted before them carries.
fn add_v10_key_columns(tx: &rusqlite::Connection) -> RecordStoreResult<()> {
    const COLUMNS: [(&str, &str); 4] = [
        // The NON-POOL scope grants, `{kind: [value, ...]}`. NULL when the key grants no scope of any
        // kind but `pool` — including every pre-v10 row, whose `allowed_pools` column was the whole
        // grant. See `scopes_to_storage` for why pools keep their own column.
        (
            "scope_grants",
            "TEXT CONSTRAINT keys_scope_grants_json CHECK (scope_grants IS NULL OR \
             (json_valid(scope_grants) AND json_type(scope_grants)='object'))",
        ),
        ("idp_subject", "TEXT"),
        ("binding_mode", "TEXT"),
        ("minted_by", "TEXT"),
    ];
    for (name, decl) in COLUMNS {
        if !column_exists(tx, "keys", name)? {
            tx.execute_batch(&format!("ALTER TABLE keys ADD COLUMN {name} {decl}"))
                .store()?;
        }
    }
    Ok(())
}

/// The legacy (v8/v9) typed plane rows, re-encoded as the opaque bodies the 1.6.0 planes decode. These
/// structs are the ONLY place this crate names a plane's row shape, and they exist for one reason: to
/// carry a pre-v10 database's rows across the crossing. The field names and order are the plane
/// crates' own (`busbar-a2a`'s `TaskRow`/`TaskEventRow`, `busbar-mcp`'s `McpDemotionRow`), which
/// serialize with `serde_json` exactly as these do.
mod legacy {
    #[derive(serde::Serialize)]
    pub(super) struct TaskBody {
        pub task_id: String,
        pub context_id: String,
        pub principal: String,
        pub direction: String,
        pub state: String,
        pub agent_id: String,
        pub artifact_cursor: u64,
        pub push_callback: String,
        pub created_at: u64,
        pub updated_at: u64,
    }

    /// No `digest_version`: a row persisted before that field existed carries none, and the plane
    /// reads its absence as the framing those rows were sealed under. Writing one here would claim a
    /// framing the stored `hash` was never computed with.
    #[derive(serde::Serialize)]
    pub(super) struct TaskEventBody {
        pub task_id: String,
        pub seq: u64,
        pub ts: u64,
        pub kind: String,
        pub context_id: String,
        pub principal: String,
        pub agent_id: String,
        pub state: String,
        pub request_id: String,
        pub prev_hash: String,
        pub hash: String,
    }

    #[derive(serde::Serialize)]
    pub(super) struct DemotionBody {
        pub server: String,
        pub reason: String,
        pub recorded_at: u64,
    }
}

/// Copy the v8/v9 typed plane tables into `plane_records`/`plane_tokens`, then drop them — all inside
/// `migrate`'s transaction, so a crash leaves the typed tables untouched and the next open re-runs
/// this. Each table is handled only if it exists, which is what makes this a no-op on a fresh or a
/// v6 database and on a second open.
///
/// `ON CONFLICT DO NOTHING` on every insert: a neutral row that is already there is newer than any
/// legacy row could be, and is never overwritten by one.
///
/// `mcp_calls` is deliberately NOT migrated, and NOT dropped. The 1.6.0 `call` body is a framed
/// digest stream the engine seals itself; a backend re-encoding a typed row into it would be forging
/// the chain the engine verifies, and busbar ships no `call` migration either. The rows stay where
/// they are, unread, so no evidence is destroyed by an upgrade.
fn migrate_legacy_plane_tables(tx: &rusqlite::Connection) -> RecordStoreResult<()> {
    let insert_record = |kind: &str,
                         identity: &str,
                         seq: i64,
                         id: &str,
                         parent: Option<&str>,
                         ts: i64,
                         terminal: bool,
                         body: Vec<u8>|
     -> RecordStoreResult<()> {
        tx.execute(
            "INSERT INTO plane_records (kind, identity, seq, id, parent, ts, disposition, body) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(kind, identity, seq) DO NOTHING",
            params![
                kind,
                identity,
                seq,
                id,
                parent,
                ts,
                if terminal { "terminal" } else { "active" },
                body
            ],
        )
        .store()?;
        Ok(())
    };
    let u = |v: i64| v.max(0) as u64;

    if table_exists(tx, "task_events")? {
        let mut stmt = tx
            .prepare(
                "SELECT task_id, seq, ts, kind, context_id, principal, agent_id, state, request_id, \
                 prev_hash, hash FROM task_events",
            )
            .store()?;
        let rows = stmt
            .query_map([], |r| {
                Ok(legacy::TaskEventBody {
                    task_id: r.get(0)?,
                    seq: u(r.get(1)?),
                    ts: u(r.get(2)?),
                    kind: r.get(3)?,
                    context_id: r.get(4)?,
                    principal: r.get(5)?,
                    agent_id: r.get(6)?,
                    state: r.get(7)?,
                    request_id: r.get(8)?,
                    prev_hash: r.get(9)?,
                    hash: r.get(10)?,
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        drop(stmt);
        for e in rows {
            insert_record(
                "task_event",
                &e.task_id,
                e.seq as i64,
                &e.task_id,
                Some(&e.task_id),
                e.ts as i64,
                false,
                encode(&e)?,
            )?;
        }
        tx.execute_batch("DROP TABLE task_events").store()?;
    }

    if table_exists(tx, "tasks")? {
        let mut stmt = tx
            .prepare(
                "SELECT task_id, context_id, principal, direction, state, agent_id, \
                 artifact_cursor, push_callback, created_at, updated_at FROM tasks",
            )
            .store()?;
        let rows = stmt
            .query_map([], |r| {
                Ok(legacy::TaskBody {
                    task_id: r.get(0)?,
                    context_id: r.get(1)?,
                    principal: r.get(2)?,
                    direction: r.get(3)?,
                    state: r.get(4)?,
                    agent_id: r.get(5)?,
                    artifact_cursor: u(r.get(6)?),
                    push_callback: r.get(7)?,
                    created_at: u(r.get(8)?),
                    updated_at: u(r.get(9)?),
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        drop(stmt);
        for t in rows {
            let terminal = TERMINAL_TASK_STATES.contains(&t.state.as_str());
            insert_record(
                "task",
                &t.task_id,
                0,
                &t.task_id,
                None,
                t.updated_at as i64,
                terminal,
                encode(&t)?,
            )?;
        }
        // Takes the `tasks_cascade_events` trigger with it; the cascade now lives in
        // `purge_plane_records_before`.
        tx.execute_batch("DROP TABLE tasks").store()?;
    }

    if table_exists(tx, "mcp_demotions")? {
        let mut stmt = tx
            .prepare("SELECT server, reason, recorded_at FROM mcp_demotions")
            .store()?;
        let rows = stmt
            .query_map([], |r| {
                Ok(legacy::DemotionBody {
                    server: r.get(0)?,
                    reason: r.get(1)?,
                    recorded_at: u(r.get(2)?),
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        drop(stmt);
        for d in rows {
            insert_record(
                "demotion",
                &d.server,
                0,
                &d.server,
                None,
                d.recorded_at as i64,
                false,
                encode(&d)?,
            )?;
        }
        tx.execute_batch("DROP TABLE mcp_demotions").store()?;
    }

    if table_exists(tx, "spent_ask_states")? {
        // The 1.6.0 kernel redeems a confirm-once grant under the token kind `ask` (its
        // `KIND_ASK`), so a spent one must be filed under that kind to stay spent. `approval` is
        // the MCP record-schema id, not a token kind: filed there, the spent nonce is never
        // consulted, and the upgrade hands every unexpired spent approval back for a second use.
        tx.execute_batch(
            "INSERT INTO plane_tokens (kind, token, expires_at) \
               SELECT 'ask', nonce, expires_at FROM spent_ask_states WHERE true \
               ON CONFLICT(kind, token) DO NOTHING;
             DROP TABLE spent_ask_states;",
        )
        .store()?;
    }
    Ok(())
}

/// `serde_json`-encode one legacy row into the opaque body the plane decodes.
fn encode<T: serde::Serialize>(row: &T) -> RecordStoreResult<Vec<u8>> {
    serde_json::to_vec(row)
        .map_err(|e| RecordStoreError(format!("v10 migration: encode a legacy plane row: {e}")))
}

// `allowed_scopes` storage. The in-memory grant is `Option<Vec<ScopeRef>>`; on disk it is split by
// kind exactly the way the contract's own wire shape splits it:
// - `allowed_pools` holds the `pool` values as a JSON array of bare strings. NULL = the grant was
//   OMITTED at mint = every scope of every kind; a JSON array (including '[]') = an explicit,
//   exhaustive grant. This column's shape is unchanged since v5, so a pre-v10 row means what it
//   always meant (C6: None vs Some([]) must never collapse into each other).
// - `scope_grants` (v10) holds every OTHER kind as `{kind: [value, ...]}`, NULL when there is none.
//   Before it existed, a non-pool grant written here had its kind thrown away and came back as a POOL
//   grant — a lost MCP grant and a pool-access widening at once.
// An explicit grant always writes `allowed_pools` (possibly '[]'), so `Some([mcp_server x])` never
// reads back as the omitted-grant wildcard.
type ScopeColumns = (Option<String>, Option<String>);

fn scopes_to_storage(scopes: &Option<Vec<ScopeRef>>) -> ScopeColumns {
    let Some(list) = scopes else {
        return (None, None);
    };
    let mut pools: Vec<&str> = Vec::new();
    let mut other: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for s in list {
        if s.kind == "pool" {
            pools.push(&s.value);
        } else {
            other.entry(&s.kind).or_default().push(&s.value);
        }
    }
    let pools = serde_json::to_string(&pools).unwrap_or_else(|_| "[]".to_string());
    let other = (!other.is_empty()).then(|| serde_json::to_string(&other).unwrap_or_default());
    (Some(pools), other)
}

// A malformed value (reachable only by an out-of-band edit of the file) reads as the most restrictive
// grant, never a silent widen: an unparseable `allowed_pools` is the empty set, and an unparseable
// `scope_grants` adds nothing.
fn scopes_from_storage(pools: Option<String>, other: Option<String>) -> Option<Vec<ScopeRef>> {
    let other: std::collections::BTreeMap<String, Vec<String>> = other
        .as_deref()
        .map(|o| serde_json::from_str(o.trim()).unwrap_or_default())
        .unwrap_or_default();
    if pools.is_none() && other.is_empty() {
        return None;
    }
    let mut list: Vec<ScopeRef> = pools
        .map(|p| serde_json::from_str::<Vec<String>>(p.trim()).unwrap_or_default())
        .unwrap_or_default()
        .into_iter()
        .map(ScopeRef::pool)
        .collect();
    for (kind, values) in other {
        // The key crosses back to the engine as JSON, and the contract serializes a non-pool kind
        // only if it is registered in THIS process. The engine registers every installed plane's kinds
        // in its own process at boot; a plugin process never sees that call. Every kind stored here
        // came in on a key the engine itself serialized, i.e. a kind the engine had registered, so
        // registering it on the way back out is restating the engine's own registration, never
        // widening it.
        busbar_contract::records::register_scope_kind(&kind);
        list.extend(values.into_iter().map(|value| ScopeRef {
            kind: kind.clone(),
            value,
        }));
    }
    Some(list)
}
fn labels_to_storage(labels: &std::collections::BTreeMap<String, String>) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_string())
}
fn labels_from_storage(stored: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(stored).unwrap_or_default()
}

fn row_to_key(r: &rusqlite::Row) -> rusqlite::Result<VirtualKey> {
    Ok(VirtualKey {
        id: r.get(0)?,
        generation_hash: r.get(1)?,
        name: r.get(2)?,
        allowed_scopes: scopes_from_storage(r.get(3)?, r.get(11)?),
        enabled: r.get::<_, i64>(4)? != 0,
        created_at: r.get::<_, i64>(5)? as u64,
        group: r.get(6)?,
        labels: labels_from_storage(&r.get::<_, String>(7)?),
        expires_at: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        deleted_at: r.get::<_, Option<i64>>(9)?.map(|v| v as u64),
        revision: r.get::<_, i64>(10)?.max(0) as u64,
        idp_subject: r.get(12)?,
        binding_mode: r.get(13)?,
        minted_by: r.get(14)?,
    })
}

const KEY_COLS: &str = "id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,\
     expires_at,deleted_at,revision,scope_grants,idp_subject,binding_mode,minted_by";

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
        revision: r.get::<_, i64>(11)?.max(0) as u64,
    })
}
const CRED_META_COLS: &str =
    "id,key_id,kind,slot,public_id,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision";
const CRED_SECRET_COLS: &str =
    "id,key_id,kind,slot,public_id,secret,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision";

fn row_to_cred_secret(r: &rusqlite::Row) -> rusqlite::Result<CredentialSecret> {
    Ok(CredentialSecret {
        meta: CredentialMeta {
            id: r.get(0)?,
            key_id: r.get(1)?,
            kind: r.get(2)?,
            slot: r.get::<_, i64>(3)? as u8,
            public_id: r.get(4)?,
            secret_form: secret_form_from_str(&r.get::<_, String>(6)?),
            created_at: r.get::<_, i64>(7)? as u64,
            updated_at: r.get::<_, i64>(8)? as u64,
            expires_at: r.get::<_, Option<i64>>(9)?.map(|v| v as u64),
            revoked_at: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
            revoke_reason: r.get(11)?,
            revision: r.get::<_, i64>(12)?.max(0) as u64,
        },
        secret: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
    })
}

fn put_key_inner(
    conn: &rusqlite::Connection,
    key: &VirtualKey,
    revision: i64,
) -> RecordStoreResult<()> {
    // `?6` (created_at) seeds `updated_at` on a fresh INSERT, where created_at == updated_at is
    // correct. The ON CONFLICT branch must NOT reuse `?6` there -- every other mutation path in
    // this file (delete_key, scrub_key, revoke_credential) stamps updated_at to the actual
    // mutation time (`now_secs()`), and put_key's UPDATE branch needs the same: reusing created_at
    // would silently freeze `keys.updated_at` at the row's original creation time forever, even
    // though this column has no Rust-side reader (KEY_COLS omits it) and exists purely for direct
    // SQL/operator inspection of "when did this key last change".
    // The `WHERE` on the conflict branch is the TOMBSTONE PRECONDITION (see `Store::put_key`): a
    // live-shaped write (`excluded.deleted_at IS NULL`) must not overwrite a tombstoned row, since
    // that reissues an id the contract says is never reissued and revives every token minted before
    // the delete. Expressed in the statement rather than as a SELECT-then-INSERT so the test and the
    // write are one atomic operation — a `delete_key` committing between a separate check and this
    // INSERT would slip straight through, which is exactly how the caller-side checks in core fail.
    // A write that CARRIES a tombstone is unaffected and still applies.
    //
    // When the guard bites, the conflict branch updates nothing and `execute` reports 0 rows, which
    // is the only signal available here that it fired — hence the row-count check below rather than
    // a bare `?`.
    let (allowed_pools, scope_grants) = scopes_to_storage(&key.allowed_scopes);
    let affected = conn.execute(
        "INSERT INTO keys (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,updated_at,revision,
                           scope_grants,idp_subject,binding_mode,minted_by)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?6,?11,?13,?14,?15,?16)
         ON CONFLICT(id) DO UPDATE SET
            generation_hash=excluded.generation_hash, name=excluded.name, allowed_pools=excluded.allowed_pools,
            enabled=excluded.enabled, key_group=excluded.key_group, labels=excluded.labels,
            expires_at=excluded.expires_at, deleted_at=excluded.deleted_at, updated_at=?12, revision=?11,
            scope_grants=excluded.scope_grants, idp_subject=excluded.idp_subject,
            binding_mode=excluded.binding_mode, minted_by=excluded.minted_by
         WHERE excluded.deleted_at IS NOT NULL OR keys.deleted_at IS NULL",
        params![
            key.id,
            key.generation_hash,
            key.name,
            allowed_pools,
            key.enabled as i64,
            key.created_at as i64,
            key.group,
            labels_to_storage(&key.labels),
            key.expires_at.map(|v| v as i64),
            key.deleted_at.map(|v| v as i64),
            revision,
            now_secs(),
            scope_grants,
            key.idp_subject,
            key.binding_mode,
            key.minted_by,
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

/// [`RecordStore::add_usage`]'s writes, inside the caller's transaction (the trait method's own, or
/// a store v3 slot's, where the `op_id` record shares it).
fn add_usage_in(
    tx: &Connection,
    bucket_id: &str,
    window_start: u64,
    delta: &UsageDelta,
) -> RecordStoreResult<()> {
    // Same sentinel-row discipline as put_usage: requests/billable_requests accumulate
    // unconditionally on model='', regardless of whether this particular delta touched any
    // models (a rejected/errored request can add to `requests` while reaching zero models).
    // `prepare_cached`, not `execute`/`prepare`: this fires once per admitted request (the
    // hottest write path in the crate), and these statement texts never vary — caching
    // avoids paying SQLite's parse+plan cost on every single request.
    tx.prepare_cached(
        "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests)
         VALUES (?1,?2,'',MAX(0,?3),MAX(0,?4))
         ON CONFLICT(window_start, bucket_id, model) DO UPDATE SET
            requests = MAX(0, requests + ?3), billable_requests = MAX(0, billable_requests + ?4)",
    )
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
        tx.prepare_cached(
            "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests,
                 tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
             VALUES (?1,?2,?3,0,0,MAX(0,?4),MAX(0,?5),MAX(0,?6),MAX(0,?7))
             ON CONFLICT(window_start, bucket_id, model) DO UPDATE SET
                tokens_input       = MAX(0, tokens_input + ?4),
                tokens_output      = MAX(0, tokens_output + ?5),
                tokens_cache_read  = MAX(0, tokens_cache_read + ?6),
                tokens_cache_write = MAX(0, tokens_cache_write + ?7)",
        )
        .store()?
        .execute(params![
            window_start as i64, bucket_id, m.model,
            d(UNIT_INPUT), d(UNIT_OUTPUT), d(UNIT_CACHE_READ), d(UNIT_CACHE_WRITE),
        ])
        .store()?;
        // Every open unit accumulates the same way the reserved columns do: one atomic
        // UPSERT per unit, floored at 0 (a refund never drives a durable counter negative).
        for (unit, d) in open_units(&m.usage_units) {
            tx.prepare_cached(
                "INSERT INTO usage_window_units (window_start, bucket_id, model, unit, count)
                 VALUES (?1,?2,?3,?4,MAX(0,?5))
                 ON CONFLICT(window_start, bucket_id, model, unit) DO UPDATE SET
                    count = MAX(0, count + ?5)",
            )
            .store()?
            .execute(params![window_start as i64, bucket_id, m.model, unit, d])
            .store()?;
        }
    }
    Ok(())
}

/// [`RecordStore::add_metering`]'s writes, inside the caller's transaction.
fn add_metering_in(tx: &Connection, d: &MeteringDelta) -> RecordStoreResult<()> {
    let clamp = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    // Refused rather than clamped: `priced_from_ms` is part of the cell's KEY, so a clamped value
    // would silently merge this accrual into a different card's cell.
    let priced_from = as_storable_i64("add_metering", "priced_from_ms", d.priced_from_ms)?;
    tx.execute(
        "INSERT INTO usage_metering (bucket, key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version,
             tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, requests, billable_requests)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(bucket, key_id, provider, model, priced_from_ms) DO UPDATE SET
             tokens_input       = tokens_input + excluded.tokens_input,
             tokens_output      = tokens_output + excluded.tokens_output,
             tokens_cache_read  = tokens_cache_read + excluded.tokens_cache_read,
             tokens_cache_write = tokens_cache_write + excluded.tokens_cache_write,
             requests           = requests + excluded.requests,
             billable_requests  = billable_requests + excluded.billable_requests",
        params![
            d.bucket as i64,
            d.key_id,
            d.provider,
            d.model,
            priced_from,
            d.key_group_at_use,
            d.pricing_version,
            clamp(d.tokens_input),
            clamp(d.tokens_output),
            clamp(d.tokens_cache_read),
            clamp(d.tokens_cache_write),
            clamp(d.requests),
            clamp(d.billable_requests),
        ],
    )
    .store()?;
    // Every ledgered class the token columns do not hold, additive like every counter here,
    // in the same transaction as the cell it belongs to.
    for (unit, count) in &d.usage_units {
        tx.execute(
            "INSERT INTO usage_metering_units (bucket, key_id, provider, model, priced_from_ms, unit, count)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(bucket, key_id, provider, model, priced_from_ms, unit) DO UPDATE SET
                 count = count + excluded.count",
            params![
                d.bucket as i64,
                d.key_id,
                d.provider,
                d.model,
                priced_from,
                unit,
                clamp(*count),
            ],
        )
        .store()?;
    }
    Ok(())
}

/// [`RecordStore::append_audit`]'s write and fork check, inside the caller's transaction.
fn append_audit_in(tx: &Connection, entry: &AuditRecord) -> RecordStoreResult<()> {
    // A `seq`/`ts` past `i64::MAX` cannot be stored faithfully: `as i64` wraps it negative and
    // `row_to_audit` clamps the negative back to 0 on read, so the record read back is NOT the
    // record written. An identical retry then compares unequal and is reported as "the audit
    // chain has forked" — naming the same action on both sides, which is the worst possible page
    // to hand an operator. Rejected outright. Comparing the round-tripped form instead would
    // trade that false alarm for silent loss, which is the wrong half to give up. Same guard as
    // store-postgres, where `clamp` produces the same hazard by a different route.
    if entry.seq > i64::MAX as u64 || entry.ts > i64::MAX as u64 {
        return Err(RecordStoreError(format!(
            "append_audit: seq {} / ts {} exceeds the storable range (i64::MAX); refusing to \
             store a record that would not read back as itself",
            entry.seq, entry.ts
        )));
    }
    let affected = tx
        .execute(
            "INSERT INTO audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(seq) DO NOTHING",
            params![
                entry.seq as i64,
                entry.ts as i64,
                entry.action,
                entry.resource,
                entry.outcome,
                entry.principal,
                entry.prev_hash,
                entry.hash,
            ],
        )
        .store()?;
    // DO NOTHING keeps the stored record, which is right for ONE of the two ways a `seq`
    // collides and wrong for the other. Compare them, in the same transaction that just
    // lost the race, and let the difference decide (see the trait contract):
    //   identical  -> the write-through retrying after a timeout. Common, benign, Ok.
    //   different  -> two records claiming one chain position: a forked or tampered log,
    //                 and the single most important thing an audit store can report.
    // Dropping the second case silently is what this used to do.
    if affected == 0 {
        let stored = tx
            .query_row(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash \
                 FROM audit_log WHERE seq=?1",
                params![entry.seq as i64],
                row_to_audit,
            )
            .store()?;
        if &stored != entry {
            return Err(RecordStoreError(format!(
                "append_audit: seq {} already holds a DIFFERENT record; the audit chain \
                 has forked (stored action '{}', incoming '{}')",
                entry.seq, stored.action, entry.action
            )));
        }
    }
    Ok(())
}

/// [`RecordStore::append_plane_record`]'s occupancy check and insert, inside the caller's
/// transaction.
fn append_plane_record_in(tx: &Connection, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
    let row = PlaneRow::of(record, "append_plane_record")?;
    let existing: Option<StoredPlaneRow> = tx
        .query_row(
            "SELECT id, parent, ts, disposition, body FROM plane_records \
             WHERE kind=?1 AND identity=?2 AND seq=?3",
            params![record.kind, row.identity, row.seq],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .store()?;
    if let Some((id, parent, ts, disposition, body)) = existing {
        // IDENTICAL is the at-least-once write-through retrying after a timeout, and is
        // success. DIFFERENT is two records claiming one chain position — a forked or
        // tampered log — and is an error: overwriting would destroy exactly the case worth
        // reporting, and silently keeping the first would drop a genuinely different record
        // on the floor. The same settlement `append_audit` makes.
        if id == record.id
            && parent.as_deref() == record.parent
            && ts == row.ts
            && disposition == row.disposition
            && body == record.body
        {
            return Ok(());
        }
        // Names the position and nothing else — it must not echo stored (or caller)
        // content back to whoever provoked it.
        return Err(RecordStoreError(format!(
            "append_plane_record: kind '{}' already holds a different record at sequence {} \
             of this chain; the chain has forked",
            record.kind, record.seq
        )));
    }
    tx.execute(
        "INSERT INTO plane_records (kind, identity, seq, id, parent, ts, disposition, body) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        row.params(&record),
    )
    .store()?;
    Ok(())
}

impl RecordStore for SqliteStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        let rev = Self::bump_revision(&tx)?;
        put_key_inner(&tx, key, rev)?;
        tx.commit().store()?;
        Ok(())
    }

    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        let conn = self.lock_reader();
        conn.query_row(
            &format!("SELECT {KEY_COLS} FROM keys WHERE id=?1"),
            params![id],
            row_to_key,
        )
        .optional()
        .store()
    }

    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(&format!("SELECT {KEY_COLS} FROM keys ORDER BY created_at"))
            .store()?;
        let rows = stmt.query_map([], row_to_key).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {KEY_COLS} FROM keys WHERE revision > ?1 ORDER BY revision"
            ))
            .store()?;
        let rows = stmt.query_map(params![since as i64], row_to_key).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
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
                // Idempotent: deleting an already-tombstoned key is a no-op, per the trait contract.
                return Ok(());
            }
            let rev = Self::bump_revision(&tx)?;
            let now = now_secs();
            // Explicit DELETE, not relying solely on the FK CASCADE: the ON DELETE CASCADE stays
            // declared for out-of-band deletes, but this statement is the one that actually runs
            // under normal operation and doesn't depend on `PRAGMA foreign_keys` being correctly
            // set by every caller.
            tx.execute("DELETE FROM credentials WHERE key_id=?1", params![id])
                .store()?;
            // enabled=0 and deleted_at=now MUST be set in the SAME statement — `keys_tombstone_off`
            // would reject a transient enabled=1,deleted_at=now state if these were split across two
            // UPDATEs, since SQLite has no deferred CHECK constraints.
            let changed = tx
                .execute(
                    "UPDATE keys SET enabled=0, deleted_at=?2, updated_at=?2, revision=?3 WHERE id=?1",
                    params![id, now, rev],
                )
                .store()?;
            if changed == 0 {
                return Err(RecordStoreError(format!("delete_key: no such key {id}")));
            }
            tx.commit().store()?;
            Ok(())
        })
    }

    fn scrub_key(&self, id: &str) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        let deleted_at: Option<i64> = tx
            .query_row(
                "SELECT deleted_at FROM keys WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .optional()
            .store()?
            .flatten();
        if deleted_at.is_none() {
            return Err(RecordStoreError(format!(
                "scrub_key: key {id} is unknown or not yet tombstoned — delete_key it first"
            )));
        }
        let rev = Self::bump_revision(&tx)?;
        tx.execute(
            "UPDATE keys SET name='', labels='{}', updated_at=?2, revision=?3 WHERE id=?1",
            params![id, now_secs(), rev],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            put_credential_inner(&tx, secret, Self::bump_revision(&tx)?)?;
            tx.commit().store()?;
            Ok(())
        })
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            let rev = Self::bump_revision(&tx)?;
            put_key_inner(&tx, key, rev)?;
            put_credential_inner(&tx, secret, rev)?;
            tx.commit().store()?;
            Ok(())
        })
    }

    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {CRED_META_COLS} FROM credentials WHERE key_id=?1 ORDER BY kind, slot"
            ))
            .store()?;
        let rows = stmt.query_map(params![key_id], row_to_cred_meta).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        let conn = self.lock_reader();
        conn.query_row(
            &format!("SELECT {CRED_SECRET_COLS} FROM credentials WHERE kind=?1 AND public_id=?2"),
            params![kind, public_id],
            row_to_cred_secret,
        )
        .optional()
        .store()
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            let rev = Self::bump_revision(&tx)?;
            // A 0 row count is AMBIGUOUS: it means either "already revoked" (idempotent, Ok) or
            // "no such id" (an error). The trait settles those as different outcomes precisely
            // because collapsing them lets an operator responding to a leak be told the credential
            // is dead when it is still live. So a 0 count is disambiguated with an EXISTS in the
            // SAME transaction — outside it, a concurrent insert could make the answer a lie.
            let affected = tx
                .execute(
                    "UPDATE credentials SET revoked_at=?2, revoke_reason=?3, updated_at=?2, revision=?4
                     WHERE id=?1 AND revoked_at IS NULL",
                    params![id, now_secs(), reason, rev],
                )
                .store()?;
            if affected == 0 {
                let exists: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=?1)",
                        params![id],
                        |r| r.get(0),
                    )
                    .store()?;
                if !exists {
                    return Err(RecordStoreError(format!(
                        "revoke_credential: unknown id '{id}'"
                    )));
                }
                // Else: the row exists and was already revoked. Idempotent, per the contract.
            }
            tx.commit().store()?;
            Ok(())
        })
    }

    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {CRED_SECRET_COLS} FROM credentials WHERE revision > ?1 ORDER BY revision"
            ))
            .store()?;
        let rows = stmt
            .query_map(params![since as i64], row_to_cred_secret)
            .store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        let conn = self.lock_reader();
        // requests/billable_requests live EXCLUSIVELY on the reserved model='' sentinel row (see
        // put_usage/add_usage) — never duplicated across per-model rows, so there is exactly one
        // source of truth regardless of how many put/add_usage calls with differing model sets
        // interleaved for this (window_start, bucket_id). A row that has never been written reads as
        // the empty ledger (0, 0).
        let (requests, billable_requests): (i64, i64) = conn
            .query_row(
                "SELECT requests, billable_requests FROM usage_windows WHERE window_start=?1 AND bucket_id=?2 AND model=''",
                params![window_start as i64, bucket_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .store()?
            .unwrap_or((0, 0));
        // model='' is the reserved sentinel carrying requests/billable_requests only — never a real
        // model row, and must not surface in the models list.
        let mut stmt = conn
            .prepare(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
                 FROM usage_windows WHERE window_start=?1 AND bucket_id=?2 AND model != '' ORDER BY model",
            )
            .store()?;
        let mut models = stmt
            .query_map(params![window_start as i64, bucket_id], |r| {
                let mut units = std::collections::BTreeMap::new();
                for (i, unit) in RESERVED_COLUMNS.iter().enumerate() {
                    let v = r.get::<_, i64>(i + 1)?.max(0) as u64;
                    // The reserved four share one map with every open unit now, and a column cannot
                    // tell "never counted" from "counted to zero" — so a zero reads as absent, which
                    // is how `ModelTokens` itself reads an absent key (`tier()` → 0).
                    if v != 0 {
                        units.insert(unit.to_string(), v);
                    }
                }
                Ok(ModelTokens {
                    model: r.get(0)?,
                    usage_units: units,
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        let mut stmt = conn
            .prepare(
                "SELECT model, unit, count FROM usage_window_units
                 WHERE window_start=?1 AND bucket_id=?2 ORDER BY model, unit",
            )
            .store()?;
        let opens = stmt
            .query_map(params![window_start as i64, bucket_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?.max(0) as u64,
                ))
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        for (model, unit, count) in opens {
            // Every open-unit row is written beside its model's row (put_usage/add_usage), so the
            // model is always already listed; the fallback only keeps an out-of-band edit readable.
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
            requests: requests.max(0) as u64,
            billable_requests: billable_requests.max(0) as u64,
            models,
        })
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        tx.execute(
            "DELETE FROM usage_windows WHERE window_start=?1 AND bucket_id=?2",
            params![window_start as i64, bucket_id],
        )
        .store()?;
        tx.execute(
            "DELETE FROM usage_window_units WHERE window_start=?1 AND bucket_id=?2",
            params![window_start as i64, bucket_id],
        )
        .store()?;
        let req = i64::try_from(ledger.requests).unwrap_or(i64::MAX);
        let bil = i64::try_from(ledger.billable_requests).unwrap_or(i64::MAX);
        // requests/billable_requests ALWAYS live on the model='' sentinel row, unconditionally — not
        // only when `ledger.models` is empty. Per-model rows carry token counts only (their own
        // requests/billable_requests columns default to 0 and are never read). This is what keeps
        // get_usage's counts correct regardless of how many put/add_usage calls with differing
        // model sets interleave for the same (window_start, bucket_id) — there is exactly one row
        // that is ever the source of truth for the counts, never a value duplicated (and therefore
        // possibly diverging) across N model rows.
        tx.execute(
            "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests) VALUES (?1,?2,'',?3,?4)",
            params![window_start as i64, bucket_id, req, bil],
        ).store()?;
        let clamp = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        for m in &ledger.models {
            tx.execute(
                "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (?1,?2,?3,0,0,?4,?5,?6,?7)",
                params![
                    window_start as i64, bucket_id, m.model,
                    clamp(m.tier(UNIT_INPUT)),
                    clamp(m.tier(UNIT_OUTPUT)),
                    clamp(m.tier(UNIT_CACHE_READ)),
                    clamp(m.tier(UNIT_CACHE_WRITE)),
                ],
            ).store()?;
            for (unit, count) in open_units(&m.usage_units) {
                tx.execute(
                    "INSERT INTO usage_window_units (window_start, bucket_id, model, unit, count)
                     VALUES (?1,?2,?3,?4,?5)",
                    params![window_start as i64, bucket_id, m.model, unit, clamp(*count)],
                )
                .store()?;
            }
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        add_usage_in(&tx, bucket_id, window_start, delta)?;
        tx.commit().store()?;
        Ok(())
    }

    fn purge_windows_before(&self, before: u64) -> RecordStoreResult<u64> {
        // Chunked: a single unchunked DELETE on the highest-churn table would transiently balloon
        // the WAL and monopolize the write lock. LIMIT on DELETE needs SQLITE_ENABLE_UPDATE_DELETE_LIMIT
        // (not in the default rusqlite bundled build) — use the subquery form instead.
        let mut total = 0u64;
        loop {
            let mut conn = self.lock_writer();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            // Count the WINDOWS this batch removes, not the rows. A window is stored as one
            // reserved `model = ''` sentinel row plus one row per model, so a row count is the
            // window count multiplied by that window's model cardinality. The contract is "returns
            // the number of windows purged", and a figure that moves with model cardinality cannot
            // be reconciled against the retention the caller asked for. A window is counted by its
            // SENTINEL row, which every window has exactly one of (`put_usage`/`add_usage` always
            // write it): a window whose rows straddle two batches is then counted once, in the
            // batch that deletes its sentinel, never once per batch. Read off the rows the DELETE
            // itself reports, so it matches exactly what this batch removes.
            let (changed, windows_in_batch) = {
                let mut stmt = tx
                    .prepare(
                        "DELETE FROM usage_windows WHERE (window_start, bucket_id, model) IN (
                            SELECT window_start, bucket_id, model FROM usage_windows
                            WHERE window_start < ?1 LIMIT 5000)
                         RETURNING model = ''",
                    )
                    .store()?;
                let sentinels = stmt
                    .query_map(params![before as i64], |r| r.get::<_, bool>(0))
                    .store()?
                    .collect::<Result<Vec<bool>, _>>()
                    .store()?;
                let windows = sentinels.iter().filter(|s| **s).count() as u64;
                (sentinels.len(), windows)
            };
            tx.commit().store()?;
            total += windows_in_batch;
            if changed < 5000 {
                break;
            }
        }
        // The same windows' open-unit rows, chunked the same way. Not counted: a window is counted
        // once, off its `usage_windows` rows above, however many units it carried.
        loop {
            let changed = self
                .lock_writer()
                .execute(
                    "DELETE FROM usage_window_units WHERE (window_start, bucket_id, model, unit) IN (
                        SELECT window_start, bucket_id, model, unit FROM usage_window_units
                        WHERE window_start < ?1 LIMIT 5000)",
                    params![before as i64],
                )
                .store()?;
            if changed < 5000 {
                break;
            }
        }
        Ok(total)
    }

    fn purge_metering_before(&self, bucket: &str) -> RecordStoreResult<u64> {
        let mut total = 0u64;
        loop {
            let mut conn = self.lock_writer();
            let changed = with_full_sync(&mut conn, |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .store()?;
                let changed = tx
                    .execute(
                        "DELETE FROM usage_metering WHERE (bucket, key_id, provider, model, priced_from_ms) IN (
                            SELECT bucket, key_id, provider, model, priced_from_ms FROM usage_metering
                            WHERE bucket = ?1 LIMIT 5000)",
                        params![bucket],
                    )
                    .store()?;
                tx.commit().store()?;
                Ok(changed)
            })?;
            total += changed as u64;
            if changed < 5000 {
                break;
            }
        }
        // The purged cells' open-unit rows go too; the count is the metering rows', as before.
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            conn.execute(
                "DELETE FROM usage_metering_units WHERE bucket = ?1",
                params![bucket],
            )
            .store()?;
            Ok(())
        })?;
        Ok(total)
    }

    fn add_metering(&self, d: &MeteringDelta) -> RecordStoreResult<()> {
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            add_metering_in(&tx, d)?;
            tx.commit().store()?;
            Ok(())
        })
    }

    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(
                "SELECT key_id, model, provider, tokens_input, tokens_output, tokens_cache_read,
                    tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version,
                    priced_from_ms
                 FROM usage_metering WHERE bucket = ?1",
            )
            .store()?;
        let mut rows = stmt
            .query_map(params![bucket.to_string()], |r| {
                let u = |v: i64| v.max(0) as u64;
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
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        let mut stmt = conn
            .prepare(
                "SELECT key_id, provider, model, priced_from_ms, unit, count
                 FROM usage_metering_units WHERE bucket = ?1",
            )
            .store()?;
        let units = stmt
            .query_map(params![bucket.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?.max(0) as u64,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?.max(0) as u64,
                ))
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        for (key_id, provider, model, priced_from_ms, unit, count) in units {
            if let Some(row) = rows.iter_mut().find(|m| {
                m.key_id == key_id
                    && m.provider == provider
                    && m.model == model
                    && m.priced_from_ms == priced_from_ms
            }) {
                row.usage_units.insert(unit, count);
            }
        }
        Ok(rows)
    }

    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        // FULL sync: the trait's contract for this method is that a hard crash loses ~0 entries,
        // which `synchronous=NORMAL` does not provide under WAL.
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            append_audit_in(&tx, entry)?;
            tx.commit().store()?;
            Ok(())
        })
    }

    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare("SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log ORDER BY seq")
            .store()?;
        let rows = stmt.query_map([], row_to_audit).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare("SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log ORDER BY seq DESC LIMIT ?1")
            .store()?;
        let mut rows = stmt
            .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], row_to_audit)
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        rows.reverse();
        Ok(rows)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        // FULL sync, like every other revocation path. This is a token revocation: the operator is
        // told the subject is denied, and under WAL with `synchronous=NORMAL` that committed
        // transaction can be lost to a power cut seconds later, so the token is valid again on
        // reboot with no error ever having been reported. `delete_key`, `revoke_credential`,
        // `put_credential`, `put_key_with_credential` and the metering flush all escalate; this one
        // and `append_audit` did not, against this file's own stated policy of covering
        // "mint/revoke/rotate/delete".
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            conn.execute(
                "INSERT INTO denylist (sub, reason, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(sub) DO UPDATE SET reason = excluded.reason",
                params![sub, reason, now_secs()],
            )
            .store()?;
            Ok(())
        })
    }

    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        let conn = self.lock_reader();
        let mut stmt = conn.prepare("SELECT sub FROM denylist").store()?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD VERBS (1.6.0) ─────────────────────────────────────
    //
    // One table, `plane_records`, for every kind. The store never decodes a `body`: identity,
    // ordering and retention read only the typed sidecar columns (`kind`, `id`, `parent`, `seq`,
    // `ts`, `disposition`). No kind is special-cased except where the contract makes the kind's own
    // retention rule part of the verb (`task`, below), so a kind a future plane declares is stored
    // and served exactly like the ones that exist today.

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let row = PlaneRow::of(record, "upsert_plane_record")?;
        // FULL sync: an upserted record is a task state transition, a demotion (a quarantine), a
        // push-callback capability — each acknowledged to a caller and each worthless if a power cut
        // a second later hands the previous state back.
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            // UPSERT BY (kind, identity, seq): a second write for one record replaces the row, never
            // appends a rival one beside it.
            conn.execute(
                "INSERT INTO plane_records (kind, identity, seq, id, parent, ts, disposition, body) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                 ON CONFLICT(kind, identity, seq) DO UPDATE SET \
                    id=excluded.id, parent=excluded.parent, ts=excluded.ts, \
                    disposition=excluded.disposition, body=excluded.body",
                row.params(&record),
            )
            .store()?;
            Ok(())
        })
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        // An upserted record lives at `(kind, id, 0)`. No caller-scoping filter, deliberately: an
        // authorization check living in the backend is one an unauthorized reader bypasses by
        // configuring a different backend, so the contract keeps it engine-side.
        let conn = self.lock_reader();
        conn.query_row(
            "SELECT body FROM plane_records WHERE kind=?1 AND identity=?2 AND seq=0",
            params![kind, id],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .store()
    }

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        // FULL sync: this is the tamper-evidence record of a transition or a call, and a chain with a
        // hole where a crash landed is a chain that fails to verify.
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            // IMMEDIATE, and the occupancy check shares the transaction with the insert: the two must
            // be one atomic step or a concurrent writer could land between them and turn a fork into
            // a silent accept.
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            append_plane_record_in(&tx, record)?;
            tx.commit().store()?;
            Ok(())
        })
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        // UNFILTERED beyond the selector, terminal rows included: the boot rehydrate wants the active
        // rows, the retention sweep the terminal ones and a scoped listing one principal's, and a
        // store that pre-filtered for any one of those would break the other two. Oldest-first by
        // `seq`, the order a chain verifier reads a parent's records in.
        let conn = self.lock_reader();
        let rows = match selector {
            PlaneSelector::All => {
                let mut stmt = conn
                    .prepare("SELECT body FROM plane_records WHERE kind=?1 ORDER BY seq, identity")
                    .store()?;
                let rows = stmt
                    .query_map([kind], |r| r.get::<_, Vec<u8>>(0))
                    .store()?
                    .collect::<Result<Vec<_>, _>>();
                rows
            }
            PlaneSelector::Parent(parent) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body FROM plane_records WHERE kind=?1 AND parent=?2 ORDER BY seq",
                    )
                    .store()?;
                let rows = stmt
                    .query_map(params![kind, parent], |r| r.get::<_, Vec<u8>>(0))
                    .store()?
                    .collect::<Result<Vec<_>, _>>();
                rows
            }
        };
        rows.store()
    }

    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        // The boot enumeration: a restart resumes a chain for a parent this process has never seen,
        // so every parent holding a record is named, exactly once.
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT parent FROM plane_records \
                 WHERE kind=?1 AND parent IS NOT NULL ORDER BY parent",
            )
            .store()?;
        let rows = stmt.query_map([kind], |r| r.get::<_, String>(0)).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        // STRICTLY older than the cutoff, and a count actually performed. WHICH rows go is the kind's
        // own contract, read off the typed `disposition` column, never out of the body:
        // - `task` drops only TERMINAL rows. An interrupted task waiting on a human is exactly the row
        //   that legitimately sits still longest; compacting it is losing the work.
        // - every other kind drops every row older than `before`.
        //
        // A purged task takes its `task_event` chain with it, and only its own. Nothing else ever
        // removes a task's events, so leaving them would grow the table forever with chains whose
        // task no longer exists — outliving the very retention decision just made about them.
        //
        // `before` is clamped rather than refused, unlike the write paths: a cutoff past what SQLite
        // can hold means "everything older than the end of time", and clamping it says exactly that.
        let before = i64::try_from(before).unwrap_or(i64::MAX);
        let terminal_only = kind == "task";
        let mut conn = self.lock_writer();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        let predicate = if terminal_only {
            "kind=?1 AND ts < ?2 AND disposition='terminal'"
        } else {
            "kind=?1 AND ts < ?2"
        };
        if terminal_only {
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
        tx.commit().store()?;
        Ok(removed as u64)
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        // Deleting what is not there is a NO-OP, not an error: the engine clears on every
        // observation that agrees with an approval rather than tracking whether it had demoted, so
        // the common call is one against no row at all. Every `seq` under the identity goes, so a
        // delete can never leave part of a chain behind. FULL sync: a clear lost to a power cut
        // re-establishes a quarantine the operator has already worked, or revives a revoked
        // callback capability.
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            conn.execute(
                "DELETE FROM plane_records WHERE kind=?1 AND identity=?2",
                params![kind, id],
            )
            .store()?;
            Ok(())
        })
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // REFUSED rather than clamped. A `now` clamped to `i64::MAX` would sweep the ENTIRE ledger
        // and then report the insert as a first redemption — an out-of-range argument silently
        // reopening every spent grant in the deployment. The only safe answer to a value this store
        // cannot hold faithfully is an error, which the engine turns into a REFUSED redemption.
        let expires = as_storable_i64("redeem_plane_token", "expires_at", expires_at)?;
        let now_i = as_storable_i64("redeem_plane_token", "now", now)?;

        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            // ONE transaction over the sweep and the test-and-set. BEGIN IMMEDIATE takes the write
            // lock up front, so two redemptions of one grant — two threads here, or two nodes on one
            // file — serialise rather than interleave. Splitting the lookup from the insert is
            // precisely the read-then-write race this verb exists NOT to be: both readers would see
            // no row and both would be told they were first.
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            // The eviction sweep, carried by the redemption itself: an entry whose grant can no
            // longer be presented protects nothing, so the table is bounded by one validity window.
            // STRICTLY less-than, so an entry expiring exactly at `now` is kept — the fail-closed
            // side of the boundary.
            tx.execute("DELETE FROM plane_tokens WHERE expires_at < ?1", [now_i])
                .store()?;
            // THE TEST AND SET, as ONE statement: 1 row inserted means this call recorded the
            // redemption, 0 means it was already there — read off what the database did, never off a
            // prior read.
            let inserted = tx
                .execute(
                    "INSERT INTO plane_tokens (kind, token, expires_at) VALUES (?1,?2,?3) \
                     ON CONFLICT(kind, token) DO NOTHING",
                    params![kind, token, expires],
                )
                .store()?;
            tx.commit().store()?;
            Ok(inserted == 1)
        })
    }

    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // MULTI-USE and SPENDS NOTHING — a plain read of the `(kind, token)` upserted record. LIVE
        // means all three: present, still `active`, and `now` not past `expires_at`. A missing row
        // holds no capability, a terminal one names work that has finished, and a lapsed one is dead
        // even if nothing finished. Asking twice answers the same twice. Fail-closed on every
        // uncertain answer, including an unrepresentable deadline.
        if now > expires_at {
            return Ok(false);
        }
        let conn = self.lock_reader();
        let disposition: Option<String> = conn
            .query_row(
                "SELECT disposition FROM plane_records WHERE kind=?1 AND identity=?2 AND seq=0",
                params![kind, token],
                |r| r.get(0),
            )
            .optional()
            .store()?;
        Ok(disposition.as_deref() == Some(DISPOSITION_ACTIVE))
    }
}

/// A stored plane row's `(id, parent, ts, disposition, body)`, as the append verb's fork check reads it.
type StoredPlaneRow = (String, Option<String>, i64, String, Vec<u8>);

const DISPOSITION_ACTIVE: &str = "active";
const DISPOSITION_TERMINAL: &str = "terminal";

/// A [`PlaneRecord`]'s storable sidecar columns, range-checked once for every verb that writes one.
struct PlaneRow {
    identity: String,
    seq: i64,
    ts: i64,
    disposition: &'static str,
}

impl PlaneRow {
    /// Refused rather than mangled: `as i64` wraps a `u64` past `i64::MAX` negative and the read
    /// clamps it back, so the row read back would not be the row written — a wrapped `seq` reorders a
    /// chain and a wrapped `ts` changes what retention does to it, with no error ever reported.
    fn of(record: PlaneRecordRef<'_>, method: &str) -> RecordStoreResult<Self> {
        Ok(Self {
            // A chain position is `(parent, seq)`; a top-level record is its own `id` at `seq`.
            identity: record.parent.unwrap_or(record.id).to_string(),
            seq: as_storable_i64(method, "seq", record.seq)?,
            ts: as_storable_i64(method, "ts", record.ts)?,
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

/// Reject a `u64` that SQLite's signed 64-bit integer cannot hold, naming the method and the field.
/// `as i64` would wrap it negative and the read would clamp it back to something else again, so the
/// row read back would not be the row written — and nothing would ever have reported an error. The
/// same guard `append_audit` applies to its own `seq`/`ts`, factored out because the plane verbs share it.
fn as_storable_i64(method: &str, field: &str, v: u64) -> RecordStoreResult<i64> {
    i64::try_from(v).map_err(|_| {
        RecordStoreError(format!(
            "{method}: {field} {v} exceeds the storable range (i64::MAX); refusing to store a row \
             that would not read back as itself"
        ))
    })
}

fn put_credential_inner(
    tx: &rusqlite::Transaction,
    secret: &CredentialSecret,
    revision: i64,
) -> RecordStoreResult<()> {
    let m = &secret.meta;
    // The owning key must EXIST and be LIVE, checked in the caller's transaction. `delete_key`
    // cascades a key's credentials away precisely so the secret material stops resolving; accepting a
    // credential onto a tombstoned key afterwards puts it back under a key an operator just revoked.
    // The FK alone only covers the "no such row" half — a tombstone is still a row. Checked here, in
    // the same IMMEDIATE transaction as the write, because a caller-side check-then-write is exactly
    // the gap a concurrent `delete_key` lands in.
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
    // UPSERT on (key_id, kind, slot): minting into an occupied LIVE slot must fail rather than
    // silently destroy a working credential mid-overlap-window. Enforced by only overwriting a row
    // whose revoked_at IS NOT NULL (or that doesn't exist yet) — the WHERE clause on the DO UPDATE.
    let changed = tx
        .execute(
            "INSERT INTO credentials (id,key_id,kind,slot,public_id,secret,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?11,?9,NULL,NULL,?10)
             ON CONFLICT(key_id,kind,slot) DO UPDATE SET
                id=excluded.id, public_id=excluded.public_id, secret=excluded.secret, secret_form=excluded.secret_form,
                created_at=excluded.created_at, updated_at=excluded.updated_at, expires_at=excluded.expires_at,
                revoked_at=NULL, revoke_reason=NULL, revision=excluded.revision
             WHERE credentials.revoked_at IS NOT NULL",
            params![
                m.id, m.key_id, m.kind, m.slot as i64, m.public_id, secret.secret,
                secret_form_to_str(m.secret_form), m.created_at as i64, m.expires_at.map(|v| v as i64), revision,
                // `updated_at` is its OWN parameter, not a second use of `created_at`'s. Bound to
                // ?8 for both, the caller's `CredentialMeta::updated_at` was silently discarded and
                // every credential reported that it was last changed when it was minted. The keys
                // table was fixed for exactly this and the credentials table was not.
                m.updated_at as i64,
            ],
        )
        .store()?;
    if changed == 0 {
        // Either the slot is occupied by a LIVE credential (the WHERE excluded it), or this is a
        // brand-new (key_id,kind,slot) row that the INSERT itself should have created — a changed
        // count of 0 there would mean the public_id UNIQUE(kind,public_id) constraint fired instead.
        // Distinguish by checking whether the row now exists.
        let occupied: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE key_id=?1 AND kind=?2 AND slot=?3 AND revoked_at IS NULL)",
                params![m.key_id, m.kind, m.slot as i64],
                |r| r.get(0),
            )
            .store()?;
        if occupied {
            return Err(RecordStoreError(format!(
                "put_credential: slot {} for key {} kind {} holds a live credential; revoke it first",
                m.slot, m.key_id, m.kind
            )));
        }
        return Err(RecordStoreError(format!(
            "put_credential: public_id {} is already taken for kind {}",
            m.public_id, m.kind
        )));
    }
    Ok(())
}

fn row_to_audit(r: &rusqlite::Row) -> rusqlite::Result<AuditRecord> {
    Ok(AuditRecord {
        seq: r.get::<_, i64>(0)?.max(0) as u64,
        ts: r.get::<_, i64>(1)?.max(0) as u64,
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

/// THE DOOR: the settings parser and the store v3 table over [`SqliteStore`] (`door::door`), the one
/// function a build that links this crate registers and the `busbar-store-sqlite-plugin` cdylib
/// exports.
pub mod door;
mod v3;

#[cfg(test)]
mod tests;
