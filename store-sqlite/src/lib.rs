// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in SQLite backend for busbar's durable governance store — the default `db` plugin.
//! Implements `busbar_api::store::Store` over embedded rusqlite connections: one mutex-guarded
//! writer, plus a small pool of `query_only` readers so a long billing report or retention sweep
//! never blocks the hot-path usage flush (WAL readers are unaffected by an in-flight writer).
//! Depends only on the `busbar-api` contract (plus rusqlite), never on the engine.

use busbar_api::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    ScopeRef, SecretForm, Store, StoreError, StoreResult, TierTokens, UsageDelta, UsageLedger,
    VirtualKey,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// rusqlite error -> the api's backend-agnostic `StoreError` (the contract crate stays storage-free,
// so the `From` impl that powers `?` cannot live there). Replace `<rusqlite call>?` with `<call>.store()?`.
trait IntoStoreResult<T> {
    fn store(self) -> StoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, rusqlite::Error> {
    fn store(self) -> StoreResult<T> {
        self.map_err(|e| StoreError(e.to_string()))
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
/// `governance::state::hydrate_budgets` in busbarAI core for the boot-time bug this closes).
const SCHEMA_VERSION: i64 = 6;

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
    PRIMARY KEY (bucket, key_id, provider, model)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS um_key_bucket_idx ON usage_metering (key_id, bucket);

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
) -> StoreResult<()> {
    conn.pragma_update(None, "busy_timeout", busy_timeout_ms)
        .store()?;
    let is_memory = is_memory_path(path);
    if !is_memory {
        conn.pragma_update(None, "journal_mode", "WAL").store()?;
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .store()?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError(format!(
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
        return Err(StoreError(
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
    f: impl FnOnce(&mut Connection) -> StoreResult<T>,
) -> StoreResult<T> {
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
    pub fn open(path: &str, busy_timeout_ms: i64) -> StoreResult<Self> {
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

    fn open_with_readers(path: &str, busy_timeout_ms: i64, n_readers: usize) -> StoreResult<Self> {
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
    pub fn open_in_memory() -> StoreResult<Self> {
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

    fn migrate(&self) -> StoreResult<()> {
        let mut conn = self.lock_writer();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .store()?;
        // ONE transaction over the drop, the recreate, and the version stamp — a crash between them
        // must not leave a half-initialised DB the re-run can't repair. BEGIN IMMEDIATE (not
        // DEFERRED): see the type-level doc for why every write transaction in this file uses it.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
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
        tx.execute_batch(SCHEMA).store()?;
        tx.execute(
            "INSERT INTO store_revision (id, revision) VALUES (0, 0) ON CONFLICT(id) DO NOTHING",
            [],
        )
        .store()?;
        // v5 -> v6, ONE-TIME durable backfill (never repeated, gated on the version crossing —
        // see governance::state::hydrate_budgets in busbarAI core for the bug this closes). A
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
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    /// Bump the store-global revision counter. MUST be called inside the same `BEGIN IMMEDIATE`
    /// transaction as the mutation it stamps — `RETURNING` hands the new value back with no second
    /// round trip, and single-writer + IMMEDIATE makes this gapless-under-commit-order for free (no
    /// sequence, no advisory lock).
    fn bump_revision(tx: &rusqlite::Transaction) -> StoreResult<i64> {
        tx.query_row(
            "UPDATE store_revision SET revision = revision + 1 WHERE id = 0 RETURNING revision",
            [],
            |r| r.get(0),
        )
        .store()
    }
}

// `allowed_pools` / `labels` JSON (de)serialization — storage shape unchanged from the
// pre-ScopeRef-generalization store: C6 intent (None vs Some([])) round-trips through NULL vs a
// JSON array of bare pool-name strings; a malformed value (only reachable via a direct
// out-of-band DB edit, since `migrate()` unconditionally recreates a pre-v5 database) reads as
// the most restrictive grant, never a silent widen. Only the in-memory Rust type changed
// (Option<Vec<String>> -> Option<Vec<ScopeRef>>) — every entry is `kind: "pool"` by construction,
// since "pool" is the only registered scope kind today, matching busbar_api's own
// allowed_scopes_wire serde shim. The conversion happens here, at construction
// (`ScopeRef::pool(name)`) and at read (`.value`), mirroring `store-postgres`'s
// `pools_to_storage`/`pools_from_storage`.
fn pools_to_storage(scopes: &Option<Vec<ScopeRef>>) -> Option<String> {
    scopes.as_ref().map(|list| {
        let bare: Vec<&str> = list.iter().map(|s| s.value.as_str()).collect();
        serde_json::to_string(&bare).unwrap_or_else(|_| "[]".to_string())
    })
}
fn pools_from_storage(stored: Option<String>) -> Option<Vec<ScopeRef>> {
    let stored = stored?;
    Some(
        serde_json::from_str::<Vec<String>>(stored.trim())
            .unwrap_or_default()
            .into_iter()
            .map(ScopeRef::pool)
            .collect(),
    )
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
        allowed_scopes: pools_from_storage(r.get::<_, Option<String>>(3)?),
        enabled: r.get::<_, i64>(4)? != 0,
        created_at: r.get::<_, i64>(5)? as u64,
        group: r.get(6)?,
        labels: labels_from_storage(&r.get::<_, String>(7)?),
        expires_at: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        deleted_at: r.get::<_, Option<i64>>(9)?.map(|v| v as u64),
        revision: r.get::<_, i64>(10)?.max(0) as u64,
    })
}

const KEY_COLS: &str =
    "id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision";

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

fn put_key_inner(conn: &rusqlite::Connection, key: &VirtualKey, revision: i64) -> StoreResult<()> {
    // `?6` (created_at) seeds `updated_at` on a fresh INSERT, where created_at == updated_at is
    // correct. The ON CONFLICT branch must NOT reuse `?6` there -- every other mutation path in
    // this file (delete_key, scrub_key, revoke_credential) stamps updated_at to the actual
    // mutation time (`now_secs()`), and put_key's UPDATE branch needs the same: reusing created_at
    // would silently freeze `keys.updated_at` at the row's original creation time forever, even
    // though this column has no Rust-side reader (KEY_COLS omits it) and exists purely for direct
    // SQL/operator inspection of "when did this key last change".
    conn.execute(
        "INSERT INTO keys (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,updated_at,revision)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?6,?11)
         ON CONFLICT(id) DO UPDATE SET
            generation_hash=excluded.generation_hash, name=excluded.name, allowed_pools=excluded.allowed_pools,
            enabled=excluded.enabled, key_group=excluded.key_group, labels=excluded.labels,
            expires_at=excluded.expires_at, deleted_at=excluded.deleted_at, updated_at=?12, revision=?11",
        params![
            key.id,
            key.generation_hash,
            key.name,
            pools_to_storage(&key.allowed_scopes),
            key.enabled as i64,
            key.created_at as i64,
            key.group,
            labels_to_storage(&key.labels),
            key.expires_at.map(|v| v as i64),
            key.deleted_at.map(|v| v as i64),
            revision,
            now_secs(),
        ],
    )
    .store()?;
    Ok(())
}

impl Store for SqliteStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let mut conn = self.lock_writer();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        let rev = Self::bump_revision(&tx)?;
        put_key_inner(&tx, key, rev)?;
        tx.commit().store()?;
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.lock_reader();
        conn.query_row(
            &format!("SELECT {KEY_COLS} FROM keys WHERE id=?1"),
            params![id],
            row_to_key,
        )
        .optional()
        .store()
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(&format!("SELECT {KEY_COLS} FROM keys ORDER BY created_at"))
            .store()?;
        let rows = stmt.query_map([], row_to_key).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn list_keys_since(&self, since: u64) -> StoreResult<Vec<VirtualKey>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {KEY_COLS} FROM keys WHERE revision > ?1 ORDER BY revision"
            ))
            .store()?;
        let rows = stmt.query_map(params![since as i64], row_to_key).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
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
                return Err(StoreError(format!("delete_key: no such key {id}")));
            }
            tx.commit().store()?;
            Ok(())
        })
    }

    fn scrub_key(&self, id: &str) -> StoreResult<()> {
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
            return Err(StoreError(format!(
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

    fn put_credential(&self, secret: &CredentialSecret) -> StoreResult<()> {
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
    ) -> StoreResult<()> {
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

    fn list_credentials(&self, key_id: &str) -> StoreResult<Vec<CredentialMeta>> {
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
    ) -> StoreResult<Option<CredentialSecret>> {
        let conn = self.lock_reader();
        conn.query_row(
            &format!("SELECT {CRED_SECRET_COLS} FROM credentials WHERE kind=?1 AND public_id=?2"),
            params![kind, public_id],
            row_to_cred_secret,
        )
        .optional()
        .store()
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> StoreResult<()> {
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            let rev = Self::bump_revision(&tx)?;
            // Idempotent per the trait contract: revoking an already-revoked (or unknown) credential
            // is not an error — a 0 row count covers both "already revoked" (no-op, correct) and
            // "unknown id" (also treated as a no-op, matching add_denylist's idempotency posture).
            tx.execute(
                "UPDATE credentials SET revoked_at=?2, revoke_reason=?3, updated_at=?2, revision=?4
                 WHERE id=?1 AND revoked_at IS NULL",
                params![id, now_secs(), reason, rev],
            )
            .store()?;
            tx.commit().store()?;
            Ok(())
        })
    }

    fn list_credentials_since(&self, since: u64) -> StoreResult<Vec<CredentialSecret>> {
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

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
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
        let models = stmt
            .query_map(params![window_start as i64, bucket_id], |r| {
                let u = |v: i64| v.max(0) as u64;
                Ok(ModelTokens {
                    model: r.get(0)?,
                    tokens: TierTokens {
                        input: u(r.get(1)?),
                        output: u(r.get(2)?),
                        cache_read: u(r.get(3)?),
                        cache_write: u(r.get(4)?),
                    },
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
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
    ) -> StoreResult<()> {
        let mut conn = self.lock_writer();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        tx.execute(
            "DELETE FROM usage_windows WHERE window_start=?1 AND bucket_id=?2",
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
        for m in &ledger.models {
            tx.execute(
                "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (?1,?2,?3,0,0,?4,?5,?6,?7)",
                params![
                    window_start as i64, bucket_id, m.model,
                    i64::try_from(m.tokens.input).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.output).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.cache_read).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.cache_write).unwrap_or(i64::MAX),
                ],
            ).store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        let mut conn = self.lock_writer();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        // Same sentinel-row discipline as put_usage: requests/billable_requests accumulate
        // unconditionally on model='', regardless of whether this particular delta touched any
        // models (a rejected/errored request can add to `requests` while reaching zero models).
        // `prepare_cached`, not `execute`/`prepare`: this fires once per admitted request (the
        // hottest write path in the crate), and these two statement texts never vary — caching
        // avoids paying SQLite's parse+plan cost on every single request.
        tx.prepare_cached(
            "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests)
             VALUES (?1,?2,'',MAX(0,?3),MAX(0,?4))
             ON CONFLICT(window_start, bucket_id, model) DO UPDATE SET
                requests = MAX(0, requests + ?3), billable_requests = MAX(0, billable_requests + ?4)",
        )
        .store()?
        .execute(params![window_start as i64, bucket_id, delta.requests, delta.billable_requests])
        .store()?;
        for m in &delta.models {
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
                m.tokens.input, m.tokens.output, m.tokens.cache_read, m.tokens.cache_write,
            ])
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn purge_windows_before(&self, before: u64) -> StoreResult<u64> {
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
            // be reconciled against the retention the caller asked for. Counted before the DELETE,
            // inside the same transaction, so it matches exactly what this batch removes.
            let windows_in_batch: u64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM (
                        SELECT DISTINCT window_start, bucket_id FROM usage_windows
                        WHERE (window_start, bucket_id, model) IN (
                            SELECT window_start, bucket_id, model FROM usage_windows
                            WHERE window_start < ?1 LIMIT 5000))",
                    params![before as i64],
                    |r| r.get::<_, i64>(0),
                )
                .store()? as u64;
            let changed = tx
                .execute(
                    "DELETE FROM usage_windows WHERE (window_start, bucket_id, model) IN (
                        SELECT window_start, bucket_id, model FROM usage_windows
                        WHERE window_start < ?1 LIMIT 5000)",
                    params![before as i64],
                )
                .store()?;
            tx.commit().store()?;
            total += windows_in_batch;
            if changed < 5000 {
                break;
            }
        }
        Ok(total)
    }

    fn purge_metering_before(&self, bucket: &str) -> StoreResult<u64> {
        let mut total = 0u64;
        loop {
            let mut conn = self.lock_writer();
            let changed = with_full_sync(&mut conn, |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .store()?;
                let changed = tx
                    .execute(
                        "DELETE FROM usage_metering WHERE (bucket, key_id, provider, model) IN (
                            SELECT bucket, key_id, provider, model FROM usage_metering
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
        Ok(total)
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            tx.execute(
                "INSERT INTO usage_metering (bucket, key_id, provider, model, key_group_at_use, pricing_version,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, requests, billable_requests)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
                 ON CONFLICT(bucket, key_id, provider, model) DO UPDATE SET
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
                    d.key_group_at_use,
                    d.pricing_version,
                    i64::try_from(d.tokens_input).unwrap_or(i64::MAX),
                    i64::try_from(d.tokens_output).unwrap_or(i64::MAX),
                    i64::try_from(d.tokens_cache_read).unwrap_or(i64::MAX),
                    i64::try_from(d.tokens_cache_write).unwrap_or(i64::MAX),
                    i64::try_from(d.requests).unwrap_or(i64::MAX),
                    i64::try_from(d.billable_requests).unwrap_or(i64::MAX),
                ],
            )
            .store()?;
            tx.commit().store()?;
            Ok(())
        })
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare(
                "SELECT key_id, model, provider, tokens_input, tokens_output, tokens_cache_read,
                    tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version
                 FROM usage_metering WHERE bucket = ?1",
            )
            .store()?;
        let rows = stmt
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
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        Ok(rows)
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // FULL sync: the trait's contract for this method is that a hard crash loses ~0 entries,
        // which `synchronous=NORMAL` does not provide under WAL.
        let mut conn = self.lock_writer();
        with_full_sync(&mut conn, |conn| {
            conn.execute(
                "INSERT INTO audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(seq) DO NOTHING",
                params![
                    entry.seq as i64, entry.ts as i64, entry.action, entry.resource,
                    entry.outcome, entry.principal, entry.prev_hash, entry.hash,
                ],
            )
            .store()?;
            Ok(())
        })
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare("SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log ORDER BY seq")
            .store()?;
        let rows = stmt.query_map([], row_to_audit).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
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

    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
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

    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        let conn = self.lock_reader();
        let mut stmt = conn.prepare("SELECT sub FROM denylist").store()?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).store()?;
        rows.collect::<Result<Vec<_>, _>>().store()
    }
}

fn put_credential_inner(
    tx: &rusqlite::Transaction,
    secret: &CredentialSecret,
    revision: i64,
) -> StoreResult<()> {
    let m = &secret.meta;
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
            return Err(StoreError(format!(
                "put_credential: slot {} for key {} kind {} holds a live credential; revoke it first",
                m.slot, m.key_id, m.kind
            )));
        }
        return Err(StoreError(format!(
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

#[cfg(test)]
mod tests;
