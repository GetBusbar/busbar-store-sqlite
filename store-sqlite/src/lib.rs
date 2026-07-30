// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in SQLite backend for busbar's durable governance store — the default `db` plugin.
//! Implements `busbar_api::store::Store` over an embedded, mutex-guarded rusqlite `Connection`,
//! depending only on the `busbar-api` contract (plus rusqlite), never on the engine.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, ModelTokens, Store, StoreError,
    StoreResult, TierTokens, UsageDelta, UsageLedger, VirtualKey,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
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

/// Store schema version, kept in SQLite's `PRAGMA user_version`. v2 (1.5.0 dev) replaced the
/// scalar `usage_counters` table with the per-(bucket, window[, model]) token-ledger pair
/// `usage_windows` + `usage_ledger`. v3 = the 1.5.0 PURE-AUTH key shape: `virtual_keys` drops the
/// inline limit columns (`max_budget_cents` / `budget_period` / `rpm_limit` / `tpm_limit` - every
/// cap now lives on the config `groups:` chain), renames `budget_group` to `key_group` (the
/// `VirtualKey.group` binding; `key_group` because bare GROUP is an SQL keyword), and makes
/// `allowed_pools` NULLABLE so the C6 grant intent round-trips faithfully: NULL = the grant was
/// omitted (ALL pools), `'[]'` = an explicit empty grant (NO pools). v4 = the usage ledger's
/// REQUEST-COUNT SPLIT: `usage_windows` gains a `billable_requests` column alongside `requests`.
/// `requests` stays the admission count (never refunded, the requests-limit truth);
/// `billable_requests` is admitted minus non-2xx refunds (the fee base for the 2xx-only charge).
/// 1.5.0 is UNRELEASED, so each
/// bump is destructive (drop + recreate), never a migration: a pre-v4 dev database is recreated
/// empty on open.
const SCHEMA_VERSION: i64 = 4;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS virtual_keys (
    id               TEXT PRIMARY KEY,
    key_hash         TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    -- NULLABLE JSON array (v3): NULL = the pool grant was OMITTED at mint = ALL pools; '[]' = an
    -- explicit empty grant = NO pools (C6: the two must never collapse into each other).
    allowed_pools    TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       INTEGER NOT NULL,
    -- The key's `groups:` binding (`VirtualKey.group`); `key_group` because GROUP is an SQL keyword.
    key_group        TEXT,
    labels           TEXT NOT NULL DEFAULT '{}'
);
-- AWS-style credentials for inbound SigV4 verification (the MinIO/S3-compatible model), kept in a
-- SEPARATE table keyed by the virtual key's id rather than as columns on `virtual_keys`. This keeps
-- the `VirtualKey` row shape (and every existing construction of it elsewhere) unchanged while still
-- TYING the credential to the key: `access_key_id` is the plaintext lookup handle carried in the
-- SigV4 `Authorization` header, and `secret_access_key` is the symmetric signing secret (stored in
-- plaintext because HMAC verification needs the same value the client signs with). `access_key_id`
-- is the PRIMARY KEY (a given AccessKeyId resolves to exactly one key); `key_id` carries the FK
-- relationship to `virtual_keys.id`. Rows are removed when the owning key is deleted (see
-- `delete_key`), so a revoked key's AWS credential cannot outlive it.
CREATE TABLE IF NOT EXISTS aws_credentials (
    access_key_id     TEXT PRIMARY KEY,
    key_id            TEXT NOT NULL,
    secret_access_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aws_credentials_key_id ON aws_credentials (key_id);
-- The TOKEN LEDGER (v2): per-(bucket, window) request counts + per-(bucket, window, model) tier
-- token counts. `bucket_id` is a virtual key's id OR a budget-group bucket id - key buckets and
-- group buckets share the shape. NO spend column: dollars are derived at read time from
-- `ledger x rate_card` in the engine, so correcting a rate is a config edit, never a data fix.
CREATE TABLE IF NOT EXISTS usage_windows (
    bucket_id    TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    -- ADMISSION count (never refunded): the requests-LIMIT truth.
    requests     INTEGER NOT NULL DEFAULT 0,
    -- v4: admitted MINUS non-2xx refunds - the FEE BASE for the 2xx-only charge. Persisted and
    -- accumulated exactly like `requests`, just with its own signed delta.
    billable_requests INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start)
);
CREATE TABLE IF NOT EXISTS usage_ledger (
    bucket_id          TEXT NOT NULL,
    window_start       INTEGER NOT NULL,
    model              TEXT NOT NULL,
    tokens_input       INTEGER NOT NULL DEFAULT 0,
    tokens_output      INTEGER NOT NULL DEFAULT 0,
    tokens_cache_read  INTEGER NOT NULL DEFAULT 0,
    tokens_cache_write INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start, model)
);
CREATE TABLE IF NOT EXISTS usage_metering (
    key_id                TEXT NOT NULL,
    bucket                INTEGER NOT NULL,
    model                 TEXT NOT NULL,
    provider              TEXT NOT NULL,
    tokens_input          INTEGER NOT NULL DEFAULT 0,
    tokens_output         INTEGER NOT NULL DEFAULT 0,
    tokens_cache_read     INTEGER NOT NULL DEFAULT 0,
    tokens_cache_creation INTEGER NOT NULL DEFAULT 0,
    requests              INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, bucket, model, provider)
);
-- The admin AUDIT log's durable home (design: the audit log persists through the configured store).
-- Append-only; `seq` is the engine's monotonic sequence (unique within a process lineage, continued
-- across restart) and the primary key. The engine computes the hash chain — the store persists each
-- record verbatim (INSERT OR REPLACE on `seq` so a replay of the same seq is idempotent) and returns
-- them oldest-first for the boot restore. No secret: action/resource/outcome/principal metadata only.
CREATE TABLE IF NOT EXISTS audit_log (
    seq       INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    action    TEXT NOT NULL,
    resource  TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    principal TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
-- The signed-token REVOCATION denylist (1.5.0): a minted token is stateless, so revoking it means
-- recording its subject id here. `sub` is the PRIMARY KEY (idempotent add); `reason` is operator
-- audit metadata; `created_at` is unused-for-now bookkeeping. The verify path hydrates an in-memory
-- set from `list_denylist` at boot and updates it live via `add_denylist`.
CREATE TABLE IF NOT EXISTS denylist (
    sub        TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT 0
);
";

/// Embedded SQLite `Store` backend (durable; opt-in via `store.module: sqlite`). The single
/// `Connection` is mutex-guarded; the governance surface is low-frequency (key CRUD) or batched
/// (usage), so it is never on the request hot path.
pub struct SqliteStore {
    // A single mutex-guarded connection. Governance is off the request hot path (key CRUD, batched
    // usage, the write-behind flush), so serializing all access on one connection is fine.
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: &str, busy_timeout_ms: i64) -> StoreResult<Self> {
        let conn = Connection::open(path).store()?;
        // Harden the on-disk DB against `SQLITE_BUSY` from a second connection or an external tool
        // (backup/inspection): WAL lets readers and a writer proceed concurrently, and a 5s busy
        // timeout makes a transient lock contention retry-then-succeed rather than fail instantly.
        // Skip both for an in-memory path: `:memory:` ignores WAL (no rollback journal file exists)
        // and has no second connection to contend with, so the pragmas are inapplicable there.
        if !path.starts_with(":memory:") && !path.contains("mode=memory") {
            // `busy_timeout` FIRST, `journal_mode` second: switching a not-yet-WAL file into WAL mode
            // itself needs to briefly acquire the database, so if another connection is already
            // holding it, that acquisition is subject to whatever busy_timeout is in effect at the
            // time — SQLite's default is 0 (fail instantly). Setting `busy_timeout` before
            // `journal_mode` ensures the CONFIGURED timeout (not the zero default) governs even this
            // first pragma, not just the queries `migrate()` runs afterward. `journal_mode` returns
            // the resulting mode as a row, so use `pragma_update`/query rather than `execute` (which
            // rejects a statement that yields rows). `busy_timeout` is a plain setter and is safe via
            // `execute_batch`.
            conn.pragma_update(None, "busy_timeout", busy_timeout_ms)
                .store()?;
            conn.pragma_update(None, "journal_mode", "WAL").store()?;
        }
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory SQLite store, for unit tests.
    pub fn open_in_memory() -> StoreResult<Self> {
        let store = Self {
            conn: Mutex::new(Connection::open_in_memory().store()?),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Acquire the SQLite connection mutex, recovering from a poisoned lock instead of panicking.
    /// Mirrors `rate_write`/`caches_read`: this lock is reachable from the request path (the atomic
    /// admission charge in `charge_within_budget_async` → `charge_within_budget_inner` runs inside
    /// `spawn_blocking`), and the project
    /// rule is no panic on the request path. A panic under the connection lock would otherwise poison
    /// it and cascade into a governance-wide outage on every subsequent CRUD/usage call. SQLite's own
    /// state stays consistent across a recovered guard (a panicked statement is rolled back by
    /// rusqlite's Drop), so continuing with `into_inner()` is safe.
    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        Self::lock_conn_raw(&self.conn)
    }

    /// Poison-recovering lock of a raw `&Mutex<Connection>` — same rationale as [`Self::lock_conn`],
    /// but takes the mutex by reference so the shared `*_inner` SQL bodies can lock it without `&self`.
    fn lock_conn_raw(conn: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
        conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn migrate(&self) -> StoreResult<()> {
        let mut conn = self.lock_conn();
        // SCHEMA-VERSION BUMP (v4, the 1.5.0 billable-requests ledger split; see SCHEMA_VERSION).
        // 1.5.0 is unreleased, so a pre-v4 database (user_version < 4 with any governance table
        // already present) is DROPPED and recreated - a bump, not a migration. A fresh database (no
        // tables) simply creates the v4 schema; a v4 database is untouched (idempotent CREATE IF
        // NOT EXISTS).
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .store()?;
        // ONE transaction over the drop, the recreate and the version stamp — the postgres backend
        // already does this and names the hazard: a crash between them leaves a half-initialised DB
        // that the re-run cannot repair. `execute_batch` commits each statement separately, so
        // dropping `virtual_keys` and losing power before `usage_windows` clears BOTH sentinels; the
        // re-run then sees no legacy tables, skips the drops, and stamps v4 over a v3-shaped table
        // that `CREATE TABLE IF NOT EXISTS` cannot fix.
        //
        // IMMEDIATE, not deferred: a plain `conn.transaction()` (deferred `BEGIN`) only acquires the
        // write lock lazily, on its first write. On an already-migrated database that first write
        // ends up being the trailing `PRAGMA user_version = ...` below — and SQLite does NOT retry a
        // deferred-transaction's lock-upgrading PRAGMA through the busy handler the way it retries a
        // normal `BEGIN IMMEDIATE`/DML write: contending with another writer at that point fails with
        // `SQLITE_BUSY` INSTANTLY, ignoring `busy_timeout_ms` entirely. Acquiring the write lock
        // up front via `BEGIN IMMEDIATE` makes the whole migration honor the configured busy_timeout
        // the same way every other write in this file already does.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .store()?;
        if version < SCHEMA_VERSION {
            let has_legacy: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='usage_counters')
                       OR EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='virtual_keys')",
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
                     DROP TABLE IF EXISTS denylist;",
                )
                .store()?;
            }
        }
        tx.execute_batch(SCHEMA).store()?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    // ── Shared SQL bodies for the accounting methods ─────────────────────────────────────────────
    // Each `*_inner` holds the EXACT SQL of its accounting method, locking the passed connection mutex
    // (poison-recovering). Takes no `&self`, so it is shared without borrowing the store.

    fn put_usage_inner(
        conn: &Mutex<Connection>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        // ABSOLUTE overwrite (memory is authoritative): replace the whole (bucket, window) record -
        // the requests row AND every model row - in ONE transaction, so a re-flush of the same cell
        // is idempotent and a reader never sees half a ledger. Clamp u64 counts into i64 (a value
        // above i64::MAX pins, never wraps).
        let mut conn = Self::lock_conn_raw(conn);
        let tx = conn.transaction().store()?;
        tx.execute(
            "DELETE FROM usage_ledger WHERE bucket_id=?1 AND window_start=?2",
            params![bucket_id, window_start as i64],
        )
        .store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(bucket_id, window_start) DO UPDATE SET
                requests = excluded.requests,
                billable_requests = excluded.billable_requests",
            params![
                bucket_id,
                window_start as i64,
                i64::try_from(ledger.requests).unwrap_or(i64::MAX),
                i64::try_from(ledger.billable_requests).unwrap_or(i64::MAX)
            ],
        )
        .store()?;
        for m in &ledger.models {
            tx.execute(
                "INSERT INTO usage_ledger
                    (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    bucket_id,
                    window_start as i64,
                    m.model,
                    i64::try_from(m.tokens.input).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.output).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.cache_read).unwrap_or(i64::MAX),
                    i64::try_from(m.tokens.cache_write).unwrap_or(i64::MAX),
                ],
            )
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_usage_inner(
        conn: &Mutex<Connection>,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> StoreResult<()> {
        // ADDITIVE fleet-honest accumulate: the signed requests delta plus every per-model tier
        // delta land in ONE transaction (atomic across the two tables), each counter floored at 0
        // so a refund can never drive a durable counter negative.
        let mut conn = Self::lock_conn_raw(conn);
        let tx = conn.transaction().store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES (?1,?2,MAX(0,?3),MAX(0,?4))
             ON CONFLICT(bucket_id, window_start) DO UPDATE SET
                requests = MAX(0, requests + ?3),
                billable_requests = MAX(0, billable_requests + ?4)",
            params![
                bucket_id,
                window_start as i64,
                delta.requests,
                delta.billable_requests
            ],
        )
        .store()?;
        for m in &delta.models {
            tx.execute(
                "INSERT INTO usage_ledger
                    (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (?1,?2,?3,MAX(0,?4),MAX(0,?5),MAX(0,?6),MAX(0,?7))
                 ON CONFLICT(bucket_id, window_start, model) DO UPDATE SET
                    tokens_input       = MAX(0, tokens_input + ?4),
                    tokens_output      = MAX(0, tokens_output + ?5),
                    tokens_cache_read  = MAX(0, tokens_cache_read + ?6),
                    tokens_cache_write = MAX(0, tokens_cache_write + ?7)",
                params![
                    bucket_id,
                    window_start as i64,
                    m.model,
                    m.tokens.input,
                    m.tokens.output,
                    m.tokens.cache_read,
                    m.tokens.cache_write,
                ],
            )
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_metering_inner(conn: &Mutex<Connection>, d: &MeteringDelta) -> StoreResult<()> {
        let conn = Self::lock_conn_raw(conn);
        conn.execute(
            "INSERT INTO usage_metering (key_id, bucket, model, provider,
                 tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(key_id, bucket, model, provider) DO UPDATE SET
                 tokens_input          = tokens_input + excluded.tokens_input,
                 tokens_output         = tokens_output + excluded.tokens_output,
                 tokens_cache_read     = tokens_cache_read + excluded.tokens_cache_read,
                 tokens_cache_creation = tokens_cache_creation + excluded.tokens_cache_creation,
                 requests              = requests + excluded.requests",
            params![
                d.key_id,
                d.bucket as i64,
                d.model,
                d.provider,
                i64::try_from(d.tokens_input).unwrap_or(i64::MAX),
                i64::try_from(d.tokens_output).unwrap_or(i64::MAX),
                i64::try_from(d.tokens_cache_read).unwrap_or(i64::MAX),
                i64::try_from(d.tokens_cache_creation).unwrap_or(i64::MAX),
                i64::try_from(d.requests).unwrap_or(i64::MAX),
            ],
        )
        .store()?;
        Ok(())
    }

    fn list_metering_inner(conn: &Mutex<Connection>, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let conn = Self::lock_conn_raw(conn);
        let mut stmt = conn
            .prepare(
                "SELECT key_id, model, provider,
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests
             FROM usage_metering WHERE bucket = ?1",
            )
            .store()?;
        let rows = stmt
            .query_map(params![bucket as i64], |r| {
                // DI-3 posture (matches get_usage): clamp a corrupt negative stored counter to 0
                // instead of wrapping a negative i64 to a huge u64 via `as`.
                let u = |v: i64| v.max(0) as u64;
                Ok(MeteringRow {
                    key_id: r.get(0)?,
                    model: r.get(1)?,
                    provider: r.get(2)?,
                    tokens_input: u(r.get(3)?),
                    tokens_output: u(r.get(4)?),
                    tokens_cache_read: u(r.get(5)?),
                    tokens_cache_creation: u(r.get(6)?),
                    requests: u(r.get(7)?),
                })
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        Ok(rows)
    }

    fn get_usage_inner(
        conn: &Mutex<Connection>,
        bucket_id: &str,
        window_start: u64,
    ) -> StoreResult<UsageLedger> {
        // Read the requests row + every model row inside ONE transaction so a concurrent
        // `put_usage`/`add_usage` (another process on the same file) can never yield a torn ledger.
        let mut conn = Self::lock_conn_raw(conn);
        let tx = conn.transaction().store()?;
        let row: Option<(i64, i64)> = tx
            .query_row(
                "SELECT requests, billable_requests
                 FROM usage_windows WHERE bucket_id=?1 AND window_start=?2",
                params![bucket_id, window_start as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .store()?;
        let (requests, billable_requests) = row.unwrap_or((0, 0));
        let mut ledger = UsageLedger {
            // DI-3: clamp a (corrupt / direct-DB) negative stored counter to 0 instead of wrapping
            // a negative i64 to a huge u64 via `as`.
            requests: requests.max(0) as u64,
            billable_requests: billable_requests.max(0) as u64,
            models: Vec::new(),
        };
        {
            let mut stmt = tx
                .prepare(
                    "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
                     FROM usage_ledger WHERE bucket_id=?1 AND window_start=?2 ORDER BY model",
                )
                .store()?;
            let rows = stmt
                .query_map(params![bucket_id, window_start as i64], |r| {
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
            ledger.models = rows;
        }
        tx.commit().store()?;
        Ok(ledger)
    }
}

// `allowed_pools` is stored in the `allowed_pools TEXT` column. The historical format was a bare
// comma-delimited string, which CORRUPTS any pool name containing a comma: a single intended pool
// `"prod,special"` round-trips as two pools `["prod", "special"]`, so `pool_allowed` matches EITHER
// fragment (a silent privilege expansion) and never matches the real compound name (a silent deny).
// A JSON array is delimiter-safe for arbitrary string values, so we now SERIALIZE as JSON. We still
// READ legacy comma-delimited rows transparently (a value that is not valid JSON array TEXT — i.e.
// every row written before this change — falls back to the comma split), so an existing on-disk DB
// keeps working without a migration. New writes are always JSON, so a comma-bearing name survives a
// write/read round-trip exactly.
fn pools_to_storage(pools: &Option<Vec<String>>) -> Option<String> {
    // C6 intent preserved through storage: `None` (grant omitted = ALL pools) persists as SQL
    // NULL; `Some(list)` - INCLUDING the explicit empty grant `Some([])` = NO pools - persists as
    // a JSON array. serde_json::to_string over a `&[String]` is infallible (no map keys, no
    // non-finite floats), but we must not panic on the admin write path: on the unreachable error
    // fall back to the empty JSON array (the most restrictive spelling - fail-safe).
    pools
        .as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_else(|_| "[]".to_string()))
}
fn pools_from_storage(stored: Option<String>) -> Option<Vec<String>> {
    let stored = stored?;
    // A stored value is always a JSON array of strings (the v3 writer). A malformed value (only
    // possible from a direct-DB edit) reads as the EMPTY grant - the most restrictive reading,
    // never a silent widen to "all pools".
    Some(serde_json::from_str::<Vec<String>>(stored.trim()).unwrap_or_default())
}

// Shared SQL bodies for the key/credential UPSERTs, so the autocommit single-statement methods
// (`put_key`, `put_aws_credential`) and the transactional mint (`put_key_with_aws_credential`) hold
// the SQL EXACTLY ONCE and can never drift. `rusqlite::Transaction` derefs to `Connection`, so a
// `&tx` coerces to `&Connection` here — the same body runs whether `conn` is a plain connection
// guard or a transaction. The SQL is byte-for-byte the original inline statements.

fn put_key_inner(conn: &rusqlite::Connection, key: &VirtualKey) -> StoreResult<()> {
    conn.execute(
        "INSERT INTO virtual_keys
                (id, key_hash, name, allowed_pools, enabled, created_at, key_group, labels)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(id) DO UPDATE SET
                key_hash=excluded.key_hash, name=excluded.name, allowed_pools=excluded.allowed_pools,
                enabled=excluded.enabled, key_group=excluded.key_group, labels=excluded.labels",
        params![
            key.id,
            key.key_hash,
            key.name,
            pools_to_storage(&key.allowed_pools),
            key.enabled as i64,
            key.created_at as i64,
            key.group,
            labels_to_storage(&key.labels),
        ],
    )
    .store()?;
    Ok(())
}

/// `labels` persist as a JSON object in the `labels TEXT` column (delimiter-safe for arbitrary
/// operator strings, mirroring the `allowed_pools` JSON storage). Serialization over a
/// `BTreeMap<String, String>` is infallible; fall back to `{}` rather than panic on a write path.
fn labels_to_storage(labels: &std::collections::BTreeMap<String, String>) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_string())
}

fn labels_from_storage(stored: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(stored).unwrap_or_default()
}

fn put_aws_credential_inner(conn: &rusqlite::Connection, cred: &AwsCredential) -> StoreResult<()> {
    conn.execute(
        "INSERT INTO aws_credentials (access_key_id, key_id, secret_access_key)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(access_key_id) DO UPDATE SET
                key_id=excluded.key_id, secret_access_key=excluded.secret_access_key",
        params![cred.access_key_id, cred.key_id, cred.secret_access_key],
    )
    .store()?;
    Ok(())
}

impl Store for SqliteStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        put_key_inner(&self.lock_conn(), key)
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id,key_hash,name,allowed_pools,enabled,created_at,key_group,labels
                 FROM virtual_keys WHERE id=?1",
                params![id],
                row_to_key,
            )
            .optional()
            .store()?;
        Ok(row)
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare(
                "SELECT id,key_hash,name,allowed_pools,enabled,created_at,key_group,labels
             FROM virtual_keys ORDER BY created_at",
            )
            .store()?;
        let rows = stmt.query_map([], row_to_key).store()?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.store()?);
        }
        Ok(out)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // Both DELETEs must be atomic. Under SQLite autocommit each `execute` commits on its own, so
        // a failure of the second statement (I/O error, disk full, constraint) would leave the key
        // row gone but its usage_counters rows orphaned — accumulating forever and, worse, poisoning
        // any future key re-created with the same id with stale usage. Wrap both in one transaction
        // so they commit together or not at all. The Mutex already serializes us against other
        // writers, so the transaction cannot deadlock against a concurrent busbar caller.
        let mut conn = self.lock_conn();
        let tx = conn.transaction().store()?;
        tx.execute("DELETE FROM virtual_keys WHERE id=?1", params![id])
            .store()?;
        tx.execute("DELETE FROM usage_windows WHERE bucket_id=?1", params![id])
            .store()?;
        tx.execute("DELETE FROM usage_ledger WHERE bucket_id=?1", params![id])
            .store()?;
        // Remove any AWS credential rows tied to this key in the SAME transaction: a revoked key's
        // SigV4 credential must NOT outlive the key, or a Bedrock-SDK client signing with that
        // AccessKeyId could keep authenticating after revocation (an auth-bypass). The in-memory
        // AccessKeyId index is rebuilt on the post-delete `refresh`, and even before that rebuild the
        // index already skips a credential whose key row is gone (see `load_by_access_key_id`), so the
        // revocation is effective immediately and durably.
        tx.execute("DELETE FROM aws_credentials WHERE key_id=?1", params![id])
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        put_aws_credential_inner(&self.lock_conn(), cred)
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        // ATOMIC mint: the bearer-key INSERT and its AWS-credential INSERT commit together or not at
        // all. Under autocommit a failure of the second statement would orphan the just-written key row
        // (inert: no resolvable AccessKeyId). Wrap both in one transaction — same pattern as
        // `delete_key`. The connection Mutex already serializes us against any other writer, so the
        // transaction cannot deadlock against a concurrent busbar caller.
        let mut conn = self.lock_conn();
        let tx = conn.transaction().store()?;
        // `&tx` coerces to `&Connection` via `Transaction`'s Deref, so both writes share the exact same
        // SQL bodies as the autocommit `put_key`/`put_aws_credential` — they can never drift.
        put_key_inner(&tx, key)?;
        put_aws_credential_inner(&tx, cred)?;
        tx.commit().store()?;
        Ok(())
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare("SELECT access_key_id, key_id, secret_access_key FROM aws_credentials")
            .store()?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AwsCredential {
                    access_key_id: r.get(0)?,
                    key_id: r.get(1)?,
                    secret_access_key: r.get(2)?,
                })
            })
            .store()?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.store()?);
        }
        Ok(out)
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        Self::put_usage_inner(&self.conn, bucket_id, window_start, ledger)
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        Self::add_usage_inner(&self.conn, bucket_id, window_start, delta)
    }

    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        Self::add_metering_inner(&self.conn, delta)
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Self::list_metering_inner(&self.conn, bucket)
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        Self::get_usage_inner(&self.conn, bucket_id, window_start)
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // INSERT OR REPLACE on the `seq` PK: append-only in practice, but idempotent if the engine
        // ever re-writes a record for the same seq (e.g. a snapshot replay), never a UNIQUE error.
        self.lock_conn()
            .execute(
                "INSERT OR REPLACE INTO audit_log
                    (seq, ts, action, resource, outcome, principal, prev_hash, hash)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
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
        Ok(())
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash
                 FROM audit_log ORDER BY seq",
            )
            .store()?;
        let rows = stmt
            .query_map([], |r| {
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
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        Ok(rows)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
        // Idempotent revoke: INSERT the subject, and on a repeat refresh its reason (either arm is
        // idempotent for the denylist's purpose - the sub stays denied exactly once).
        self.lock_conn()
            .execute(
                "INSERT INTO denylist (sub, reason, created_at) VALUES (?1, ?2, 0)
                 ON CONFLICT(sub) DO UPDATE SET reason = excluded.reason",
                params![sub, reason],
            )
            .store()?;
        Ok(())
    }

    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare("SELECT sub FROM denylist").store()?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        Ok(rows)
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        // BOUNDED restore read (audit issue): select only the most-recent `limit` rows at the SOURCE
        // (a `LIMIT` on a descending scan), then reverse into oldest-first. This keeps the ABI
        // response and the engine ring bounded regardless of how large the never-pruned durable log
        // has grown, so restore cannot exceed the plugin response cap or OOM.
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash
                 FROM audit_log ORDER BY seq DESC LIMIT ?1",
            )
            .store()?;
        let mut rows = stmt
            .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
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
            })
            .store()?
            .collect::<Result<Vec<_>, _>>()
            .store()?;
        rows.reverse(); // DESC LIMIT gave newest-first; the restore contract is oldest-first.
        Ok(rows)
    }
}

// Hash-lookup primitive retained for the governance unit tests that pin the by-hash resolution
// semantics. (The legacy direct-SQL charge/refund/add primitives died with `usage_counters` - v2
// production enforcement is the in-memory chain charge in `GovState`; the store is a pure
// write-behind ledger.)
impl SqliteStore {
    pub fn get_key_by_hash(&self, key_hash: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.lock_conn();
        let row = conn
            .query_row(
                "SELECT id,key_hash,name,allowed_pools,enabled,created_at,key_group,labels
                 FROM virtual_keys WHERE key_hash=?1",
                params![key_hash],
                row_to_key,
            )
            .optional()
            .store()?;
        Ok(row)
    }
}

fn row_to_key(r: &rusqlite::Row) -> rusqlite::Result<VirtualKey> {
    Ok(VirtualKey {
        id: r.get(0)?,
        key_hash: r.get(1)?,
        name: r.get(2)?,
        // NULL column = the grant was omitted (ALL pools); a JSON array = the exhaustive grant,
        // including the explicit empty grant (NO pools). See `pools_from_storage`.
        allowed_pools: pools_from_storage(r.get::<_, Option<String>>(3)?),
        enabled: r.get::<_, i64>(4)? != 0,
        created_at: r.get::<_, i64>(5)? as u64,
        group: r.get(6)?,
        labels: labels_from_storage(&r.get::<_, String>(7)?),
    })
}

#[cfg(test)]
mod tests;
