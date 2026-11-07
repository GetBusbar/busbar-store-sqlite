-- Frozen development physical catalogue from pre-cutover SQLite source.
-- Historical-reader test input only; never runtime migrations.

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
    CONSTRAINT keys_expiry_after CHECK (expires_at IS NULL OR (created_at >= 0 AND expires_at < 0) OR (((created_at < 0) = (expires_at < 0)) AND expires_at > created_at))
) STRICT;
CREATE INDEX IF NOT EXISTS keys_revision_idx ON keys (revision);

-- Only for auth verified by ROW LOOKUP from a wire-supplied public identifier (today: sigv4).
CREATE TABLE IF NOT EXISTS credentials (
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
    CONSTRAINT cred_expiry_after CHECK (expires_at IS NULL OR (created_at >= 0 AND expires_at < 0) OR (((created_at < 0) = (expires_at < 0)) AND expires_at > created_at))
) STRICT;
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

ALTER TABLE keys ADD COLUMN scope_grants TEXT CONSTRAINT keys_scope_grants_json CHECK (scope_grants IS NULL OR (json_valid(scope_grants) AND json_type(scope_grants)='object'));
ALTER TABLE keys ADD COLUMN idp_subject TEXT;
ALTER TABLE keys ADD COLUMN binding_mode TEXT;
ALTER TABLE keys ADD COLUMN minted_by TEXT;
ALTER TABLE keys ADD COLUMN idp_provider TEXT;
