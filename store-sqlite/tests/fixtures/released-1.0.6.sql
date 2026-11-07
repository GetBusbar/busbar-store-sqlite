
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
