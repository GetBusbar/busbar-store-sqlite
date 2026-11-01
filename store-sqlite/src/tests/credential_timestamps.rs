// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::path::Path;

const SIGNED_MAX: u64 = i64::MAX as u64;

fn credential(store: &SqliteStore, public: &str) -> CredentialSecret {
    store
        .lookup_credential_secret("sigv4", public)
        .unwrap()
        .unwrap()
}

#[test]
fn unsigned_credential_timestamps_round_trip_through_both_mint_paths_and_reopen() {
    for paired in [false, true] {
        for (created, expires) in [
            (0, Some(SIGNED_MAX)),
            (SIGNED_MAX, Some(SIGNED_MAX + 1)),
            (SIGNED_MAX + 1, Some(u64::MAX)),
            (u64::MAX, None),
        ] {
            let dir = tempdir();
            let path = dir.join("timestamps.db");
            let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
            let owner = sample_key("owner", "hash");
            let mut offered = sample_credential("owner", "public", 0);
            offered.meta.created_at = created;
            offered.meta.updated_at = created.wrapping_add(17);
            offered.meta.expires_at = expires;
            if paired {
                store.put_key_with_credential(&owner, &offered).unwrap();
            } else {
                store.put_key(&owner).unwrap();
                store.put_credential(&offered).unwrap();
            }
            let stored = credential(&store, "public");
            offered.meta.revision = stored.meta.revision;
            assert!(stored == offered);
            let before = store_revision(&store);
            store.put_credential(&stored).unwrap();
            assert_eq!(store_revision(&store), before, "identical PUT stays a noop");
            if let Some(expiry) = expires {
                assert!(stored.meta.is_live(expiry - 1));
                assert!(!stored.meta.is_live(expiry));
            }
            let raw: (i64, i64, Option<i64>) = store.lock_reader().query_row(
                "SELECT created_at, updated_at, expires_at FROM credentials WHERE public_id='public'",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).unwrap();
            assert_eq!(
                raw,
                (
                    created as i64,
                    offered.meta.updated_at as i64,
                    expires.map(|v| v as i64)
                )
            );
            drop(store);
            let reopened = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
            assert!(credential(&reopened, "public") == stored);
            assert_eq!(store_revision(&reopened), before);
        }
    }
}

#[test]
fn unsigned_expiry_refusals_leave_no_credential_key_or_revision_behind() {
    for paired in [false, true] {
        for (created, expires) in [
            (SIGNED_MAX, SIGNED_MAX),
            (SIGNED_MAX + 1, SIGNED_MAX),
            (SIGNED_MAX + 1, SIGNED_MAX + 1),
            (u64::MAX, 0),
            (u64::MAX, u64::MAX),
        ] {
            let store = SqliteStore::open_in_memory().unwrap();
            let owner = sample_key("owner", "hash");
            if !paired {
                store.put_key(&owner).unwrap();
            }
            let before = store_revision(&store);
            let owners = store.list_keys().unwrap();
            let mut offered = sample_credential("owner", "public", 0);
            offered.meta.created_at = created;
            offered.meta.updated_at = u64::MAX;
            offered.meta.expires_at = Some(expires);
            let result = if paired {
                store.put_key_with_credential(&owner, &offered)
            } else {
                store.put_credential(&offered)
            };
            assert!(
                result.is_err(),
                "expiry must follow creation in unsigned order"
            );
            assert!(store.list_credentials_since(0).unwrap().is_empty());
            assert!(store.list_keys().unwrap() == owners);
            assert_eq!(store_revision(&store), before);
        }
    }
}

// The released v14 signed-expiry table, retained as a migration input rather than borrowed from
// the current DDL. The surrounding database is made by the real provider.
const V14_CREDENTIALS: &str = "CREATE TABLE credentials_legacy (
 id TEXT NOT NULL PRIMARY KEY,
 key_id TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE ON UPDATE RESTRICT,
 kind TEXT NOT NULL,
 slot INTEGER NOT NULL,
 public_id TEXT NOT NULL,
 secret TEXT,
 secret_form TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 expires_at INTEGER,
 revoked_at INTEGER,
 revoke_reason TEXT,
 revision INTEGER NOT NULL DEFAULT 0,
 CONSTRAINT cred_kind CHECK (kind IN ('sigv4')),
 CONSTRAINT cred_slot CHECK (slot IN (0,1)),
 CONSTRAINT cred_form CHECK (secret_form IN ('none','recoverable','digest')),
 CONSTRAINT cred_form_null CHECK ((secret_form='none') = (secret IS NULL)),
 CONSTRAINT cred_sigv4_recov CHECK (kind <> 'sigv4' OR secret_form = 'recoverable' OR revoked_at IS NOT NULL),
 CONSTRAINT cred_revoked_bare CHECK (revoked_at IS NULL OR secret IS NULL),
 CONSTRAINT cred_secret_fmt CHECK (secret IS NULL OR secret GLOB 'v1:?*:?*'),
 CONSTRAINT cred_reason_ord CHECK (revoke_reason IS NULL OR revoked_at IS NOT NULL),
 CONSTRAINT cred_expiry_after CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;";

fn legacy_file(path: &Path, version: i64, rows: &[(u64, Option<u64>)], imported_cross_sign: bool) {
    let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    for (n, (created, _)) in rows.iter().enumerate() {
        let owner = format!("owner-{n}");
        store.put_key(&sample_key(&owner, "hash")).unwrap();
        let mut row = sample_credential(&owner, &format!("public-{n}"), 0);
        row.meta.created_at = *created;
        row.meta.updated_at = u64::MAX - n as u64;
        store.put_credential(&row).unwrap();
    }
    drop(store);
    let conn = Connection::open(path).unwrap();
    let ddl = if version < 14 {
        V13_CREDENTIALS.replace("credentials_v13", "credentials_legacy")
    } else {
        V14_CREDENTIALS.to_owned()
    };
    conn.execute_batch(&ddl).unwrap();
    conn.execute_batch(
        "INSERT INTO credentials_legacy SELECT * FROM credentials;
        DROP TRIGGER keys_cascade_credentials;
        DROP TABLE credentials;
        ALTER TABLE credentials_legacy RENAME TO credentials;",
    )
    .unwrap();
    if imported_cross_sign {
        // Imported unsigned-valid rows can predate this CHECK repair. They must not be copied
        // through another intermediate signed-expiry table on the way to the final schema.
        conn.pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
    }
    for (n, (_, expiry)) in rows.iter().enumerate() {
        conn.execute(
            "UPDATE credentials SET expires_at=?1 WHERE public_id=?2",
            params![expiry.map(|value| value as i64), format!("public-{n}")],
        )
        .unwrap();
    }
    conn.pragma_update(None, "ignore_check_constraints", false)
        .unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    conn.pragma_update(None, "user_version", version).unwrap();
}

type Snapshot = (
    i64,
    i64,
    Vec<(String, String, Option<String>)>,
    Vec<CredentialSecret>,
);

fn snapshot(path: &Path) -> Snapshot {
    let conn = Connection::open(path).unwrap();
    let version = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let revision = conn
        .query_row(
            "SELECT revision FROM store_revision WHERE id=0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let schema = conn
        .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let rows = conn
        .prepare(&format!(
            "SELECT {CRED_SECRET_COLS} FROM credentials ORDER BY id"
        ))
        .unwrap()
        .query_map([], row_to_cred_secret)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    (version, revision, schema, rows)
}

#[test]
fn v14_timestamp_rows_keep_all_bits_metadata_and_revision_on_upgrade() {
    let dir = tempdir();
    let path = dir.join("v14.db");
    legacy_file(
        &path,
        14,
        &[
            (0, Some(SIGNED_MAX)),
            (SIGNED_MAX + 1, Some(u64::MAX)),
            (u64::MAX, None),
        ],
        false,
    );
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE credentials SET secret=NULL, secret_form='none', revoked_at=?1,
             revoke_reason='legacy-revoked' WHERE public_id='public-2'",
            params![u64::MAX as i64],
        )
        .unwrap();
    let before = snapshot(&path);
    let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    assert_eq!(store_revision(&store), before.1);
    for expected in &before.3 {
        assert!(credential(&store, &expected.meta.public_id) == *expected);
    }
    let version: i64 = store
        .lock_reader()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        version, SCHEMA_VERSION,
        "older v14 readers must not reopen the repaired schema"
    );
    drop(store);
    let reopened = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    assert_eq!(store_revision(&reopened), before.1);
    for expected in &before.3 {
        assert!(credential(&reopened, &expected.meta.public_id) == *expected);
    }
}

#[test]
fn a_pre_v14_import_goes_directly_to_unsigned_expiry_order() {
    let dir = tempdir();
    let path = dir.join("v13-import.db");
    legacy_file(&path, 13, &[(SIGNED_MAX, Some(SIGNED_MAX + 1))], true);
    let before = snapshot(&path);
    let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    assert!(credential(&store, "public-0") == before.3[0]);
    assert_eq!(store_revision(&store), before.1);
    assert_schema_matches_a_fresh_one(&store, &[]);
}

#[test]
fn a_legacy_signed_only_expiry_refuses_upgrade_without_changing_the_database() {
    for version in [13, 14] {
        let dir = tempdir();
        let path = dir.join("invalid-expiry.db");
        legacy_file(&path, version, &[(u64::MAX, Some(0)), (0, None)], false);
        if version < 14 {
            Connection::open(&path)
                .unwrap()
                .execute(
                    "UPDATE credentials SET revoked_at=1, revoke_reason='legacy-revoked'
                     WHERE public_id='public-1'",
                    [],
                )
                .unwrap();
        }
        let before = snapshot(&path);
        let error = match SqliteStore::open(path.to_str().unwrap(), 5000) {
            Ok(_) => panic!("an unsigned-invalid legacy expiry must refuse migration"),
            Err(error) => error,
        };
        assert!(error.0.contains("cred_public-0"));
        assert!(error.0.contains("unsigned timestamp order"));
        assert!(error.0.contains(&u64::MAX.to_string()));
        let after = snapshot(&path);
        assert_eq!(after.0, before.0, "version stamp must not change");
        assert_eq!(after.1, before.1, "global revision must not change");
        assert_eq!(
            after.2, before.2,
            "tables, indexes and triggers must not change"
        );
        assert!(
            after.3 == before.3,
            "all row metadata and secret bytes must survive"
        );
    }
}

#[test]
fn future_schema_refusal_keeps_unsigned_rows_unchanged() {
    let dir = tempdir();
    let path = dir.join("newer-timestamps.db");
    let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    let mut offered = sample_credential("owner", "public", 0);
    offered.meta.created_at = SIGNED_MAX;
    offered.meta.updated_at = u64::MAX;
    offered.meta.expires_at = Some(SIGNED_MAX + 1);
    store.put_credential(&offered).unwrap();
    drop(store);
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    let before = snapshot(&path);
    let error = match SqliteStore::open(path.to_str().unwrap(), 5000) {
        Ok(_) => panic!("an older-schema provider must refuse the file"),
        Err(error) => error,
    };
    assert!(error.0.contains("newer than this build"));
    let after = snapshot(&path);
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert_eq!(after.2, before.2);
    assert!(after.3 == before.3);
}
