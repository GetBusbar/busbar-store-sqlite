// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use rusqlite::types::Value;
use std::path::Path;

const SIGNED_MAX: u64 = i64::MAX as u64;

#[test]
fn unsigned_key_expiry_round_trips_through_both_mint_paths_and_reopen() {
    for paired in [false, true] {
        for (created, expires) in [
            (1, Some(u64::MAX)),
            (SIGNED_MAX, Some(SIGNED_MAX + 1)),
            (SIGNED_MAX + 1, Some(u64::MAX)),
            (u64::MAX, None),
        ] {
            let dir = tempdir();
            let path = dir.join("key-times.db");
            let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
            let mut key = sample_key("owner", "generation");
            key.created_at = created;
            key.expires_at = expires;
            if paired {
                store
                    .put_key_with_credential(&key, &sample_credential("owner", "public", 0))
                    .unwrap();
            } else {
                store.put_key(&key).unwrap();
            }
            let stored = store.get_key("owner").unwrap().unwrap();
            key.revision = stored.revision;
            assert!(stored == key);
            let before = store_revision(&store);
            let raw: (i64, i64, Option<i64>) = store
                .lock_reader()
                .query_row(
                    "SELECT created_at, updated_at, expires_at FROM keys WHERE id='owner'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(
                raw,
                (created as i64, created as i64, expires.map(|v| v as i64))
            );
            drop(store);
            let reopened = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
            assert!(reopened.get_key("owner").unwrap().unwrap() == stored);
            assert_eq!(store_revision(&reopened), before);
            assert_eq!(
                reopened.list_credentials("owner").unwrap().len(),
                usize::from(paired)
            );
        }
    }
}

#[test]
fn unsigned_invalid_key_expiry_rolls_back_owner_credential_and_revision() {
    for paired in [false, true] {
        for (created, expires) in [
            (SIGNED_MAX, SIGNED_MAX),
            (SIGNED_MAX + 1, 1),
            (SIGNED_MAX + 1, SIGNED_MAX + 1),
            (u64::MAX, 0),
            (u64::MAX, u64::MAX),
        ] {
            let store = SqliteStore::open_in_memory().unwrap();
            store
                .put_key(&sample_key("untouched", "generation"))
                .unwrap();
            let before = store_revision(&store);
            let keys = store.list_keys().unwrap();
            let mut offered = sample_key("owner", "generation");
            offered.created_at = created;
            offered.expires_at = Some(expires);
            let result = if paired {
                store.put_key_with_credential(&offered, &sample_credential("owner", "public", 0))
            } else {
                store.put_key(&offered)
            };
            assert!(
                result.is_err(),
                "expiry must follow creation in unsigned order"
            );
            assert!(store.list_keys().unwrap() == keys);
            assert!(store.list_credentials_since(0).unwrap().is_empty());
            assert_eq!(store_revision(&store), before);
        }
    }
}

const LEGACY_KEYS: &str = "CREATE TABLE keys_legacy (
 id TEXT NOT NULL PRIMARY KEY,
 name TEXT NOT NULL,
 key_group TEXT,
 allowed_pools TEXT,
 labels TEXT NOT NULL DEFAULT '{}',
 enabled INTEGER NOT NULL DEFAULT 1,
 generation_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 expires_at INTEGER,
 deleted_at INTEGER,
 revision INTEGER NOT NULL DEFAULT 0,
 scope_grants TEXT CONSTRAINT keys_scope_grants_json CHECK (scope_grants IS NULL OR (json_valid(scope_grants) AND json_type(scope_grants)='object')),
 idp_subject TEXT,
 binding_mode TEXT,
 minted_by TEXT,
 idp_provider TEXT,
 CONSTRAINT keys_enabled_bool CHECK (enabled IN (0,1)),
 CONSTRAINT keys_pools_json CHECK (allowed_pools IS NULL OR (json_valid(allowed_pools) AND json_type(allowed_pools)='array')),
 CONSTRAINT keys_labels_json CHECK (json_valid(labels) AND json_type(labels)='object' AND length(labels)<=4096),
 CONSTRAINT keys_tombstone_off CHECK (deleted_at IS NULL OR enabled=0),
 CONSTRAINT keys_expiry_after CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;";

fn disable_fixture_foreign_keys(conn: &Connection) {
    assert!(
        conn.is_autocommit(),
        "fixture FK policy must be set before a transaction"
    );
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    let enabled: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    assert_eq!(enabled, 0, "the legacy fixture must not execute FK actions");
}

fn legacy_file(path: &Path, times: &[(u64, Option<u64>)]) {
    let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    for n in 0..times.len() {
        let id = format!("owner-{n}");
        let mut key = sample_key(&id, "generation");
        key.group = Some("group".into());
        key.labels.insert("label".into(), "value".into());
        key.allowed_scopes = Some(vec![ScopeRef::pool("pool")]);
        key.idp_subject = Some("subject".into());
        key.binding_mode = Some("bound".into());
        key.minted_by = Some("minted-by".into());
        key.idp_provider = Some("provider".into());
        store
            .put_key_with_credential(&key, &sample_credential(&id, &format!("public-{n}"), 0))
            .unwrap();
    }

    store
        .append_audit(&AuditRecord {
            seq: 1,
            ts: 1,
            action: "migration-fixture".into(),
            principal: "test".into(),
            resource: "owner-0".into(),
            outcome: "applied".into(),
            prev_hash: String::new(),
            hash: "fixture-hash".into(),
        })
        .unwrap();
    drop(store);
    let conn = Connection::open(path).unwrap();

    disable_fixture_foreign_keys(&conn);
    let credentials_before: i64 = conn
        .query_row("SELECT count(*) FROM credentials", [], |row| row.get(0))
        .unwrap();
    assert_eq!(credentials_before as usize, times.len());
    conn.execute_batch(LEGACY_KEYS).unwrap();
    conn.execute_batch(
        "INSERT INTO keys_legacy SELECT * FROM keys;
         DROP TABLE keys;
         ALTER TABLE keys_legacy RENAME TO keys;",
    )
    .unwrap();
    let credentials_after: i64 = conn
        .query_row("SELECT count(*) FROM credentials", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        credentials_after, credentials_before,
        "legacy fixture setup must preserve every child credential"
    );

    conn.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    for (n, (created, expires)) in times.iter().enumerate() {
        conn.execute(
            "UPDATE keys SET created_at=?1,updated_at=?2,expires_at=?3 WHERE id=?4",
            params![
                *created as i64,
                u64::MAX as i64,
                expires.map(|v| v as i64),
                format!("owner-{n}")
            ],
        )
        .unwrap();
    }
    conn.pragma_update(None, "ignore_check_constraints", false)
        .unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    conn.execute_batch(
        "CREATE INDEX keys_custom_name_idx ON keys(name);
         CREATE TRIGGER keys_custom_guard BEFORE UPDATE OF name ON keys
         WHEN NEW.name='blocked' BEGIN SELECT RAISE(ABORT,'custom key guard'); END;",
    )
    .unwrap();
    conn.pragma_update(None, "user_version", FIRST_RELEASED_SCHEMA)
        .unwrap();
}

type Snapshot = (
    i64,
    Vec<(String, String, Option<String>)>,
    Vec<(String, Vec<Vec<Value>>)>,
);

fn snapshot(path: &Path) -> Snapshot {
    let conn =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let version = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let schema = conn
        .prepare("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let names = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let rows = names
        .into_iter()
        .map(|name| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT * FROM \"{}\" ORDER BY rowid",
                    name.replace('"', "\"\"")
                ))
                .or_else(|_| {
                    conn.prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                })
                .unwrap();
            let width = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    (0..width)
                        .map(|i| row.get::<_, Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (name, rows)
        })
        .collect();
    (version, schema, rows)
}

#[test]
fn legacy_unsigned_keys_preserve_every_row_revision_and_external_guard() {
    let dir = tempdir();
    let path = dir.join("legacy-keys.db");
    legacy_file(
        &path,
        &[
            (1, Some(u64::MAX)),
            (SIGNED_MAX + 1, Some(u64::MAX)),
            (u64::MAX, None),
        ],
    );
    let before = snapshot(&path);
    let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    assert_eq!(
        snapshot(&path).0,
        SCHEMA_VERSION,
        "released readers must refuse the repaired schema"
    );
    assert_eq!(
        snapshot(&path).2,
        before.2,
        "all rows and the global counter must survive"
    );
    let keys = store.list_keys().unwrap();
    let before_revision = store_revision(&store);
    for key in &keys {
        assert_eq!(
            store.list_credentials(&key.id).unwrap().len(),
            1,
            "the parent rebuild must not cascade-delete credentials"
        );
    }
    let conn = store.lock_writer();
    assert!(conn
        .execute("UPDATE keys SET name='blocked' WHERE id='owner-0'", [])
        .is_err());
    let index: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='keys_custom_name_idx'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(index, 1);
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    assert_eq!(fk, 1);
    assert!(conn
        .execute("DELETE FROM keys WHERE id='owner-0'", [])
        .is_ok());
    drop(conn);
    assert!(
        store.list_credentials("owner-0").unwrap().is_empty(),
        "cascade still works after migration"
    );
    store
        .put_key(&sample_key("after-upgrade", "generation"))
        .unwrap();
    let after = store_revision(&store);
    assert_eq!(
        after,
        before_revision + 1,
        "migration consumes no mutation revision"
    );
    drop(store);
    let reopened = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    assert_eq!(store_revision(&reopened), after);
    assert!(reopened.get_key("after-upgrade").unwrap().is_some());
}

#[test]
fn legacy_signed_only_key_expiry_refuses_without_changing_any_schema_or_row() {
    let dir = tempdir();
    let path = dir.join("invalid-key-times.db");
    legacy_file(&path, &[(SIGNED_MAX + 1, Some(1)), (0, None)]);
    let before = snapshot(&path);
    let error = match SqliteStore::open(path.to_str().unwrap(), 5000) {
        Ok(_) => panic!("unsigned-invalid legacy keys must refuse migration"),
        Err(error) => error,
    };
    assert!(error.0.contains("owner-0"));
    assert!(error.0.contains("unsigned timestamp order"));
    assert!(error.0.contains(&(SIGNED_MAX + 1).to_string()));
    assert_eq!(
        snapshot(&path),
        before,
        "schema, all rows, secrets, counter and stamp must roll back together"
    );
}

#[test]
fn refused_key_migration_restores_foreign_key_enforcement() {
    let store = SqliteStore::open_in_memory().unwrap();
    store.put_key(&sample_key("owner", "generation")).unwrap();
    {
        let conn = store.lock_writer();
        conn.pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        conn.execute(
            "UPDATE keys SET created_at=?1,expires_at=1 WHERE id='owner'",
            params![(SIGNED_MAX + 1) as i64],
        )
        .unwrap();
        conn.pragma_update(None, "ignore_check_constraints", false)
            .unwrap();
        conn.pragma_update(None, "user_version", FIRST_RELEASED_SCHEMA)
            .unwrap();
    }
    assert!(store.migrate().is_err());
    let conn = store.lock_writer();
    assert!(
        conn.is_autocommit(),
        "the refused migration must roll back before restoring FK checks"
    );
    let enabled: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    assert_eq!(enabled, 1);
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, FIRST_RELEASED_SCHEMA);
}

#[test]
fn an_orphan_legacy_credential_refuses_parent_rebuild_atomically() {
    let dir = tempdir();
    let path = dir.join("orphan.db");
    legacy_file(&path, &[(0, None)]);
    let conn = Connection::open(&path).unwrap();

    disable_fixture_foreign_keys(&conn);
    assert_eq!(
        conn.execute("UPDATE credentials SET key_id='missing-owner'", [])
            .unwrap(),
        1,
        "the orphan fixture must corrupt one existing credential"
    );
    drop(conn);
    let before = snapshot(&path);
    let error = match SqliteStore::open(path.to_str().unwrap(), 5000) {
        Ok(_) => panic!("a migration must refuse an orphan credential"),
        Err(error) => error,
    };
    assert!(error.0.contains("foreign key violation"));
    assert_eq!(snapshot(&path), before);
}
