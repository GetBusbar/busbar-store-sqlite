// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regressions for the fleet audit's confirmed findings: URI routing and private creation that
//! must agree with SQLite's own URI parsing, the sync level of a record put, and the schema's
//! index set.

use super::*;

fn index_names(store: &SqliteStore) -> Vec<String> {
    let conn = store.lock_reader();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// SQLite applies URI options in order, so the LAST `mode` wins: a URI ending in `mode=rwc`
/// opens the named file read-write-create even after an earlier `mode=memory`. The store must
/// open that durable file rather than silently route to a private in-memory database.
#[test]
fn the_last_mode_parameter_decides_memory_routing_as_sqlite_does() {
    let dir = tempdir();
    let file = dir.join("last-mode.db");
    let uri = format!("file:{}?mode=memory&mode=rwc", file.display());
    let store = SqliteStore::open(&uri, 5000).expect("a file URI whose last mode is rwc opens");
    assert!(
        !store.readers.is_empty(),
        "{uri}: the last mode is rwc, so this is a file-backed store with a reader pool"
    );
    store.put_key(&sample_key("vk_last_mode", "g")).unwrap();
    drop(store);
    assert!(file.exists(), "{uri}: SQLite wrote the named file");
    let reopened = SqliteStore::open(file.to_str().unwrap(), 5000).unwrap();
    assert!(
        reopened.get_key("vk_last_mode").unwrap().is_some(),
        "the key is durable in the named file"
    );

    // And the other order: a last `mode=memory` is memory.
    let memory = format!(
        "file:{}?mode=rwc&mode=memory",
        dir.join("never.db").display()
    );
    let store = SqliteStore::open(&memory, 5000).unwrap();
    assert!(
        store.readers.is_empty(),
        "{memory}: the last mode is memory"
    );
    assert!(
        !dir.join("never.db").exists(),
        "{memory}: no file is created"
    );
}

/// SQLite ignores the rest of a URI path after `%00`, so `gov.db%00junk` names `gov.db`. The
/// store's private pre-create must create THAT file 0600, not give up and leave SQLite to create
/// the secrets-bearing file under the umask.
#[cfg(unix)]
#[test]
fn a_nul_escape_in_a_uri_path_still_precreates_the_file_sqlite_opens_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir();
    let file = dir.join("nul-path.db");
    let uri = format!("file:{}%00junk", file.display());
    let store = SqliteStore::open(&uri, 5000).expect("SQLite opens the truncated path");
    store.put_key(&sample_key("vk_nul", "g")).unwrap();
    drop(store);
    let mode = std::fs::metadata(&file)
        .expect("SQLite opened the path before %00")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the database file is private");
}

/// A record put (and its empty-value strike) is a plane write: it commits at `synchronous=FULL`,
/// like the conditional record transaction over the same table, so a power cut cannot hand back
/// the old state.
#[test]
fn a_record_put_commits_at_full_sync() {
    let dir = tempdir();
    let store = SqliteStore::open(dir.join("sync.db").to_str().unwrap(), 5000).unwrap();
    store
        .put_usage("sync-bucket", 1, &UsageLedger::default())
        .unwrap();
    let level = |store: &SqliteStore| -> i64 {
        store
            .lock_writer()
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(level(&store), 1, "a usage put commits at NORMAL");
    store.v3_record_put("schema", b"key", b"value").unwrap();
    assert_eq!(level(&store), 2, "a record put commits at FULL");
    store
        .put_usage("sync-bucket", 1, &UsageLedger::default())
        .unwrap();
    store.v3_record_put("schema", b"key", b"").unwrap();
    assert_eq!(level(&store), 2, "a record strike commits at FULL");
}

/// No query reads `keys` by group or `audit_log` by resource, so the schema carries no index for
/// either (each only cost a B-tree write per commit). An upgraded file loses them too.
#[test]
fn the_schema_carries_no_index_without_a_reader() {
    const UNREAD: [&str; 2] = ["audit_resource_seq_idx", "keys_group_live_idx"];
    let dir = tempdir();
    let path = dir.join("indexes.db");
    let path = path.to_str().unwrap();
    let store = SqliteStore::open(path, 5000).unwrap();
    let fresh = index_names(&store);
    for name in UNREAD {
        assert!(
            !fresh.contains(&name.to_string()),
            "fresh schema has {name}: {fresh:?}"
        );
    }
    store
        .lock_writer()
        .execute_batch(
            "CREATE INDEX audit_resource_seq_idx ON audit_log (resource, seq);
             CREATE INDEX keys_group_live_idx ON keys (key_group) WHERE deleted_at IS NULL;",
        )
        .unwrap();
    drop(store);
    let reopened = SqliteStore::open(path, 5000).unwrap();
    let upgraded = index_names(&reopened);
    for name in UNREAD {
        assert!(
            !upgraded.contains(&name.to_string()),
            "reopened file kept {name}: {upgraded:?}"
        );
    }
    assert!(
        upgraded.contains(&"keys_revision_idx".to_string()),
        "{upgraded:?}"
    );
}

/// Key timestamps are full-width `u64`s stored by bit pattern; `list_keys` lists them in that
/// unsigned order, the order every expiry check and the migration use, so a creation instant at
/// or past 2^63 sorts after an ordinary one.
#[test]
fn list_keys_orders_by_unsigned_creation_time() {
    let store = SqliteStore::open_in_memory().unwrap();
    let mut late = sample_key("vk_late", "g");
    late.created_at = 1 << 63;
    let mut early = sample_key("vk_early", "g");
    early.created_at = 1;
    store.put_key(&late).unwrap();
    store.put_key(&early).unwrap();
    let ids: Vec<String> = store
        .list_keys()
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .collect();
    assert_eq!(ids, ["vk_early", "vk_late"]);
}
