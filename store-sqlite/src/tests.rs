// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_api::{AwsCredential, ModelTokensDelta, Store, TierTokensDelta, VirtualKey};

fn sample_key(id: &str, hash: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        key_hash: hash.to_string(),
        name: "test".to_string(),
        allowed_pools: None,
        enabled: true,
        created_at: 0,
        group: None,
        labels: std::collections::BTreeMap::new(),
    }
}

fn delta(requests: i64, model: &str, input: i64, output: i64) -> UsageDelta {
    UsageDelta {
        requests,
        // Default the billable delta to mirror `requests` for the token-focused helpers; the
        // dedicated split test drives `billable_requests` independently.
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: model.to_string(),
            tokens: TierTokensDelta {
                input,
                output,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    }
}

/// The TRAIT `add_usage` (fleet-additive flush primitive) accumulates per-model signed deltas
/// atomically and floors at 0 on an over-refund; `put_usage` stays an absolute overwrite.
#[test]
fn trait_add_usage_accumulates_and_floors() {
    let s = SqliteStore::open(":memory:", 5000).unwrap();
    let base = UsageLedger {
        requests: 3,
        billable_requests: 3,
        models: vec![ModelTokens {
            model: "gpt-5".into(),
            tokens: TierTokens {
                input: 9,
                output: 4,
                cache_read: 1,
                cache_write: 0,
            },
        }],
    };
    s.put_usage("k_add", 100, &base).unwrap();
    Store::add_usage(&s, "k_add", 100, &delta(2, "gpt-5", 1, 1)).unwrap();
    let u = s.get_usage("k_add", 100).unwrap();
    assert_eq!(u.requests, 5);
    let t = u.tokens_for("gpt-5").unwrap();
    assert_eq!((t.input, t.output, t.cache_read), (10, 5, 1));
    // A second model materializes its own row.
    Store::add_usage(&s, "k_add", 100, &delta(0, "haiku", 7, 3)).unwrap();
    assert_eq!(s.get_usage("k_add", 100).unwrap().models.len(), 2);
    // Negative (refund) delta lands; an over-refund floors at 0.
    Store::add_usage(&s, "k_add", 100, &delta(-10, "gpt-5", -100, -100)).unwrap();
    let u = s.get_usage("k_add", 100).unwrap();
    assert_eq!(u.requests, 0);
    assert_eq!(u.tokens_for("gpt-5").unwrap().input, 0);
    // Fresh row via add alone (INSERT arm), floored on a negative first delta.
    Store::add_usage(&s, "k_new", 100, &delta(1, "m", -5, 7)).unwrap();
    let u = s.get_usage("k_new", 100).unwrap();
    assert_eq!(u.requests, 1);
    let t = u.tokens_for("m").unwrap();
    assert_eq!((t.input, t.output), (0, 7));
}

/// `put_usage` is an ABSOLUTE overwrite: a model row present in the old snapshot but absent
/// from the new one is REMOVED (the whole (bucket, window) record is replaced).
#[test]
fn put_usage_replaces_whole_ledger() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_usage(
        "k",
        0,
        &UsageLedger {
            requests: 2,
            billable_requests: 2,
            models: vec![
                ModelTokens {
                    model: "a".into(),
                    tokens: TierTokens {
                        input: 1,
                        output: 1,
                        cache_read: 0,
                        cache_write: 0,
                    },
                },
                ModelTokens {
                    model: "b".into(),
                    tokens: TierTokens {
                        input: 2,
                        output: 2,
                        cache_read: 0,
                        cache_write: 0,
                    },
                },
            ],
        },
    )
    .unwrap();
    s.put_usage(
        "k",
        0,
        &UsageLedger {
            requests: 1,
            billable_requests: 1,
            models: vec![ModelTokens {
                model: "a".into(),
                tokens: TierTokens {
                    input: 9,
                    output: 0,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        },
    )
    .unwrap();
    let u = s.get_usage("k", 0).unwrap();
    assert_eq!(u.requests, 1);
    assert_eq!(
        u.models.len(),
        1,
        "stale model rows are replaced, not merged"
    );
    assert_eq!(u.tokens_for("a").unwrap().input, 9);
}

/// v4: `billable_requests` persists and accumulates INDEPENDENTLY of `requests` (admission
/// count vs the 2xx-only fee base). An absolute put with requests != billable_requests survives
/// a get; an additive delta touches each counter on its own axis and floors each at 0.
#[test]
fn billable_requests_roundtrips_independently_of_requests() {
    let s = SqliteStore::open_in_memory().unwrap();
    // Admission 5, but only 3 billable (2 non-2xx refunded off the fee base).
    s.put_usage(
        "k_bill",
        7,
        &UsageLedger {
            requests: 5,
            billable_requests: 3,
            models: vec![],
        },
    )
    .unwrap();
    let u = s.get_usage("k_bill", 7).unwrap();
    assert_eq!((u.requests, u.billable_requests), (5, 3));
    // A delta that refunds one non-2xx: -2 off both axes lands independently and floors at 0.
    Store::add_usage(
        &s,
        "k_bill",
        7,
        &UsageDelta {
            requests: -2,
            billable_requests: -2,
            models: vec![],
        },
    )
    .unwrap();
    let u = s.get_usage("k_bill", 7).unwrap();
    assert_eq!((u.requests, u.billable_requests), (3, 1));
    // An over-refund of the fee base alone floors billable_requests at 0 while requests holds.
    Store::add_usage(
        &s,
        "k_bill",
        7,
        &UsageDelta {
            requests: 0,
            billable_requests: -100,
            models: vec![],
        },
    )
    .unwrap();
    let u = s.get_usage("k_bill", 7).unwrap();
    assert_eq!(
        (u.requests, u.billable_requests),
        (3, 0),
        "the fee base floors at 0 without disturbing the admission count"
    );
}

/// SCHEMA BUMP (v4): opening a database that still carries a pre-v4 schema (here: a v1-shaped
/// `usage_counters` + inline-limit `virtual_keys`) DROPS and recreates the governance tables
/// (1.5.0 unreleased: bump, not migrate) and stamps `user_version = 4`. A v4 database re-opens
/// untouched.
#[test]
fn legacy_schema_is_bumped_to_v4_on_open() {
    let dir = std::env::temp_dir().join(format!("busbar-sqlite-bump-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("legacy.db");
    let path_str = path.to_str().unwrap().to_string();
    {
        // Write a legacy (v1-shaped) database by hand.
        let conn = Connection::open(&path_str).unwrap();
        conn.execute_batch(
            "CREATE TABLE virtual_keys (
                 id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
                 allowed_pools TEXT NOT NULL DEFAULT '', max_budget_cents INTEGER,
                 budget_period TEXT NOT NULL DEFAULT 'total', rpm_limit INTEGER,
                 tpm_limit INTEGER, enabled INTEGER NOT NULL DEFAULT 1,
                 created_at INTEGER NOT NULL);
             CREATE TABLE usage_counters (
                 key_id TEXT NOT NULL, window_start INTEGER NOT NULL,
                 spend_cents INTEGER NOT NULL DEFAULT 0, tokens INTEGER NOT NULL DEFAULT 0,
                 requests INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (key_id, window_start));
             INSERT INTO usage_counters VALUES ('vk_old', 0, 42, 9, 3);",
        )
        .unwrap();
    }
    let s = SqliteStore::open(&path_str, 5000).unwrap();
    // The legacy table is gone; the v4 ledger is empty and functional.
    assert_eq!(s.get_usage("vk_old", 0).unwrap(), UsageLedger::default());
    Store::add_usage(&s, "vk_old", 0, &delta(1, "m", 1, 1)).unwrap();
    assert_eq!(s.get_usage("vk_old", 0).unwrap().requests, 1);
    let version: i64 = s
        .lock_conn()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, SCHEMA_VERSION);
    // Re-open: v4 data survives (no re-drop).
    drop(s);
    let s2 = SqliteStore::open(&path_str, 5000).unwrap();
    assert_eq!(
        s2.get_usage("vk_old", 0).unwrap().requests,
        1,
        "a v4 database must re-open without being dropped"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A migration that fails partway must leave the database EXACTLY as it was. Without one
/// transaction over the drop/recreate/stamp, `execute_batch` commits the drops on their own and
/// the legacy tables are gone forever while the schema is never rebuilt - unrecoverable data
/// loss from a single failed open.
///
/// The failure is induced with a VIEW named `denylist`: the drop list drops TABLEs, so the view
/// survives it, and `CREATE TABLE IF NOT EXISTS denylist` in SCHEMA then errors on the name
/// collision - a real sqlite failure at the recreate step, not a mocked one.
#[test]
fn a_failed_migration_leaves_the_legacy_database_intact() {
    let dir = std::env::temp_dir().join(format!("busbar-sqlite-atomic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("halfway.db");
    let path_str = path.to_str().unwrap().to_string();
    {
        let conn = Connection::open(&path_str).unwrap();
        conn.execute_batch(
            "CREATE TABLE virtual_keys (id TEXT PRIMARY KEY, key_hash TEXT NOT NULL);
             INSERT INTO virtual_keys (id, key_hash) VALUES ('vk_precious', 'h');
             CREATE VIEW denylist AS SELECT id AS sub FROM virtual_keys;",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
    }

    assert!(
        SqliteStore::open(&path_str, 5000).is_err(),
        "the denylist name collision must fail the migration"
    );

    let conn = Connection::open(&path_str).unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM virtual_keys", [], |r| r.get(0))
        .expect("the legacy table must still exist after a failed migration");
    assert_eq!(rows, 1, "the legacy row must survive a failed migration");
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1, "a failed migration must not stamp the version");
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `group` + `labels` persist through the sqlite row round-trip (the `key_group` column).
#[test]
fn group_and_labels_roundtrip() {
    let s = SqliteStore::open_in_memory().unwrap();
    let mut k = sample_key("kg", "hashG");
    k.group = Some("growth".to_string());
    k.labels = std::collections::BTreeMap::from([
        ("team".to_string(), "growth".to_string()),
        ("env".to_string(), "prod".to_string()),
    ]);
    s.put_key(&k).unwrap();
    let got = s.get_key("kg").unwrap().unwrap();
    assert_eq!(got.group.as_deref(), Some("growth"));
    assert_eq!(got.labels.get("env").map(String::as_str), Some("prod"));
    assert_eq!(got, k);
}

/// C6 grant round-trip (v3): NULL (grant omitted = ALL pools) vs '[]' (explicit empty grant =
/// NO pools) must survive the SQL column faithfully and never collapse into each other.
#[test]
fn allowed_pools_none_vs_empty_roundtrip() {
    let s = SqliteStore::open_in_memory().unwrap();
    let mut all = sample_key("k_all", "hash_all");
    all.allowed_pools = None;
    let mut none = sample_key("k_none", "hash_none");
    none.allowed_pools = Some(vec![]);
    let mut some = sample_key("k_some", "hash_some");
    some.allowed_pools = Some(vec!["fast".to_string()]);
    s.put_key(&all).unwrap();
    s.put_key(&none).unwrap();
    s.put_key(&some).unwrap();
    assert_eq!(s.get_key("k_all").unwrap().unwrap().allowed_pools, None);
    assert_eq!(
        s.get_key("k_none").unwrap().unwrap().allowed_pools,
        Some(vec![])
    );
    assert_eq!(
        s.get_key("k_some").unwrap().unwrap().allowed_pools,
        Some(vec!["fast".to_string()])
    );
}

/// DI-3: direct-DB NEGATIVE stored ledger counters clamp to 0 on read, never wrap to a huge u64.
#[test]
fn test_negative_ledger_counters_clamp_to_zero_on_read() {
    let s = SqliteStore::open_in_memory().unwrap();
    {
        let conn = s.lock_conn();
        conn.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests) VALUES ('kneg', 0, -3)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage_ledger (bucket_id, window_start, model,
                 tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
             VALUES ('kneg', 0, 'm', -5, -1, -2, -4)",
            [],
        )
        .unwrap();
    }
    let u = s.get_usage("kneg", 0).unwrap();
    assert_eq!(
        u.requests, 0,
        "a negative stored request counter must clamp to 0"
    );
    let t = u.tokens_for("m").unwrap();
    assert_eq!(
        (t.input, t.output, t.cache_read, t.cache_write),
        (0, 0, 0, 0),
        "negative stored token counters clamp to 0"
    );
}

/// DI-3 parity for metering: a direct-DB negative metering counter clamps to 0 on read.
#[test]
fn test_negative_metering_counters_clamp_to_zero_on_read() {
    let s = SqliteStore::open_in_memory().unwrap();
    {
        let conn = s.lock_conn();
        conn.execute(
                "INSERT INTO usage_metering (key_id, bucket, model, provider,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests)
                 VALUES ('kneg', 0, 'm', 'p', -5, -1, -2, -3, -4)",
                [],
            )
            .unwrap();
    }
    let rows = s.list_metering(0).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        (
            r.tokens_input,
            r.tokens_output,
            r.tokens_cache_read,
            r.tokens_cache_creation,
            r.requests
        ),
        (0, 0, 0, 0, 0)
    );
}

/// A pool name CONTAINING a comma must survive a persist/read round-trip as ONE pool.
#[test]
fn test_comma_bearing_pool_name_roundtrips_as_single_pool() {
    let s = SqliteStore::open_in_memory().unwrap();
    let mut k = sample_key("kc", "hashCOMMA");
    k.allowed_pools = Some(vec!["prod,special".to_string(), "plain".to_string()]);
    s.put_key(&k).unwrap();
    let got = s.get_key("kc").unwrap().unwrap();
    assert_eq!(
        got.allowed_pools,
        Some(vec!["prod,special".to_string(), "plain".to_string()])
    );
}

/// `pools_from_storage` (v3): NULL reads as None (all pools); a JSON array reads exactly; a
/// malformed direct-DB value reads as the EMPTY grant (fail-restrictive, never "all").
#[test]
fn test_pools_from_storage_v3_semantics() {
    assert_eq!(pools_from_storage(None), None);
    assert_eq!(
        pools_from_storage(Some("[\"a\",\"b\"]".to_string())),
        Some(vec!["a".to_string(), "b".to_string()])
    );
    assert_eq!(pools_from_storage(Some("[]".to_string())), Some(vec![]));
    assert_eq!(
        pools_from_storage(Some("not-json".to_string())),
        Some(vec![]),
        "a malformed stored grant must read restrictive (no pools), never as all pools"
    );
}

#[test]
fn test_poisoned_conn_lock_recovers_not_panics() {
    // Regression: a panic while the SqliteStore `conn` Mutex is held poisons it. Every `Store`
    // method acquires the connection via `lock_conn`, which must RECOVER (via into_inner)
    // rather than `.unwrap()`-panic on every subsequent call.
    use std::sync::Arc;

    let s = Arc::new(SqliteStore::open_in_memory().unwrap());
    Store::add_usage(&*s, "k_poison", 100, &delta(1, "m", 50, 0)).unwrap();

    let s2 = Arc::clone(&s);
    let _ = std::thread::spawn(move || {
        let _guard = s2.conn.lock().unwrap();
        panic!("intentional poison");
    })
    .join();
    assert!(
        s.conn.is_poisoned(),
        "conn lock must be poisoned for the test"
    );

    assert_eq!(
        s.get_usage("k_poison", 100).unwrap().requests,
        1,
        "get_usage must recover the poisoned conn lock instead of panicking"
    );
    Store::add_usage(&*s, "k_poison", 100, &delta(1, "m", 25, 0)).unwrap();
    let u = s.get_usage("k_poison", 100).unwrap();
    assert_eq!(u.requests, 2);
    assert_eq!(u.tokens_for("m").unwrap().input, 75);
}

/// Durable audit (#17): `append_audit` persists records and `list_audit` returns them
/// oldest-first by `seq`, verbatim; a re-append of the same seq upserts (idempotent).
#[test]
fn test_audit_append_and_list_roundtrip() {
    use busbar_api::AuditRecord;
    let s = SqliteStore::open_in_memory().unwrap();
    let mk = |seq: u64, prev: &str, hash: &str| AuditRecord {
        seq,
        ts: 1000 + seq,
        action: "hook.register".into(),
        resource: format!("hook:{seq}"),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: prev.into(),
        hash: hash.into(),
    };
    s.append_audit(&mk(2, "h1", "h2")).unwrap();
    s.append_audit(&mk(1, "", "h1")).unwrap();
    s.append_audit(&mk(3, "h2", "h3")).unwrap();
    let got = s.list_audit().unwrap();
    assert_eq!(got.len(), 3);
    assert_eq!((got[0].seq, got[1].seq, got[2].seq), (1, 2, 3));
    assert_eq!(got[0].prev_hash, "");
    assert_eq!(got[1].prev_hash, "h1");
    s.append_audit(&mk(2, "h1", "h2b")).unwrap();
    let got2 = s.list_audit().unwrap();
    assert_eq!(got2.len(), 3);
    assert_eq!(got2[1].hash, "h2b");
}

/// The signed-token revocation denylist (P3): `add_denylist` records a subject, `list_denylist`
/// returns it, and adding the same sub twice is idempotent (the list holds it exactly once).
#[test]
fn test_denylist_add_and_list_idempotent() {
    let s = SqliteStore::open_in_memory().unwrap();
    assert!(s.list_denylist().unwrap().is_empty());
    s.add_denylist("sub-abc", "compromised").unwrap();
    s.add_denylist("sub-def", "rotation").unwrap();
    let mut got = s.list_denylist().unwrap();
    got.sort();
    assert_eq!(got, vec!["sub-abc".to_string(), "sub-def".to_string()]);
    // Adding the same sub again (even with a new reason) is idempotent - one entry, not two.
    s.add_denylist("sub-abc", "still compromised").unwrap();
    let got = s.list_denylist().unwrap();
    assert_eq!(got.iter().filter(|x| *x == "sub-abc").count(), 1);
    assert_eq!(got.len(), 2);
}

#[test]
fn test_key_crud_roundtrip() {
    let s = SqliteStore::open_in_memory().unwrap();
    let k = sample_key("k1", "hashAAA");
    s.put_key(&k).unwrap();

    assert_eq!(s.get_key("k1").unwrap().as_ref(), Some(&k));
    assert_eq!(s.get_key_by_hash("hashAAA").unwrap().as_ref(), Some(&k));
    assert_eq!(s.get_key("missing").unwrap(), None);
    assert_eq!(s.list_keys().unwrap(), vec![k.clone()]);

    let mut k2 = k.clone();
    k2.enabled = false;
    k2.allowed_pools = Some(vec![]);
    s.put_key(&k2).unwrap();
    let got = s.get_key("k1").unwrap().unwrap();
    assert!(!got.enabled);
    assert_eq!(got.allowed_pools, Some(vec![]));

    s.delete_key("k1").unwrap();
    assert_eq!(s.get_key("k1").unwrap(), None);
}

#[test]
fn test_delete_key_removes_key_and_ledger_atomically() {
    // After delete, both the key row AND all of its ledger rows across windows are gone.
    let s = SqliteStore::open_in_memory().unwrap();
    let key = sample_key("vk_delete_me", "hash_delete_me");
    s.put_key(&key).unwrap();
    Store::add_usage(&s, "vk_delete_me", 100, &delta(1, "m", 1000, 0)).unwrap();
    Store::add_usage(&s, "vk_delete_me", 200, &delta(1, "m", 50, 0)).unwrap();
    assert!(s.get_key("vk_delete_me").unwrap().is_some());
    assert_eq!(s.get_usage("vk_delete_me", 100).unwrap().requests, 1);

    s.delete_key("vk_delete_me").unwrap();

    assert!(s.get_key("vk_delete_me").unwrap().is_none());
    assert_eq!(
        s.get_usage("vk_delete_me", 100).unwrap(),
        UsageLedger::default()
    );
    assert_eq!(
        s.get_usage("vk_delete_me", 200).unwrap(),
        UsageLedger::default()
    );
}

#[test]
fn test_delete_key_removes_usage_metering_rows() {
    // The raw per-(key_id,bucket,model,provider) billing ledger keys on the same id and must not
    // survive a delete: an orphaned row here silently corrupts cost reconstruction if the id is
    // ever reused.
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_meter_del", "hash_meter_del"))
        .unwrap();
    let bucket = 20_270_101_u64;
    s.add_metering(&MeteringDelta {
        key_id: "vk_meter_del".into(),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_creation: 0,
        requests: 1,
    })
    .unwrap();
    assert!(
        s.list_metering(bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == "vk_meter_del"),
        "metering row must exist before delete"
    );
    s.delete_key("vk_meter_del").unwrap();
    assert!(
        !s.list_metering(bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == "vk_meter_del"),
        "delete_key must remove usage_metering rows too"
    );
}

#[test]
fn test_delete_key_does_not_inherit_stale_ledger_on_recreate() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_reuse", "hash_vk_reuse")).unwrap();
    Store::add_usage(&s, "vk_reuse", 100, &delta(1, "m", 9999, 0)).unwrap();
    s.delete_key("vk_reuse").unwrap();
    s.put_key(&sample_key("vk_reuse", "hash_vk_reuse")).unwrap();
    assert_eq!(
        s.get_usage("vk_reuse", 100).unwrap(),
        UsageLedger::default(),
        "re-created key must not inherit the deleted key's ledger"
    );
}

/// The AWS-credential path (`put_aws_credential`, `list_aws_credentials`,
/// `put_key_with_aws_credential`, and the cascade-delete of `aws_credentials` inside `delete_key`)
/// had zero test coverage anywhere in this crate despite `delete_key`'s own doc comment claiming
/// the cascade as a load-bearing security property ("a revoked key's SigV4 credential must NOT
/// outlive the key").
#[test]
fn test_aws_credential_path_end_to_end() {
    let s = SqliteStore::open_in_memory().unwrap();

    // put_key_with_aws_credential: the atomic mint path.
    let key = sample_key("vk_cred_mint", "hash_cred_mint");
    let cred = AwsCredential {
        access_key_id: "AKIACREDMINT".into(),
        key_id: "vk_cred_mint".into(),
        secret_access_key: "secret1".into(),
    };
    s.put_key_with_aws_credential(&key, &cred).unwrap();
    assert!(s.get_key("vk_cred_mint").unwrap().is_some());
    let creds = s.list_aws_credentials().unwrap();
    assert!(
        creds
            .iter()
            .any(|c| c.access_key_id == "AKIACREDMINT" && c.key_id == "vk_cred_mint"),
        "put_key_with_aws_credential must mint both the key and its credential atomically"
    );

    // put_aws_credential: standalone add (a second credential for the same key).
    let cred2 = AwsCredential {
        access_key_id: "AKIACREDSTANDALONE".into(),
        key_id: "vk_cred_mint".into(),
        secret_access_key: "secret2".into(),
    };
    s.put_aws_credential(&cred2).unwrap();
    let creds = s.list_aws_credentials().unwrap();
    assert!(
        creds
            .iter()
            .any(|c| c.access_key_id == "AKIACREDSTANDALONE"),
        "put_aws_credential must add a standalone credential"
    );
    assert_eq!(
        creds.iter().filter(|c| c.key_id == "vk_cred_mint").count(),
        2,
        "a key may have more than one credential"
    );

    // The cascade-delete: delete_key must remove EVERY credential tied to that key.
    s.delete_key("vk_cred_mint").unwrap();
    assert!(s.get_key("vk_cred_mint").unwrap().is_none());
    let creds_after = s.list_aws_credentials().unwrap();
    assert!(
        !creds_after.iter().any(|c| c.key_id == "vk_cred_mint"),
        "delete_key must remove ALL AWS credentials tied to the key, not just leave them behind: \
         a revoked key's SigV4 credential must not outlive it. Survivors: {creds_after:?}"
    );
}
