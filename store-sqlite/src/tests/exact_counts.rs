// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{
    MeteringDelta, ModelTokens, ModelTokensDelta, RecordStore, UsageDelta, UsageLedger,
};
use std::collections::BTreeMap;

fn delta(scale: u32, amount: i64, requests: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            scale,
            model: "exact-model".into(),
            usage_units: BTreeMap::from([
                ("input".into(), amount),
                ("audio_seconds".into(), amount),
            ]),
        }],
    }
}

fn meter(key: &str, scale: u32, amount: u64, requests: u64) -> MeteringDelta {
    MeteringDelta {
        scale,
        key_id: key.into(),
        bucket: 0,
        model: "exact-model".into(),
        provider: "provider".into(),
        tokens_input: amount,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests,
        billable_requests: requests,
        key_group_at_use: "group".into(),
        pricing_version: "opening".into(),
        priced_from_ms: 0,
        usage_units: BTreeMap::from([("audio_seconds".into(), amount)]),
    }
}

fn exercise(store: &dyn RecordStore, key: &str) {
    store.add_usage(key, 0, &delta(0, 2, 1)).unwrap();
    let op = OpId::from_parts(0xe81, 1);
    let cells = [(key, 0, delta(6, 123_456, 2))];
    store.add_usage_batch_deduped(op, &cells).unwrap();
    store.add_usage_batch_deduped(op, &cells).unwrap();
    let got = store.get_usage(key, 0).unwrap();
    assert_eq!((got.requests, got.billable_requests), (3, 3));
    assert_eq!(got.models[0].scale, 6);
    assert_eq!(got.models[0].usage_units["input"], 2_123_456);
    assert_eq!(got.models[0].usage_units["audio_seconds"], 2_123_456);
    store.add_usage(key, 0, &delta(6, -123_455, 0)).unwrap();
    assert_eq!(
        store.get_usage(key, 0).unwrap().models[0].usage_units["input"],
        2_000_001
    );
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 0, delta(6, 1, 2))])
        .is_err());

    store.add_metering(&meter(key, 0, 2, 1)).unwrap();
    let op = OpId::from_parts(0xe81, 2);
    let meters = [meter(key, 6, 123_456, 2)];
    store.add_metering_batch_deduped(op, &meters).unwrap();
    store.add_metering_batch_deduped(op, &meters).unwrap();
    let before = store.list_metering(0).unwrap();
    let got = before.iter().find(|row| row.key_id == key).unwrap();
    assert_eq!(
        (
            got.scale,
            got.tokens_input,
            got.requests,
            got.billable_requests
        ),
        (6, 2_123_456, 3, 3)
    );
    assert_eq!(got.usage_units["audio_seconds"], 2_123_456);
    let op = OpId::from_parts(0xe81, 3);
    assert!(store
        .add_metering_batch_deduped(
            op,
            &[meter(key, 6, 1, 1), meter(key, 6, i64::MAX as u64, 1)]
        )
        .is_err());
    assert_eq!(
        store.list_metering(0).unwrap(),
        before,
        "overflow rolls the entire batch back"
    );
    store
        .add_metering_batch_deduped(op, &[meter(key, 6, 1, 1)])
        .unwrap();

    let max = UsageLedger {
        requests: 7,
        billable_requests: 5,
        models: vec![ModelTokens {
            scale: 6,
            model: "exact-model".into(),
            usage_units: BTreeMap::from([("input".into(), i64::MAX as u64)]),
        }],
    };
    store.put_usage(key, 0, &max).unwrap();
    let op = OpId::from_parts(0xe81, 4);
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1)), (key, 0, delta(6, 1, 1))])
        .is_err());
    assert_eq!(store.get_usage(key, 0).unwrap(), max);
    assert_eq!(store.get_usage(key, 1).unwrap(), UsageLedger::default());
    // A refused operation leaves no receipt; the same id can now commit another body.
    store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1))])
        .unwrap();
    assert_eq!(
        store.get_usage(key, 1).unwrap().models[0].usage_units["input"],
        1
    );
    assert!(store.add_usage(key, 2, &delta(3, 1, 1)).is_err());
    assert_eq!(store.get_usage(key, 2).unwrap(), UsageLedger::default());
}

#[test]
fn exact_counts_decimal_legacy_replay_and_atomic_overflow() {
    let store = SqliteStore::open_in_memory().unwrap();
    store.put_key(&sample_key("exact-counts", "g")).unwrap();
    exercise(&store, "exact-counts");
}

fn migrated(store: &dyn RecordStore) {
    let row = store.get_usage("legacy", 0).unwrap();
    assert_eq!((row.requests, row.billable_requests), (7, 5));
    let model = row
        .models
        .iter()
        .find(|row| row.model == "exact-model")
        .unwrap();
    assert_eq!(model.scale, 6);
    assert_eq!(model.usage_units["input"], 2_000_000);
    assert_eq!(model.usage_units["audio_seconds"], 3_000_000);
    let rows = store.list_metering(0).unwrap();
    let row = rows.iter().find(|row| row.key_id == "legacy").unwrap();
    assert_eq!(
        (row.scale, row.tokens_input, row.requests),
        (6, 4_000_000, 9)
    );
    assert_eq!(row.usage_units["audio_seconds"], 5_000_000);
}

#[test]
fn exact_counts_legacy_migration_preflight_reopen_idempotent() {
    let dir = tempdir();
    let path = dir.join("exact-counts.db");
    let path = path.to_str().unwrap();
    let store = SqliteStore::open(path, 5000).unwrap();
    store.put_key(&sample_key("legacy", "g")).unwrap();
    drop(store);
    let raw = Connection::open(path).unwrap();
    raw.execute_batch("PRAGMA user_version=7;
        INSERT INTO usage_windows(bucket_id,window_start,model,requests,billable_requests) VALUES('legacy',0,'',7,5);
        INSERT INTO usage_windows(bucket_id,window_start,model,tokens_input) VALUES('legacy',0,'exact-model',2);
        INSERT INTO usage_window_units(bucket_id,window_start,model,unit,count) VALUES('legacy',0,'exact-model','audio_seconds',9223372036855);
        INSERT INTO usage_metering(key_id,bucket,model,provider,tokens_input,requests) VALUES('legacy',0,'exact-model','provider',4,9);
        INSERT INTO usage_metering_units(key_id,bucket,model,provider,unit,count) VALUES('legacy',0,'exact-model','provider','audio_seconds',5);").unwrap();
    let legacy = serde_json::to_vec(&serde_json::json!({"requests":7,"billable_requests":5,"models":[{"model":"exact-model","usage_units":{"input":2,"audio_seconds":3}}]})).unwrap();
    raw.execute(
        "INSERT INTO usage_window_exact(window_start,bucket_id,ledger) VALUES(0,'legacy',?1)",
        params![legacy],
    )
    .unwrap();
    let legacy_meter = serde_json::to_vec(&serde_json::json!({
        "key_id":"legacy", "model":"exact-model", "provider":"provider",
        "tokens_input":4, "tokens_output":0, "tokens_cache_read":0,
        "tokens_cache_write":0, "requests":9, "usage_units":{"audio_seconds":5}
    }))
    .unwrap();
    raw.execute("INSERT INTO usage_metering_exact(bucket,key_id,provider,model,priced_from_ms,key_group_at_use,pricing_version,ledger) VALUES('0','legacy','provider','exact-model',0,'','',?1)",params![legacy_meter]).unwrap();
    assert!(SqliteStore::open(path, 5000).is_err());
    let value: i64 = raw
        .query_row(
            "SELECT tokens_input FROM usage_windows WHERE model='exact-model'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(value, 2);
    let version: i64 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 7);
    raw.execute("UPDATE usage_window_units SET count=3", [])
        .unwrap();
    // The JSON authority is also checked before any SQL mirror is converted.
    let too_large = serde_json::to_vec(&serde_json::json!({"requests":7,"billable_requests":5,
        "models":[{"model":"exact-model","usage_units":{"input":9223372036855u64,"audio_seconds":3}}]})).unwrap();
    raw.execute(
        "UPDATE usage_window_exact SET ledger=?1",
        params![too_large],
    )
    .unwrap();
    assert!(SqliteStore::open(path, 5000).is_err());
    let value: i64 = raw
        .query_row(
            "SELECT tokens_input FROM usage_windows WHERE model='exact-model'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(value, 2);
    let legacy = serde_json::to_vec(&serde_json::json!({"requests":7,"billable_requests":5,
        "models":[{"model":"exact-model","usage_units":{"input":2,"audio_seconds":3}}]}))
    .unwrap();
    raw.execute("UPDATE usage_window_exact SET ledger=?1", params![legacy])
        .unwrap();
    drop(raw);
    for _ in 0..2 {
        let store = SqliteStore::open(path, 5000).unwrap();
        migrated(&store);
    }
    let store = SqliteStore::open(path, 5000).unwrap();
    store.add_usage("legacy", 0, &delta(6, 1, 0)).unwrap();
    drop(store);
    let store = SqliteStore::open(path, 5000).unwrap();
    assert_eq!(
        store.get_usage("legacy", 0).unwrap().models[0].usage_units["input"],
        2_000_001
    );
}
