// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::correction;
use busbar_contract::abi::store::OpId;

fn ledger(quantity: i128) -> UsageLedger {
    UsageLedger {
        requests: u64::MAX,
        billable_requests: u64::MAX,
        models: vec![ModelTokens {
            scale: 6,
            model: "wide".into(),
            usage_units: [(UNIT_INPUT.into(), quantity), ("custom".into(), quantity)].into(),
        }],
    }
}

fn change(quantity: i128) -> UsageDelta {
    UsageDelta {
        requests: 0,
        billable_requests: 0,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: "wide".into(),
            usage_units: [(UNIT_INPUT.into(), quantity), ("custom".into(), quantity)].into(),
        }],
    }
}

fn meter(quantity: i128, model: &str) -> MeteringDelta {
    MeteringDelta {
        scale: 6,
        key_id: "wide-key".into(),
        bucket: 0,
        model: model.into(),
        provider: "provider".into(),
        tokens_input: quantity,
        tokens_output: quantity,
        tokens_cache_read: quantity,
        tokens_cache_write: quantity,
        requests: u64::MAX,
        billable_requests: u64::MAX,
        key_group_at_use: "group".into(),
        pricing_version: "price".into(),
        priced_from_ms: 0,
        usage_units: [("custom".into(), quantity)].into(),
    }
}

#[test]
fn wide_usage_numeric_authority_refunds_and_overflow_survive_reopen() {
    let dir = tempdir();
    let path = dir.join("wide-usage.db");
    let path = path.to_str().unwrap();
    let store = SqliteStore::open(path, 5000).unwrap();
    let wide = i128::from(u64::MAX) + 17;
    store.put_usage("wide-key", 0, &ledger(wide)).unwrap();
    let (mirror, bytes): (i64, Vec<u8>) = store.lock_reader().query_row(
        "SELECT tokens_input,ledger FROM usage_windows JOIN usage_window_exact USING(window_start,bucket_id) WHERE model='wide'",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(mirror, i64::MAX);
    let json = std::str::from_utf8(&bytes).unwrap();
    assert!(
        json.contains(&format!("\"input\":{wide}")),
        "numeric token: {json}"
    );
    assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(wide));
    // A refund must use exact pre-state, not the already clipped SQL mirror.
    store
        .add_usage("wide-key", 0, &change(-(wide - 7)))
        .unwrap();
    assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(7));
    let mirror: i64 = store
        .lock_reader()
        .query_row(
            "SELECT tokens_input FROM usage_windows WHERE model='wide'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(mirror, 7);
    store.put_usage("wide-key", 0, &ledger(i128::MAX)).unwrap();
    assert!(store.add_usage("wide-key", 0, &change(1)).is_err());
    assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(i128::MAX));
    assert!(store.put_usage("wide-key", 0, &ledger(-1)).is_err());
    assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(i128::MAX));
    drop(store);
    let store = SqliteStore::open(path, 5000).unwrap();
    assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(i128::MAX));
    // Ordinary signed refunds retain floor-at-zero behavior, even for the minimum delta.
    store.add_usage("wide-key", 0, &change(i128::MIN)).unwrap();
    let got = store.get_usage("wide-key", 0).unwrap();
    assert_eq!((got.requests, got.billable_requests), (u64::MAX, u64::MAX));
    assert_eq!(got.models[0].tier(UNIT_INPUT), 0);
    assert_eq!(got.models[0].tier("custom"), 0);
}

#[test]
fn wide_metering_batch_replay_and_overflow_are_atomic() {
    let dir = tempdir();
    let path = dir.join("wide-meter.db");
    let path = path.to_str().unwrap();
    let store = SqliteStore::open(path, 5000).unwrap();
    let op = OpId::from_parts(0x128, 1);
    let deltas = [meter(i128::MAX, "wide")];
    store.add_metering_batch_deduped(op, &deltas).unwrap();
    store.add_metering_batch_deduped(op, &deltas).unwrap();
    let expected = store.list_metering(0).unwrap();
    assert_eq!(expected[0].tokens_input, i128::MAX);
    assert_eq!(expected[0].usage_units["custom"], i128::MAX);
    assert_eq!(expected[0].requests, u64::MAX);
    let mirror: i64 = store
        .lock_reader()
        .query_row(
            "SELECT tokens_input FROM usage_metering WHERE model='wide'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(mirror, i64::MAX);
    let refused = OpId::from_parts(0x128, 2);
    assert!(store
        .add_metering_batch_deduped(refused, &[meter(1, "new"), meter(1, "wide")])
        .is_err());
    assert_eq!(store.list_metering(0).unwrap(), expected);
    // Refusal recorded no receipt; corrected work under that id is still new.
    store
        .add_metering_batch_deduped(refused, &[meter(1, "new")])
        .unwrap();
    drop(store);
    let store = SqliteStore::open(path, 5000).unwrap();
    store.add_metering_batch_deduped(op, &deltas).unwrap();
    let rows = store.list_metering(0).unwrap();
    assert_eq!(
        rows.iter().find(|row| row.model == "wide").unwrap(),
        &expected[0]
    );
    assert_eq!(
        rows.iter()
            .find(|row| row.model == "new")
            .unwrap()
            .tokens_input,
        1
    );
}

#[test]
fn wide_correction_compares_exact_rows_and_rejects_negative_replacements() {
    let store = SqliteStore::open_in_memory().unwrap();
    store.put_key(&sample_key("wide-key", "g")).unwrap();
    let request = correction::Request {
        version: correction::VERSION,
        op_id: OpId::from_parts(0x128, 3),
        key_id: "wide-key".into(),
        day_start: 0,
        metering: Vec::new(),
        usage: vec![correction::UsageChange {
            address: correction::UsageAddress {
                bucket_id: "wide-key".into(),
                window_start: 0,
            },
            expected: UsageLedger::default(),
            replacement: ledger(i128::MAX),
        }],
    };
    assert_eq!(
        store.apply_usage_correction(&request).unwrap(),
        correction::Decision::Applied
    );
    assert_eq!(
        store.apply_usage_correction(&request).unwrap(),
        correction::Decision::Applied
    );
    assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(i128::MAX));
    let mut invalid = request.clone();
    invalid.op_id = OpId::from_parts(0x128, 4);
    invalid.usage[0].expected = ledger(i128::MAX);
    invalid.usage[0].replacement = ledger(-1);
    assert!(store.apply_usage_correction(&invalid).is_err());
    assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(i128::MAX));
    invalid.usage[0].replacement = ledger(7);
    assert_eq!(
        store.apply_usage_correction(&invalid).unwrap(),
        correction::Decision::Applied
    );
    assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(7));
}

#[test]
fn wide_migration_promotes_whole_sql_without_real_and_fences_old_readers() {
    let dir = tempdir();
    let path = dir.join("wide-old.db");
    let path = path.to_str().unwrap();
    drop(SqliteStore::open(path, 5000).unwrap());
    let raw = Connection::open(path).unwrap();
    raw.execute_batch("PRAGMA user_version=7;
        INSERT INTO usage_windows(window_start,bucket_id,model,requests,billable_requests) VALUES(0,'old','',7,5);
        INSERT INTO usage_windows(window_start,bucket_id,model,tokens_input) VALUES(0,'old','wide',9223372036854775807);
        INSERT INTO usage_window_units(window_start,bucket_id,model,unit,count) VALUES(0,'old','wide','custom',9223372036854775807);
        INSERT INTO usage_metering(bucket,key_id,provider,model,tokens_input,requests,billable_requests) VALUES('0','old','p','wide',9223372036854775807,7,5);
        INSERT INTO usage_metering_units(bucket,key_id,provider,model,unit,count) VALUES('0','old','p','wide','custom',9223372036854775807);").unwrap();
    drop(raw);
    for _ in 0..2 {
        let store = SqliteStore::open(path, 5000).unwrap();
        let expected = i128::from(i64::MAX) * 1_000_000;
        let usage = store.get_usage("old", 0).unwrap();
        assert_eq!((usage.requests, usage.billable_requests), (7, 5));
        assert_eq!(usage.models[0].tier(UNIT_INPUT), expected);
        assert_eq!(usage.models[0].tier("custom"), expected);
        let rows = store.list_metering(0).unwrap();
        assert_eq!((rows[0].requests, rows[0].billable_requests), (7, 5));
        assert_eq!(rows[0].tokens_input, expected);
        assert_eq!(rows[0].usage_units["custom"], expected);
        let conn = store.lock_reader();
        let (kind, mirror): (String, i64) = conn
            .query_row(
                "SELECT typeof(tokens_input),tokens_input FROM usage_metering",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((kind.as_str(), mirror), ("integer", i64::MAX));
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 9);
    }
}

#[test]
fn wide_migration_keeps_v8_micro_units_and_full_width_request_counters() {
    let dir = tempdir();
    let path = dir.join("wide-v8.db");
    let path = path.to_str().unwrap();
    {
        let store = SqliteStore::open(path, 5000).unwrap();
        store.put_usage("wide-key", 0, &ledger(7)).unwrap();
        store.add_metering(&meter(11, "wide")).unwrap();
        store
            .lock_writer()
            .pragma_update(None, "user_version", 8)
            .unwrap();
    }
    for _ in 0..2 {
        let store = SqliteStore::open(path, 5000).unwrap();
        assert_eq!(store.get_usage("wide-key", 0).unwrap(), ledger(7));
        let rows = store.list_metering(0).unwrap();
        assert_eq!(rows[0].tokens_input, 11);
        assert_eq!(rows[0].usage_units["custom"], 11);
        assert_eq!(
            (rows[0].requests, rows[0].billable_requests),
            (u64::MAX, u64::MAX)
        );
    }
}
