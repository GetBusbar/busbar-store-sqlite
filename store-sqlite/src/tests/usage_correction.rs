// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Atomic correction through the actual negotiated synchronous store slot.
use super::{
    correction, exec, put_usage_in, query_all, record, Dedupe, MeteringDelta, MeteringRow, Op,
    OpId, OpRefused, OpResult, RecordStore, SqliteStore, Step, UsageDelta, UsageLedger, VirtualKey,
};
use busbar_contract::abi::sdk::store::correction::{Decision, Request, UsageAddress, UsageChange};
use busbar_contract::records::{ModelTokens, ModelTokensDelta, UNIT_INPUT, UNIT_OUTPUT};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::params;
use rusqlite::types::Value;
use std::sync::mpsc;
use std::time::Duration;

const KEY: &str = "correction-key";
const OTHER_KEY: &str = "unrelated-key";
const BUCKET: &str = "plain-key-usage";
const MODEL: &str = "serving-model";
const OPEN_UNIT: &str = "tool_calls";
const DAY: u64 = 86_400;
const WINDOW: u64 = 300;
const BUSY_TIMEOUT_MS: i64 = 5_000;
const DEADLINE: Duration = Duration::from_secs(10);
const OP_DOMAIN: u64 = 93;

fn op(serial: u64) -> OpId {
    OpId::from_parts(OP_DOMAIN, serial)
}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: "fixture-generation".into(),
        name: "correction".into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        idp_subject: None,
        binding_mode: None,
        minted_by: None,
        idp_provider: None,
    }
}

fn on_file() -> (SqliteStore, String, crate::tests::TempDir) {
    let dir = crate::tests::tempdir();
    let path = dir.join("usage-correction.db").display().to_string();
    let store = SqliteStore::open(&path, BUSY_TIMEOUT_MS).unwrap();
    store.put_key(&key(KEY)).unwrap();
    (store, path, dir)
}

fn ledger(count: u64) -> UsageLedger {
    UsageLedger {
        requests: count,
        billable_requests: count,
        models: vec![ModelTokens {
            model: MODEL.into(),
            usage_units: [(UNIT_INPUT.into(), count), (OPEN_UNIT.into(), count)].into(),
        }],
    }
}

fn delta() -> UsageDelta {
    UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            model: MODEL.into(),
            usage_units: [(UNIT_INPUT.into(), 1), (OPEN_UNIT.into(), 1)].into(),
        }],
    }
}

fn metering(key_id: &str) -> MeteringDelta {
    MeteringDelta {
        key_id: key_id.into(),
        bucket: DAY,
        model: MODEL.into(),
        provider: "fixture-provider".into(),
        tokens_input: 3,
        tokens_output: 5,
        tokens_cache_read: 7,
        tokens_cache_write: 11,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "historical-group".into(),
        pricing_version: "historical-price".into(),
        priced_from_ms: 13,
        usage_units: [(OPEN_UNIT.into(), 17)].into(),
    }
}

fn candidate(store: &SqliteStore, serial: u64) -> Request {
    let mut metering = store.list_metering(DAY).unwrap();
    metering.retain(|row| row.key_id == KEY);
    correction::canonical_metering(&mut metering);
    Request {
        version: correction::VERSION,
        op_id: op(serial),
        key_id: KEY.into(),
        day_start: DAY,
        metering,
        usage: vec![UsageChange {
            address: UsageAddress {
                bucket_id: BUCKET.into(),
                window_start: WINDOW,
            },
            expected: store.get_usage(BUCKET, WINDOW).unwrap(),
            replacement: ledger(23),
        }],
    }
}

fn apply(store: &SqliteStore, request: &Request) -> OpResult<Decision> {
    match <SqliteStore as busbar_contract::abi::sdk::store::StoreSlots>::apply_usage_correction(
        store,
        &mut Op::detached(),
        request,
    ) {
        Step::Ready(answer) => answer,
        Step::Pending { .. } => panic!("local SQLite never retains an operation across Pending"),
    }
}

// Include all physical raw rows and the receipt, so a conflict/rollback cannot hide partial effects
// behind only the public row projection. Every query observes one reader snapshot.
fn snapshot(store: &SqliteStore) -> Vec<Vec<Vec<Value>>> {
    let conn = store.lock_reader();
    let _snapshot = conn.unchecked_transaction().unwrap();
    [
        "usage_windows",
        "usage_window_units",
        "usage_window_exact",
        "usage_metering",
        "usage_metering_units",
        "store_ops",
        "store_revision",
        "keys",
    ]
    .into_iter()
    .map(|table| {
        query_all(
            &conn,
            &format!("SELECT * FROM {table} ORDER BY 1,2"),
            [],
            |row| {
                (0..row.as_ref().column_count())
                    .map(|column| row.get(column))
                    .collect()
            },
        )
        .unwrap()
    })
    .collect()
}

#[test]
fn absent_insert_all_rows_high_u64_and_receipt_replay_survive_restart() {
    let (store, path, _dir) = on_file();
    store.add_metering(&metering(KEY)).unwrap();
    let mut request = candidate(&store, 1);
    request.usage[0].replacement = ledger(u64::MAX);
    request.usage.push(UsageChange {
        address: UsageAddress {
            bucket_id: correction::ADJUST_UP_BUCKET.into(),
            window_start: u64::MAX,
        },
        expected: UsageLedger::default(),
        replacement: ledger(i64::MAX as u64 + 1),
    });
    request
        .usage
        .sort_by(|left, right| left.address.cmp(&right.address));
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    for change in &request.usage {
        assert_eq!(
            store
                .get_usage(&change.address.bucket_id, change.address.window_start)
                .unwrap(),
            change.replacement
        );
    }
    let committed = snapshot(&store);
    drop(store); // The caller lost the result and retains the exact candidate across restart.
    let reopened = SqliteStore::open(&path, BUSY_TIMEOUT_MS).unwrap();
    assert_eq!(apply(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(snapshot(&reopened), committed);
    reopened.delete_key(KEY).unwrap();
    let deleted = snapshot(&reopened);
    assert_eq!(apply(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(snapshot(&reopened), deleted);
    let mut changed = request.clone();
    changed.usage[0].replacement.requests -= 1;
    assert_eq!(apply(&reopened, &changed), Err(OpRefused::Conflict));
    assert_eq!(snapshot(&reopened), deleted);
}

#[test]
fn mismatched_usage_live_key_or_metering_has_no_effect_or_receipt() {
    let (store, _path, _dir) = on_file();
    let request = candidate(&store, 1);
    store.add_usage(BUCKET, WINDOW, &delta()).unwrap();
    let before = snapshot(&store);
    assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
    assert_eq!(snapshot(&store), before);
    let request = candidate(&store, 1); // A refused candidate never consumes its operation identity.
    store.add_metering(&metering(KEY)).unwrap();
    let before = snapshot(&store);
    assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
    assert_eq!(snapshot(&store), before);
    let request = candidate(&store, 1);
    store.delete_key(KEY).unwrap();
    let before = snapshot(&store);
    assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
    assert_eq!(snapshot(&store), before);
}

#[test]
fn every_historical_metering_identity_and_counter_participates_in_the_compare() {
    let (store, _path, _dir) = on_file();
    let original = metering(KEY);
    store.add_metering(&original).unwrap();
    let request = candidate(&store, 1);
    let changes: &[fn(&mut MeteringRow)] = &[
        |row| row.provider.push_str("-changed"),
        |row| row.model.push_str("-changed"),
        |row| row.key_group_at_use.push_str("-changed"),
        |row| row.pricing_version.push_str("-changed"),
        |row| row.priced_from_ms += 1,
        |row| row.requests += 1,
        |row| row.billable_requests += 1,
        |row| row.tokens_input += 1,
        |row| row.tokens_output += 1,
        |row| row.tokens_cache_read += 1,
        |row| row.tokens_cache_write += 1,
        |row| *row.usage_units.get_mut(OPEN_UNIT).unwrap() += 1,
        |row| {
            row.usage_units.insert("another-open-unit".into(), 1);
        },
    ];
    for mutate in changes {
        let mut changed = request.clone();
        mutate(&mut changed.metering[0]);
        let before = snapshot(&store);
        assert_eq!(apply(&store, &changed), Ok(Decision::ConditionConflict));
        assert_eq!(snapshot(&store), before);
    }
    store.put_key(&key(OTHER_KEY)).unwrap();
    store.add_metering(&metering(OTHER_KEY)).unwrap();
    // A different key in the same day does not change this complete key/day selection.
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
}

#[test]
fn complete_day_selection_includes_new_c4_attribution_cells() {
    let (store, _path, _dir) = on_file();
    let mut accrued = metering(KEY);
    store.add_metering(&accrued).unwrap();
    let request = candidate(&store, 1);
    accrued.key_group_at_use.push_str("-second");
    accrued.pricing_version.push_str("-second");
    store.add_metering(&accrued).unwrap();
    let before = snapshot(&store);
    assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
    assert_eq!(snapshot(&store), before);
    assert_eq!(apply(&store, &candidate(&store, 1)), Ok(Decision::Applied));
}

#[test]
fn later_row_abort_ignore_or_receipt_failure_rolls_back_every_effect() {
    for trigger in [
        "CREATE TRIGGER stop_correction AFTER INSERT ON usage_windows WHEN NEW.bucket_id='z-last' BEGIN SELECT RAISE(ABORT,'later row'); END;",
        "CREATE TRIGGER stop_correction BEFORE INSERT ON usage_windows WHEN NEW.bucket_id='z-last' BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TRIGGER stop_correction BEFORE INSERT ON usage_window_exact WHEN NEW.bucket_id='z-last' BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TRIGGER stop_correction BEFORE INSERT ON store_ops BEGIN SELECT RAISE(ABORT,'receipt'); END;",
        "CREATE TRIGGER stop_correction BEFORE INSERT ON store_ops BEGIN SELECT RAISE(IGNORE); END;",
    ] {
        let (store, path, _dir) = on_file();
        let mut request = candidate(&store, 1);
        request.usage.push(UsageChange { address: UsageAddress { bucket_id: "z-last".into(), window_start: WINDOW },
            expected: UsageLedger::default(), replacement: ledger(29) });
        store.lock_writer().execute_batch(trigger).unwrap();
        let before = snapshot(&store);
        assert!(matches!(apply(&store, &request), Err(OpRefused::Failed(_))));
        assert_eq!(snapshot(&store), before);
        let independent = SqliteStore::open(&path, BUSY_TIMEOUT_MS).unwrap();
        assert_eq!(snapshot(&independent), before);
        store.lock_writer().execute_batch("DROP TRIGGER stop_correction").unwrap();
        assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    }
}

#[test]
fn ordinary_put_add_and_unsigned_purge_share_the_exact_row_authority() {
    let (store, path, _dir) = on_file();
    let high_window = i64::MAX as u64 + 1;
    store
        .put_usage(BUCKET, high_window, &ledger(u64::MAX - 1))
        .unwrap();
    store.add_usage(BUCKET, high_window, &delta()).unwrap();
    assert_eq!(
        store.get_usage(BUCKET, high_window).unwrap(),
        ledger(u64::MAX)
    );
    let mut refund = delta();
    refund.requests = -1;
    refund.billable_requests = -1;
    for amount in refund.models[0].usage_units.values_mut() {
        *amount = -1;
    }
    store
        .v3_add_usage_batch(op(1), &[(BUCKET, high_window, refund)])
        .unwrap();
    assert_eq!(
        store.get_usage(BUCKET, high_window).unwrap(),
        ledger(u64::MAX - 1)
    );
    store.put_usage(BUCKET, high_window, &ledger(31)).unwrap();
    assert_eq!(store.get_usage(BUCKET, high_window).unwrap(), ledger(31));
    assert_eq!(store.v3_purge_usage_before(u64::MAX).unwrap(), 1);
    assert_eq!(
        store.get_usage(BUCKET, high_window).unwrap(),
        UsageLedger::default()
    );
    drop(store);
    let reopened = SqliteStore::open(&path, BUSY_TIMEOUT_MS).unwrap();
    assert_eq!(
        reopened.get_usage(BUCKET, high_window).unwrap(),
        UsageLedger::default()
    );
}

#[test]
fn legacy_reserved_writes_refuse_but_an_exact_old_receipt_replays_first() {
    let (store, _path, _dir) = on_file();
    let cells = [(correction::ADJUST_UP_BUCKET, WINDOW, delta())];
    let before = snapshot(&store);
    assert!(matches!(
        store.v3_add_usage_batch(op(1), &cells),
        Err(OpRefused::Refused(_))
    ));
    assert_eq!(snapshot(&store), before);
    assert!(store
        .put_usage(correction::ADJUST_UP_BUCKET, WINDOW, &ledger(1))
        .is_err());
    assert!(store
        .add_usage(correction::ADJUST_DOWN_BUCKET, WINDOW, &delta())
        .is_err());
    assert_eq!(snapshot(&store), before);
    // A historical durable receipt is replayed before the new legacy-write guard.
    let body = Dedupe::usage(&cells).body_hex();
    store
        .write(true, |tx| {
            put_usage_in(tx, correction::ADJUST_UP_BUCKET, WINDOW, &ledger(1))?;
            record(tx, op(1), &body, false)
        })
        .unwrap();
    let before = snapshot(&store);
    assert_eq!(store.v3_add_usage_batch(op(1), &cells), Ok(()));
    assert_eq!(snapshot(&store), before);
    let changed = [(correction::ADJUST_UP_BUCKET, WINDOW + 1, delta())];
    assert_eq!(
        store.v3_add_usage_batch(op(1), &changed),
        Err(OpRefused::Conflict)
    );
    assert_eq!(snapshot(&store), before);
}

#[test]
fn invalid_requests_and_cross_operation_id_conflicts_write_nothing() {
    let (store, _path, _dir) = on_file();
    let request = candidate(&store, 1);
    let mut invalid = request.clone();
    invalid.version += 1;
    let before = snapshot(&store);
    assert!(matches!(
        apply(&store, &invalid),
        Err(OpRefused::Refused(_))
    ));
    assert_eq!(snapshot(&store), before);
    store.v3_add_usage_batch(request.op_id, &[]).unwrap();
    let before = snapshot(&store);
    assert_eq!(apply(&store, &request), Err(OpRefused::Conflict));
    assert_eq!(snapshot(&store), before);
    let request = candidate(&store, 2);
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    let before = snapshot(&store);
    assert_eq!(
        store.v3_add_usage_batch(request.op_id, &[]),
        Err(OpRefused::Conflict)
    );
    assert_eq!(snapshot(&store), before);
}

/// Pause a real SELECT after BEGIN IMMEDIATE has acquired SQLite's shared-file writer authority.
fn pause_after_begin(store: &SqliteStore) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (entered, waiting) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let mut paused = false;
    store
        .lock_writer()
        .authorizer(Some(move |context: AuthContext<'_>| {
            if !paused
                && matches!(
                    context.action,
                    AuthAction::Read {
                        table_name: "keys",
                        ..
                    }
                )
            {
                paused = true;
                let _ = entered.send(());
                if released.recv_timeout(DEADLINE).is_err() {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }))
        .unwrap();
    (waiting, release)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OrdinaryWriter {
    Metering,
    KeyDelete,
    AbsentUsage,
}

#[test]
fn ordinary_metering_key_delete_and_absent_row_insert_serialize_after_acceptance() {
    for mutation in [
        OrdinaryWriter::Metering,
        OrdinaryWriter::KeyDelete,
        OrdinaryWriter::AbsentUsage,
    ] {
        let (store, path, _dir) = on_file();
        let other = SqliteStore::open(&path, BUSY_TIMEOUT_MS).unwrap();
        let request = candidate(&store, 1);
        let (waiting, release) = pause_after_begin(&store);
        std::thread::scope(|scope| {
            let correction = scope.spawn(|| apply(&store, &request));
            waiting
                .recv_timeout(DEADLINE)
                .expect("acceptance owns the real writer authority");
            let (started, starting) = mpsc::sync_channel(1);
            let ordinary_store = &other;
            let ordinary = scope.spawn(move || {
                started.send(()).unwrap();
                match mutation {
                    OrdinaryWriter::Metering => ordinary_store.add_metering(&metering(KEY)),
                    OrdinaryWriter::KeyDelete => ordinary_store.delete_key(KEY),
                    OrdinaryWriter::AbsentUsage => {
                        ordinary_store.add_usage(BUCKET, WINDOW, &delta())
                    }
                }
            });
            starting.recv_timeout(DEADLINE).unwrap();
            // The correction's transaction is invisible to an independent WAL reader.
            let during = other.get_usage(BUCKET, WINDOW).unwrap();
            release.send(()).unwrap(); // Release before assertions to avoid stranding a worker.
            assert_eq!(correction.join().unwrap(), Ok(Decision::Applied));
            ordinary.join().unwrap().unwrap();
            assert_eq!(during, UsageLedger::default());
        });
        store
            .lock_writer()
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .unwrap();
        let expected = if mutation == OrdinaryWriter::AbsentUsage {
            ledger(24)
        } else {
            ledger(23)
        };
        assert_eq!(other.get_usage(BUCKET, WINDOW).unwrap(), expected);
        let committed = snapshot(&other);
        assert_eq!(apply(&store, &request), Ok(Decision::Applied));
        assert_eq!(snapshot(&other), committed);
    }
}

#[test]
fn a_persisted_empty_row_compares_as_absence_and_all_conditions_precede_effects() {
    let (store, _path, _dir) = on_file();
    let empty = UsageLedger {
        models: vec![ModelTokens {
            model: MODEL.into(),
            usage_units: Default::default(),
        }],
        ..Default::default()
    };
    store.put_usage(BUCKET, WINDOW, &empty).unwrap();
    let mut request = candidate(&store, 1);
    request.usage[0].expected = UsageLedger::default();
    request.usage.push(UsageChange {
        address: UsageAddress {
            bucket_id: "z-last".into(),
            window_start: WINDOW,
        },
        expected: ledger(1),
        replacement: ledger(29),
    });
    let before = snapshot(&store);
    assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
    assert_eq!(snapshot(&store), before);
    request.usage[1].expected = UsageLedger::default();
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), ledger(23));
}

#[test]
fn direct_record_store_uses_the_same_acceptance_and_receipt_domain() {
    let (store, _path, _dir) = on_file();
    assert!(RecordStore::supports_usage_correction(&store));
    let request = candidate(&store, 1);
    assert_eq!(
        RecordStore::apply_usage_correction(&store, &request).unwrap(),
        Decision::Applied
    );
    let committed = snapshot(&store);
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    assert_eq!(snapshot(&store), committed);
}

#[test]
fn two_correction_writers_compare_under_the_same_sqlite_authority() {
    let (first, path, _dir) = on_file();
    let second = SqliteStore::open(&path, BUSY_TIMEOUT_MS).unwrap();
    let first_request = candidate(&first, 1);
    let mut second_request = first_request.clone();
    second_request.op_id = op(2);
    second_request.usage[0].replacement = ledger(29);
    let barrier = std::sync::Barrier::new(2);
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            apply(&first, &first_request).unwrap()
        });
        let right = scope.spawn(|| {
            barrier.wait();
            apply(&second, &second_request).unwrap()
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    assert!(matches!(
        (left, right),
        (Decision::Applied, Decision::ConditionConflict)
            | (Decision::ConditionConflict, Decision::Applied)
    ));
    let expected = if left == Decision::Applied {
        ledger(23)
    } else {
        ledger(29)
    };
    assert_eq!(first.get_usage(BUCKET, WINDOW).unwrap(), expected);
    let receipt_count: i64 = first
        .lock_reader()
        .query_row("SELECT count(*) FROM store_ops", [], |row| row.get(0))
        .unwrap();
    assert_eq!(receipt_count, 1);
}

#[test]
fn empty_model_totals_and_units_roundtrip_through_put_add_and_correction() {
    let (store, path, _dir) = on_file();
    let mut expected = ledger(u64::MAX - 1);
    expected.models[0].model.clear();
    store.put_usage(BUCKET, WINDOW, &expected).unwrap();
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), expected);
    let mut increment = delta();
    increment.models[0].model.clear();
    store.add_usage(BUCKET, WINDOW, &increment).unwrap();
    expected = ledger(u64::MAX);
    expected.models[0].model.clear();
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), expected);
    let mut request = candidate(&store, 1);
    request.usage[0].replacement.models[0].model.clear();
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    expected = request.usage[0].replacement.clone();
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), expected);
    store
        .v3_add_usage_batch(op(2), &[(BUCKET, WINDOW, increment)])
        .unwrap();
    expected.requests += 1;
    expected.billable_requests += 1;
    for count in expected.models[0].usage_units.values_mut() {
        *count += 1;
    }
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), expected);
    drop(store);
    let reopened = SqliteStore::open(&path, BUSY_TIMEOUT_MS).unwrap();
    assert_eq!(reopened.get_usage(BUCKET, WINDOW).unwrap(), expected);
}

#[test]
fn legacy_sentinel_empty_model_units_survive_read_and_first_exact_add() {
    let (store, _path, _dir) = on_file();
    // A legacy empty-model accrual shares the totals sentinel. Its tokens remain real raw counts.
    store.lock_writer().execute(
        "INSERT INTO usage_windows(window_start,bucket_id,model,requests,billable_requests,tokens_input) VALUES (?1,?2,'',?3,?4,?5)",
        params![WINDOW as i64, BUCKET, 41, 37, 31]).unwrap();
    store.lock_writer().execute(
        "INSERT INTO usage_window_units(window_start,bucket_id,model,unit,count) VALUES (?1,?2,'',?3,?4)",
        params![WINDOW as i64, BUCKET, OPEN_UNIT, 29]).unwrap();
    let mut expected = UsageLedger {
        requests: 41,
        billable_requests: 37,
        models: vec![ModelTokens {
            model: String::new(),
            usage_units: [(UNIT_INPUT.into(), 31), (OPEN_UNIT.into(), 29)].into(),
        }],
    };
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), expected);
    let mut increment = delta();
    increment.models[0].model.clear();
    store.add_usage(BUCKET, WINDOW, &increment).unwrap();
    expected.requests += 1;
    expected.billable_requests += 1;
    for count in expected.models[0].usage_units.values_mut() {
        *count += 1;
    }
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), expected);
    // Fresh ordinary empty-model deltas must also retain both request totals and all unit classes.
    store.add_usage(BUCKET, WINDOW + 1, &increment).unwrap();
    let mut fresh = ledger(1);
    fresh.models[0].model.clear();
    assert_eq!(store.get_usage(BUCKET, WINDOW + 1).unwrap(), fresh);
}

#[test]
fn zero_open_units_stay_sparse_in_exact_rows_and_correction_replays() {
    let (store, path, _dir) = on_file();
    let mut offered = ledger(u64::MAX);
    offered.models[0].model = "future.model/v7:\u{1e}opaque%|空".into();
    offered.models[0].usage_units.insert("idle".into(), 0);
    offered.models[0].usage_units.insert(UNIT_OUTPUT.into(), 0);
    let mut expected = offered.clone();
    expected.models[0].usage_units.remove("idle");
    store.put_usage(BUCKET, WINDOW, &offered).unwrap();
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), expected);
    let saved: Vec<u8> = store
        .lock_reader()
        .query_row(
            "SELECT ledger FROM usage_window_exact WHERE window_start=?1 AND bucket_id=?2",
            params![WINDOW as i64, BUCKET],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<UsageLedger>(&saved).unwrap(),
        expected
    );

    // A v18 exact row written before the sparse repair reads the same way without a rewrite.
    store
        .write(true, |tx| {
            exec(
                tx,
                "UPDATE usage_window_exact SET ledger=?3 WHERE window_start=?1 AND bucket_id=?2",
                params![WINDOW as i64, BUCKET, serde_json::to_vec(&offered).unwrap()],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(store.get_usage(BUCKET, WINDOW).unwrap(), expected);

    let mut request = candidate(&store, 1);
    correction::canonical_ledger(&mut request.usage[0].expected).unwrap();
    request.usage[0].replacement = request.usage[0].expected.clone();
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    assert_eq!(
        store.get_usage(BUCKET, WINDOW).unwrap(),
        request.usage[0].replacement
    );

    let mut refund = delta();
    refund.requests = -1;
    refund.billable_requests = -1;
    refund.models[0].model = offered.models[0].model.clone();
    for count in refund.models[0].usage_units.values_mut() {
        *count = -1;
    }
    store.add_usage(BUCKET, WINDOW, &refund).unwrap();
    let committed = snapshot(&store);
    drop(store);
    let reopened = SqliteStore::open(&path, BUSY_TIMEOUT_MS).unwrap();
    assert_eq!(apply(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(snapshot(&reopened), committed);
    assert_eq!(
        reopened.get_usage(BUCKET, WINDOW).unwrap().requests,
        u64::MAX - 1
    );
}
