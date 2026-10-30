// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `store-sqlite/src/v3.rs`: the store v3 slots' dedupe (S1-S4) and its DURABILITY across
//! a reopen of the file, the count batches, the schema records, and the v13 drop of the money
//! tables. The behavioural cases
//! are the in-tree memory store's (`crates/store-memory/src/tests/v3_tests.rs` at the pin), held to
//! this backend; the durability cases are this backend's own.

use super::*;
use busbar_contract::records::{ModelTokensDelta, RecordStore};

/// A fresh in-memory store.
fn fresh() -> SqliteStore {
    SqliteStore::open_in_memory().expect("open")
}

/// A store on a real file in a fresh scratch directory, and the file's path.
fn on_file(tag: &str) -> (SqliteStore, String) {
    let dir = std::env::temp_dir().join(format!(
        "store-sqlite-v3-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v3.db").display().to_string();
    (SqliteStore::open(&path, 5000).expect("open"), path)
}

fn op(n: u64) -> OpId {
    OpId::from_parts(7, n)
}

fn delta(requests: i64, input: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [("input".to_string(), input)].into_iter().collect(),
        }],
    }
}

#[test]
fn the_sqlite_store_states_it_is_durable_and_refuses_forks() {
    assert_eq!(
        <SqliteStore as StoreSlots>::TAIL,
        Tail {
            ephemeral: false,
            durable_plane: true,
            fork_refusal: true,
        }
    );
}

#[test]
fn a_replayed_usage_batch_applies_once() {
    let s = fresh();
    let cells = [("k", 60, delta(1, 10))];
    s.v3_add_usage_batch(op(1), &cells).expect("first");
    s.v3_add_usage_batch(op(1), &cells)
        .expect("replay answers the original");
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60).expect("read").requests,
        1
    );
}

#[test]
fn equal_bodies_under_distinct_op_ids_both_apply() {
    let s = fresh();
    let cells = [("k", 60, delta(2, 4))];
    s.v3_add_usage_batch(op(1), &cells).expect("a");
    s.v3_add_usage_batch(op(2), &cells).expect("b");
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60).expect("read").requests,
        4
    );
}

#[test]
fn a_reused_op_id_with_a_different_body_is_a_conflict_and_applies_nothing() {
    let s = fresh();
    s.v3_add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("first");
    assert_eq!(
        s.v3_add_usage_batch(op(1), &[("k", 60, delta(5, 5))]),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60).expect("read").requests,
        1
    );
}

#[test]
fn an_op_id_reused_across_slots_is_a_conflict() {
    let s = fresh();
    s.v3_add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("usage");
    assert_eq!(
        s.v3_add_metering_batch(op(1), &[]),
        Err(OpRefused::Conflict)
    );
    assert!(RecordStore::list_metering(&s, 86_400)
        .expect("list")
        .is_empty());
}

#[test]
fn a_usage_batch_applies_its_cells_in_order() {
    let s = fresh();
    let neg = UsageDelta {
        requests: 0,
        billable_requests: -1,
        models: vec![],
    };
    let pos = UsageDelta {
        requests: 0,
        billable_requests: 1,
        models: vec![],
    };
    s.v3_add_usage_batch(op(1), &[("k", 60, neg), ("k", 60, pos)])
        .expect("batch");
    // The floor at zero makes order matter: -1 then +1 is 1, not 0.
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60)
            .expect("read")
            .billable_requests,
        1
    );
}

#[test]
fn a_metering_batch_replay_applies_once() {
    let s = fresh();
    let d = MeteringDelta {
        key_id: "k".into(),
        bucket: 86_400,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 3,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 2,
        billable_requests: 2,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    s.v3_add_metering_batch(op(1), std::slice::from_ref(&d))
        .expect("a");
    s.v3_add_metering_batch(op(1), std::slice::from_ref(&d))
        .expect("replay");
    let rows = RecordStore::list_metering(&s, 86_400).expect("list");
    assert_eq!(rows.iter().map(|r| r.requests).sum::<u64>(), 2);
}

#[test]
fn an_op_id_is_forgotten_after_its_retention() {
    let s = fresh();
    s.v3_add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("a");
    // Age op 1 past its retention, as the clock would.
    let old = now_secs() - OP_ID_RETENTION_SECS as i64;
    s.lock_writer()
        .execute(
            "UPDATE store_ops SET recorded_at=?1 WHERE op_id=?2",
            params![old, op(1).0.as_slice()],
        )
        .expect("age");
    // The expired op_id reads as new, whether or not a sweep has run.
    s.v3_add_usage_batch(op(2), &[("j", 60, delta(1, 1))])
        .expect("b");
    s.v3_add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("new again");
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60).expect("read").requests,
        2
    );
}

/// An expired row is not honoured when no sweep has run: the sweep fires on op 0 and every 256th,
/// so after op 0 the aged row below is still in the table when its op_id returns.
#[test]
fn an_expired_op_id_is_not_honoured_before_any_sweep() {
    let s = fresh();
    s.v3_add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("a");
    s.v3_add_usage_batch(op(2), &[("j", 60, delta(1, 1))])
        .expect("b");
    let old = now_secs() - OP_ID_RETENTION_SECS as i64;
    s.lock_writer()
        .execute(
            "UPDATE store_ops SET recorded_at=?1 WHERE op_id=?2",
            params![old, op(2).0.as_slice()],
        )
        .expect("age");
    let rows = |s: &crate::SqliteStore| -> i64 {
        s.lock_writer()
            .query_row("SELECT COUNT(*) FROM store_ops", [], |r| r.get(0))
            .expect("count")
    };
    assert_eq!(rows(&s), 2, "no sweep has run since the aging");
    s.v3_add_usage_batch(op(2), &[("j", 60, delta(1, 1))])
        .expect("applies again, not replayed");
    assert_eq!(
        RecordStore::get_usage(&s, "j", 60).expect("read").requests,
        2
    );
    assert_eq!(rows(&s), 2, "the row was refreshed in place");
}

#[test]
fn schema_records_upsert_read_back_and_scan_a_prefix_in_key_order() {
    let s = fresh();
    s.v3_record_put("a", b"k\x01", b"one").expect("put");
    s.v3_record_put("a", b"k\x00", b"zero").expect("put");
    s.v3_record_put("a", b"k\xff", b"max").expect("put");
    s.v3_record_put("a", b"l", b"next").expect("put");
    s.v3_record_put("b", b"k\x00", b"other schema")
        .expect("put");
    s.v3_record_put("a", b"k\x01", b"one again")
        .expect("overwrite");
    let read = |k: &[u8]| {
        s.v3_record_get("a", k)
            .expect("get")
            .map(|r| r.as_slice().to_vec())
    };
    assert_eq!(read(b"k\x01"), Some(b"one again".to_vec()));
    assert_eq!(read(b"missing"), None);
    let keys = |prefix: &[u8], limit: u32| -> Vec<Vec<u8>> {
        s.v3_record_scan("a", prefix, limit)
            .expect("scan")
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    };
    assert_eq!(
        keys(b"k", 10),
        vec![b"k\x00".to_vec(), b"k\x01".to_vec(), b"k\xff".to_vec()]
    );
    assert_eq!(keys(b"k", 2), vec![b"k\x00".to_vec(), b"k\x01".to_vec()]);
    assert_eq!(keys(b"k", 0), Vec::<Vec<u8>>::new());
    assert_eq!(
        keys(b"", 10).len(),
        4,
        "an empty prefix is the whole schema"
    );
    assert_eq!(keys(b"k\xff", 10), vec![b"k\xff".to_vec()]);
}

/// AN EMPTY PUT REMOVES THE ROW (slot 40's rule, ARCHITECT 2026-10-21): the host writes every
/// strike as an empty `record_put` and reads empty as absent, so the row LEAVES the table:
/// `record_get` answers `None`, `record_scan` never returns it, and the table shrinks. Removing a
/// row that is not there is `Ok`.
#[test]
fn an_empty_put_removes_the_row() {
    let s = fresh();
    let held = || -> i64 {
        s.lock_reader()
            .query_row("SELECT COUNT(*) FROM schema_records", [], |r| r.get(0))
            .expect("count")
    };
    s.v3_record_put("a", b"a/1", b"one").expect("put");
    s.v3_record_put("a", b"a/2", b"two").expect("put");
    assert_eq!(held(), 2);

    s.v3_record_put("a", b"a/1", b"").expect("strike");
    assert_eq!(held(), 1, "the struck row left the table");
    assert_eq!(s.v3_record_get("a", b"a/1").expect("get"), None);
    let scanned: Vec<(Vec<u8>, Vec<u8>)> = s
        .v3_record_scan("a", b"a/", 10)
        .expect("scan")
        .into_iter()
        .map(|(k, v)| (k, v.as_slice().to_vec()))
        .collect();
    assert_eq!(
        scanned,
        vec![(b"a/2".to_vec(), b"two".to_vec())],
        "a scan never returns a struck row"
    );

    s.v3_record_put("a", b"a/9", b"")
        .expect("a strike of nothing is Ok");
    assert_eq!(held(), 1);
    s.v3_record_put("a", b"a/1", b"again").expect("put again");
    assert_eq!(
        s.v3_record_get("a", b"a/1")
            .expect("get")
            .map(|r| r.as_slice().to_vec()),
        Some(b"again".to_vec())
    );
}

#[test]
fn a_prefix_scan_returns_exactly_the_keys_the_prefix_starts() {
    let s = fresh();
    for k in [
        &b"aa"[..],
        b"ab",
        b"ab\x00",
        b"ac",
        b"a\xff",
        b"a\xff\x01",
        b"b",
        b"\xff\xff",
        b"\xff\xff\x00",
    ] {
        s.v3_record_put("p", k, b"v").expect("put");
    }
    let keys = |prefix: &[u8]| -> Vec<Vec<u8>> {
        s.v3_record_scan("p", prefix, 100)
            .expect("scan")
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    };
    assert_eq!(keys(b"ab"), vec![b"ab".to_vec(), b"ab\x00".to_vec()]);
    assert_eq!(
        keys(b"a\xff"),
        vec![b"a\xff".to_vec(), b"a\xff\x01".to_vec()]
    );
    assert_eq!(
        keys(b"\xff\xff"),
        vec![b"\xff\xff".to_vec(), b"\xff\xff\x00".to_vec()],
        "an all-0xff prefix is unbounded above"
    );
}

/// S4: dedupe is DURABLE. Every write below is replayed on a REOPENED file: the replays apply
/// nothing and answer the originals, and a reused id with another body is still a conflict.
#[test]
fn dedupe_survives_a_reopen_of_the_file() {
    let (s, path) = on_file("durable");
    s.v3_add_usage_batch(op(3), &[("k", 60, delta(1, 1))])
        .expect("usage");
    s.v3_record_put("plane", b"k", b"v").expect("record");
    drop(s);

    let s = SqliteStore::open(&path, 5000).expect("reopen");
    s.v3_add_usage_batch(op(3), &[("k", 60, delta(1, 1))])
        .expect("replay");
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60).expect("read").requests,
        1,
        "a replayed batch applies nothing after a restart"
    );
    assert_eq!(
        s.v3_add_usage_batch(op(3), &[("k", 60, delta(2, 2))]),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        s.v3_record_get("plane", b"k")
            .expect("get")
            .map(|v| v.as_slice().to_vec()),
        Some(b"v".to_vec())
    );
}

#[test]
fn a_replayed_plane_record_append_applies_once_and_a_fork_fails_unrecorded() {
    let s = fresh();
    let rec = |body: &'static [u8]| PlaneRecordRef {
        kind: "task_event",
        id: "e1",
        parent: Some("t1"),
        seq: 1,
        ts: 5,
        disposition: busbar_contract::records::PlaneDisposition::Active,
        body,
    };
    s.v3_append_plane_record_op(op(1), rec(b"{}"))
        .expect("append");
    s.v3_append_plane_record_op(op(1), rec(b"{}"))
        .expect("replay");
    assert_eq!(
        s.v3_append_plane_record_op(op(1), rec(b"{\"x\":1}")),
        Err(OpRefused::Conflict)
    );
    assert!(matches!(
        s.v3_append_plane_record_op(op(2), rec(b"{\"x\":1}")),
        Err(OpRefused::Failed(_))
    ));
    assert_eq!(
        RecordStore::list_plane_records(
            &s,
            "task_event",
            &busbar_contract::records::PlaneSelector::All
        )
        .expect("list"),
        vec![b"{}".to_vec()]
    );
}

/// A body an older build recorded (`slot:{:?}`) still dedupes after the upgrade, inside the
/// retention window: the same op replays and applies nothing, a different op conflicts.
#[test]
fn an_older_builds_recorded_body_replays_across_the_upgrade() {
    let s = fresh();
    let recorded = |n: u64, body: String| {
        s.lock_writer()
            .execute(
                "INSERT INTO store_ops (op_id, body, answer, recorded_at) \
                 VALUES (?1, ?2, '\"Done\"', ?3)",
                params![op(n).0.as_slice(), body, now_secs()],
            )
            .expect("record");
    };
    let cells = [("k", 60, delta(1, 1))];
    recorded(1, format!("add_usage_batch:{cells:?}"));
    s.v3_add_usage_batch(op(1), &cells).expect("replay");
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60).expect("read").requests,
        0,
        "the replay applied nothing"
    );
    assert_eq!(
        s.v3_add_usage_batch(op(1), &[("k", 60, delta(2, 2))]),
        Err(OpRefused::Conflict)
    );

    let d = MeteringDelta {
        key_id: "k".into(),
        bucket: 86_400,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 3,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 2,
        billable_requests: 2,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let deltas = std::slice::from_ref(&d);
    recorded(2, format!("add_metering_batch:{deltas:?}"));
    s.v3_add_metering_batch(op(2), deltas).expect("replay");
    assert!(RecordStore::list_metering(&s, 86_400)
        .expect("list")
        .is_empty());
    assert_eq!(
        s.v3_add_metering_batch(op(2), &[]),
        Err(OpRefused::Conflict)
    );

    let rec = |body: &'static [u8]| PlaneRecordRef {
        kind: "task_event",
        id: "e1",
        parent: Some("t1"),
        seq: 1,
        ts: 5,
        disposition: busbar_contract::records::PlaneDisposition::Active,
        body,
    };
    recorded(3, format!("append_plane_record:{:?}", rec(b"{}")));
    s.v3_append_plane_record_op(op(3), rec(b"{}"))
        .expect("replay");
    assert_eq!(
        s.v3_append_plane_record_op(op(3), rec(b"{\"x\":1}")),
        Err(OpRefused::Conflict)
    );
    assert!(RecordStore::list_plane_records(
        &s,
        "task_event",
        &busbar_contract::records::PlaneSelector::All
    )
    .expect("list")
    .is_empty());
}

/// A value the columns cannot hold is REFUSED (the host may re-send), not Failed (replayed forever),
/// and nothing is applied or recorded.
#[test]
fn values_the_columns_cannot_hold_are_refused_not_failed() {
    let s = fresh();
    let rec = |seq: u64, ts: u64| PlaneRecordRef {
        kind: "task_event",
        id: "e1",
        parent: Some("t1"),
        seq,
        ts,
        disposition: busbar_contract::records::PlaneDisposition::Active,
        body: b"{}",
    };
    for r in [rec(u64::MAX, 1), rec(1, u64::MAX)] {
        assert!(matches!(
            s.v3_append_plane_record_op(op(1), r),
            Err(OpRefused::Refused(_))
        ));
    }
    let m = MeteringDelta {
        key_id: "k".into(),
        bucket: 1,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 0,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: u64::MAX,
        usage_units: Default::default(),
    };
    assert!(matches!(
        s.v3_add_metering_batch(op(2), &[m]),
        Err(OpRefused::Refused(_))
    ));
    assert!(RecordStore::list_plane_records(
        &s,
        "task_event",
        &busbar_contract::records::PlaneSelector::All
    )
    .unwrap()
    .is_empty());
    assert!(RecordStore::list_metering(&s, 1).unwrap().is_empty());
    let n: i64 = s
        .lock_writer()
        .query_row("SELECT COUNT(*) FROM store_ops", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "a refused op records nothing");
}

/// A bounded prefix scan stops at the prefix: the VM work does not grow with the rows past it.
#[test]
fn a_prefix_scan_does_no_work_for_rows_past_the_prefix() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STEPS: AtomicU64 = AtomicU64::new(0);
    let s = fresh();
    s.v3_record_put("p", b"aa", b"v").expect("put");
    let steps = |s: &SqliteStore| {
        // `:memory:` has one connection, so the scan runs on the writer holding the handler.
        s.lock_writer()
            .progress_handler(
                1,
                Some(|| {
                    STEPS.fetch_add(1, Ordering::Relaxed);
                    false
                }),
            )
            .unwrap();
        STEPS.store(0, Ordering::Relaxed);
        let rows = s.v3_record_scan("p", b"a", 100).expect("scan");
        s.lock_writer()
            .progress_handler(1, None::<fn() -> bool>)
            .unwrap();
        assert_eq!(rows.len(), 1);
        STEPS.load(Ordering::Relaxed)
    };
    steps(&s); // prepares and caches the statement
    let few = steps(&s);
    for i in 0..2000u32 {
        s.v3_record_put("p", format!("z{i:05}").as_bytes(), b"v")
            .expect("put");
    }
    let many = steps(&s);
    // A deeper b-tree costs a step or two; stepping over 2000 rows costs thousands.
    assert!(
        many <= few + 10,
        "rows past the prefix were stepped over: {few} vs {many}"
    );
}

fn ops_recorded(s: &SqliteStore) -> i64 {
    s.lock_writer()
        .query_row("SELECT COUNT(*) FROM store_ops", [], |r| r.get(0))
        .unwrap()
}

/// A failed op (a fork) records nothing, so the same `op_id` retried with a record that does not
/// fork applies instead of conflicting.
#[test]
fn a_failed_op_records_nothing_and_its_op_id_can_be_retried() {
    let s = fresh();
    let rec = |seq: u64, body: &'static [u8]| PlaneRecordRef {
        kind: "task_event",
        id: "e1",
        parent: Some("t1"),
        seq,
        ts: 5,
        disposition: busbar_contract::records::PlaneDisposition::Active,
        body,
    };
    s.v3_append_plane_record_op(op(1), rec(1, b"{}")).unwrap();
    assert!(matches!(
        s.v3_append_plane_record_op(op(2), rec(1, b"{\"x\":1}")),
        Err(OpRefused::Failed(_))
    ));
    assert_eq!(ops_recorded(&s), 1, "the fork recorded its op_id");
    s.v3_append_plane_record_op(op(2), rec(2, b"{}"))
        .expect("the retry of the failed op_id applies");
    assert_eq!(ops_recorded(&s), 2);
}

/// A usage batch whose second cell fails rolls back the first and records nothing.
#[test]
fn a_usage_batch_whose_second_cell_fails_rolls_back_the_first() {
    let s = fresh();
    s.lock_writer()
        .execute_batch("ALTER TABLE usage_window_units RENAME TO units_away")
        .unwrap();
    let open_unit = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [("custom".to_string(), 1)].into_iter().collect(),
        }],
    };
    let cells = [("k", 60, delta(1, 1)), ("k", 61, open_unit)];
    assert!(matches!(
        s.v3_add_usage_batch(op(1), &cells),
        Err(OpRefused::Failed(_))
    ));
    let rows: i64 = s
        .lock_writer()
        .query_row("SELECT COUNT(*) FROM usage_windows", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "the first cell was not rolled back");
    assert_eq!(ops_recorded(&s), 0);
    s.lock_writer()
        .execute_batch("ALTER TABLE units_away RENAME TO usage_window_units")
        .unwrap();
    s.v3_add_usage_batch(op(1), &cells)
        .expect("the retry applies");
    assert_eq!(RecordStore::get_usage(&s, "k", 60).unwrap().requests, 1);
}

/// The retention sweep runs every `SWEEP_EVERY`th recorded op and drops only rows past retention.
#[test]
fn the_retention_sweep_deletes_aged_rows_every_sweep_every_ops() {
    let s = fresh();
    s.v3_add_usage_batch(op(0), &[("k", 60, delta(1, 1))])
        .unwrap(); // the first op sweeps
    let aged = |s: &SqliteStore| -> i64 {
        s.lock_writer()
            .query_row(
                "SELECT COUNT(*) FROM store_ops WHERE recorded_at < 1000",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    {
        let c = s.lock_writer();
        for i in 0..5u64 {
            c.execute(
                "INSERT INTO store_ops (op_id, body, answer, recorded_at) VALUES (?1, 'x', '', 1)",
                [OpId::from_parts(9, i).0.as_slice()],
            )
            .unwrap();
        }
    }
    for n in 1..SWEEP_EVERY {
        s.v3_add_usage_batch(op(n), &[("k", 60, delta(1, 1))])
            .unwrap();
    }
    assert_eq!(aged(&s), 5, "swept before SWEEP_EVERY ops");
    s.v3_add_usage_batch(op(SWEEP_EVERY), &[("k", 60, delta(1, 1))])
        .unwrap();
    assert_eq!(aged(&s), 0, "aged rows survived the sweep");
    assert_eq!(
        ops_recorded(&s),
        SWEEP_EVERY as i64 + 1,
        "fresh rows were swept"
    );
}
