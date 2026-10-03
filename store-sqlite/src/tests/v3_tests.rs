// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `store-sqlite/src/v3.rs`: the store v3 slots' dedupe (S1-S4) and its DURABILITY across
//! a reopen of the file, the reserve grant rule pinned to 1.5.5, slice release clamping, window caps,
//! batches, the ledger streams, the session directory and the schema records. The behavioural cases
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

fn key(dimension: Dimension<'static>) -> CellKey<'static> {
    CellKey {
        bucket: "b",
        pool: None,
        dimension,
        window_start: 1_000,
    }
}

fn cap(dimension: Dimension<'static>, cap: u64, config_gen: u64) -> Cap<'static> {
    Cap {
        key: key(dimension),
        cap,
        config_gen,
    }
}

fn cell(dimension: Dimension<'static>, amount: u64) -> Cell<'static> {
    Cell {
        key: key(dimension),
        amount,
    }
}

/// `reserve`, its grants collected.
fn reserve(
    s: &SqliteStore,
    op: OpId,
    epoch: u64,
    cells: &[Cell<'_>],
) -> Result<Vec<Grant>, ReserveRefused> {
    let mut grants = Vec::new();
    s.v3_reserve(op, epoch, cells.iter().copied(), &mut grants)
        .map(|()| grants)
}

/// `slice_release`, its amounts collected.
fn release(s: &SqliteStore, op: OpId, epoch: u64, items: &[(u64, u64)]) -> OpResult<Vec<u64>> {
    let mut released = Vec::new();
    s.v3_slice_release(op, epoch, items.iter().copied(), &mut released)
        .map(|()| released)
}

fn capped(dimension: Dimension<'static>, c: u64) -> SqliteStore {
    let s = fresh();
    s.v3_window_caps(op(1_000_000), &[cap(dimension, c, 1)])
        .expect("caps");
    s
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

fn audit(seq: u64, action: &str) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 1,
        action: action.to_string(),
        resource: "r".to_string(),
        outcome: "ok".to_string(),
        principal: "p".to_string(),
        prev_hash: String::new(),
        hash: format!("h{seq}{action}"),
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
    s.v3_add_usage_op(op(1), "k", 60, &delta(1, 1))
        .expect("usage");
    assert_eq!(
        s.v3_append_audit_op(op(1), &audit(1, "a")),
        Err(OpRefused::Conflict)
    );
    assert!(RecordStore::list_audit(&s).expect("list").is_empty());
}

#[test]
fn a_failed_write_is_not_recorded_so_a_retry_is_evaluated_afresh() {
    let s = fresh();
    s.append_audit(&audit(1, "a")).expect("seed");
    // A fork FAILS and is not recorded under the op_id ...
    assert!(matches!(
        s.v3_append_audit_op(op(9), &audit(1, "forked")),
        Err(OpRefused::Failed(_))
    ));
    // ... so the same op_id with a different, applicable body is new, not a conflict.
    s.v3_append_audit_op(op(9), &audit(2, "b")).expect("fresh");
    assert_eq!(RecordStore::list_audit(&s).expect("list").len(), 2);
}

#[test]
fn an_audit_batch_with_one_fork_applies_none_of_it() {
    let s = fresh();
    s.append_audit(&audit(2, "a")).expect("seed");
    let batch = [audit(1, "x"), audit(2, "forked")];
    assert!(matches!(
        s.v3_append_audit_batch(op(1), &batch),
        Err(OpRefused::Failed(_))
    ));
    assert_eq!(RecordStore::list_audit(&s).expect("list").len(), 1);
    // Two different records at one seq INSIDE the batch are a fork too.
    let inner = [audit(5, "x"), audit(5, "y")];
    assert!(s.v3_append_audit_batch(op(2), &inner).is_err());
    assert_eq!(RecordStore::list_audit(&s).expect("list").len(), 1);
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
fn a_reserve_with_no_cap_pushed_is_refused_naming_the_cell() {
    let s = fresh();
    assert_eq!(
        reserve(&s, op(1), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::NoCap { cell: 0 })
    );
}

#[test]
fn a_grant_is_always_the_whole_amount() {
    let s = capped(Dimension::NanoUnits, 100);
    let g = reserve(&s, op(1), 0, &[cell(Dimension::NanoUnits, 60)]).expect("grant");
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].granted, 60);
}

#[test]
fn requests_refuse_when_used_plus_amount_passes_the_cap() {
    let s = capped(Dimension::Requests, 2);
    reserve(&s, op(1), 0, &[cell(Dimension::Requests, 2)]).expect("at the cap");
    assert_eq!(
        reserve(&s, op(2), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

#[test]
fn a_class_meter_grants_the_draw_that_crosses_the_cap_and_refuses_at_it() {
    let s = capped(Dimension::Class("tokens"), 10);
    reserve(&s, op(1), 0, &[cell(Dimension::Class("tokens"), 9)]).expect("under");
    reserve(&s, op(2), 0, &[cell(Dimension::Class("tokens"), 50)])
        .expect("crossing is granted whole (1.5.5 `tokens >= cap`)");
    assert_eq!(
        reserve(&s, op(3), 0, &[cell(Dimension::Class("tokens"), 1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

#[test]
fn money_refuses_a_draw_that_would_pass_the_cap() {
    let s = capped(Dimension::NanoUnits, 100);
    assert_eq!(
        reserve(&s, op(1), 0, &[cell(Dimension::NanoUnits, 101)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    reserve(&s, op(2), 0, &[cell(Dimension::NanoUnits, 100)]).expect("exactly the cap");
}

#[test]
fn an_overflowing_draw_is_exhausted_not_wrapped() {
    let s = capped(Dimension::Requests, u64::MAX);
    reserve(&s, op(1), 0, &[cell(Dimension::Requests, u64::MAX - 1)]).expect("near max");
    assert_eq!(
        reserve(&s, op(2), 0, &[cell(Dimension::Requests, 5)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

#[test]
fn a_chain_draw_is_all_or_nothing() {
    let s = fresh();
    s.v3_window_caps(
        op(100),
        &[
            cap(Dimension::Requests, 10, 1),
            cap(Dimension::NanoUnits, 5, 1),
        ],
    )
    .expect("caps");
    // The second cell fails, so the first draws nothing either.
    assert_eq!(
        reserve(
            &s,
            op(1),
            0,
            &[cell(Dimension::Requests, 10), cell(Dimension::NanoUnits, 6)]
        ),
        Err(ReserveRefused::Exhausted { cell: 1 })
    );
    reserve(&s, op(2), 0, &[cell(Dimension::Requests, 10)])
        .expect("the first cell's headroom is untouched");
}

#[test]
fn two_cells_on_one_slot_count_against_each_other() {
    let s = capped(Dimension::Requests, 3);
    assert_eq!(
        reserve(
            &s,
            op(1),
            0,
            &[cell(Dimension::Requests, 2), cell(Dimension::Requests, 2)]
        ),
        Err(ReserveRefused::Exhausted { cell: 1 })
    );
}

#[test]
fn a_replayed_reserve_answers_the_same_grants_and_draws_nothing_more() {
    let s = capped(Dimension::Requests, 10);
    let a = reserve(&s, op(1), 0, &[cell(Dimension::Requests, 6)]).expect("a");
    let b = reserve(&s, op(1), 0, &[cell(Dimension::Requests, 6)]).expect("replay");
    assert_eq!(a, b);
    // Only 6 are drawn: 4 more fit, 5 do not.
    assert_eq!(
        reserve(&s, op(2), 0, &[cell(Dimension::Requests, 5)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    reserve(&s, op(3), 0, &[cell(Dimension::Requests, 4)]).expect("the rest");
}

#[test]
fn a_reserve_op_id_reused_with_another_body_is_a_conflict() {
    let s = capped(Dimension::Requests, 10);
    reserve(&s, op(1), 0, &[cell(Dimension::Requests, 1)]).expect("a");
    assert_eq!(
        reserve(&s, op(1), 0, &[cell(Dimension::Requests, 2)]),
        Err(ReserveRefused::Conflict)
    );
}

#[test]
fn a_refused_reserve_is_not_recorded() {
    let s = capped(Dimension::Requests, 1);
    reserve(&s, op(1), 0, &[cell(Dimension::Requests, 1)]).expect("fill");
    assert_eq!(
        reserve(&s, op(2), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.v3_window_caps(op(3), &[cap(Dimension::Requests, 2, 2)])
        .expect("raise");
    // The same op_id is evaluated afresh and now fits.
    reserve(&s, op(2), 0, &[cell(Dimension::Requests, 1)]).expect("afresh");
}

/// The store kind's shared epoch and slice-life cases (`abi::store::SLICE_TTL_MS` (a)-(c)), run over
/// ONE file this harness reopens, on a clock it moves. The store is durable and shared by every node
/// that opens the file, so it runs the FLEET cases (`busbar_contract::testkit::store_v3`).
struct FileHarness {
    path: String,
    clock: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// A test clock, held still at a real instant.
fn still_clock() -> std::sync::Arc<std::sync::atomic::AtomicU64> {
    std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_790_000_000_000))
}

impl busbar_contract::testkit::store_v3::Harness for FileHarness {
    type Store = SqliteStore;
    fn open(&self) -> SqliteStore {
        SqliteStore::open(&self.path, 5000)
            .expect("open")
            .on_clock(std::sync::Arc::clone(&self.clock))
    }
    fn now_ms(&self) -> u64 {
        self.clock.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn advance_ms(&self, ms: u64) {
        self.clock
            .fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn the_sqlite_store_follows_the_fleet_epoch_and_slice_life() {
    let (s, path) = on_file("fleet");
    drop(s);
    busbar_contract::testkit::store_v3::fleet_store(&FileHarness {
        path,
        clock: still_clock(),
    });
}

#[test]
fn a_stale_epoch_is_refused_and_records_nothing_under_its_op_id() {
    let s = capped(Dimension::Requests, 10);
    reserve(&s, op(1), 9, &[cell(Dimension::Requests, 1)]).expect("epoch 9");
    assert_eq!(
        reserve(&s, op(2), 1, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::StaleEpoch)
    );
    // Nothing was recorded under op 2: the same id at the current epoch applies afresh.
    reserve(&s, op(2), 9, &[cell(Dimension::Requests, 1)]).expect("afresh at epoch 9");
}

#[test]
fn a_grant_is_valid_for_slice_ttl_on_the_stores_clock() {
    let skew = still_clock();
    let s = capped(Dimension::Requests, 10).on_clock(std::sync::Arc::clone(&skew));
    let g = reserve(&s, op(1), 0, &[cell(Dimension::Requests, 3)]).expect("draw");
    assert_eq!(g[0].valid_until_ms, s.now_ms() + SLICE_TTL_MS);
    // Past its validity a release returns nothing: expiry already gave the 3 back.
    skew.fetch_add(SLICE_TTL_MS + 1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(release(&s, op(2), 0, &[(g[0].slice_id, 3)]), Ok(vec![0]));
    reserve(&s, op(3), 0, &[cell(Dimension::Requests, 10)]).expect("all 10 drawable again");
}

/// v11 -> v12: a slice granted before the crossing keeps the never-expiring validity it was granted,
/// and the file gains the epoch row's table.
#[test]
fn a_v11_slice_crosses_to_v12_never_expiring() {
    let (s, path) = on_file("v11");
    s.v3_window_caps(op(1), &[cap(Dimension::Requests, 10, 1)])
        .expect("caps");
    drop(s);
    {
        let conn = rusqlite::Connection::open(&path).expect("raw open");
        conn.execute_batch(
            "DROP TABLE money_epoch;
             DROP TABLE money_slices;
             CREATE TABLE money_slices (
                 slice_id  INTEGER PRIMARY KEY AUTOINCREMENT,
                 slot      TEXT NOT NULL,
                 remaining INTEGER NOT NULL
             ) STRICT;
             PRAGMA user_version = 11;",
        )
        .expect("a v11 file");
        let (slot, _) = slot_of(&key(Dimension::Requests));
        conn.execute(
            "INSERT INTO money_slices (slot, remaining) VALUES (?1, 4)",
            [&slot],
        )
        .expect("a v11 slice");
        conn.execute(
            "INSERT INTO money_used (slot, used) VALUES (?1, 4)",
            [&slot],
        )
        .expect("its draw");
    }
    let skew = still_clock();
    let s = SqliteStore::open(&path, 5000)
        .expect("reopen at v12")
        .on_clock(std::sync::Arc::clone(&skew));
    skew.fetch_add(10 * SLICE_TTL_MS, std::sync::atomic::Ordering::Relaxed);
    // Still drawn: 6 fit, 7 do not.
    assert_eq!(
        reserve(&s, op(2), 0, &[cell(Dimension::Requests, 7)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    assert_eq!(release(&s, op(3), 0, &[(1, 4)]), Ok(vec![4]));
    reserve(&s, op(4), 0, &[cell(Dimension::Requests, 10)]).expect("the release freed all 4");
}

#[test]
fn slice_release_is_clamped_deduped_and_frees_headroom() {
    let s = capped(Dimension::Requests, 10);
    let g = reserve(&s, op(1), 0, &[cell(Dimension::Requests, 10)]).expect("draw all");
    let id = g[0].slice_id;
    assert_eq!(release(&s, op(2), 0, &[(id, 4)]), Ok(vec![4]));
    assert_eq!(
        release(&s, op(2), 0, &[(id, 4)]),
        Ok(vec![4]),
        "a replay answers the original and takes nothing more back"
    );
    // Clamped to what the slice has left (6), never more.
    assert_eq!(release(&s, op(3), 0, &[(id, u64::MAX)]), Ok(vec![6]));
    // All 10 are free again.
    reserve(&s, op(4), 0, &[cell(Dimension::Requests, 10)]).expect("headroom back");
}

#[test]
fn releasing_an_unknown_slice_fails_and_applies_nothing() {
    let s = capped(Dimension::Requests, 10);
    let g = reserve(&s, op(1), 0, &[cell(Dimension::Requests, 10)]).expect("draw");
    assert!(matches!(
        release(&s, op(2), 0, &[(g[0].slice_id, 3), (999, 1)]),
        Err(OpRefused::Failed(_))
    ));
    // The known item was not applied either: still exhausted.
    assert_eq!(
        reserve(&s, op(3), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

#[test]
fn window_caps_newest_generation_wins_and_equal_generation_conflicts() {
    let s = fresh();
    s.v3_window_caps(op(1), &[cap(Dimension::Requests, 1, 5)])
        .expect("gen 5");
    s.v3_window_caps(op(2), &[cap(Dimension::Requests, 99, 4)])
        .expect("an older generation is ignored");
    assert_eq!(
        reserve(&s, op(3), 0, &[cell(Dimension::Requests, 2)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    assert_eq!(
        s.v3_window_caps(
            op(4),
            &[
                cap(Dimension::Requests, 3, 6),
                cap(Dimension::Requests, 7, 6)
            ]
        ),
        Err(CapsRefused::CapConflict { index: 1 }),
        "equal gen with a different cap refuses the WHOLE push"
    );
    // Nothing of the refused push applied: the cap is still 1.
    assert_eq!(
        reserve(&s, op(5), 0, &[cell(Dimension::Requests, 2)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.v3_window_caps(op(6), &[cap(Dimension::Requests, 3, 6)])
        .expect("gen 6");
    reserve(&s, op(7), 0, &[cell(Dimension::Requests, 2)]).expect("cap 3");
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
    // Recording another op sweeps the expired one; the old op_id then reads as new.
    s.v3_add_usage_batch(op(2), &[("j", 60, delta(1, 1))])
        .expect("b");
    s.v3_add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("new again");
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60).expect("read").requests,
        2
    );
}

#[test]
fn append_batch_advances_the_stream_head_once_per_op() {
    let s = fresh();
    let r = |b: u8| RecordBytes::new(vec![b]).expect("record");
    assert_eq!(
        s.v3_append_batch(op(1), "journal", &[r(1), r(2)])
            .expect("a")
            .seq,
        2
    );
    assert_eq!(
        s.v3_append_batch(op(1), "journal", &[r(1), r(2)])
            .expect("replay")
            .seq,
        2
    );
    assert_eq!(
        s.v3_append_batch(op(2), "journal", &[r(3)]).expect("b").seq,
        3
    );
    let heads = s.v3_heads().expect("heads");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].0, "journal");
    assert_eq!(heads[0].1.seq, 3);
}

#[test]
fn sessions_are_listed_per_principal_and_removed() {
    let s = fresh();
    s.v3_session_put(1, "n1", "alice").expect("put");
    s.v3_session_put(2, "n2", "alice").expect("put");
    s.v3_session_put(3, "n1", "bob").expect("put");
    assert_eq!(
        s.v3_sessions_for("alice").expect("list"),
        vec![(1, "n1".to_string()), (2, "n2".to_string())]
    );
    s.v3_session_remove(1).expect("remove");
    s.v3_session_remove(1).expect("absent is Ok");
    assert_eq!(
        s.v3_sessions_for("alice").expect("list"),
        vec![(2, "n2".to_string())]
    );
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

#[test]
fn prefix_successor_bounds_every_key_the_prefix_starts() {
    assert_eq!(prefix_successor(b"ab"), Some(b"ac".to_vec()));
    assert_eq!(prefix_successor(b"a\xff"), Some(b"b".to_vec()));
    assert_eq!(prefix_successor(b"\xff\xff"), None);
    assert_eq!(prefix_successor(b""), None);
}

/// S4: dedupe is DURABLE. Every write below is replayed on a REOPENED file: the replays apply
/// nothing and answer the originals, and a reused id with another body is still a conflict.
#[test]
fn dedupe_and_money_state_survive_a_reopen_of_the_file() {
    let (s, path) = on_file("durable");
    s.v3_window_caps(op(1), &[cap(Dimension::Requests, 10, 1)])
        .expect("caps");
    let grants = reserve(&s, op(2), 0, &[cell(Dimension::Requests, 6)]).expect("draw");
    s.v3_add_usage_batch(op(3), &[("k", 60, delta(1, 1))])
        .expect("usage");
    let r = |b: u8| RecordBytes::new(vec![b]).expect("record");
    s.v3_append_batch(op(4), "journal", &[r(1), r(2)])
        .expect("journal");
    s.v3_session_put(9, "n1", "alice").expect("session");
    s.v3_record_put("plane", b"k", b"v").expect("record");
    drop(s);

    let s = SqliteStore::open(&path, 5000).expect("reopen");
    assert_eq!(
        reserve(&s, op(2), 0, &[cell(Dimension::Requests, 6)]).expect("replay"),
        grants,
        "a replayed reserve answers the original grants after a restart"
    );
    assert_eq!(
        reserve(&s, op(2), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::Conflict)
    );
    // Only the original 6 are drawn: 4 more fit, 5 do not.
    assert_eq!(
        reserve(&s, op(5), 0, &[cell(Dimension::Requests, 5)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.v3_add_usage_batch(op(3), &[("k", 60, delta(1, 1))])
        .expect("replay");
    assert_eq!(
        RecordStore::get_usage(&s, "k", 60).expect("read").requests,
        1
    );
    assert_eq!(
        s.v3_append_batch(op(4), "journal", &[r(1), r(2)])
            .expect("replay")
            .seq,
        2
    );
    assert_eq!(s.v3_heads().expect("heads")[0].1.seq, 2);
    assert_eq!(
        s.v3_sessions_for("alice").expect("sessions"),
        vec![(9, "n1".to_string())]
    );
    assert_eq!(
        s.v3_record_get("plane", b"k")
            .expect("get")
            .map(|v| v.as_slice().to_vec()),
        Some(b"v".to_vec())
    );
    // The slice drawn before the restart is still held, and releasing it frees its headroom.
    assert_eq!(
        release(&s, op(6), 0, &[(grants[0].slice_id, 6)]),
        Ok(vec![6])
    );
    reserve(&s, op(7), 0, &[cell(Dimension::Requests, 10)]).expect("headroom back");
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
