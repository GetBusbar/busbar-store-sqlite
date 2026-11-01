// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The conditional-record backend's ordinary behavior. These feature tests require the negotiated
//! SDK interface; an older SDK's missing API is not a behavioral RED for this implementation.

use super::*;
use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request, VERSION,
};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

const SCHEMA: &str = "opaque/任务";

fn op(n: u64) -> OpId {
    OpId::from_parts(91, n)
}

fn predicate(key: &[u8], expected: Expected) -> Predicate {
    Predicate {
        schema: SCHEMA.into(),
        key: key.to_vec(),
        expected,
    }
}

fn put(key: &[u8], value: &[u8]) -> Mutation {
    Mutation::Put {
        schema: SCHEMA.into(),
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

fn delete(key: &[u8]) -> Mutation {
    Mutation::Delete {
        schema: SCHEMA.into(),
        key: key.to_vec(),
    }
}

fn candidate(n: u64, predicates: Vec<Predicate>, mutations: Vec<Mutation>) -> Request {
    Request {
        version: VERSION,
        op_id: op(n),
        predicates,
        mutations,
    }
}

fn on_file(tag: &str) -> (SqliteStore, String, crate::tests::TempDir) {
    let dir = crate::tests::tempdir();
    let path = dir.join(format!("{tag}.db")).display().to_string();
    (SqliteStore::open(&path, 5000).unwrap(), path, dir)
}

fn transact(store: &SqliteStore, request: &Request) -> OpResult<Decision> {
    match <SqliteStore as StoreSlots>::record_transaction(store, &mut Op::detached(), request) {
        Step::Ready(answer) => answer,
        Step::Pending { .. } => panic!("a local SQLite transaction must finish synchronously"),
    }
}

fn value(store: &SqliteStore, key: &[u8]) -> Option<Vec<u8>> {
    query_one(
        &store.lock_reader(),
        "SELECT value FROM schema_records WHERE schema=?1 AND record_key=?2",
        params![SCHEMA, key],
        |row| row.get(0),
    )
    .unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    records: Vec<(String, Vec<u8>, Vec<u8>)>,
    receipts: Vec<(Vec<u8>, String, String, i64)>,
    revision: i64,
}

fn snapshot(store: &SqliteStore) -> Snapshot {
    let conn = store.lock_reader();
    Snapshot {
        records: query_all(
            &conn,
            "SELECT schema, record_key, value FROM schema_records ORDER BY schema, record_key",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap(),
        receipts: query_all(
            &conn,
            "SELECT op_id, body, answer, recorded_at FROM store_ops ORDER BY op_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap(),
        revision: conn
            .query_row(
                "SELECT revision FROM store_revision WHERE id=0",
                [],
                |row| row.get(0),
            )
            .unwrap(),
    }
}

#[test]
fn absent_key_writers_on_two_connections_have_one_applied_receipt() {
    let (first, path, _dir) = on_file("absent-race");
    let second = SqliteStore::open(&path, 5000).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        let handles: Vec<_> = [first, second]
            .into_iter()
            .enumerate()
            .map(|(n, store)| {
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let request = candidate(
                        n as u64,
                        vec![predicate(b"claimed", Expected::Absent)],
                        vec![put(b"claimed", &[n as u8 + 1])],
                    );
                    barrier.wait();
                    transact(&store, &request).unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        outcomes.iter().filter(|&&d| d == Decision::Applied).count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|&&d| d == Decision::ConditionConflict)
            .count(),
        1
    );
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let state = snapshot(&reopened);
    assert_eq!(state.records.len(), 1);
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.revision, 0);
    assert!(matches!(
        value(&reopened, b"claimed").as_deref(),
        Some([1] | [2])
    ));
}

#[test]
fn all_predicates_read_the_prestate_and_binary_bytes_remain_exact() {
    let (store, _path, _dir) = on_file("prestate");
    store.v3_record_put(SCHEMA, b"a", b"old-a").unwrap();
    store.v3_record_put(SCHEMA, b"b", b"old-b").unwrap();
    let request = candidate(
        1,
        vec![
            predicate(b"a", Expected::Bytes(b"old-a".to_vec())),
            predicate(b"b", Expected::Bytes(b"old-b".to_vec())),
        ],
        vec![put(b"b", b"new-b"), put(b"a", b"new-a")],
    );
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(value(&store, b"a"), Some(b"new-a".to_vec()));
    assert_eq!(value(&store, b"b"), Some(b"new-b".to_vec()));
    let request = candidate(
        2,
        vec![predicate(&[0xff, 0, 0x80], Expected::Absent)],
        vec![put(&[0xff, 0, 0x80], &[0, 0xff, 1])],
    );
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(value(&store, &[0xff, 0, 0x80]), Some(vec![0, 0xff, 1]));
    let before = snapshot(&store);
    let wrong = candidate(
        3,
        vec![predicate(&[0xff, 0, 0x80], Expected::Bytes(vec![0, 0xff]))],
        vec![delete(b"a")],
    );
    assert_eq!(transact(&store, &wrong), Ok(Decision::ConditionConflict));
    assert_eq!(snapshot(&store), before);
}

#[test]
fn an_empty_blob_is_present_and_differs_from_an_absent_record() {
    let (store, _path, _dir) = on_file("empty-blob");
    store
        .lock_writer()
        .execute(
            "INSERT INTO schema_records(schema,record_key,value) VALUES (?1,?2,?3)",
            params![SCHEMA, b"empty".as_slice(), b"".as_slice()],
        )
        .unwrap();
    let absent = candidate(
        1,
        vec![predicate(b"empty", Expected::Absent)],
        vec![put(b"other", b"v")],
    );
    let before = snapshot(&store);
    assert_eq!(transact(&store, &absent), Ok(Decision::ConditionConflict));
    assert_eq!(snapshot(&store), before);
    let present = candidate(
        2,
        vec![predicate(b"empty", Expected::Bytes(Vec::new()))],
        vec![delete(b"empty")],
    );
    assert_eq!(transact(&store, &present), Ok(Decision::Applied));
    assert_eq!(value(&store, b"empty"), None);
}

/// Pause SQLite while it prepares the second, DELETE mutation, after the first INSERT executed.
/// A separate live store observes the old pair and no receipt, then the new pair and its receipt.
#[test]
fn independent_readers_never_observe_a_partial_record_batch_or_receipt() {
    let (writer, path, _dir) = on_file("atomic-visibility");
    writer.v3_record_put(SCHEMA, b"a", b"old-a").unwrap();
    writer.v3_record_put(SCHEMA, b"b", b"old-b").unwrap();
    let reader = SqliteStore::open(&path, 5000).unwrap();
    let request = candidate(
        1,
        vec![
            predicate(b"a", Expected::Bytes(b"old-a".to_vec())),
            predicate(b"b", Expected::Bytes(b"old-b".to_vec())),
        ],
        vec![put(b"a", b"new-a"), delete(b"b")],
    );
    let (waiting, release) = pause_before_record_delete(&writer);
    let observe = || {
        reader
            .lock_reader()
            .query_row(
                "SELECT (SELECT value FROM schema_records WHERE schema=?1 AND record_key=?2),
                    (SELECT value FROM schema_records WHERE schema=?1 AND record_key=?3),
                    EXISTS(SELECT 1 FROM store_ops WHERE op_id=?4)",
                params![SCHEMA, b"a".as_slice(), b"b".as_slice(), op(1).0.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| transact(&writer, &request));
        waiting
            .recv_timeout(Duration::from_secs(10))
            .expect("the real second mutation was reached");
        let during = observe();
        // Release before asserting, so a failed observation cannot strand the worker.
        release.send(()).unwrap();
        let answer = worker.join().unwrap();
        assert_eq!(
            during,
            (Some(b"old-a".to_vec()), Some(b"old-b".to_vec()), false)
        );
        assert_eq!(answer, Ok(Decision::Applied));
    });
    writer
        .lock_writer()
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    assert_eq!(observe(), (Some(b"new-a".to_vec()), None, true));
    let synchronous: i64 = writer
        .lock_writer()
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .unwrap();
    assert_eq!(
        synchronous, 2,
        "the transaction uses SQLite FULL synchronization"
    );
}

#[test]
fn an_aborted_later_mutation_rolls_back_earlier_effects_and_allows_same_id_retry() {
    for phase in ["BEFORE", "AFTER"] {
        let (store, path, _dir) = on_file(phase);
        store
            .lock_writer()
            .execute_batch(&format!(
                "CREATE TRIGGER stop_second {phase} INSERT ON schema_records
             WHEN NEW.record_key=X'62' BEGIN SELECT RAISE(ABORT,'injected later mutation'); END;"
            ))
            .unwrap();
        let request = candidate(
            1,
            vec![predicate(b"a", Expected::Absent)],
            vec![put(b"a", b"one"), put(b"b", b"two")],
        );
        let before = snapshot(&store);
        assert!(matches!(
            transact(&store, &request),
            Err(OpRefused::Failed(_))
        ));
        assert_eq!(snapshot(&store), before);
        let independent = SqliteStore::open(&path, 5000).unwrap();
        assert_eq!(snapshot(&independent), before);
        store
            .lock_writer()
            .execute_batch("DROP TRIGGER stop_second")
            .unwrap();
        assert_eq!(transact(&store, &request), Ok(Decision::Applied));
        assert_eq!(snapshot(&independent).receipts.len(), 1);
    }
}

#[test]
fn ignored_puts_and_deletes_do_not_publish_a_partial_batch() {
    for deleting in [false, true] {
        let (store, _path, _dir) = on_file("ignored-mutation");
        store.v3_record_put(SCHEMA, b"a", b"old-a").unwrap();
        if deleting {
            store.v3_record_put(SCHEMA, b"b", b"old-b").unwrap();
        }
        let event = if deleting { "DELETE" } else { "INSERT" };
        let key = if deleting {
            "OLD.record_key"
        } else {
            "NEW.record_key"
        };
        store
            .lock_writer()
            .execute_batch(&format!(
                "CREATE TRIGGER ignore_second BEFORE {event} ON schema_records
             WHEN {key}=X'62' BEGIN SELECT RAISE(IGNORE); END;"
            ))
            .unwrap();
        let request = candidate(
            1,
            vec![predicate(b"a", Expected::Bytes(b"old-a".to_vec()))],
            vec![
                put(b"a", b"new-a"),
                if deleting {
                    delete(b"b")
                } else {
                    put(b"b", b"new-b")
                },
            ],
        );
        let before = snapshot(&store);
        assert!(matches!(
            transact(&store, &request),
            Err(OpRefused::Failed(_))
        ));
        assert_eq!(snapshot(&store), before);
        store
            .lock_writer()
            .execute_batch("DROP TRIGGER ignore_second")
            .unwrap();
        assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    }
}

#[test]
fn a_receipt_write_failure_rolls_back_every_record_effect() {
    for action in ["RAISE(ABORT,'injected receipt failure')", "RAISE(IGNORE)"] {
        let (store, _path, _dir) = on_file("receipt-failure");
        store
            .lock_writer()
            .execute_batch(
                &format!(
            "CREATE TRIGGER stop_receipt BEFORE INSERT ON store_ops BEGIN SELECT {action}; END;"),
            )
            .unwrap();
        let request = candidate(
            1,
            vec![predicate(b"a", Expected::Absent)],
            vec![put(b"a", b"one"), put(b"b", b"two")],
        );
        let before = snapshot(&store);
        assert!(matches!(
            transact(&store, &request),
            Err(OpRefused::Failed(_))
        ));
        assert_eq!(snapshot(&store), before);
        store
            .lock_writer()
            .execute_batch("DROP TRIGGER stop_receipt")
            .unwrap();
        assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    }
}

#[test]
fn noops_conflicts_and_replays_preserve_revision_and_existing_receipts() {
    let (store, _path, _dir) = on_file("stability");
    store.v3_record_put(SCHEMA, b"a", b"same").unwrap();
    let before = snapshot(&store);
    let request = candidate(
        1,
        vec![predicate(b"a", Expected::Bytes(b"same".to_vec()))],
        vec![put(b"a", b"same"), delete(b"already-absent")],
    );
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    // Make an accidental receipt rewrite observable independently of the wall-clock tick.
    store
        .lock_writer()
        .execute(
            "UPDATE store_ops SET recorded_at=?1",
            params![now_secs() - 300],
        )
        .unwrap();
    let applied = snapshot(&store);
    assert_eq!(applied.records, before.records);
    assert_eq!(applied.revision, before.revision);
    assert_eq!(applied.receipts.len(), before.receipts.len() + 1);
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(snapshot(&store), applied);
    let conflict = candidate(
        2,
        vec![predicate(b"a", Expected::Bytes(b"wrong".to_vec()))],
        vec![delete(b"a")],
    );
    assert_eq!(transact(&store, &conflict), Ok(Decision::ConditionConflict));
    assert_eq!(snapshot(&store), applied);
    let mut changed = request.clone();
    changed.mutations[0] = put(b"a", b"different");
    assert_eq!(transact(&store, &changed), Err(OpRefused::Conflict));
    assert_eq!(snapshot(&store), applied);
}

#[test]
fn a_lost_answer_replays_the_same_receipt_after_restart_before_rechecking_predicates() {
    let (store, path, _dir) = on_file("lost-answer");
    let request = candidate(
        1,
        vec![predicate(b"a", Expected::Absent)],
        vec![put(b"a", b"committed")],
    );
    // The caller loses the answer after the durable write. It retains this immutable candidate.
    let _lost_answer = transact(&store, &request).unwrap();
    let committed = snapshot(&store);
    drop(store);
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    assert_eq!(transact(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(snapshot(&reopened), committed);
    let mut different_id = request.clone();
    different_id.op_id = op(2);
    assert_eq!(
        transact(&reopened, &different_id),
        Ok(Decision::ConditionConflict)
    );
    assert_eq!(snapshot(&reopened), committed);
    let mut changed_body = request.clone();
    changed_body.predicates[0].expected = Expected::Bytes(b"committed".to_vec());
    assert_eq!(transact(&reopened, &changed_body), Err(OpRefused::Conflict));
    assert_eq!(snapshot(&reopened), committed);
}

#[test]
fn invalid_requests_refuse_before_effects_or_receipt_creation() {
    let (store, _path, _dir) = on_file("invalid");
    let valid = candidate(
        1,
        vec![predicate(b"a", Expected::Absent)],
        vec![put(b"a", b"v")],
    );
    let mut cases = Vec::new();
    let mut wrong = valid.clone();
    wrong.version += 1;
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.predicates.clear();
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.mutations.clear();
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.predicates.push(wrong.predicates[0].clone());
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.mutations.push(wrong.mutations[0].clone());
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.mutations[0] = put(b"a", b"");
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.mutations[0] = put(
        b"a",
        &vec![0; busbar_contract::bounded::MAX_RECORD_BYTES + 1],
    );
    cases.push(wrong);
    let before = snapshot(&store);
    for request in cases {
        assert!(matches!(
            transact(&store, &request),
            Err(OpRefused::Refused(_))
        ));
        assert_eq!(snapshot(&store), before);
    }
    assert_eq!(transact(&store, &valid), Ok(Decision::Applied));
}

#[test]
fn conditional_receipts_share_the_existing_operation_id_domain_and_retention() {
    let (store, _path, _dir) = on_file("receipt-domain");
    let request = candidate(
        1,
        vec![predicate(b"a", Expected::Absent)],
        vec![put(b"a", b"v")],
    );
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    let before = snapshot(&store);
    assert_eq!(
        store.v3_add_usage_batch(request.op_id, &[]),
        Err(OpRefused::Conflict)
    );
    assert_eq!(snapshot(&store), before);
    store.v3_add_usage_batch(op(2), &[]).unwrap();
    let mut another = request.clone();
    another.op_id = op(2);
    let before = snapshot(&store);
    assert_eq!(transact(&store, &another), Err(OpRefused::Conflict));
    assert_eq!(snapshot(&store), before);
    let expired_at = retention_cutoff(now_secs()) - 5;
    store
        .lock_writer()
        .execute(
            "UPDATE store_ops SET recorded_at=?1 WHERE op_id=?2",
            params![expired_at, request.op_id.0.as_slice()],
        )
        .unwrap();
    store.v3_record_put(SCHEMA, b"a", b"").unwrap();
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(value(&store, b"a"), Some(b"v".to_vec()));
    let retained: i64 = store
        .lock_reader()
        .query_row(
            "SELECT recorded_at FROM store_ops WHERE op_id=?1",
            params![request.op_id.0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(retained > expired_at);
}

fn range(prefix: &[u8], exact_key_length: u64) -> Mutation {
    Mutation::DeleteRange {
        schema: SCHEMA.into(),
        prefix: prefix.to_vec(),
        exact_key_length,
    }
}

/// Block on the actual DELETE statement's preparation, after preceding mutations have run.
fn pause_before_record_delete(store: &SqliteStore) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (entered, waiting) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let mut paused = false;
    store
        .lock_writer()
        .authorizer(Some(move |context: AuthContext<'_>| {
            if !paused
                && matches!(
                    context.action,
                    AuthAction::Delete {
                        table_name: "schema_records"
                    }
                )
            {
                paused = true;
                let _ = entered.send(());
                if released.recv_timeout(Duration::from_secs(10)).is_err() {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }))
        .unwrap();
    (waiting, release)
}

#[test]
fn a_range_deletes_only_its_schema_raw_prefix_and_exact_byte_length() {
    let (store, _path, _dir) = on_file("range-selector");
    let prefix = [0xff, 0, b'%', b'_'];
    let a = [0xff, 0, b'%', b'_', 1, 2];
    let b = [0xff, 0, b'%', b'_', 3, 4];
    let short = [0xff, 0, b'%', b'_', 1];
    let long = [0xff, 0, b'%', b'_', 1, 2, 3];
    let different = [0xff, 0, b'%', b'x', 1, 2];
    for key in [
        a.as_slice(),
        b.as_slice(),
        short.as_slice(),
        long.as_slice(),
        different.as_slice(),
    ] {
        store.v3_record_put(SCHEMA, key, b"old").unwrap();
    }
    store.v3_record_put("other-schema", &a, b"other").unwrap();
    let request = candidate(
        1,
        vec![
            predicate(&a, Expected::Bytes(b"old".to_vec())),
            predicate(b"parent", Expected::Absent),
        ],
        vec![put(b"parent", b"published"), range(&prefix, 6)],
    );
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(value(&store, &a), None);
    assert_eq!(value(&store, &b), None);
    assert_eq!(value(&store, &short), Some(b"old".to_vec()));
    assert_eq!(value(&store, &long), Some(b"old".to_vec()));
    assert_eq!(value(&store, &different), Some(b"old".to_vec()));
    assert_eq!(value(&store, b"parent"), Some(b"published".to_vec()));
    assert_eq!(
        store
            .v3_record_get("other-schema", &a)
            .unwrap()
            .map(|v| v.as_slice().to_vec()),
        Some(b"other".to_vec())
    );
    assert_eq!(snapshot(&store).receipts.len(), 1);
}

#[test]
fn ranges_cover_empty_and_all_ff_prefixes_without_length_truncation() {
    let (store, _path, _dir) = on_file("range-edges");
    for key in [
        b"".as_slice(),
        &[0xff],
        &[0xff, 0],
        &[0xff, 0xff],
        &[0xff, 0, 1],
        &[0xfe, 0xff],
    ] {
        store.v3_record_put(SCHEMA, key, b"old").unwrap();
    }
    let request = candidate(
        1,
        vec![predicate(b"parent", Expected::Absent)],
        vec![range(&[0xff], 2)],
    );
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(value(&store, &[0xff, 0]), None);
    assert_eq!(value(&store, &[0xff, 0xff]), None);
    assert_eq!(value(&store, &[0xff]), Some(b"old".to_vec()));
    assert_eq!(value(&store, &[0xff, 0, 1]), Some(b"old".to_vec()));
    assert_eq!(value(&store, &[0xfe, 0xff]), Some(b"old".to_vec()));
    let request = candidate(
        2,
        vec![predicate(b"parent", Expected::Absent)],
        vec![range(b"", 0)],
    );
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(value(&store, b""), None);
    assert_eq!(value(&store, &[0xff]), Some(b"old".to_vec()));
    if usize::try_from(u64::MAX).is_ok() {
        let before = snapshot(&store);
        let request = candidate(
            3,
            vec![predicate(b"parent", Expected::Absent)],
            vec![range(b"", u64::MAX)],
        );
        assert_eq!(transact(&store, &request), Ok(Decision::Applied));
        let after = snapshot(&store);
        assert_eq!(after.records, before.records);
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.receipts.len(), before.receipts.len() + 1);
    }
}

#[test]
fn range_cleanup_and_parent_publication_are_visible_in_one_commit() {
    let (writer, path, _dir) = on_file("range-atomic");
    writer.v3_record_put(SCHEMA, b"parent", b"old").unwrap();
    for key in [b"range/a".as_slice(), b"range/b", b"range/aa"] {
        writer.v3_record_put(SCHEMA, key, b"child").unwrap();
    }
    let reader = SqliteStore::open(&path, 5000).unwrap();
    let before = snapshot(&reader);
    let request = candidate(
        1,
        vec![predicate(b"parent", Expected::Bytes(b"old".to_vec()))],
        vec![put(b"parent", b"new"), range(b"range/", 7)],
    );
    let (waiting, release) = pause_before_record_delete(&writer);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| transact(&writer, &request));
        waiting
            .recv_timeout(Duration::from_secs(10))
            .expect("the real range delete was reached");
        let during = snapshot(&reader);
        release.send(()).unwrap();
        let answer = worker.join().unwrap();
        assert_eq!(during, before);
        assert_eq!(answer, Ok(Decision::Applied));
    });
    writer
        .lock_writer()
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    assert_eq!(value(&reader, b"parent"), Some(b"new".to_vec()));
    assert_eq!(value(&reader, b"range/a"), None);
    assert_eq!(value(&reader, b"range/b"), None);
    assert_eq!(value(&reader, b"range/aa"), Some(b"child".to_vec()));
    assert_eq!(snapshot(&reader).receipts.len(), 1);
}

#[test]
fn range_abort_ignore_and_receipt_failure_restore_every_child_and_parent() {
    for mode in ["range-abort", "range-ignore", "receipt-ignore"] {
        let (store, _path, _dir) = on_file(mode);
        store.v3_record_put(SCHEMA, b"parent", b"old").unwrap();
        store.v3_record_put(SCHEMA, b"p:a", b"a").unwrap();
        store.v3_record_put(SCHEMA, b"p:b", b"b").unwrap();
        let sql = match mode {
            "range-abort" => "CREATE TRIGGER stop_range AFTER DELETE ON schema_records WHEN OLD.record_key=X'703a61' BEGIN SELECT RAISE(ABORT,'injected range failure'); END;",
            "range-ignore" => "CREATE TRIGGER stop_range BEFORE DELETE ON schema_records WHEN OLD.record_key=X'703a61' BEGIN SELECT RAISE(IGNORE); END;",
            _ => "CREATE TRIGGER stop_range BEFORE INSERT ON store_ops BEGIN SELECT RAISE(IGNORE); END;",
        };
        store.lock_writer().execute_batch(sql).unwrap();
        let request = candidate(
            1,
            vec![predicate(b"parent", Expected::Bytes(b"old".to_vec()))],
            vec![put(b"parent", b"new"), range(b"p:", 3)],
        );
        let before = snapshot(&store);
        assert!(matches!(
            transact(&store, &request),
            Err(OpRefused::Failed(_))
        ));
        assert_eq!(snapshot(&store), before);
        store
            .lock_writer()
            .execute_batch("DROP TRIGGER stop_range")
            .unwrap();
        assert_eq!(transact(&store, &request), Ok(Decision::Applied));
        assert_eq!(value(&store, b"parent"), Some(b"new".to_vec()));
        assert_eq!(value(&store, b"p:a"), None);
        assert_eq!(value(&store, b"p:b"), None);
    }
}

#[test]
fn invalid_or_overlapping_range_selectors_refuse_without_a_receipt() {
    let (store, _path, _dir) = on_file("range-overlap");
    store.v3_record_put(SCHEMA, b"p:a", b"old").unwrap();
    let before = snapshot(&store);
    for mutations in [
        vec![range(b"p:", 1)],
        vec![range(b"p:", 3), put(b"p:a", b"new")],
        vec![range(b"p", 3), range(b"p:", 3)],
    ] {
        let request = candidate(1, vec![predicate(b"parent", Expected::Absent)], mutations);
        assert!(matches!(
            transact(&store, &request),
            Err(OpRefused::Refused(_))
        ));
        assert_eq!(snapshot(&store), before);
    }
    let allowed = candidate(
        2,
        vec![predicate(b"parent", Expected::Absent)],
        vec![range(b"p:", 3), put(b"p:aa", b"longer")],
    );
    assert_eq!(transact(&store, &allowed), Ok(Decision::Applied));
    assert_eq!(value(&store, b"p:a"), None);
    assert_eq!(value(&store, b"p:aa"), Some(b"longer".to_vec()));
}

#[test]
fn a_range_lost_answer_replay_never_deletes_children_created_after_its_commit() {
    let (store, path, _dir) = on_file("range-lost-answer");
    store.v3_record_put(SCHEMA, b"p:a", b"old-child").unwrap();
    let request = candidate(
        1,
        vec![predicate(b"parent", Expected::Absent)],
        vec![put(b"parent", b"published"), range(b"p:", 3)],
    );
    let _lost_answer = transact(&store, &request).unwrap();
    drop(store);
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    reopened
        .v3_record_put(SCHEMA, b"p:b", b"new-child")
        .unwrap();
    let committed = snapshot(&reopened);
    assert_eq!(transact(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(snapshot(&reopened), committed);
    let mut different_body = request.clone();
    different_body.mutations[1] = range(b"p:", 4);
    assert_eq!(
        transact(&reopened, &different_body),
        Err(OpRefused::Conflict)
    );
    assert_eq!(snapshot(&reopened), committed);
    let mut different_id = request.clone();
    different_id.op_id = op(2);
    assert_eq!(
        transact(&reopened, &different_id),
        Ok(Decision::ConditionConflict)
    );
    assert_eq!(snapshot(&reopened), committed);
}
