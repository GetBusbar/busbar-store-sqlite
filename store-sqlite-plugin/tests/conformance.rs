// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE SQLITE STORE, BOTH DOORS, ONE TABLE** — the store's linked + dropped-in conformance on the
//! store kind's memory ABI (THE DESIGN §11, store v3), run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! The store is held two ways at once: LINKED (the logic crate's `door::door`, through the loader's
//! `load_linked`, the row a busbar build that compiles it in registers) and DROPPED IN (this crate's
//! built cdylib, `dlopen`ed by the loader's `load_dropped` against the Statement rendering the door
//! states, which is what `busbar-plugin-pack` signs into the manifest). Each is bound to a real
//! dispatcher and opened as the host opens a store (`LoadedStore`), and driven through ONE scenario
//! against its own real database file: the config refusals, a key, a usage window, plane records of
//! an upsert and an append-only kind, the v3 slots (a count batch and its replay and conflict, and
//! schema records), a SECOND live handle on the same file (the
//! cross-handle view), and a RESTART — every handle closed, the file reopened, everything read back
//! and every `op_id` replayed. The two arms must agree on the whole transcript.
//!
//! The RED arms are their own tests (plugin-gates `bothways` needs a RED arm beside the both-ways
//! test): (a) the door asked for as another kind is refused, linked and dropped in; (b) the
//! dropped-in door opened on a file that already holds a foreign key yields a transcript that
//! DIFFERS from the linked one — so the comparison above can see a real difference
//! and is not vacuously equal. A missing cdylib PANICS: this test IS the dropped-in door's proof.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::slot as lc;
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, UsageDelta, VirtualKey,
};

use busbar_contract::store_calls as sc;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of_library, rendering_of_macro, Bind,
    DispatchConfig, Dispatcher, Frame, LinkedRow, LoadError, NoSink, Plugin,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use busbar_store_sqlite::door::MACRO_DOOR;

#[path = "support/credential_rewrap.rs"]
mod credential_rewrap;

fn stamp_newer_schema(_: &str, settings: &[u8]) {
    let settings: serde_json::Value = serde_json::from_slice(settings).unwrap();
    let path = settings["db_path"].as_str().expect("SQLite file path");
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "user_version", i32::MAX).unwrap();
}

/// CI builds this exact package immediately before running these tests. An explicit artifact
/// path supports isolated build lanes; absence is always a hard failure.
fn cdylib() -> PathBuf {
    if let Some(path) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        let path = PathBuf::from(path);
        assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
        assert!(path.is_file(), "missing SQLite cdylib: {}", path.display());
        return path;
    }
    let exe = std::env::current_exe().expect("test binary path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/profile");
    let path = profile.join(busbar_plugin_loader::plugin_library_filename(
        "busbar_store_sqlite_plugin",
    ));
    assert!(
        path.is_file(),
        "build busbar-store-sqlite-plugin --lib before testing: {}",
        path.display()
    );
    path
}

/// Which door a handle came in by.
#[derive(Clone, Copy)]
enum Door {
    Linked,
    Dropped,
}

/// What every instance is bound to: its own dispatcher, a label unique to it, no envelope sink.
fn bind(d: &Dispatcher) -> Bind {
    static N: AtomicU64 = AtomicU64::new(0);
    Bind {
        instance: Arc::from(format!("sqlite-{}", N.fetch_add(1, Ordering::Relaxed))),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    }
}

/// The store `door` loaded through `by`, asked for as kind `K`.
fn load<K: busbar_plugin_loader::dispatch::Kind>(
    by: Door,
    d: &Dispatcher,
) -> Result<Plugin<K>, LoadError> {
    match by {
        Door::Linked => load_linked::<K>(&LinkedRow::of_macro(MACRO_DOOR)?, bind(d)),
        Door::Dropped => load_dropped::<K>(&cdylib(), &rendering_of_macro(MACRO_DOOR)?, bind(d)),
    }
}

/// The node's one `op_id` allocator, as the kernel hands a store handle its own: the bridge's
/// additive writes mint from it. Its node half is one no test op id uses.
fn mint() -> busbar_contract::abi::store::OpId {
    static N: AtomicU64 = AtomicU64::new(0);
    busbar_contract::abi::store::OpId::from_parts(0x5e1f, N.fetch_add(1, Ordering::Relaxed) + 1)
}
/// One store instance through `by`, opened on `cfg` as the host opens a store.
fn open(by: Door, cfg: &str) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load::<Store>(by, &d).map_err(|e| e.to_string())?;
    LoadedStore::open(plugin, d, cfg.as_bytes(), mint)
}

/// `close` the instance, as the host does at a restart: its connections to the file go with it.
fn close(s: LoadedStore) {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    let c = s.plugin().call(lc::CLOSE, &mut f);
    assert_eq!(c.outcome, Outcome::Ready, "close answers Ready");
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

/// A fresh scratch directory for this process.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("store-sqlite-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: format!("binding:{id}:1"),
        enabled: true,
        ..Default::default()
    }
}

fn record(kind: &str, id: &str, parent: Option<&str>, seq: u64, body: &str) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(Into::into),
        seq,
        ts: 1_700_000_000 + seq,
        disposition: PlaneDisposition::Active,
        body: body.as_bytes().to_vec(),
    }
}

fn op(n: u64) -> OpId {
    OpId::from_parts(42, n)
}

/// Everything a store holds that the scenario wrote, as one comparable value.
fn contents(s: &LoadedStore) -> serde_json::Value {
    let mut keys: Vec<serde_json::Value> = s
        .list_keys()
        .expect("list_keys")
        .iter()
        .map(|k| serde_json::to_value(k).unwrap())
        .collect();
    keys.sort_by_key(|k| k["id"].to_string());
    let text = |rows: Vec<Vec<u8>>| -> Vec<String> {
        rows.into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect()
    };
    let bytes =
        |r: Option<RecordBytes>| r.map(|r| String::from_utf8_lossy(r.as_slice()).into_owned());
    let (record, scan) = block(async {
        (
            sc::StoreCalls::record_get(s, "conf", b"k1").await,
            sc::StoreCalls::record_scan(s, "conf", b"k", 10).await,
        )
    });
    serde_json::json!({
        "keys": keys,
        "usage": s.get_usage("vk_conf", 1_700_000_000).expect("get_usage"),
        "task": s.get_plane_record("task", "t1").expect("get_plane_record")
            .map(|b| String::from_utf8(b).unwrap()),
        "events": text(s.list_plane_records("task_event", &PlaneSelector::Parent("t1".into()))
            .expect("list_plane_records")),
        "parents": s.list_plane_record_parents("task_event").expect("parents"),
        "record": format!("{:?}", record.map(bytes)),
        "scan": format!("{:?}", scan.map(|rows| rows.into_iter()
            .map(|(k, v)| (String::from_utf8_lossy(&k).into_owned(), bytes(Some(v))))
            .collect::<Vec<_>>())),
        "batched": s.get_usage("vk_batch", 60).expect("get_usage"),
    })
}

/// The usage batch the scenario writes, and replays after the restart.
fn batch() -> [(&'static str, u64, UsageDelta); 1] {
    [(
        "vk_batch",
        60,
        UsageDelta {
            requests: 2,
            billable_requests: 2,
            models: vec![],
        },
    )]
}

/// The v3 writes, through the door's table: one line per answer.
fn v3_writes(s: &LoadedStore) -> Vec<String> {
    let r = |v: &[u8]| RecordBytes::new(v.to_vec()).expect("a record");
    block(async {
        vec![
            format!(
                "usage batch = {:?}",
                sc::StoreCalls::add_usage_batch(s, op(1), &batch()).await
            ),
            format!(
                "replay = {:?}",
                sc::StoreCalls::add_usage_batch(s, op(1), &batch()).await
            ),
            format!(
                "conflict = {:?}",
                sc::StoreCalls::add_usage_batch(s, op(1), &[]).await
            ),
            format!(
                "record_put = {:?}",
                sc::StoreCalls::record_put(s, "conf", b"k1", &r(b"one")).await
            ),
            format!(
                "record_put k2 = {:?}",
                sc::StoreCalls::record_put(s, "conf", b"k2", &r(b"two")).await
            ),
        ]
    })
}

/// The `op_id`s replayed after the restart: each answers its original, applying nothing.
fn v3_replays(s: &LoadedStore) -> Vec<String> {
    block(async {
        vec![
            format!(
                "replay = {:?}",
                sc::StoreCalls::add_usage_batch(s, op(1), &batch()).await
            ),
            format!(
                "conflict = {:?}",
                sc::StoreCalls::add_usage_batch(s, op(1), &[]).await
            ),
        ]
    })
}

/// What one door does with the store, as one comparable transcript.
fn transcript(by: Door, tag: &str, seed: Option<&str>) -> serde_json::Value {
    let refusals: Vec<String> = [
        "{ not json",
        r#"{"db_path": 5}"#,
        r#"{"db_path": ":memory:", "busy_timeout_ms": -1}"#,
        r#"{"db_path": ":memory:", "busy_timeout_ms": "5000"}"#,
    ]
    .iter()
    .map(|cfg| match open(by, cfg) {
        Ok(_) => format!("{cfg} OPENED"),
        Err(e) => e,
    })
    .collect();

    let dir = scratch(&format!("db-{tag}"));
    let db = dir.join("governance.db");
    let cfg = serde_json::json!({"db_path": db.display().to_string(), "busy_timeout_ms": 2000})
        .to_string();
    if let Some(foreign) = seed {
        let s = open(by, &cfg).expect("seed open");
        s.put_key(&key(foreign)).expect("seed put_key");
        close(s);
    }

    let a = open(by, &cfg).expect("the store opens");
    let name = a.name().to_string();
    let facts = format!("{:?}", a.facts());
    a.put_key(&key("vk_conf")).expect("put_key");
    a.add_usage(
        "vk_conf",
        1_700_000_000,
        &UsageDelta {
            requests: 3,
            billable_requests: 2,
            models: vec![],
        },
    )
    .expect("add_usage");
    a.upsert_plane_record(record("task", "t1", None, 0, "{\"state\":\"working\"}").view())
        .expect("upsert");
    a.upsert_plane_record(record("task", "t1", None, 0, "{\"state\":\"input-required\"}").view())
        .expect("upsert again");
    for seq in 1..=3 {
        a.append_plane_record(
            record(
                "task_event",
                &format!("e{seq}"),
                Some("t1"),
                seq,
                &format!("{{\"seq\":{seq}}}"),
            )
            .view(),
        )
        .expect("append");
    }

    let dup = a
        .append_plane_record(record("task_event", "e1", Some("t1"), 1, "{}").view())
        .map_err(|e| e.0);
    let writes = v3_writes(&a);

    let b = open(by, &cfg).expect("a second handle opens");
    b.put_key(&key("vk_other")).expect("second-handle put_key");
    let cross = serde_json::json!({"b_sees": contents(&b), "dup": format!("{dup:?}")});
    let live = contents(&a);
    close(b);
    close(a);

    let c = open(by, &cfg).expect("the store reopens");
    let restarted = contents(&c);
    let replays = v3_replays(&c);
    close(c);
    let _ = std::fs::remove_dir_all(&dir);
    serde_json::json!({
        "name": name,
        "facts": facts,
        "refusals": refusals,
        "writes": writes,
        "live": live,
        "cross": cross,
        "restarted": restarted,
        "replays": replays,
    })
}

/// The sqlite store behaves as ONE store through either door (the RED arms below show the
/// comparison can tell a different store apart).
#[test]
fn the_linked_and_the_dropped_in_sqlite_store_are_one_store() {
    assert_eq!(
        rendering_of_library(&cdylib()).expect("the cdylib loads"),
        Some(rendering_of_macro(MACRO_DOOR).expect("the door renders")),
        "the dropped-in library must state exactly the linked door's Statement"
    );

    let linked = transcript(Door::Linked, "linked", None);
    let dropped_in = transcript(Door::Dropped, "dropped", None);
    assert_eq!(linked, dropped_in, "the two doors are not one store");

    assert_eq!(linked["name"], "busbar-store-sqlite");
    let restarted = &linked["restarted"];
    assert_eq!(
        restarted["keys"].as_array().unwrap().len(),
        2,
        "{restarted}"
    );
    assert_eq!(restarted["usage"]["requests"], 3);
    assert_eq!(restarted["task"], "{\"state\":\"input-required\"}");
    assert_eq!(
        restarted["events"],
        serde_json::json!(["{\"seq\":1}", "{\"seq\":2}", "{\"seq\":3}"])
    );
    assert_eq!(restarted["parents"], serde_json::json!(["t1"]));
    assert_eq!(restarted["record"], "Ok(Some(\"one\"))");
    assert_eq!(restarted["batched"]["requests"], 2);
    assert_eq!(linked["cross"]["b_sees"]["task"], restarted["task"]);
    assert!(
        linked["cross"]["dup"].as_str().unwrap().starts_with("Err("),
        "a different record at a used (parent, seq) must be refused: {}",
        linked["cross"]["dup"]
    );
    let refusals = linked["refusals"].as_array().unwrap();
    assert!(
        refusals
            .iter()
            .all(|r| r.as_str().unwrap().contains("invalid sqlite plugin config")),
        "every bad config is refused in the store's own words: {refusals:?}"
    );

    let writes = linked["writes"].as_array().unwrap();
    let w = |i: usize| writes[i].as_str().unwrap().to_string();
    assert_eq!(w(0), "usage batch = Ok(())", "{writes:?}");
    assert_eq!(w(1), "replay = Ok(())", "{writes:?}");
    assert!(w(2).contains("Conflict"), "{writes:?}");
    let replays = linked["replays"].as_array().unwrap();
    let r = |i: usize| replays[i].as_str().unwrap().to_string();
    assert_eq!(r(0), "replay = Ok(())", "{replays:?}");
    assert!(r(1).contains("Conflict"), "{replays:?}");
}

/// Loading a store door as a secret is refused through both linked and dropped-in forms.
#[test]
fn a_store_door_loaded_as_another_kind_is_refused() {
    let d = Dispatcher::new(DispatchConfig::default());
    for by in [Door::Linked, Door::Dropped] {
        match load::<Secret>(by, &d) {
            Ok(_) => panic!("a store door loaded as a secret; it must be refused"),
            Err(e) => assert!(
                matches!(
                    e,
                    LoadError::WrongKind { .. } | LoadError::ManifestKind { .. }
                ),
                "{e}"
            ),
        }
    }
}

/// A dropped-in store holding a foreign row produces a different transcript.
#[test]
fn a_store_holding_a_foreign_row_does_not_compare_equal() {
    let linked = transcript(Door::Linked, "linked-red", None);
    let red = transcript(Door::Dropped, "red", Some("vk_foreign"));
    assert_ne!(
        red, linked,
        "a store holding a foreign row must not compare equal"
    );
}

/// The store's Statement declares exactly its secret fields (`secret_refs`), never `*`: busbar
/// resolves a secret reference only at a position the Statement declares secret and refuses one
/// anywhere else (busbar #1699, ORACLE-SIGNOFF G14: each plugin declares its secret fields). The one
/// secret-valued key a 1.5.5 sqlite config carried is `license_key` (busbar oracle BOOT-170: its
/// unresolved reference refuses the boot with the 1.5.5 text); `db_path` and `busy_timeout_ms` are
/// not secrets. The dropped-in library states the same Statement (the test above).
#[test]
fn the_statement_declares_exactly_its_secret_fields() {
    let stated = busbar_contract::abi::mechanism::rendering::read(
        &rendering_of_macro(MACRO_DOOR).expect("the door renders"),
    )
    .expect("the rendering reads back");
    assert_eq!(stated.secret_refs, ["license_key".to_string()]);
}

fn cleanup_ledger() -> busbar_contract::records::UsageLedger {
    busbar_contract::records::UsageLedger {
        requests: 7,
        billable_requests: 6,
        models: ["a", "b"]
            .into_iter()
            .map(|model| busbar_contract::records::ModelTokens {
                model: model.into(),
                usage_units: [("input".into(), 11), ("tool_calls".into(), 3)].into(),
            })
            .collect(),
    }
}

#[test]
fn usage_cleanup_is_strict_and_durable_through_either_door() {
    use busbar_contract::records::{MeteringDelta, UsageLedger};

    for (by, tag) in [(Door::Linked, "linked"), (Door::Dropped, "dropped")] {
        let dir = scratch(&format!("usage-cleanup-{tag}"));
        let path = dir.join("store.db");
        let cfg = serde_json::json!({"db_path": path}).to_string();
        let s = open(by, &cfg).expect("the store opens");
        let ledger = cleanup_ledger();
        let high = i64::MAX as u64;
        for (bucket, window) in [
            ("a", 0),
            ("a", 10),
            ("b", 10),
            ("a", 19),
            ("b", 19),
            ("a", 20),
            ("b", 21),
            ("a", high),
            ("a", high + 1),
            ("a", u64::MAX - 1),
            ("a", u64::MAX),
        ] {
            let value = if (bucket, window) == ("a", 19) {
                UsageLedger {
                    models: Vec::new(),
                    ..ledger.clone()
                }
            } else {
                ledger.clone()
            };
            s.put_usage(bucket, window, &value).unwrap();
        }
        let raw = rusqlite::Connection::open(&path).unwrap();

        raw.execute(
            "DELETE FROM usage_windows WHERE bucket_id='b' AND window_start=19 AND model=''",
            [],
        )
        .unwrap();
        s.put_key(&key("keep")).unwrap();
        s.upsert_plane_record(record("task", "keep", None, 0, "keep").view())
            .unwrap();
        let billing = MeteringDelta {
            key_id: "keep".into(),
            bucket: 100,
            model: "a".into(),
            provider: "p".into(),
            tokens_input: 11,
            tokens_output: 2,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
            priced_from_ms: 0,
            usage_units: [("tool_calls".into(), 3)].into(),
        };
        s.add_metering(&billing).unwrap();
        let billed = s.list_metering(100).unwrap();
        assert_eq!(
            block(sc::StoreCalls::purge_usage_before(&s, 20)).unwrap(),
            4,
            "count logical windows, including model-only and counters-only windows"
        );
        for (bucket, window) in [("a", 10), ("b", 10), ("a", 19), ("b", 19)] {
            assert_eq!(s.get_usage(bucket, window).unwrap(), UsageLedger::default());
        }
        for table in ["usage_windows", "usage_window_units"] {
            let count: i64 = raw
                .query_row(
                    &format!(
                        "SELECT count(*) FROM {table} WHERE window_start>0 AND window_start<20"
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "no old model or open-unit rows remain in {table}");
        }
        for (bucket, window) in [
            ("a", 0),
            ("a", 20),
            ("b", 21),
            ("a", high),
            ("a", high + 1),
            ("a", u64::MAX - 1),
            ("a", u64::MAX),
        ] {
            assert_eq!(s.get_usage(bucket, window).unwrap(), ledger);
        }
        assert_eq!(
            block(sc::StoreCalls::purge_usage_before(&s, 20)).unwrap(),
            0
        );
        assert_eq!(block(sc::StoreCalls::purge_usage_before(&s, 0)).unwrap(), 0);
        assert_eq!(
            block(sc::StoreCalls::purge_usage_before(&s, high)).unwrap(),
            2
        );
        assert_eq!(
            s.get_usage("a", high).unwrap(),
            ledger,
            "cutoff equality survives"
        );
        assert_eq!(
            block(sc::StoreCalls::purge_usage_before(&s, high + 1)).unwrap(),
            1
        );
        assert_eq!(s.get_usage("a", high + 1).unwrap(), ledger);
        assert_eq!(
            block(sc::StoreCalls::purge_usage_before(&s, u64::MAX)).unwrap(),
            2
        );
        assert_eq!(s.get_usage("a", 0).unwrap(), ledger);
        assert_eq!(s.get_usage("a", u64::MAX).unwrap(), ledger);
        assert_eq!(
            s.list_metering(100).unwrap(),
            billed,
            "billing history is separate"
        );
        assert!(s.get_key("keep").unwrap().is_some());
        assert_eq!(
            s.get_plane_record("task", "keep").unwrap(),
            Some(b"keep".to_vec())
        );
        drop(raw);
        close(s);
        let reopened = open(by, &cfg).unwrap();
        assert_eq!(
            block(sc::StoreCalls::purge_usage_before(&reopened, u64::MAX)).unwrap(),
            0
        );
        assert_eq!(reopened.get_usage("a", 0).unwrap(), ledger);
        assert_eq!(reopened.get_usage("a", u64::MAX).unwrap(), ledger);
        assert_eq!(reopened.list_metering(100).unwrap(), billed);
        close(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn a_failed_usage_cleanup_rolls_back_both_tables_through_either_door() {
    for (by, tag) in [(Door::Linked, "linked"), (Door::Dropped, "dropped")] {
        let dir = scratch(&format!("usage-cleanup-rollback-{tag}"));
        let path = dir.join("store.db");
        let cfg = serde_json::json!({"db_path": path}).to_string();
        let s = open(by, &cfg).unwrap();
        let ledger = cleanup_ledger();
        s.put_usage("a", 10, &ledger).unwrap();
        let raw = rusqlite::Connection::open(&path).unwrap();

        raw.execute_batch(
            "
            CREATE TRIGGER reject_window_without_units BEFORE DELETE ON usage_windows
            WHEN NOT EXISTS (SELECT 1 FROM usage_window_units WHERE
                window_start=OLD.window_start AND bucket_id=OLD.bucket_id)
            BEGIN SELECT RAISE(ABORT, 'cleanup rollback fixture'); END;
            CREATE TRIGGER reject_units_without_window BEFORE DELETE ON usage_window_units
            WHEN NOT EXISTS (SELECT 1 FROM usage_windows WHERE
                window_start=OLD.window_start AND bucket_id=OLD.bucket_id)
            BEGIN SELECT RAISE(ABORT, 'cleanup rollback fixture'); END;
        ",
        )
        .unwrap();
        assert!(block(sc::StoreCalls::purge_usage_before(&s, 20)).is_err());
        assert_eq!(
            s.get_usage("a", 10).unwrap(),
            ledger,
            "all models and units roll back"
        );
        raw.execute_batch(
            "DROP TRIGGER reject_window_without_units; DROP TRIGGER reject_units_without_window;",
        )
        .unwrap();
        assert_eq!(
            block(sc::StoreCalls::purge_usage_before(&s, 20)).unwrap(),
            1
        );
        assert_eq!(s.get_usage("a", 10).unwrap(), Default::default());
        drop(raw);
        close(s);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn exact_usage_keeps_opaque_models_and_sparse_open_units_through_either_door() {
    use busbar_contract::records::{ModelTokens, ModelTokensDelta, UsageLedger};

    for (by, tag) in [(Door::Linked, "linked"), (Door::Dropped, "dropped")] {
        let dir = scratch(&format!("sparse-exact-usage-{tag}"));
        let cfg = serde_json::json!({"db_path": dir.join("store.db")}).to_string();
        let store = open(by, &cfg).unwrap();
        let model = "future.model/v7:\u{1e}opaque%|空";
        let mut offered = UsageLedger {
            requests: u64::MAX,
            billable_requests: u64::MAX,
            models: vec![ModelTokens {
                model: model.into(),
                usage_units: [
                    ("input".into(), u64::MAX),
                    ("tool_calls".into(), 17),
                    ("idle".into(), 0),
                ]
                .into(),
            }],
        };
        store.put_usage("opaque", 60, &offered).unwrap();
        offered.models[0].usage_units.remove("idle");
        assert_eq!(store.get_usage("opaque", 60).unwrap(), offered);
        let cells = [(
            "opaque",
            60,
            UsageDelta {
                requests: -1,
                billable_requests: -1,
                models: vec![ModelTokensDelta {
                    model: model.into(),
                    usage_units: [
                        ("input".into(), -1),
                        ("tool_calls".into(), -1),
                        ("idle".into(), 0),
                    ]
                    .into(),
                }],
            },
        )];
        block(sc::StoreCalls::add_usage_batch(&store, op(1), &cells)).unwrap();
        offered.requests -= 1;
        offered.billable_requests -= 1;
        offered.models[0]
            .usage_units
            .insert("input".into(), u64::MAX - 1);
        offered.models[0]
            .usage_units
            .insert("tool_calls".into(), 16);
        assert_eq!(store.get_usage("opaque", 60).unwrap(), offered);
        close(store);
        let reopened = open(by, &cfg).unwrap();
        block(sc::StoreCalls::add_usage_batch(&reopened, op(1), &cells)).unwrap();
        assert_eq!(reopened.get_usage("opaque", 60).unwrap(), offered);
        close(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn a_store_refuses_a_schema_newer_than_its_build() {
    for (by, tag) in [(Door::Linked, "linked"), (Door::Dropped, "dropped")] {
        let dir = scratch(&format!("newer-schema-{tag}"));
        let cfg = serde_json::json!({"db_path": dir.join("store.db")}).to_string();
        close(open(by, &cfg).expect("own schema opens"));
        stamp_newer_schema("", cfg.as_bytes());
        match open(by, &cfg) {
            Ok(_) => panic!("a newer schema must be refused"),
            Err(e) => assert!(
                e.contains("newer than this build"),
                "the refusal states why, across the door: {e}"
            ),
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[path = "support/store_behavior.rs"]
mod store_behavior;

#[test]
fn every_store_operation_has_the_same_product_behavior_through_both_doors() {
    assert_eq!(
        store_behavior::behavior(Door::Linked, "all-operations-linked"),
        store_behavior::behavior(Door::Dropped, "all-operations-dropped")
    );
}

#[path = "support/loader_refusals.rs"]
mod loader_refusals;

#[test]
fn the_declared_needs_are_the_statements() {
    let rendering = rendering_of_macro(MACRO_DOOR).unwrap();
    let statement = busbar_contract::abi::mechanism::rendering::read(&rendering).unwrap();
    let declares: serde_json::Value =
        serde_json::from_str(include_str!("../../store-sqlite/declares.json")).unwrap();
    let mut declared: Vec<String> = match declares.get("needs") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .expect("needs is an array")
            .iter()
            .map(|v| v.as_str().expect("scheme is string").to_string())
            .collect(),
    };
    let mut actual: Vec<_> = statement
        .needs
        .iter()
        .filter(|n| !n.transport.is_empty())
        .map(|n| n.transport.clone())
        .collect();
    declared.sort();
    declared.dedup();
    actual.sort();
    actual.dedup();
    assert_eq!(declared, actual);
}

#[test]
fn the_suite_runs_in_the_profile_it_was_asked_to() {
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "BUSBAR_EXPECT_RELEASE is set: run conformance with --release"
    );
}

#[test]
fn the_dropped_store_has_a_distinct_door_and_operation_table() {
    let (door, ops) = busbar_plugin_loader::dispatch::load::door_addresses_of_library(&cdylib())
        .expect("the image loads")
        .expect("exports a door");
    let linked = busbar_store_sqlite::door::door();
    // SAFETY: this macro-produced static door owns its complete immutable table.
    let parts = unsafe { busbar_contract::abi::mechanism::door::Door::read_parts(linked) };
    assert_ne!(door, linked as *const _ as usize);
    assert_ne!(ops, parts.ops as usize);
}

#[test]
fn each_open_reports_actual_memory_or_file_durability_through_both_doors() {
    for by in [Door::Linked, Door::Dropped] {
        let memory = open(by, r#"{"db_path":":memory:"}"#).unwrap();
        assert_eq!(sc::StoreCalls::ephemeral(&memory), Some(true));
        close(memory);
        let dir = scratch("runtime-durability");
        let path = dir.join("store.db");
        let settings = serde_json::json!({"db_path": path}).to_string();
        let file = open(by, &settings).unwrap();
        assert_eq!(sc::StoreCalls::ephemeral(&file), Some(false));
        close(file);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
