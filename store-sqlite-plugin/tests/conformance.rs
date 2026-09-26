// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE SQLITE STORE, BOTH DOORS, ONE ROW** — the store's linked + dropped-in conformance, run
//! against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The store is held two ways at once: LINKED (its `linked::STORE` statement and boundary, the row a
//! busbar build that compiles it in registers) and DROPPED IN (this crate's built cdylib, signed
//! first-party under the SAME statement into a temp `plugins/` directory and found by the loader's
//! scan). Each arm is opened by the one `open_store` and driven through ONE scenario against its own
//! real database file: the config refusals, a key, a usage window, plane records of an upsert and an
//! append-only kind, a SECOND live handle on the same file (the cross-handle view), and a RESTART —
//! every handle closed, the file reopened, everything read back. The two arms must agree byte for
//! byte on the whole transcript.
//!
//! The RED arms are in the same test: (a) the same cdylib signed as `kind: secret` is refused at the
//! kind handshake, naming both kinds; (b) the dropped-in door opened on a file that already holds a
//! foreign key yields a transcript that DIFFERS from the linked one — so the comparison above can
//! see a real difference and is not vacuously equal.

use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, UsageDelta, VirtualKey,
};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}

/// The version both arms state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_store_sqlite_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-store-sqlite-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// The statement both doors carry for `kind`, at the newest payload schema this loader speaks.
fn statement(kind: &str) -> Manifest {
    let (name, alias, _) = busbar_store_sqlite::linked::STORE;
    let abi = busbar_plugin_loader::supported_abi(kind)
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: kind.into(),
        version: VERSION.into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: abi,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

/// The LINKED row: exactly what a busbar composition root that links this store states.
fn linked_row() -> LinkedPlugin {
    LinkedPlugin::boundary(statement("store"), busbar_store_sqlite::linked::STORE.2)
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/`
/// directory, scanned under a policy holding the release key.
fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = scratch(&format!("plugins-{tag}"));
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libstore.so", lib).unwrap();
    std::fs::write(dir.join("store.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed store scans")
}

/// A fresh scratch directory for this process.
fn scratch(tag: &str) -> std::path::PathBuf {
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

/// Everything a store holds that the scenario wrote, as one comparable value.
fn contents(s: &dyn RecordStore) -> serde_json::Value {
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
    serde_json::json!({
        "keys": keys,
        "usage": s.get_usage("vk_conf", 1_700_000_000).expect("get_usage"),
        "task": s.get_plane_record("task", "t1").expect("get_plane_record")
            .map(|b| String::from_utf8(b).unwrap()),
        "events": text(s.list_plane_records("task_event", &PlaneSelector::Parent("t1".into()))
            .expect("list_plane_records")),
        "parents": s.list_plane_record_parents("task_event").expect("parents"),
    })
}

/// What one door does with the `sqlite` row, as one comparable transcript.
fn transcript(tag: &str, registry: &PluginRegistry, seed: Option<&str>) -> serde_json::Value {
    let alias = busbar_store_sqlite::linked::STORE.1;
    let p = registry.resolve(alias).expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    // The config refusals, in the store's own words, through the door.
    let refusals: Vec<String> = [
        "{ not json",
        r#"{"db_path": 5}"#,
        r#"{"db_path": ":memory:", "busy_timeout_ms": -1}"#,
        r#"{"db_path": ":memory:", "busy_timeout_ms": "5000"}"#,
    ]
    .iter()
    .map(|cfg| match registry.open_store(alias, cfg) {
        Ok(_) => format!("{cfg} OPENED"),
        Err(e) => e,
    })
    .collect();

    let dir = scratch(&format!("db-{tag}"));
    let db = dir.join("governance.db");
    let cfg = serde_json::json!({"db_path": db.display().to_string(), "busy_timeout_ms": 2000})
        .to_string();
    if let Some(foreign) = seed {
        let s = registry.open_store(alias, &cfg).expect("seed open");
        s.put_key(&key(foreign)).expect("seed put_key");
    }

    let (live, cross) = {
        let a = registry.open_store(alias, &cfg).expect("the store opens");
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
        a.upsert_plane_record(&record("task", "t1", None, 0, "{\"state\":\"working\"}"))
            .expect("upsert");
        a.upsert_plane_record(&record(
            "task",
            "t1",
            None,
            0,
            "{\"state\":\"input-required\"}",
        ))
        .expect("upsert again");
        for seq in 1..=3 {
            a.append_plane_record(&record(
                "task_event",
                &format!("e{seq}"),
                Some("t1"),
                seq,
                &format!("{{\"seq\":{seq}}}"),
            ))
            .expect("append");
        }
        // A duplicate append (same parent, same seq) is refused, in the store's words.
        let dup = a
            .append_plane_record(&record("task_event", "e1", Some("t1"), 1, "{}"))
            .map_err(|e| e.0);
        // A SECOND live handle on the same file sees the first handle's writes, and its own write
        // is seen back by the first.
        let b = registry
            .open_store(alias, &cfg)
            .expect("a second handle opens");
        b.put_key(&key("vk_other")).expect("second-handle put_key");
        let cross = serde_json::json!({"b_sees": contents(b.as_ref()), "dup": format!("{dup:?}")});
        (contents(a.as_ref()), cross)
    };
    // THE RESTART: every handle above is closed; a fresh open's only source is the file.
    let restarted = contents(
        registry
            .open_store(alias, &cfg)
            .expect("the store reopens")
            .as_ref(),
    );
    let _ = std::fs::remove_dir_all(&dir);
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "refusals": refusals,
        "live": live,
        "cross": cross,
        "restarted": restarted,
    })
}

/// The sqlite store registers ONE row and behaves as ONE store through either door — and the RED
/// arms show the comparison can tell a different store apart.
#[test]
fn the_linked_and_the_dropped_in_sqlite_store_are_one_store() {
    let lib = cdylib();
    let linked_registry = PluginRegistry::empty().link(vec![linked_row()]).unwrap();
    let linked = transcript("linked", &linked_registry, None);
    let dropped_registry = dropped("dropped", statement("store"), &lib);
    let dropped_in = transcript("dropped", &dropped_registry, None);
    assert_eq!(linked, dropped_in, "the two doors are not one store");

    // The scenario did what a durable store is for.
    assert_eq!(linked["first_party"], true);
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
    assert_eq!(linked["cross"]["b_sees"]["task"], restarted["task"]);
    assert!(
        linked["cross"]["dup"].as_str().unwrap().starts_with("Err("),
        "a duplicate (parent, seq) append must be refused: {}",
        linked["cross"]["dup"]
    );
    let refusals = linked["refusals"].as_array().unwrap();
    assert!(
        refusals
            .iter()
            .all(|r| r.as_str().unwrap().contains("invalid sqlite plugin config")),
        "every bad config is refused in the store's own words: {refusals:?}"
    );

    // RED (a): the same bytes signed as `secret` are refused at the kind handshake, naming both kinds.
    let wrong = dropped("as-secret", statement("secret"), &lib);
    let e = match wrong.open_secret(busbar_store_sqlite::linked::STORE.1, "{}") {
        Ok(_) => panic!("a store library signed as secret opened; it must be refused"),
        Err(e) => e,
    };
    assert!(
        e.contains("exports kind 'store' but is being loaded as 'secret'"),
        "{e}"
    );

    // RED (b): the dropped-in door on a file that already holds a foreign key is NOT the same
    // transcript — the equality above is not vacuous.
    let red = transcript("red", &dropped_registry, Some("vk_foreign"));
    assert_ne!(
        red, linked,
        "a store holding a foreign row must not compare equal"
    );
}
