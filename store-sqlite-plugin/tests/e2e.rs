// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the built `busbar-store-sqlite-plugin` cdylib, loaded over the real
//! `busbar-plugin-loader` C ABI seam (`load_store`) — a real `dlopen`, real FFI, real SQLite-file
//! test.
//!
//! KNOWN GAP, not fixed here: `load_store()` is called directly, in-process, by these tests — no
//! real end user or operator does this (nobody imports `busbar-plugin-loader` and calls its
//! internal function). The two real, end-user-mimicking mechanisms are (1) drop the packed tarball
//! in `plugins.dir` and boot a real `busbar` binary, or (2) install it live via the real
//! `POST /plugins` admin API against a running instance. `store-postgres` has already been
//! converted to mechanism 1 (see `GetBusbar/store-postgres`'s `store-postgres-plugin/tests/e2e.rs`
//! for the pattern — packs via `busbar-plugin-pack`, drops in a real `plugins.dir`, runs the real
//! `busbar --validate` binary, confirms via an independent connection). This file should get the
//! same treatment; tracked as part of the plugin closeout audit pass, not done in this commit.
//!
//! Ported from the monorepo's `busbar-plugin-loader::tests::load_and_exercise_sqlite_plugin_*`
//! (`crates/plugin-loader/src/lib.rs`), which is where this plugin's real ABI-crossing coverage
//! historically lived (since the monorepo's `plugin-loader` crate owns the loader used to dlopen
//! it). This repo carries its own copy so every push to `GetBusbar/store-sqlite` proves, for real,
//! over the C ABI, that the plugin loads and correctly persists data — mirroring the pattern
//! `webrequest-hook` uses for its own `tests/e2e.rs`.
//!
//! Coverage:
//! - a real file on disk (not `:memory:`) is written to via the plugin over the C ABI, the plugin
//!   is dropped (closing its connection), then the data is verified to have actually landed in the
//!   file two independent ways: (1) re-`dlopen`ing the SAME cdylib against the SAME path, and
//!   (2) opening the SAME file directly with the plain `busbar-store-sqlite` `SqliteStore`, a code
//!   path that never touches the cdylib, the C ABI, or the loader at all;
//! - a bad config (malformed JSON, or a `db_path` under a nonexistent parent directory) fails
//!   cleanly across the ABI as an `Err`, never a panic or a silently-succeeded load.

use busbar_api::{ModelTokens, Store, TierTokens, UsageLedger, VirtualKey};
use busbar_plugin_loader::{load_store, plugin_library_filename};

/// RAII scratch directory: removes itself on drop, including on an early return via a panicking
/// assertion partway through a test — unlike a manual `remove_dir_all` call placed at the end of the
/// test body, which never runs if an assertion above it fails first.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn create(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "busbar-sqlite-plugin-e2e-{}-{tag}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir for the real sqlite file");
        Self(dir)
    }
}

impl std::ops::Deref for ScratchDir {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Locate the built `busbar-store-sqlite-plugin` cdylib in the target dir (mirrors the loader's own
/// `sqlite_plugin_path` helper in the monorepo).
fn plugin_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?; // .../target/<profile>/deps/e2e-<hash>
    let profile_dir = exe.parent()?.parent()?; // .../target/<profile>
    let name = plugin_library_filename("busbar_store_sqlite_plugin");
    let candidate = profile_dir.join(&name);
    candidate.exists().then_some(candidate)
}

/// End-to-end PERSISTENCE: dlopen the real sqlite plugin against a REAL file on disk (not
/// `:memory:`), write a key and usage through the plugin over the C ABI, drop the plugin (closing
/// its connection via the loader's `Drop`, which runs `busbar_close`), then verify the data
/// actually landed in the file two independent ways:
///   1. re-dlopen the SAME cdylib against the SAME path — a fresh `busbar_open`/fresh store
///      instance, proving the plugin itself doesn't just hold an in-memory cache across calls.
///   2. open the SAME file with `busbar_store_sqlite::SqliteStore::open` directly — a totally
///      independent code path that never goes through the cdylib, the C ABI, or the loader at all
///      — proving the plugin actually wrote real SQLite rows, not just satisfying its own
///      in-process round-trip.
///
/// This is the proof that `store: sqlite` operations over the ABI aren't silently no-ops.
#[test]
fn load_and_exercise_sqlite_plugin_persists_to_real_file_across_reopen() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run cargo test/build first)");
        return;
    };
    let dir = ScratchDir::create("persist");
    let db_path = dir.join("governance.db");
    let db_path_str = db_path.to_str().unwrap();
    let cfg = serde_json::json!({ "db_path": db_path_str }).to_string();

    let key = VirtualKey {
        id: "vk_real_file".into(),
        generation_hash: "hash-real".into(),
        name: "real-file-key".into(),
        allowed_pools: Some(vec!["p".into()]),
        enabled: true,
        created_at: 42,
        group: Some("infra".into()),
        labels: std::collections::BTreeMap::from([("env".into(), "prod".into())]),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    };
    let ledger = UsageLedger {
        requests: 5,
        billable_requests: 5,
        models: vec![ModelTokens {
            model: "gpt-5".into(),
            tokens: TierTokens {
                input: 20,
                output: 8,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };

    {
        let store = load_store(&path, &cfg).expect("load sqlite plugin against a real file");
        store.put_key(&key).expect("put_key");
        store
            .put_usage("vk_real_file", 200, &ledger)
            .expect("put_usage");
        assert_eq!(
            store
                .get_key("vk_real_file")
                .expect("get_key")
                .expect("present in the same session")
                .id,
            "vk_real_file"
        );
        // `store` (and the loader's `RawPlugin` it wraps) drops here, running `busbar_close` and
        // dropping the plugin's `SqliteStore`/`Connection` — the file must hold the committed data
        // after this, not just an in-process cache.
    }

    assert!(
        db_path.exists(),
        "the plugin must have created a real file on disk at the configured db_path"
    );

    // (1) Re-dlopen the SAME cdylib against the SAME path: a fresh plugin instance, fresh
    // `busbar_open`, fresh connection inside the plugin process — proves the ABI round-trip isn't
    // relying on the first instance still being alive.
    let reopened = load_store(&path, &cfg).expect("re-load sqlite plugin against the same file");
    let got = reopened
        .get_key("vk_real_file")
        .expect("get_key after reopen")
        .expect("the key must survive a full plugin close + reopen against the same file");
    assert_eq!(got.group.as_deref(), Some("infra"));
    assert_eq!(got.labels.get("env").map(String::as_str), Some("prod"));
    let usage = reopened
        .get_usage("vk_real_file", 200)
        .expect("get_usage after reopen");
    assert_eq!(usage.requests, 5, "usage ledger must survive the reopen");
    let t = usage
        .tokens_for("gpt-5")
        .expect("model row survives reopen");
    assert_eq!((t.input, t.output), (20, 8));
    drop(reopened);

    // (2) Open the SAME file with the plain `SqliteStore` — a code path that never touches the
    // cdylib, the C ABI, or `plugin-loader` at all. If the plugin's `put_key`/`put_usage` over the
    // ABI were silent no-ops (or wrote somewhere other than the configured `db_path`), this
    // independent reader would come back empty even though the reopen-via-plugin check above
    // passed (a bug shared by both `open` calls, e.g. always using `:memory:`, would otherwise slip
    // through unnoticed).
    let direct = busbar_store_sqlite::SqliteStore::open(db_path_str, 5000)
        .expect("open the real file directly with the plain SqliteStore, bypassing the plugin");
    let direct_key = Store::get_key(&direct, "vk_real_file")
        .expect("get_key via the direct connection")
        .expect("the row must be physically present in the sqlite file on disk");
    assert_eq!(direct_key.name, "real-file-key");
    assert_eq!(direct_key.allowed_pools, Some(vec!["p".to_string()]));
    let direct_usage = Store::get_usage(&direct, "vk_real_file", 200)
        .expect("get_usage via the direct connection");
    assert_eq!(
        direct_usage.requests, 5,
        "usage must be physically present in the sqlite file, not just cached in-process"
    );

    drop(dir); // explicit: removes the scratch dir now rather than at end of scope by coincidence
}

/// End-to-end FAILURE: an `open()` config that cannot produce a usable database — here, a
/// `db_path` under a directory that doesn't exist, which `rusqlite::Connection::open` refuses —
/// surfaces back across the C ABI as a clean `Err`, never a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_sqlite_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run cargo test/build first)");
        return;
    };

    // Malformed JSON: the plugin's own `open()` config parsing must reject it, surfaced intact
    // across the ABI.
    let err = load_store(&path, "{ not json")
        .err()
        .expect("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid sqlite plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    // A `db_path` whose parent directory does not exist: sqlite cannot create the file, so
    // `SqliteStore::open` fails and that failure must surface as a load error, not a panic or a
    // store that silently has no backing file.
    let bogus_dir = std::env::temp_dir().join(format!(
        "busbar-sqlite-plugin-e2e-{}-does-not-exist",
        std::process::id()
    ));
    // Make sure it really doesn't exist (it never should, but be defensive against test reruns).
    let _ = std::fs::remove_dir_all(&bogus_dir);
    let bogus_path = bogus_dir.join("nested").join("governance.db");
    let cfg = serde_json::json!({ "db_path": bogus_path.to_str().unwrap() }).to_string();
    let err = load_store(&path, &cfg)
        .err()
        .expect("a db_path under a nonexistent directory must fail to load");
    assert!(
        !err.is_empty(),
        "expected a descriptive sqlite open failure, got an empty string"
    );
    assert!(
        !bogus_dir.exists(),
        "a failed open must not have created the parent directory or file"
    );
}
