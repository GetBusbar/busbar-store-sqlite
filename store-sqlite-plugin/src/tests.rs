// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::open;
fn expect_err(result: Result<Box<dyn busbar_api::Store>, String>) -> String {
    match result {
        Ok(_) => panic!("expected open() to fail, but it succeeded"),
        Err(e) => e,
    }
}

#[test]
fn malformed_json_is_rejected() {
    let err = expect_err(open("{ this is not json"));
    assert!(
        err.contains("invalid sqlite plugin config"),
        "error should name the config as invalid: {err}"
    );
}

/// RAII guard that switches the process cwd to a fresh scratch temp directory and restores the
/// original cwd (then removes the scratch directory) on drop — including on an early return via
/// panic/`?`, so a failing assertion can never strand files in the repo root. `set_current_dir` is
/// process-global, so only ONE test may use this guard at a time; see the caller for how that's
/// enforced against cargo's parallel test runner.
struct ScratchCwd {
    original: std::path::PathBuf,
    scratch: std::path::PathBuf,
}

impl ScratchCwd {
    fn enter(tag: &str) -> Self {
        let original = std::env::current_dir().expect("read the current cwd");
        let scratch = std::env::temp_dir().join(format!(
            "busbar-sqlite-plugin-defaults-{}-{tag}",
            std::process::id()
        ));
        std::fs::create_dir_all(&scratch).expect("create scratch cwd");
        std::env::set_current_dir(&scratch).expect("switch into scratch cwd");
        Self { original, scratch }
    }
}

impl Drop for ScratchCwd {
    fn drop(&mut self) {
        // Best-effort: restore the real cwd first (so the process is never left pinned inside a
        // directory we're about to delete), then clean up the scratch directory and whatever
        // `busbar-governance.db`/`-wal`/`-shm` sidecars `open()` created inside it.
        let _ = std::env::set_current_dir(&self.original);
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

#[test]
fn empty_and_bare_object_configs_use_defaults_and_succeed() {
    // Empty config is NOT an error for this plugin (unlike oidc, sqlite has usable defaults for
    // every field) — both `""` and `"{}"` fall back to the default relative `db_path`. Proving that
    // fallback actually happens means calling `open` with the key genuinely ABSENT, which resolves
    // to the CWD-relative `busbar-governance.db` — so this test runs `open` from a scratch temp cwd
    // (via `ScratchCwd`, restored/cleaned up on drop even if an assertion below panics) rather than
    // the repo root, keeping the suite hermetic: never the repo's actual cwd, never a stray file
    // left behind. Both configs are exercised SEQUENTIALLY in one test (rather than as separate
    // `#[test]`s) because `set_current_dir` is process-global — two tests changing it concurrently
    // under cargo's parallel runner would race each other, and both would otherwise try to open the
    // same default-named file concurrently and contend on SQLite's file lock.
    let cwd = ScratchCwd::enter("empty-and-bare");

    let store = open("").expect("empty config must fall back to defaults and succeed");
    drop(store);
    assert!(
        cwd.scratch.join("busbar-governance.db").exists(),
        "open(\"\") must have created the default-named db in the scratch cwd"
    );
    let _ = std::fs::remove_file(cwd.scratch.join("busbar-governance.db"));

    let store = open("{}").expect("{} must fall back to defaults and succeed");
    drop(store);
    assert!(
        cwd.scratch.join("busbar-governance.db").exists(),
        "open(\"{{}}\") must have created the default-named db in the scratch cwd"
    );
}

#[test]
fn explicit_in_memory_db_path_is_honored() {
    // Proves `db_path` is actually read (not ignored in favor of the default) via the one value
    // that's observable without touching disk: `:memory:` opens instantly with no file created.
    let store = open(r#"{"db_path": ":memory:"}"#).expect("in-memory db_path must open");
    let key = busbar_api::VirtualKey {
        id: "vk_adapter_test".into(),
        generation_hash: "h".into(),
        name: "n".into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 1,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    };
    store
        .put_key(&key)
        .expect("put_key on the constructed store");
    assert_eq!(
        store.get_key("vk_adapter_test").unwrap().unwrap().id,
        "vk_adapter_test"
    );
}

#[test]
fn explicit_db_path_overrides_the_default_and_creates_that_exact_file() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-sqlite-plugin-open-{}-explicit",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("custom.db");
    let cfg = serde_json::json!({ "db_path": path.to_str().unwrap() }).to_string();
    let store = open(&cfg).expect("explicit db_path must open");
    drop(store);
    assert!(
        path.exists(),
        "open() must create the file at the CONFIGURED path, not the default"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nonexistent_parent_directory_is_a_clean_error_not_a_panic() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-sqlite-plugin-open-{}-missing-parent",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("nested").join("db.sqlite");
    let cfg = serde_json::json!({ "db_path": path.to_str().unwrap() }).to_string();
    let err = expect_err(open(&cfg));
    assert!(
        err.contains(&path.to_string_lossy().to_string())
            || err.to_lowercase().contains("no such file"),
        "error should describe the underlying open failure (missing parent dir), not be an opaque \
         placeholder: {err}"
    );
    assert!(!dir.exists(), "a failed open must not create the directory");
}

#[test]
fn busy_timeout_ms_is_actually_applied() {
    // The audit's own concern: `busy_timeout_ms` is threaded from the JSON config all the way
    // through to `SqliteStore::open`'s `pragma_update(None, "busy_timeout", ...)`, and nothing tested
    // that wiring — a regression that dropped the value on the floor (e.g. always using the 5000ms
    // default) would pass unnoticed. `SqliteStore` doesn't expose its inner connection, and
    // `busy_timeout` is a per-connection runtime setting with no on-disk trace, so we can't just read
    // it back after the fact. Instead we observe it BEHAVIORALLY: hold an exclusive write lock on the
    // file from a second, independent connection, then call `open()` through the plugin with a small
    // non-default `busy_timeout_ms` against that same locked file. `SqliteStore::open` runs its own
    // write transaction during `migrate()`, so it must block on the lock and then fail with
    // `SQLITE_BUSY` once ITS configured timeout elapses. Asserting the elapsed time lands near the
    // CONFIGURED value (and well under the 5000ms default) proves the value was actually threaded
    // through, not silently defaulted.
    let dir = std::env::temp_dir().join(format!(
        "busbar-sqlite-plugin-busy-timeout-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("busy_timeout.db");
    let path_str = path.to_str().unwrap().to_string();

    // Pre-create the file with a normal open/migrate so the plugin's later `open()` under lock
    // contention only has to run `migrate()`'s idempotent (but still write-locking) schema pass.
    let store = open(&serde_json::json!({ "db_path": path_str }).to_string())
        .expect("initial open to create the schema");
    drop(store);

    // Grab and hold an exclusive write lock from an independent connection with NO busy_timeout of
    // its own (so it never yields the lock voluntarily) — this is what the plugin's `open()` below
    // will contend against.
    let locker = rusqlite::Connection::open(&path).expect("open locker connection");
    locker
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("acquire exclusive write lock");

    const CONFIGURED_TIMEOUT_MS: u128 = 400;
    let cfg = serde_json::json!({
        "db_path": path_str,
        "busy_timeout_ms": CONFIGURED_TIMEOUT_MS as i64,
    })
    .to_string();

    let start = std::time::Instant::now();
    let result = open(&cfg);
    let elapsed = start.elapsed().as_millis();

    // Release the lock immediately so a failure below doesn't strand the test process.
    drop(locker);

    assert!(
        result.is_err(),
        "open() must fail while the file is exclusively locked by another connection"
    );
    assert!(
        elapsed >= CONFIGURED_TIMEOUT_MS.saturating_sub(150),
        "open() returned too fast ({elapsed}ms) to have honored the configured \
         {CONFIGURED_TIMEOUT_MS}ms busy_timeout — it looks like the timeout wasn't applied at all"
    );
    assert!(
        elapsed < 2500,
        "open() took {elapsed}ms, far longer than the configured {CONFIGURED_TIMEOUT_MS}ms — it \
         looks like the plugin silently fell back to the 5000ms default instead of the configured \
         value"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
