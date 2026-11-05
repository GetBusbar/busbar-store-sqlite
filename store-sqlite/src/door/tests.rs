// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::open;
use busbar_contract::records::RecordStore;
fn expect_err(result: Result<crate::SqliteStore, String>) -> String {
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

/// A negative `busy_timeout_ms` passes the existing type check (`n.is_i64()` is true for a negative
/// integer) but is nonsensical as a duration and can only be a config mistake -- unlike `0`, which
/// is a legal, deliberate "never retry" setting, a negative number names nothing SQLite or an
/// operator could sensibly mean. That's the same silent-footgun class the type-strict parsing above
/// already guards against for the wrong JSON type; a negative number must be rejected the same way,
/// not passed straight through to `SqliteStore::open`. `db_path` is pinned to `:memory:` to keep
/// the test hermetic: an implementation that fails to reject the negative value would otherwise
/// reach a real `SqliteStore::open` against the default relative `busbar-governance.db` path and
/// create a real file in the test's cwd.
#[test]
fn negative_busy_timeout_ms_is_rejected() {
    let err = expect_err(open(r#"{"db_path": ":memory:", "busy_timeout_ms": -1}"#));
    assert!(
        err.contains("busy_timeout_ms") && err.contains("negative"),
        "error should name the offending field and explain why: {err}"
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

/// Serialises every test that switches the process cwd (`ScratchCwd`), since cargo runs tests in
/// parallel and the cwd is process-global.
static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        let _ = std::env::set_current_dir(&self.original);
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

#[test]
fn empty_and_bare_object_configs_use_defaults_and_succeed() {
    let _serial = CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
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
    let _serial = CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let cwd = ScratchCwd::enter("explicit-memory");
    let store = open(r#"{"db_path": ":memory:"}"#).expect("in-memory db_path must open");
    let key = busbar_contract::records::VirtualKey {
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
        ..Default::default()
    };
    store
        .put_key(&key)
        .expect("put_key on the constructed store");
    assert_eq!(
        store.get_key("vk_adapter_test").unwrap().unwrap().id,
        "vk_adapter_test"
    );
    let other = open(r#"{"db_path": ":memory:"}"#).unwrap();
    assert!(other.get_key("vk_adapter_test").unwrap().is_none());
    assert!(
        !cwd.scratch.join("busbar-governance.db").exists(),
        "a `:memory:` db_path must not create the default file"
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
    let dir = crate::tests::tempdir();
    let path = dir.join("busy_timeout.db");
    let path_str = path.to_str().unwrap().to_string();

    let store = open(&serde_json::json!({ "db_path": path_str }).to_string())
        .expect("initial open to create the schema");
    drop(store);

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
    // Below the 5000ms default with room for a loaded runner: the bound only has to tell the
    // configured timeout from a silent fallback to the default.
    assert!(
        elapsed < 4500,
        "open() took {elapsed}ms, far longer than the configured {CONFIGURED_TIMEOUT_MS}ms — it \
         looks like the plugin silently fell back to the 5000ms default instead of the configured \
         value"
    );
}

/// A fractional or exponent `busy_timeout_ms` says what is wrong with it (it is a number, just not
/// a whole one), still without echoing the value.
#[test]
fn a_non_integer_busy_timeout_ms_names_the_number_form() {
    for cfg in [
        r#"{"busy_timeout_ms": 1.5}"#,
        r#"{"busy_timeout_ms": 5000.0}"#,
        r#"{"busy_timeout_ms": 1e3}"#,
    ] {
        let err = super::Settings::parse(cfg).unwrap_err();
        assert!(
            err.contains("whole number of milliseconds") && !err.contains("got a number"),
            "{cfg}: {err}"
        );
    }
}

/// An explicit JSON `null` for either key is read as ABSENT and falls back to the default, the
/// semantics this plugin shipped with in busbar 1.5.5. Pinned so a change to them is a decision,
/// not an accident: `db_path: null` opens the default relative file, exactly as `{}` does.
#[test]
fn null_db_path_and_busy_timeout_read_as_absent() {
    let _serial = CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let cwd = ScratchCwd::enter("null-reads-as-absent");
    let store = open(r#"{"db_path": null, "busy_timeout_ms": null}"#)
        .expect("an explicit null must fall back to the defaults and succeed");
    drop(store);
    assert!(
        cwd.scratch.join("busbar-governance.db").exists(),
        "`db_path: null` must have opened the default-named db in the scratch cwd"
    );
    assert_eq!(
        super::Settings::parse(r#"{"db_path": null, "busy_timeout_ms": null}"#).unwrap(),
        super::Settings {
            db_path: "busbar-governance.db".into(),
            busy_timeout_ms: 5000
        }
    );
}

/// `0` is a legal, deliberate "never retry" setting (only a negative value is refused), so it must
/// open.
#[test]
fn zero_busy_timeout_ms_is_accepted() {
    open(r#"{"db_path": ":memory:", "busy_timeout_ms": 0}"#)
        .expect("busy_timeout_ms 0 is a legal explicit setting and must open");
}

/// An unsigned value past `i64::MAX` passes the integer type check (`is_u64`) but cannot be a
/// SQLite busy timeout; it must be refused as out of range, never wrapped or clamped.
#[test]
fn busy_timeout_ms_past_i64_max_is_refused_as_out_of_range() {
    let err = expect_err(open(
        r#"{"db_path": ":memory:", "busy_timeout_ms": 18446744073709551615}"#,
    ));
    assert!(
        err.contains("busy_timeout_ms") && err.contains("out of range"),
        "error should name the offending field and say it is out of range: {err}"
    );
}

/// SQLite parses `PRAGMA busy_timeout` as a 32-bit int; a larger value reads back as 0 and silently
/// disables the busy handler, so anything above `i32::MAX` is refused (and `i32::MAX` itself is fine).
#[test]
fn busy_timeout_ms_above_i32_max_is_refused() {
    use super::Settings;
    for ms in ["2147483648", "3000000000"] {
        let err = Settings::parse(&format!(r#"{{"busy_timeout_ms": {ms}}}"#))
            .expect_err("a busy_timeout_ms above i32::MAX must be refused");
        assert!(
            err.contains("busy_timeout_ms"),
            "error should name the field: {err}"
        );
    }
    let ok = Settings::parse(r#"{"busy_timeout_ms": 2147483647}"#).expect("i32::MAX is accepted");
    assert_eq!(ok.busy_timeout_ms, 2147483647);
}

/// An unknown top-level key is refused (a typo such as `dbpath` would otherwise silently open the
/// default relative path), naming the accepted keys.
#[test]
fn an_unknown_setting_is_refused() {
    let err = expect_err(open(r#"{"db_path": ":memory:", "dbpath": "x"}"#));
    assert_eq!(
        err,
        "invalid sqlite plugin config: unknown setting `dbpath` (accepted: db_path, busy_timeout_ms)"
    );
}

/// An empty or whitespace-only `db_path` is refused with an explanation, not an obscure WAL error.
#[test]
fn an_empty_or_blank_db_path_is_refused() {
    for p in ["", "   ", "\t"] {
        let err = expect_err(open(&format!(r#"{{"db_path": {p:?}}}"#)));
        assert!(
            err.starts_with("invalid sqlite plugin config:")
                && err.contains("db_path")
                && err.contains("empty"),
            "{p:?}: {err}"
        );
    }
}

/// A non-object top level must not skip the settings check and open the default database.
#[test]
fn a_non_object_top_level_is_refused_naming_only_its_type() {
    use super::Settings;
    for (cfg, ty) in [
        (r#""/var/lib/x.db""#, "a string"),
        ("[]", "an array"),
        ("5", "a number"),
        ("true", "a boolean"),
    ] {
        let err = Settings::parse(cfg).unwrap_err();
        assert_eq!(
            err,
            format!("invalid sqlite plugin config: expected a JSON object, got {ty}")
        );
        assert!(!err.contains("/var/lib"), "{err}");
    }
    assert!(Settings::parse("null").is_ok());
    assert!(Settings::parse("  ").is_ok());
}

/// The runtime accepts only settings it uses; old ignored fields belong to config migration.
#[test]
fn license_key_is_rejected_as_an_unknown_setting() {
    use super::Settings;
    let err = Settings::parse(r#"{"db_path":":memory:","license_key":"x"}"#).unwrap_err();
    assert_eq!(
        err,
        "invalid sqlite plugin config: unknown setting `license_key` (accepted: db_path, busy_timeout_ms)"
    );
}

/// A wrongly typed setting is refused naming the expected and the given JSON type, never the value
/// (a template can put a secret where a path was expected).
#[test]
fn a_wrongly_typed_setting_names_types_never_the_value() {
    use super::Settings;
    for cfg in [
        r#"{"db_path": 987654321}"#,
        r#"{"db_path": ["s3cr3t-value"]}"#,
        r#"{"busy_timeout_ms": "s3cr3t-value"}"#,
        r#"{"busy_timeout_ms": 1.5}"#,
    ] {
        let err = Settings::parse(cfg).unwrap_err();
        assert!(
            !err.contains("987654321") && !err.contains("s3cr3t-value") && !err.contains("1.5"),
            "{err}"
        );
    }
}
