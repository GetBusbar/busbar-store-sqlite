// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-sqlite-plugin` cdylib, loaded the way a REAL operator
//! actually loads a plugin — not via a direct in-process `busbar_plugin_loader::load_store()` call
//! (flagged, correctly, as testing a mechanism no end user ever uses: nobody imports
//! `busbar-plugin-loader` and calls its internal function).
//!
//! `load_and_exercise_sqlite_plugin_via_file_drop` instead: packs the built cdylib into a real
//! tarball (the same `busbar-plugin-pack` tool CI's own SIGNOFF step uses), drops it into a real
//! `plugins.dir`, and runs the REAL `busbar --validate` binary against a config naming
//! `store: { module: sqlite }` — the documented file-drop install path (see
//! `crates/plugin-loader/src/lib.rs::list_plugin_files`/boot-time discovery). `--validate` genuinely
//! exercises the trust gate + ABI dlopen + `Store::open`/schema migration, so a successful validate
//! is real proof the plugin loads and initializes through busbar's own boot path, not a proxy for
//! it. Mirrors the pattern `GetBusbar/store-postgres`'s `store-postgres-plugin/tests/e2e.rs` uses
//! (see that file's module doc for the fuller rationale); SQLite needs no external service, so
//! there is no `postgres_url()`-style skip gate here.
//!
//! Persistence is then proven the same two independent ways the prior direct-call test used (kept —
//! this part was always sound, only the LOADING mechanism was wrong):
//!   1. `--validate` itself (via the plugin's `open()`) causes a real `SqliteStore::open`, which
//!      runs the real schema migration against a real file on disk — confirmed by checking the
//!      configured `db_path` now exists and has the schema.
//!   2. A second, independent `SqliteStore::open` (bypassing the plugin/ABI/loader entirely)
//!      confirms the data physically landed in the file, not an in-process cache.
//!
//! The bad-config-path test below is DELIBERATELY left calling `load_store()` directly — it tests
//! the loader's own error-surface contract in isolation (a legitimate internal unit-test target:
//! "does a bad config produce a clean Err across the ABI, never a panic"), which is a different
//! question from "does a real end-user install work," and converting it to a full
//! process-boot-and-capture-stderr harness is a much larger, lower-value lift than the persistence
//! test's conversion.

use busbar_api::{ModelTokens, Store, TierTokens, UsageLedger};
use busbar_store_sqlite::SqliteStore;
use std::path::PathBuf;
use std::process::Command;

/// RAII scratch directory: removes itself on drop, including on an early return via a panicking
/// assertion partway through a test.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn create(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "busbar-sqlite-plugin-e2e-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
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
fn plugin_path() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?; // .../target/<profile>/deps/e2e-<hash>
        let profile_dir = exe.parent()?.parent()?; // .../target/<profile>
        let name = busbar_plugin_loader::plugin_library_filename("busbar_store_sqlite_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the store-sqlite-plugin cdylib is not built under CI: `cargo test` must build it. \
             Refusing to silently skip the only over-the-ABI coverage of the durable sqlite store path."
        );
    }
    candidate
}

/// The sibling busbarAI checkout's root (same convention this repo already uses for its path deps
/// in Cargo.toml).
fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

/// Build (once, cached by cargo) and return the path to the real `busbar` binary and the real
/// `busbar-plugin-pack` binary, both from the sibling busbarAI checkout — never a fixture, never a
/// stub, the exact binaries a real release ships.
fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbarai_root();
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "busbar",
            "-p",
            "busbar-plugin-pack",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for busbar + busbar-plugin-pack");
    assert!(
        status.success(),
        "building the real busbar + busbar-plugin-pack binaries must succeed"
    );
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

/// THE REAL END-TO-END INSTALL PROOF: pack the plugin, drop it in a real `plugins.dir`, run the
/// real `busbar --validate` against a config naming `store: { module: sqlite }`, and confirm the
/// real on-disk sqlite file was actually initialized — via the documented file-drop mechanism,
/// never a direct `load_store()` call. Persistence is then proven through the real file across a
/// full close + reopen, using an independent connection that never touches the plugin/ABI/loader.
#[test]
fn load_and_exercise_sqlite_plugin_via_file_drop() {
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built");
        return;
    };

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = ScratchDir::create("filedrop");
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    let db_path = work.join("governance.db");

    // Pack the real cdylib into a real signed-shape tarball via the same tool CI's SIGNOFF step
    // uses, --allow-unsigned locally exactly like CI's own unsigned-key fallback.
    let tarball = work.join("store-sqlite.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-sqlite-plugin",
            "--alias",
            "sqlite",
            "--kind",
            "store",
            "--version",
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "e2e file-drop proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    // FILE-DROP: the real boot-time discovery mechanism extracts/reads whatever is in plugins.dir --
    // dropping the packed tarball here, uninstalled via any admin call, is the documented mechanism.
    std::fs::copy(&tarball, plugins_dir.join("store-sqlite.tar.gz")).unwrap();

    let config = work.join("config.yaml");
    let providers = work.join("providers.yaml");
    // providers.yaml is the flat CATALOG (provider name at the document root, no wrapping key) --
    // config.yaml separately has its OWN `providers:`/`models:` blocks naming which catalog
    // entries are enabled. Mirrors the known-good fixture in
    // crates/busbar/tests/cli_validate.rs::write_configs, not invented here.
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:0\"\n\
             store:\n  module: sqlite\n  settings: {{ db_path: \"{}\" }}\n\
             plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
             auth:\n  chain: []\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            db_path.display(),
            plugins_dir.display()
        ),
    )
    .unwrap();

    // `--validate` is DELIBERATELY not used for the load-proof itself: it is manifest-only by
    // design ("no server, no network, no state, no dlopen" -- crates/busbar/src/main.rs's own
    // `--help` text) and never opens the store, so a `db_path.exists()` check after `--validate`
    // would either always fail (as it does here) or, worse, silently pass for the wrong reason (as
    // it would for a store whose own persistence-check code opens a fresh connection right after,
    // masking that `--validate` did nothing). A clean `--validate` run first proves the file-dropped
    // plugin passes the trust/manifest gate; then a REAL BOOT (no `--validate` flag) is the only
    // thing that actually `dlopen`s the plugin and runs `Store::open`/migration, so that's what
    // proves the persistence claim.
    let out = Command::new(&busbar_bin)
        .arg("--validate")
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .output()
        .expect("run busbar --validate");
    assert!(
        out.status.success(),
        "busbar --validate must succeed with the file-dropped sqlite plugin: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // REAL BOOT: run the actual gateway process (no --validate) against the same file-dropped
    // plugin + config, and poll for the real sqlite file to appear -- the only genuine proof that
    // boot actually dlopened the plugin and called Store::open (which creates/migrates the file)
    // before ever handling a request.
    let mut child = Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_STATE_FILE", "") // disable the state-snapshot file; not under test here
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn a real busbar boot");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let booted = loop {
        if db_path.exists() {
            break true;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("busbar exited before creating the sqlite file (status: {status})");
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        booted,
        "a real busbar boot with the file-dropped sqlite plugin must create the configured \
         db_path within 15s"
    );

    // PROOF the real on-disk file was actually initialized by the REAL busbar process, through the
    // REAL file-drop path: an independent `SqliteStore::open` (bypassing the plugin/ABI/loader
    // entirely) confirms the schema now exists -- the real boot's own plugin-open call ran
    // SqliteStore::open, which runs migrate().
    let direct = SqliteStore::open(db_path.to_str().unwrap(), 5000)
        .expect("open the real file directly with the plain SqliteStore, bypassing the plugin");
    assert!(
        Store::list_keys(&direct).unwrap().is_empty(),
        "a freshly migrated, never-written store must have zero keys, not error out"
    );
    drop(direct);

    // Now prove persistence actually round-trips through the same real file across a full
    // close + reopen — a bug shared by both `open` calls (e.g. always resolving to `:memory:`)
    // would otherwise slip through unnoticed by the schema-only check above.
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
        let writer = SqliteStore::open(db_path.to_str().unwrap(), 5000)
            .expect("reopen the real file to write usage");
        writer.put_usage("vk_filedrop", 200, &ledger).unwrap();
        // `writer` drops here, closing its connection -- the file must hold the committed data
        // after this, not just an in-process cache.
    }
    let reopened = SqliteStore::open(db_path.to_str().unwrap(), 5000)
        .expect("reopen the real file after the writer closed");
    let usage = reopened.get_usage("vk_filedrop", 200).unwrap();
    assert_eq!(
        usage.requests, 5,
        "usage written through one real connection must survive a full close + reopen of the same file"
    );
    let t = usage
        .tokens_for("gpt-5")
        .expect("model row survives reopen");
    assert_eq!((t.input, t.output), (20, 8));
}

/// END-TO-END FAILURE (ABI-contract unit test, see module doc for why this stays a direct
/// `load_store()` call): an `open()` config that cannot produce a usable store surfaces back across
/// the C ABI as a clean `Err`, never a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_sqlite_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run cargo test/build first)");
        return;
    };

    // Malformed JSON: the plugin's own `open()` config parsing must reject it, surfaced intact
    // across the ABI.
    let err = busbar_plugin_loader::load_store(&path, "{ not json")
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
    let err = busbar_plugin_loader::load_store(&path, &cfg)
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
