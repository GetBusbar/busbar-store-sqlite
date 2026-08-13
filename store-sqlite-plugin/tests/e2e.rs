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
//!
//! `install_sqlite_plugin_via_admin_api_and_verify_persistence` goes one step further than the
//! file-drop test above: file-drop proves the plugin loads through the DOCUMENTED discovery
//! mechanism, but an operator installing a NEW plugin onto a LIVE gateway does it over the real
//! Admin API (`POST /api/v1/admin/plugins`), never by hand-copying a file onto the host. That test
//! boots a real busbar process with its admin listener up, installs the plugin over that live HTTP
//! API, restarts onto `store: sqlite` (the store backend is documented restart-to-apply — see
//! `admin/v1/json/handlers.rs::restart`'s doc comment — so a fresh boot picking up the
//! admin-API-installed tarball is the real mechanism, not an invented shortcut), mints a virtual
//! key + an attached AWS SigV4 credential through THAT live instance's own `POST
//! /api/v1/admin/keys`, and independently verifies both landed in the real on-disk file with a
//! second `SqliteStore::open` that never touches the plugin/ABI/admin-API/loader.

use busbar_api::{
    McpCallRecord, McpDemotionRow, ModelTokens, Store, TaskEventRow, TaskRow, TierTokens,
    UsageLedger,
};
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

/// Locate the cdylib THIS `cargo test` invocation just built — never a leftover artifact.
///
/// This looks in `target/<profile>/deps/`, NOT `target/<profile>/`, and that distinction is the
/// whole point of this function.
///
/// `cargo` emits the lib target's cdylib into `deps/` as part of the very build graph that produces
/// this test binary (this package's lib unit is compiled with BOTH declared crate-types — see
/// `[lib] crate-type = ["cdylib", "rlib"]` in Cargo.toml — so `deps/libbusbar_store_sqlite_plugin.dylib`
/// is by construction up to date with the source tree being tested). It only *uplifts* a copy to
/// `target/<profile>/` for `cargo build`, NEVER for `cargo test`. So the old lookup in
/// `target/<profile>/` read an artifact that nothing in the test's dependency graph ever refreshes:
/// whatever some earlier `cargo build` happened to leave there, from any commit, or nothing at all.
///
/// Both failure modes of that are lies about durability, and the second is the dangerous one:
///   * NOTHING there  -> the test used to `return` with a "skip:" line and report GREEN, which is
///     how `cargo test --workspace` on a fresh clone reported success with ZERO over-the-ABI
///     coverage of the ten task/call-log methods.
///   * STALE artifact -> a cdylib older than the ABI relay answers every write `Ok(())` and every
///     read empty, which is BYTE-FOR-BYTE the signature of the unrelayed-seam defect this file
///     exists to catch (that defect was real: `DynStore`'s `impl Store` overrode 24 methods, none
///     of them task methods, so `put_task` took the accept-and-keep-nothing trait default). RED on
///     a stale artifact is indistinguishable from RED on the real bug; and an artifact that happens
///     to be NEWER than a regression reports GREEN while the shipped ABI is broken.
///
/// Same hazard, and the same reasoning, as the engine's `crates/busbar/Cargo.toml` dev-dependency on
/// `busbar-store-example-plugin`: put the cdylib in the graph so the test cannot judge a stale one.
/// Here the plugin's lib IS this package, so the graph edge already exists — what was missing was
/// looking at the artifact that edge produces.
///
/// Panics rather than skipping. A missing cdylib under `cargo test` means the build graph changed
/// shape, and the only honest report is a failure, not a silent pass.
/// The newest mtime across every workspace crate's `src/` — "how fresh must a cdylib be to be the
/// one this source tree describes".
///
/// Deliberately ONLY `src/**/*.rs` of each workspace member: editing a `tests/` file or a
/// `[dev-dependencies]` line recompiles the test binary but NOT the lib, so including those would
/// fail a perfectly current cdylib.
fn newest_source_mtime() -> std::time::SystemTime {
    fn walk(dir: &std::path::Path, newest: &mut std::time::SystemTime) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, newest);
            } else if p.extension().is_some_and(|x| x == "rs") {
                if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                    if m > *newest {
                        *newest = m;
                    }
                }
            }
        }
    }
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the plugin crate always sits under the workspace root");
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    for e in std::fs::read_dir(ws_root).into_iter().flatten().flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk(&src, &mut newest);
        }
    }
    newest
}

fn plugin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe"); // .../target/<profile>/deps/e2e-<hash>
    let deps_dir = exe.parent().expect("the test binary always lives in deps/");
    let name = busbar_plugin_loader::plugin_library_filename("busbar_store_sqlite_plugin");
    let fresh = deps_dir.join(&name);
    assert!(
        fresh.exists(),
        "the store-sqlite-plugin cdylib is not at {}, where cargo emits it for the same build that \
         produced this test binary. Refusing to fall back to target/<profile>/ (an artifact only \
         `cargo build` refreshes) or to skip: judging a stale cdylib is exactly how an unrelayed \
         plugin ABI reads as green.",
        fresh.display()
    );
    // FRESHNESS, ASSERTED — not assumed. Under `cargo test` the artifact above is rebuilt by the
    // same graph that built this binary (proven: delete it, re-run, cargo re-emits it). But this
    // test binary can also be executed DIRECTLY out of `deps/`, where nothing rebuilds anything,
    // and a stale cdylib there produces empty reads — indistinguishable from the unrelayed-ABI
    // defect. So compare it against the sources and fail with a message that says STALE ARTIFACT,
    // explicitly NOT a durability verdict.
    let built = std::fs::metadata(&fresh)
        .and_then(|m| m.modified())
        .expect("cdylib mtime");
    let newest_src = newest_source_mtime();
    assert!(
        built >= newest_src,
        "STALE ARTIFACT — THIS IS NOT A DURABILITY FAILURE. {} predates this workspace's sources, \
         so it cannot answer for the code in the tree; a pre-change cdylib returns empty for every \
         read, which reads exactly like an unrelayed plugin ABI. Run `cargo build -p {}` (or just \
         `cargo test`, which rebuilds it) and re-run.",
        fresh.display(),
        "busbar-store-sqlite-plugin"
    );
    fresh
}

/// Every `env:` secret-ref name a config text references, in first-seen order, de-duplicated.
///
/// busbar 1.5.3 made `--validate` RESOLVE built-in (`env`/`file`) secret references and exit 1 when
/// one cannot resolve, rather than only checking the reference's SHAPE. A fixture config that names
/// a real-looking env var (here, `MOCK_KEY`) then fails `--validate` on any machine that doesn't
/// happen to have that var set -- which is every CI runner and most dev machines. Hardcoding
/// `MOCK_KEY` here would fix today's failure but rot the moment this fixture, or a future one, names
/// a different variable. Extracting the names generically (same approach `GetBusbar/store-mysql`'s
/// own `store-mysql-plugin/tests/e2e.rs` already took for this exact change, and the core repo's
/// `crates/busbar/tests/docs_examples.rs`) keeps the harness working no matter what the fixture
/// references.
fn referenced_env_vars(text: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for (i, _) in text.match_indices("env:") {
        let rest = &text[i + 4..];
        let name: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && !v.contains(&name) {
            v.push(name);
        }
    }
    v
}

/// A placeholder value for a fixture-referenced secret: 64 hex chars, which is valid for
/// `auth.signing_key` and harmless as any other secret's value.
const SECRET_PLACEHOLDER: &str = "0000000000000000000000000000000000000000000000000000000000000001";

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
    let so_path = plugin_path();

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
    let config_text = format!(
        "listen: \"127.0.0.1:0\"\n\
         store:\n  module: sqlite\n  settings: {{ db_path: \"{}\" }}\n\
         plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
         auth:\n  chain: []\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        db_path.display(),
        plugins_dir.display()
    );
    std::fs::write(&config, &config_text).unwrap();

    // `--validate` is DELIBERATELY not used for the load-proof itself: it is manifest-only by
    // design ("no server, no network, no state, no dlopen" -- crates/busbar/src/main.rs's own
    // `--help` text) and never opens the store, so a `db_path.exists()` check after `--validate`
    // would either always fail (as it does here) or, worse, silently pass for the wrong reason (as
    // it would for a store whose own persistence-check code opens a fresh connection right after,
    // masking that `--validate` did nothing). A clean `--validate` run first proves the file-dropped
    // plugin passes the trust/manifest gate; then a REAL BOOT (no `--validate` flag) is the only
    // thing that actually `dlopen`s the plugin and runs `Store::open`/migration, so that's what
    // proves the persistence claim.
    //
    // `--validate` RESOLVES built-in `env:` secret references (busbar 1.5.3); give every one this
    // fixture names a placeholder so the gate tests the config's SHAPE, not this machine's
    // environment. See `referenced_env_vars`'s doc comment for why this is generic, not hardcoded.
    let mut validate_cmd = Command::new(&busbar_bin);
    validate_cmd
        .arg("--validate")
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers);
    for name in referenced_env_vars(&config_text) {
        validate_cmd.env(name, SECRET_PLACEHOLDER);
    }
    let out = validate_cmd.output().expect("run busbar --validate");
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

/// Bind an ephemeral loopback port and immediately drop the listener, handing the bare port number
/// back for a spawned child process's config. Small bind-then-drop TOCTOU race, same pattern this
/// monorepo's own plugin e2e suites already use for picking a free port ahead of a subprocess spawn
/// (e.g. `auth-oidc-plugin/tests/e2e.rs`'s `spawn_https_fixture`), acceptable for a test harness.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Pack the built sqlite plugin cdylib into a real signed-shape tarball (same `busbar-plugin-pack`
/// tool CI's SIGNOFF step uses, `--allow-unsigned` locally exactly like CI's own unsigned-key
/// fallback), returning the raw tarball bytes.
fn pack_sqlite_tarball(
    pack_bin: &std::path::Path,
    so_path: &std::path::Path,
    out: &std::path::Path,
) -> Vec<u8> {
    let status = Command::new(pack_bin)
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
            "0.0.0-e2e-admin-api",
            "--publisher",
            "busbar",
            "--description",
            "e2e admin-API install proof",
            "--license",
            "Apache-2.0",
            "--out",
            out.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");
    std::fs::read(out).expect("read packed tarball")
}

/// Poll `GET /api/v1/admin/info` (with the admin token) until it answers 200, or the deadline
/// passes / the child exits first. Real over-the-wire readiness, not a fixed sleep.
fn wait_for_admin_ready(
    client: &reqwest::blocking::Client,
    admin_addr: &str,
    token: &str,
    child: &mut std::process::Child,
) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Ok(resp) = client
            .get(format!("http://{admin_addr}/api/v1/admin/info"))
            .header("x-admin-token", token)
            .send()
        {
            if resp.status().is_success() {
                return true;
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("busbar exited before the admin API became ready (status: {status})");
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// The full install-path proof: the sqlite plugin installed the way a real operator
/// actually installs it — a `POST /api/v1/admin/plugins` call against a REAL running busbar admin
/// listener, never file-drop, never a direct `load_store()`/loader call — then EXERCISED through
/// that same live instance's own admin API (mint a virtual key + an attached AWS SigV4 credential
/// via `POST /api/v1/admin/keys`), with the write independently verified by opening the real sqlite
/// file on disk with a SECOND, completely independent connection that never touches the
/// plugin/ABI/admin-API/loader at all.
///
/// Two-boot shape, because `store:` is documented as restart-to-apply (busbar never hot-swaps the
/// durable governance store on a config reload — see `admin/v1/json/handlers.rs::restart`'s own doc
/// comment): boot 1 runs with an in-memory store just to reach a live admin listener to install
/// against; boot 2 (a fresh process over the SAME plugins dir, so it dlopens the EXACT tarball boot
/// 1's admin API wrote to disk, not a copy this test placed by hand) runs with `store: { module:
/// sqlite }` and is the one whose admin API mints the key/credential that lands in the real file.
#[test]
fn install_sqlite_plugin_via_admin_api_and_verify_persistence() {
    let so_path = plugin_path();
    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = ScratchDir::create("admin-api-install");
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    let db_path = work.join("governance.db");
    const ADMIN_TOKEN: &str = "e2e-admin-api-token";
    // S2 KEY-SIGNING SECRET (64 hex chars = 32 raw ed25519 bytes). Required as of core 1.5.1:
    // busbar no longer auto-generates a signing key, so `POST /api/v1/admin/keys` refuses with
    // `409 conflict` / `no_signing_key` when `auth.signing_key` is absent.
    const TEST_SIGNING_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();

    // Shared config skeleton for both boots: only `store:` differs between the two.
    let write_config = |path: &std::path::Path,
                        data_port: u16,
                        admin_port: u16,
                        store_yaml: &str| {
        std::fs::write(
            path,
            format!(
                "listen: \"127.0.0.1:{data_port}\"\n\
                 admin_listen: \"127.0.0.1:{admin_port}\"\n\
                 {store_yaml}\n\
                 plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
                 identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
                 auth:\n  chain: []\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth: [admin-tokens]\n\
                 providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
                 models:\n  test-model:\n    provider: mock\n",
                plugins_dir.display()
            ),
        )
        .unwrap();
    };

    let client = reqwest::blocking::Client::new();

    // ── BOOT 1: store: memory, just to reach a live admin listener to install against. ──
    let config1 = work.join("config1.yaml");
    write_config(
        &config1,
        free_port(),
        free_port(),
        "store:\n  module: memory\n",
    );
    let admin_addr1 = {
        // Re-read the port we just picked back out of the file we wrote (avoids a second TOCTOU
        // window between picking the port and writing it).
        let text = std::fs::read_to_string(&config1).unwrap();
        text.lines()
            .find(|l| l.starts_with("admin_listen:"))
            .unwrap()
            .trim_start_matches("admin_listen: \"127.0.0.1:")
            .trim_end_matches('"')
            .to_string()
    };
    let admin_addr1 = format!("127.0.0.1:{admin_addr1}");

    let mut child1 = Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config1)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
        .env("BUSBAR_STATE_FILE", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn boot 1 (memory store, admin listener up)");
    assert!(
        wait_for_admin_ready(&client, &admin_addr1, ADMIN_TOKEN, &mut child1),
        "boot 1's admin API must become ready within 15s"
    );

    // ── REAL ADMIN-API INSTALL: POST the packed sqlite plugin tarball to /api/v1/admin/plugins. ──
    let tarball_path = work.join("store-sqlite-admin.tar.gz");
    let tarball = pack_sqlite_tarball(&pack_bin, &so_path, &tarball_path);
    let file = "store-sqlite-admin.tar.gz";
    use base64::Engine as _;
    let install_resp = client
        .post(format!("http://{admin_addr1}/api/v1/admin/plugins"))
        .header("x-admin-token", ADMIN_TOKEN)
        .json(&serde_json::json!({
            "file": file,
            "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
        }))
        .send()
        .expect("POST /api/v1/admin/plugins");
    assert_eq!(
        install_resp.status().as_u16(),
        201,
        "the real admin API must accept the sqlite plugin install"
    );
    let installed: serde_json::Value = install_resp.json().unwrap();
    assert_eq!(installed["file"], file);
    assert_eq!(installed["name"], "busbar-store-sqlite-plugin");
    assert!(
        plugins_dir.join(file).exists(),
        "the admin API install must have written the tarball to the real plugins dir"
    );

    // Confirm the catalog reports it too (not just the install response).
    let catalog: serde_json::Value = client
        .get(format!(
            "http://{admin_addr1}/api/v1/admin/plugins?type=store"
        ))
        .header("x-admin-token", ADMIN_TOKEN)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let listed = catalog["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["target"] == file)
        .expect("the just-installed sqlite plugin appears in the store catalog");
    assert_eq!(listed["valid"], true);

    let _ = child1.kill();
    let _ = child1.wait();

    // ── BOOT 2: store: sqlite, over the SAME plugins dir the admin API wrote into above. `store:`
    // is restart-to-apply, so a fresh process picking up the freshly-installed tarball is the real
    // mechanism an operator uses (edit config, restart) — not a hot in-process swap. ──
    let config2 = work.join("config2.yaml");
    write_config(
        &config2,
        free_port(),
        free_port(),
        &format!(
            "store:\n  module: sqlite\n  settings: {{ db_path: \"{}\" }}\n",
            db_path.display()
        ),
    );
    let admin_addr2 = {
        let text = std::fs::read_to_string(&config2).unwrap();
        text.lines()
            .find(|l| l.starts_with("admin_listen:"))
            .unwrap()
            .trim_start_matches("admin_listen: \"127.0.0.1:")
            .trim_end_matches('"')
            .to_string()
    };
    let admin_addr2 = format!("127.0.0.1:{admin_addr2}");

    let mut child2 = Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config2)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
        .env("BUSBAR_STATE_FILE", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn boot 2 (sqlite store, over the admin-API-installed plugin)");
    assert!(
        wait_for_admin_ready(&client, &admin_addr2, ADMIN_TOKEN, &mut child2),
        "boot 2 (real dlopen of the admin-API-installed sqlite plugin, real Store::open/migrate) \
         must bring the admin API up within 15s"
    );
    assert!(
        db_path.exists(),
        "boot 2 dlopening the admin-API-installed plugin must have created the real sqlite file"
    );

    // ── EXERCISE THROUGH THE LIVE ADMIN API: mint a virtual key + an attached AWS SigV4 credential
    // — the real `POST /api/v1/admin/keys` an operator uses, not a direct store call. ──
    let mint_resp = client
        .post(format!("http://{admin_addr2}/api/v1/admin/keys"))
        .header("x-admin-token", ADMIN_TOKEN)
        .json(&serde_json::json!({
            "name": "e2e-admin-api-key",
            "issue_aws_credential": true,
        }))
        .send()
        .expect("POST /api/v1/admin/keys");
    // The REFUSAL BODY is part of the assertion, not something to go re-derive from core's source
    // after the fact. A bare `assert_eq!(status, 201)` reported only `left: 409, right: 201`, which
    // is indistinguishable between at-least-four different admin 409s (`no_signing_key`,
    // `at_key_cap`, `governance_off`, `idempotency_in_flight`) — the last CI failure cost a full
    // core-source spelunk to tell them apart. Read the body BEFORE asserting so the message names
    // the actual condition.
    let mint_status = mint_resp.status().as_u16();
    let mint_body = mint_resp.text().expect("read POST /api/v1/admin/keys body");
    assert_eq!(
        mint_status, 201,
        "minting a key + AWS credential through the live sqlite-backed instance must succeed; \
         admin API answered {mint_status}: {mint_body}"
    );
    let minted: serde_json::Value = serde_json::from_str(&mint_body).unwrap();
    let key_id = minted["id"].as_str().expect("minted key id").to_string();
    let access_key_id = minted["aws_access_key_id"]
        .as_str()
        .expect("minted AWS access key id")
        .to_string();
    assert!(
        minted["aws_secret_access_key"].as_str().is_some(),
        "mint response must carry the AWS secret access key once"
    );

    let _ = child2.kill();
    let _ = child2.wait();

    // ── INDEPENDENT VERIFICATION: a second, brand-new `SqliteStore::open` on the real file,
    // bypassing the plugin/ABI/admin-API/loader entirely, must see the exact key + credential the
    // live admin API just wrote. ──
    let direct = SqliteStore::open(db_path.to_str().unwrap(), 5000)
        .expect("open the real file directly, bypassing the plugin and the admin API");
    let key = Store::get_key(&direct, &key_id).unwrap().expect(
        "the virtual key minted over the admin API must be readable directly from the file",
    );
    assert_eq!(key.name, "e2e-admin-api-key");

    let creds = Store::list_credentials(&direct, &key_id).unwrap();
    let cred = creds.iter().find(|c| c.public_id == access_key_id).expect(
        "the AWS SigV4 credential minted over the admin API must be readable directly \
             from the file, keyed by the same access-key-id the admin API returned",
    );
    assert_eq!(cred.kind, "sigv4");
}

/// END-TO-END FAILURE (ABI-contract unit test, see module doc for why this stays a direct
/// `load_store()` call): an `open()` config that cannot produce a usable store surfaces back across
/// the C ABI as a clean `Err`, never a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_sqlite_plugin_bad_config_fails_over_abi() {
    let path = plugin_path();

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

/// THE DURABILITY PROOF FOR THE TEN TASK / CALL-LOG METHODS, OVER THE REAL PLUGIN PATH.
///
/// Every other test of these methods in this repo calls `SqliteStore` DIRECTLY, in-process, and none
/// of them can see the failure that actually matters in production. `busbar_api::Store` DEFAULTS all
/// ten of `put_task`/`get_task`/`list_tasks`/`purge_tasks_before`/`append_task_event`/
/// `list_task_events`/`append_mcp_call`/`list_mcp_calls`/`list_mcp_call_principals`/
/// `purge_mcp_calls_before` to accept-and-keep-nothing, so a plugin seam that does not RELAY them
/// silently substitutes those defaults: every write returns `Ok`, every read answers empty, and a
/// deployment running this backend as a plugin — which is the ONLY way it ever runs — loses every
/// in-flight A2A task and every tool-call record while reporting success.
///
/// So this test goes through `busbar_plugin_loader::load_store`: a REAL `dlopen` of the packed
/// cdylib, the real C ABI, the real `DynStore`. It writes AT ARITY > 1 (three tasks across two
/// states, three events on one task and one on another, three call records for one principal and
/// one for a second), DROPS the handle — which unloads the library — then `dlopen`s AGAIN over the
/// same file and reads everything back. A single-row round trip would not distinguish a relayed
/// method from a lucky default; a multi-row one over a restart cannot be faked by either.
///
/// EXPECT THIS TEST TO BE RED until the engine-side ABI relay for these ten methods is on the
/// busbar ref this repo builds against (`busbar-plugin-abi`'s `StoreRequest`/`StoreResponse`
/// variants, the SDK dispatch and the `DynStore` overrides). THAT IS THE POINT: red here is the
/// truthful report that durable tasks do not yet work through the only path that ships, and the
/// alternative — no coverage at all — is how the seam stayed silently broken.
#[test]
fn tasks_and_call_log_survive_an_unload_and_reload_over_the_real_plugin_abi() {
    let path = plugin_path();
    let scratch = ScratchDir::create("abi-durable");
    let db_path = scratch.join("tasks.db");
    let cfg = serde_json::json!({ "db_path": db_path.to_str().unwrap() }).to_string();

    let task = |id: &str, state: &str, updated_at: u64| TaskRow {
        task_id: id.to_string(),
        context_id: format!("ctx-{id}"),
        principal: "vk_abi".to_string(),
        direction: "inbound".to_string(),
        state: state.to_string(),
        agent_id: "planner".to_string(),
        artifact_cursor: 7,
        push_callback: "https://example.test/push".to_string(),
        created_at: 1_000,
        updated_at,
    };
    let event = |task_id: &str, seq: u64, prev: &str, hash: &str| TaskEventRow {
        task_id: task_id.to_string(),
        seq,
        ts: 1_000 + seq,
        kind: "task.working".to_string(),
        context_id: format!("ctx-{task_id}"),
        principal: "vk_abi".to_string(),
        agent_id: "planner".to_string(),
        state: "working".to_string(),
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };
    let call = |principal: &str, seq: u64, prev: &str, hash: &str| McpCallRecord {
        principal: principal.to_string(),
        seq,
        ts: 2_000 + seq,
        server: "srv".to_string(),
        tool: "srv_read_file".to_string(),
        outcome: "dispatched".to_string(),
        reason: String::new(),
        tool_digest: format!("sha256:tool{seq}"),
        pin_generation: 3,
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = busbar_plugin_loader::load_store(&path, &cfg)
            .expect("the sqlite plugin must load over the real ABI");
        for (id, state, updated) in [
            ("t_alpha", "working", 10_u64),
            ("t_beta", "input-required", 20),
            ("t_gamma", "completed", 30),
        ] {
            store.put_task(&task(id, state, updated)).expect("put_task");
        }
        for (seq, prev, hash) in [(1_u64, "", "e1"), (2, "e1", "e2"), (3, "e2", "e3")] {
            store
                .append_task_event(&event("t_alpha", seq, prev, hash))
                .expect("append_task_event");
        }
        store
            .append_task_event(&event("t_beta", 1, "", "b1"))
            .expect("append_task_event");
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_mcp_call(&call("vk_abi", seq, prev, hash))
                .expect("append_mcp_call");
        }
        store
            .append_mcp_call(&call("vk_other", 1, "", "o1"))
            .expect("append_mcp_call");
        // Dropping the boxed store drops the loader's `Library` handle: the dylib is UNLOADED, so
        // nothing this process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen over the same file.
    let store = busbar_plugin_loader::load_store(&path, &cfg)
        .expect("the sqlite plugin must load again over the real ABI");

    let tasks = store.list_tasks().expect("list_tasks");
    assert_eq!(
        tasks.len(),
        3,
        "all three tasks must survive the unload/reload over the plugin ABI; got {} back, which is \
         the accept-and-keep-nothing shape of the trait default that an unrelayed seam substitutes",
        tasks.len()
    );
    let beta = store
        .get_task("t_beta")
        .expect("get_task")
        .expect("the interrupted task must be readable by id after a reload");
    assert_eq!(beta.state, "input-required");
    assert_eq!(
        beta.artifact_cursor, 7,
        "the artifact cursor must round-trip"
    );
    assert_eq!(beta.push_callback, "https://example.test/push");
    assert_eq!(beta.context_id, "ctx-t_beta");

    let events = store.list_task_events("t_alpha").expect("list_task_events");
    assert_eq!(
        events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-task provenance chain must come back oldest-first and complete"
    );
    for w in events.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the chain must still link after the reload: seq {} carries prev_hash {:?} but seq {} \
             persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    assert_eq!(
        store
            .list_task_events("t_beta")
            .expect("list_task_events")
            .len(),
        1,
        "one task's events must not leak into another's chain"
    );

    let calls = store.list_mcp_calls("vk_abi").expect("list_mcp_calls");
    assert_eq!(
        calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-principal call chain must survive the reload in chain order"
    );
    assert_eq!(calls[2].tool_digest, "sha256:tool3");
    assert_eq!(calls[2].request_id, "req-3");
    assert_eq!(calls[1].pin_generation, 3);
    assert_eq!(
        store
            .list_mcp_calls("vk_other")
            .expect("list_mcp_calls")
            .len(),
        1,
        "one principal's chain must not carry another's records"
    );
    let mut principals = store
        .list_mcp_call_principals()
        .expect("list_mcp_call_principals");
    principals.sort();
    assert_eq!(
        principals,
        vec!["vk_abi".to_string(), "vk_other".to_string()],
        "the boot enumeration must name every principal holding records, exactly once each"
    );

    // Retention crosses the ABI too, count and all — and both purges are checked for the number
    // they ACTUALLY removed, because a relay that dropped the return value would read as 0.
    assert_eq!(
        store.purge_mcp_calls_before(2_002).expect("purge"),
        2,
        "both records at ts 2001 go (one per principal); the one sitting exactly at the cutoff stays"
    );
    assert_eq!(
        store
            .list_mcp_calls("vk_abi")
            .expect("list_mcp_calls")
            .len(),
        2
    );
    assert!(store
        .list_mcp_calls("vk_other")
        .expect("list_mcp_calls")
        .is_empty());
    assert_eq!(
        store.purge_tasks_before(25).expect("purge"),
        0,
        "no TERMINAL task is older than the cutoff: t_alpha and t_beta are active and must never be \
         swept no matter how old"
    );
    assert_eq!(
        store.purge_tasks_before(31).expect("purge"),
        1,
        "the one completed task at updated_at 30 is the only row retention may drop"
    );
    assert_eq!(store.list_tasks().expect("list_tasks").len(), 2);
}

/// THE DURABILITY PROOF FOR THE FOUR TRUST-STATE METHODS, OVER THE REAL PLUGIN PATH.
///
/// Same reasoning as the task/call-log test above, and a sharper cost. `busbar_api::Store` defaults
/// `put_mcp_demotion`/`list_mcp_demotions`/`clear_mcp_demotion` to accept-and-keep-nothing and
/// `redeem_ask_state` to `Ok(true)` — "this call is the first redemption" — so a seam that does not
/// RELAY them substitutes exactly two security failures, both of them silent and both green:
///
///   * a demotion is written, reported successful and DISCARDED, so a restart hands a quarantined
///     upstream the operator's approval back; and
///   * every redeemer of one single-use approval is told it is the first, so the confirm-once tool
///     an operator gated because it moves money executes once per node and once per restart.
///
/// This backend only ever runs as a plugin, so in-process tests against `SqliteStore` cannot see
/// either. This one goes through `busbar_plugin_loader::load_store`: a real `dlopen`, the real C
/// ABI, the real `DynStore`. TWO CONCURRENT LOADS of one file are the fleet — the ledger has to
/// refuse the second node — and a drop-and-reload is the restart.
#[test]
fn trust_state_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    let path = plugin_path();
    let scratch = ScratchDir::create("abi-trust-state");
    let db_path = scratch.join("trust.db");
    let cfg = serde_json::json!({ "db_path": db_path.to_str().unwrap() }).to_string();

    let demotion = |server: &str, reason: &str, at: u64| McpDemotionRow {
        server: server.to_string(),
        reason: reason.to_string(),
        recorded_at: at,
    };
    let now = 1_700_000_000u64;

    {
        // BOOT 1 — a real dlopen; every call below crosses the C ABI.
        let store = busbar_plugin_loader::load_store(&path, &cfg)
            .expect("the sqlite plugin must load over the real ABI");
        store
            .put_mcp_demotion(&demotion("payments", "tool-drift", now))
            .expect("put_mcp_demotion");
        store
            .put_mcp_demotion(&demotion("payments", "digest-mismatch", now + 10))
            .expect("the upsert path crosses the ABI too");
        store
            .put_mcp_demotion(&demotion("search", "tool-drift", now + 20))
            .expect("put_mcp_demotion");
        store
            .put_mcp_demotion(&demotion("mail", "tool-drift", now + 30))
            .expect("put_mcp_demotion");
        store
            .clear_mcp_demotion("mail")
            .expect("a later agreeing observation clears the quarantine");

        assert!(
            store
                .redeem_ask_state("nonce-abi", now + 900, now)
                .expect("redeem_ask_state"),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen over the same file. The library was unloaded, so
    // nothing this process still holds can be answering these reads out of RAM.
    let store = busbar_plugin_loader::load_store(&path, &cfg)
        .expect("the sqlite plugin must load again over the real ABI");

    let mut rows = store.list_mcp_demotions().expect("list_mcp_demotions");
    rows.sort_by(|a, b| a.server.cmp(&b.server));
    assert_eq!(
        rows,
        vec![
            demotion("payments", "digest-mismatch", now + 10),
            demotion("search", "tool-drift", now + 20),
        ],
        "the boot read must put every recorded quarantine back in force before the first request is \
         served — upserted to the LATEST reason, and without the one a later observation cleared. \
         An empty answer here is the trait default an unrelayed seam substitutes, and it means a \
         restart hands a demoted upstream the operator's approval back"
    );

    assert!(
        !store
            .redeem_ask_state("nonce-abi", now + 900, now + 1)
            .expect("redeem_ask_state"),
        "a restart handed a spent approval back over the plugin ABI. The approval has not lapsed — \
         outliving a restart is the point of it — so the only thing that changed is that the \
         process which recorded the redemption is gone"
    );

    // THE FLEET. A second, simultaneous dlopen of the same cdylib over the same file is what a
    // second node of one deployment is: it shares the signing key, so it shares the seal, and every
    // check but this one passes on both.
    let node_b = busbar_plugin_loader::load_store(&path, &cfg)
        .expect("a second node loads the same plugin against the same store");
    assert!(
        store
            .redeem_ask_state("nonce-fleet", now + 900, now + 2)
            .expect("redeem_ask_state"),
        "node A's first redemption of a fresh approval must proceed"
    );
    assert!(
        !node_b
            .redeem_ask_state("nonce-fleet", now + 900, now + 3)
            .expect("redeem_ask_state"),
        "a second node redeemed an approval the first already spent, which is one operator \
         confirmation executing once per node"
    );
    // THE CONTROL: a ledger that refused everything would satisfy both cases above and would have
    // deleted the feature.
    assert!(
        node_b
            .redeem_ask_state("nonce-distinct", now + 900, now + 4)
            .expect("redeem_ask_state"),
        "a freshly minted approval is not the one that was spent; refusing it would make the shared \
         ledger a blanket refusal of every confirmation after the first"
    );
}
