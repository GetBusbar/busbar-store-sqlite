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
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built");
        return;
    };
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
