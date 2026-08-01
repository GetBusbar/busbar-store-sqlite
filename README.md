# store-sqlite

**This plugin's version: v1.0.0.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![CI](https://github.com/GetBusbar/store-sqlite/actions/workflows/ci.yml/badge.svg)](https://github.com/GetBusbar/store-sqlite/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GetBusbar/store-sqlite)](https://github.com/GetBusbar/store-sqlite/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The first-party, signed `kind: store` plugin for
[busbar](https://getbusbar.com): the SQLite governance store packaged as
a droppable plugin — a `cdylib` exporting the store C ABI. Drop the
built library into busbar's plugins folder, set
`store: { module: sqlite, settings: {...} }`, and busbar loads it in-process at boot
(`dlopen`'d, not spawned as a separate process).

## Versioning

This plugin is versioned **independently of busbar** — `v1.0.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.5.0+** (the release that ships the
signed hybrid plugin ABI this crate loads over). Pin both versions
explicitly in production; do not assume they move together.

All the actual SQLite logic — schema, key/usage/audit persistence, a
mutex-guarded writer connection plus a small pool of `query_only` reader
connections (so a long billing report or retention sweep never blocks the
hot-path usage flush) — lives in the `busbar-store-sqlite` `lib` crate in
[busbarAI](https://github.com/GetBusbar/busbar). This crate is
deliberately tiny: it adapts the engine's JSON `open` config into a
`SqliteStore` and hands the trait object to
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbar/tree/main/crates/plugin-sdk),
which emits the six `extern "C"` symbols the loader resolves. (A custom
build can also link `busbar-store-sqlite` statically instead of using
this dynamic wrapper — see busbarAI's plugin docs.)

## What it is for

- The **default durable store** for busbar's governance data: virtual
  keys, usage ledgers, and the durable audit log — single-node,
  file-backed, zero external dependencies (SQLite is bundled).
- The reference `kind: store` plugin: a minimal example of adapting an
  engine-agnostic storage backend to the plugin C ABI.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbarAI](https://github.com/GetBusbar/busbar) ships publicly —
a sibling checkout of `busbarAI` at `../busbarAI` (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_store_sqlite_plugin.{so,dylib}
cargo test                 # unit tests + the end-to-end loader test (see tests/e2e.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

This crate depends on `busbar-api`, `busbar-store-sqlite`, and
`busbar-plugin-sdk` (and, as a dev-dependency for the end-to-end test,
`busbar-plugin-loader`) from the
[busbarAI](https://github.com/GetBusbar/busbar) monorepo. Because
busbarAI is not yet public, `Cargo.toml` points at these as **local path
dependencies** (`../busbarAI/crates/...`), which means this repo expects
to be checked out as a sibling of `busbarAI`:

```
some-parent-dir/
├── busbarAI/
└── store-sqlite/
```

This is an interim measure — once busbarAI ships publicly, these should
become git (pinned rev/tag) or crates.io dependencies instead. Grep
`Cargo.toml` for the `INTERIM` comments when doing that migration.

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbarAI for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_store_sqlite_plugin.so \
    --name busbar-store-sqlite-plugin --alias sqlite --kind store \
    --version 1.0.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-store-sqlite-plugin-1.0.0-x86_64-linux.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir` and
set:

```yaml
store:
  module: sqlite
  settings: { db_path: /var/lib/busbar/governance.db }
```

— see [`docs/configuration.md`](https://github.com/GetBusbar/busbar/blob/main/docs/configuration.md)
for the full store config reference.

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `db_path` | no | `busbar-governance.db` | Path to the SQLite database file. `:memory:` opens an in-process, non-durable database. |
| `busy_timeout_ms` | no | `5000` | SQLite's `busy_timeout`, in milliseconds. |

**`db_path` must be an explicit absolute path in any real deployment.** The
`busbar-governance.db` default is resolved relative to the engine
process's *current working directory* at the moment it calls `open` —
not relative to the plugin, the config file, or `plugins.dir`. Under
systemd without an explicit `WorkingDirectory=`, or across a deploy that
changes cwd between restarts, the engine can silently bind to a
*different* file each time: it boots healthy, but against an empty
database (no virtual keys, no budgets, no usage history). This looks
like nothing is wrong at boot — it reads as data loss only once someone
notices the governance state is missing. Always set `db_path` to a full
absolute path (e.g. `/var/lib/busbar/governance.db`, as in the example
above) in production.

A `db_path`/`busy_timeout_ms` key that is *present* in the config but
the wrong JSON type (a number for `db_path`, a string for
`busy_timeout_ms`, etc.) is a config error and `open` fails loudly — it
is never silently replaced with the default. Only an *absent* key falls
back to its default.

## Tests

`cargo test` runs both the pure unit tests (`src/lib.rs` — adapting the
engine's JSON config into a `SqliteStore`; the underlying SQLite/
governance logic is `busbar-store-sqlite`'s own job, covered by that
crate's own test suite) and the end-to-end test in `tests/e2e.rs`, which
loads the *built* cdylib over the real `busbar-plugin-loader` ABI seam
— the same seam busbar's engine uses — against a real SQLite file on
disk. It writes a key and a usage ledger through the plugin over the C
ABI, closes the plugin, then verifies the data actually landed on disk
two independent ways: re-`dlopen`ing the same cdylib against the same
file, and opening the same file directly with the plain
`busbar-store-sqlite::SqliteStore` (a code path that never touches the
cdylib, the C ABI, or the loader at all). A second test proves a bad
`open` config (malformed JSON, or a `db_path` under a nonexistent
directory) fails cleanly across the ABI rather than panicking or
silently succeeding.

Build under `cargo test` (which builds the cdylib as part of the test
run) so the e2e test finds the library; it self-skips with a message if
the cdylib isn't present.

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
