<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-store-sqlite

First-party signed kind:store plugin cdylib: the SQLite governance store packaged as a droppable busbar plugin exporting the store C ABI. Drop the built library into the plugins folder and set store.module: sqlite.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `store` | `sqlite` | `busbar-store-sqlite-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-store-sqlite/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-store-sqlite/actions/workflows/ci.yml)
<!-- fleet:header:end -->

**This plugin's version: v1.0.0.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![CI](https://github.com/GetBusbar/busbar-store-sqlite/actions/workflows/ci.yml/badge.svg)](https://github.com/GetBusbar/busbar-store-sqlite/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/GetBusbar/busbar-store-sqlite/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-store-sqlite)
[![Release](https://img.shields.io/github/v/release/GetBusbar/busbar-store-sqlite)](https://github.com/GetBusbar/busbar-store-sqlite/releases)
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
stated separately: **requires busbar 1.6.0+** — the release whose store
interface this crate implements (the kind-tagged plane-record verbs that
replaced the per-protocol task/MCP methods, and the 1.6.0 key, usage and
metering record shapes). Pin both versions explicitly in production; do
not assume they move together.

## Upgrading an existing database

Opening a database written by an earlier release upgrades it in place,
forward-only, in one transaction (schema v6 — the v1.0.x releases — or
later, to v10). Nothing an operator already has is dropped: keys,
credentials, tombstones, usage and metering counts, the audit log and the
denylist all read back exactly as before, and existing metering rows are
attributed to the opening rate card. Back the file up before the first
boot on the new version — there is no downgrade path, and an older plugin
build must not be pointed at an upgraded file.

All the actual SQLite logic — schema, key/usage/audit persistence, a
mutex-guarded writer connection plus a small pool of `query_only` reader
connections (so a long billing report or retention sweep never blocks the
hot-path usage flush) — lives in the `busbar-store-sqlite` `lib` crate in
this repository's `store-sqlite/` directory. The
`store-sqlite-plugin` crate is deliberately tiny: the logic crate also holds
its one door registration (`busbar_contract::abi::sdk::export_store_plugin!(open)`,
where `open` adapts the engine's JSON config into a `SqliteStore`), and the
plugin crate re-exports it, so the cdylib answers the loader through the same
door a busbar build that LINKS `busbar-store-sqlite` registers (its
`linked::STORE` row) — one source, both doors.

## What it is for

- The **default durable store** for busbar's governance data: virtual
  keys, credentials, usage and metering ledgers, the durable audit log,
  and every plane's durable records (A2A tasks and their provenance
  chains, the MCP call log and demotions, single-use approval tokens,
  push-callback capabilities, and any record kind a plane declares) —
  single-node, file-backed, zero external dependencies (SQLite is bundled).
- The reference `kind: store` plugin: a minimal example of adapting an
  engine-agnostic storage backend to the plugin C ABI.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbar](https://github.com/GetBusbar/busbar) ships publicly —
a sibling checkout of `busbar` at `../busbar` (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_store_sqlite_plugin.{so,dylib}
cargo test                 # unit tests + the end-to-end loader test (see tests/e2e.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

The only busbar crate this repo names is `busbar-contract` (plus
`busbar-plugin-loader`, dev-only, for the conformance and end-to-end tests),
as a **git dependency** on [busbar](https://github.com/GetBusbar/busbar)
pinned to the rev in field 1 of `.busbar-ref`. No sibling checkout is needed
to build or unit-test. The end-to-end tests (`store-sqlite-plugin/tests/e2e.rs`)
boot a REAL busbar binary, so they need a busbar checkout at that same rev:
set `BUSBAR_CHECKOUT=/path/to/busbar`, or check it out as a sibling:

```
some-parent-dir/
├── busbar/
└── store-sqlite/
```

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference. In short:

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
| `busy_timeout_ms` | no | `5000` | SQLite's `busy_timeout`, in milliseconds. `0` is accepted (a deliberate "never retry, fail fast on any contention" setting); a negative value is rejected as a config error, since it can only be a mistake. |

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
`busy_timeout_ms`, etc.) — or a negative `busy_timeout_ms` — is a config
error and `open` fails loudly — it is never silently replaced with the
default. Only an *absent* key falls back to its default.

## Tests

`cargo test` runs the store's own suite (`store-sqlite/src/tests*`, including
the config-adapting `open` in `store-sqlite/src/door/tests.rs`), the
linked == dropped-in conformance test (`store-sqlite-plugin/tests/conformance.rs`:
the linked `linked::STORE` row and the signed, dropped-in cdylib driven through
one scenario, including a restart, and compared byte for byte, with RED arms),
and the end-to-end tests in `store-sqlite-plugin/tests/e2e.rs`, which
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
run) so the e2e test finds the library; it fails, rather than skipping,
if the cdylib isn't present or is older than the sources.

The upgrade path is tested against real database files the previous
code wrote (`store-sqlite/tests/fixtures/`, with the programs that wrote
them beside them).

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
