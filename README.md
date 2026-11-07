<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-store-sqlite

First-party signed kind:store plugin cdylib: the SQLite governance store packaged as a droppable busbar plugin exporting the store C ABI. Drop the built library into the plugins folder and set store.module: sqlite.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `store` | `sqlite` | `busbar-store-sqlite-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

<!-- fleet:header:end -->

## What it is for

**This plugin's version: v1.6.0.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![codecov](https://codecov.io/gh/GetBusbar/busbar-store-sqlite/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-store-sqlite)
[![Release](https://img.shields.io/github/v/release/GetBusbar/busbar-store-sqlite)](https://github.com/GetBusbar/busbar-store-sqlite/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The first-party, signed `kind: store` plugin for
[busbar](https://getbusbar.com): the SQLite governance store packaged as
a droppable plugin — a `cdylib` exporting the store C ABI. Drop the
built library into busbar's plugins folder, set
`store: { module: sqlite, settings: {...} }`, and busbar loads it in-process at boot
(`dlopen`'d, not spawned as a separate process).

- A durable store for busbar's governance data (the config names its store): virtual
  keys, credentials, usage and metering ledgers, the durable audit log,
  and every plane's durable records (A2A tasks and their provenance
  chains, MCP demotions, single-use approval tokens,
  push-callback capabilities, and any record kind a plane declares) —
  single-node, file-backed, zero external dependencies (SQLite is bundled).
- The reference `kind: store` plugin: a minimal example of adapting an
  engine-agnostic storage backend to the plugin C ABI.

### Versioning

This plugin is versioned **independently of busbar** — `v1.6.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.6.0+** — the release whose primitive persistence interface this crate implements. Pin both versions explicitly in production; do
not assume they move together.

### Persistence and upgrades

The SQLite backend implements opaque reads, scans, conditional atomic commits and
store-clock observations. Identity, accounting, retention and token policy belong
to core. SQLite uses a local host clock; sharing a file across hosts with independent
clocks is unsupported.

Normal startup inspects SQLite before ordinary opening. Supported historical
schemas upgrade automatically through Busbar's migration library. SQLite drains
preceding writers and installs persistent write guards on the retained original
tables before exposing bounded source pages and an inactive target. Interrupted
upgrades resume the same durable identities; unknown formats remain closed.
No export command or manual fencing file is required.

The logic crate exposes `v4::door`, shared by linked installations and the thin
`store-sqlite-plugin` cdylib's `busbar_plugin_door` export. There is no typed
backend business API.

## Config

```yaml
store:
  module: sqlite
  settings:
    db_path: /var/lib/busbar/governance.db
    busy_timeout_ms: 5000
```

| Setting | Required | Default | Notes |
|---|---|---|---|
| `db_path` | no | `busbar-governance.db` | Path to the SQLite database file, or a `file:` URI naming one (created `0600` like a plain path; only `mode=rw`, `mode=rwc`, `mode=memory` and `cache=private` are accepted for writable runtime access; locking/VFS overrides and shared-cache aliases are refused; missing `mode=rw` files are an open error, and `mode=ro` can be inspected but cannot acquire writable runtime authority). `:memory:` (or a `file:` URI with `mode=memory`) opens an in-process, non-durable database: everything, including `op_id` dedupe receipts and redeemed single-use tokens, is lost on restart. The opened store reports itself ephemeral, so busbar's boot-time ephemeral-store warning fires for it. |
| `busy_timeout_ms` | no | `5000` | SQLite's `busy_timeout`, in milliseconds. `0` is accepted (a deliberate "never retry, fail fast on any contention" setting); a negative value, or one above 2147483647 (SQLite's 32-bit limit; larger silently disables the timeout), is rejected as a config error. |

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
below) in production.

Any other setting is refused, naming the accepted ones, so a typo such as
`dbpath` cannot quietly open the default file; a settings value that is not
a JSON object (other than empty or `null`) is refused too. The former ignored
`license_key` setting has no SQLite behavior and is no longer accepted.
Existing configurations must pass through the coordinated upgrade migration,
which removes this obsolete setting before runtime settings validation.

A `db_path`/`busy_timeout_ms` key that is *present* in the config but
the wrong JSON type (a number for `db_path`, a string for
`busy_timeout_ms`, etc.) — or a negative `busy_timeout_ms` — is a config
error and `open` fails loudly — it is never silently replaced with the
default. An *absent* key falls back to its default, and so does a key
whose value is an explicit JSON `null`: `null` is read as absent (the
behaviour this plugin has always had). A template variable that renders
`db_path` as `null` therefore opens the default relative path, which is
one more reason to set it explicitly.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)). No sibling busbar
checkout is needed to build or unit-test; only the end-to-end tests need one
(see [Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_store_sqlite_plugin.{so,dylib}
cargo test                 # native persistence, historical readers and loader conformance
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Dependencies

The only busbar crate this repo names is `busbar-contract` (plus
`busbar-plugin-loader`, dev-only, for native conformance and migration tests),
as a **git dependency** on [busbar](https://github.com/GetBusbar/busbar)
pinned to the rev in field 1 of `.busbar-ref`. No sibling checkout is needed
to build or unit-test. Native conformance tests load the linked door and built cdylib
through the loader. Build the plugin library before running dropped-in tests.

### Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_store_sqlite_plugin.so \
    --name busbar-store-sqlite-plugin --alias sqlite --kind store \
    --version 1.6.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-store-sqlite-plugin-1.6.0-x86_64-linux.tar.gz
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

## Tests

`cargo test` runs native primitive regressions, bounded historical reader/export tests,
settings validation, and linked/dropped loader conformance. The loader tests reopen
the same dataset and independently inspect the physical schema. Build the plugin
library first, or set `BUSBAR_PLUGIN_CDYLIB` to the built artifact.

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
