<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-store-sqlite

First-party signed kind:store plugin cdylib: the SQLite governance store packaged as a droppable busbar plugin exporting the store C ABI. Drop the built library into the plugins folder and set store.module: sqlite.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `store` | `sqlite` | `busbar-store-sqlite-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-store-sqlite/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-store-sqlite/actions/workflows/ci.yml)
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
stated separately: **requires busbar 1.6.0+** — the release whose store
interface this crate implements (the kind-tagged plane-record verbs that
replaced the per-protocol task/MCP methods, and the 1.6.0 key, usage and
metering record shapes). Pin both versions explicitly in production; do
not assume they move together.

### Single-use tokens and ticket deadlines

Single-use token redemption uses SQLite's Unix clock inside its write transaction. The caller's
`now` does not authorize expiry or cleanup. SQLite has no separate server clock: connections to one
local file must share one host clock. Sharing a database file across hosts with independent clocks
is not a supported shared-clock deployment; use a server-backed store for that topology. Expired
candidates leave the replay ledger unchanged. Generic multi-use token checks retain their separate policy. Reserved ticket preflight reads a terminal record with the exact signed deadline against the store clock and never spends the token. The reserved kernel `ticket` record kind stores an absolute deadline in `ts`; its age cleanup is capped at the same store clock. Other record kinds keep their existing retention policy.

### Upgrading an existing database

Opening a database written by an earlier release upgrades it in place,
forward-only, in one transaction (schema v6 — the v1.0.x releases — or
v7 to the current schema v8). Keys and credentials retain their full-width unsigned
timestamps. An older signed expiry check could admit an expiry that
precedes creation in unsigned order; such a row refuses the upgrade with
its identity and decoded timestamps. The transaction leaves the schema,
rows and revision counter unchanged on refusal, so the source data can be
reviewed before retrying.

Schema v7 preserves each metering row’s recorded group and price version in its identity, including open units. Existing rows keep their recorded attribution; history already combined by an older writer cannot be reconstructed. An open-unit row without its parent refuses the transaction rather than guessing attribution. Stop older writers before upgrading; they cannot safely write the new metering keys.

Schema v8 converts legacy whole-unit quantities to exact scale-6 micro-unit
mantissas in both the quantity columns and JSON ledgers. Request counters
remain unscaled. Quantities outside the supported range refuse the entire
upgrade without changing the database. Reopening an upgraded database does
not scale its quantities again. Older writers cannot safely write these
quantity representations.

On a successful upgrade, keys, credentials, tombstones, usage and metering
counts, the audit log and the denylist retain their data. A credential
revoked under an older build loses the secret it kept (a revoke now
destroys the secret, and the row keeps only its metadata); the upgrade
zeroes the pages of the tables it replaces, so the destroyed secret is not
left readable in the file. Back the file
up before the first boot on the new version — there is no downgrade path,
and an older plugin build must not be pointed at an upgraded file.

All the actual SQLite logic — schema, key/usage/audit persistence, a
mutex-guarded writer connection plus a small pool of `query_only` reader
connections (so a long billing report never blocks the hot-path usage
flush; a retention sweep is a write and takes the writer like any other) —
lives in the `busbar-store-sqlite` `lib` crate in
this repository's `store-sqlite/` directory. The
`store-sqlite-plugin` crate is deliberately tiny: the logic crate also holds
its one door (`door::door`, the store v3 table over `SqliteStore` through
`busbar_contract::store_door!`; its `open` slot adapts the operator's settings
into a `SqliteStore`), and the plugin crate exports that door as
`busbar_plugin_door` (`export_door!`), so the cdylib answers the loader
through the same door a busbar build that LINKS `busbar-store-sqlite`
registers — one source, both doors. The image carries no other export.

A revoke, a credential rewrap, a key delete and a `put_key` that writes a
tombstone (which also destroys the key's credentials) checkpoint and truncate
the WAL once they commit, so the destroyed secret does not linger in
`governance.db-wal`. This never blocks or fails the write: if a reader holds
a snapshot at that moment, the residue goes with a later checkpoint.

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
| `db_path` | no | `busbar-governance.db` | Path to the SQLite database file, or a `file:` URI naming one (created `0600` like a plain path; the URI parameters `cache=shared`, `nolock`, `immutable` and `vfs=unix-none` break the store's single-writer locking and are refused; `mode=rw`/`mode=ro` keep SQLite's rule that a missing file is an open error). `:memory:` (or a `file:` URI with `mode=memory`) opens an in-process, non-durable database: everything, including `op_id` dedupe receipts and redeemed single-use tokens, is lost on restart, and busbar's boot-time ephemeral-store warning does not fire for it (the plugin states one durability for every `db_path`). |
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
a JSON object (other than empty or `null`) is refused too. `license_key`, the
secret-valued key a 1.5.5 sqlite config carried, is the one exception: it is
accepted and ignored.

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
cargo test                 # unit tests + the end-to-end loader test (see tests/e2e.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Dependencies

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

`cargo test` runs the store's own suite (`store-sqlite/src/tests*`, including
the config-adapting `open` in `store-sqlite/src/door/tests.rs`), the
linked == dropped-in conformance test (`store-sqlite-plugin/tests/conformance.rs`:
the linked `door::door` and the dropped-in cdylib, each opened through the
loader's store v3 table and driven through one scenario, including the v3
slots and a restart, and compared, with RED arms),
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

The end-to-end tests need a busbar checkout at the rev `.busbar-ref` pins:
set `BUSBAR_CHECKOUT=/path/to/busbar` (or check it out as a sibling). A
missing checkout is a FAILURE, locally and in CI alike, never a skip: they
are the only proof the plugin installs through a real busbar's boot and
admin paths. CI checks that rev out beside this repo.

The upgrade path is tested against real database files the previous
code wrote (`store-sqlite/tests/fixtures/`, with the programs that wrote
them beside them).

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
