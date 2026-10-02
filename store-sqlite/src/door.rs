// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: [`door`], the store v3 table over [`SqliteStore`] (`store_door!`, the contract's store
//! SDK), and [`open`], the settings parser its `open` slot runs. A busbar build that links this crate
//! registers `door` as its compiled-in row; the `busbar-store-sqlite-plugin` cdylib exports the same
//! `door` as `busbar_plugin_door`. Compiled in or dropped in, the host reaches one table. The store
//! answers every call Ready: it is local-disk-bound, and the host runs it on its bounded disk lane
//! (THE DESIGN §11.11 R4, Q-DISK).

use crate::SqliteStore;

/// The store's name, as its Statement states it and its signed manifest names it.
pub const NAME: &str = "busbar-store-sqlite";

busbar_contract::store_door!(SqliteStore, NAME, env!("CARGO_PKG_VERSION"), 64);

/// Construct a SQLite store from the settings the host passes through `open`. Shape (both keys
/// optional, sensible defaults so an empty `{}` works):
///
/// ```json
/// { "db_path": "busbar-governance.db", "busy_timeout_ms": 5000 }
/// ```
///
/// A key that is ABSENT falls back to its default (this plugin's whole design point — an empty
/// `{}` must work), and so does a key whose value is an explicit JSON `null`: `null` is read as
/// absent, the semantics this plugin has shipped with since busbar 1.5. A key that is PRESENT with
/// any other wrong JSON type (e.g. `db_path: 5` or `busy_timeout_ms: "5000"`) is a config error,
/// not silently defaulted: a template variable that resolves to a number for `db_path` must never
/// be swallowed into quietly opening the default relative path — that reads as a healthy boot
/// against an empty governance database (data loss), not a config error.
pub fn open(cfg: &str) -> Result<SqliteStore, String> {
    let v: serde_json::Value = if cfg.trim().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid sqlite plugin config: {e}"))?
    };
    let path = match v.get("db_path") {
        None | Some(serde_json::Value::Null) => "busbar-governance.db",
        Some(serde_json::Value::String(s)) => s.as_str(),
        Some(other) => {
            return Err(format!(
                "invalid sqlite plugin config: `db_path` must be a string, got {other}"
            ))
        }
    };
    let busy_timeout_ms = match v.get("busy_timeout_ms") {
        None | Some(serde_json::Value::Null) => 5000,
        Some(serde_json::Value::Number(n)) if n.is_i64() || n.is_u64() => {
            let ms = n.as_i64().ok_or_else(|| {
                format!("invalid sqlite plugin config: `busy_timeout_ms` out of range, got {n}")
            })?;
            // A negative duration has no meaning and can only be a config mistake (a unit-
            // conversion bug, a stray sign, a bad template substitution) -- unlike `0`, which is a
            // real, deliberate SQLite setting (see `apply_pragmas`'s own doc: SQLite's own
            // zero-second default), a negative number names nothing SQLite or an operator could
            // sensibly mean. SQLite doesn't reject it either -- like `0`, any `busy_timeout <= 0`
            // silently disables the busy handler entirely (every write fails instantly on the
            // slightest lock contention instead of retrying), which reads as a healthy boot with a
            // quietly degraded reliability posture. `0` is left as a legal, if unusual, explicit
            // "never retry" choice; only the never-sensible negative case is rejected here, the
            // same silent-footgun class the wrong-JSON-type check above already guards against.
            if ms < 0 {
                return Err(format!(
                    "invalid sqlite plugin config: `busy_timeout_ms` must not be negative, got {ms}"
                ));
            }
            ms
        }
        Some(other) => {
            return Err(format!(
                "invalid sqlite plugin config: `busy_timeout_ms` must be an integer, got {other}"
            ))
        }
    };
    SqliteStore::open(path, busy_timeout_ms).map_err(|e| e.0)
}

// ── unit tests for the door's own responsibility: adapting the engine's JSON config into a real
// `SqliteStore`. Hermetic — every case uses `:memory:` or a scratch temp file, never the relative
// default path (which would write into the test's cwd). The real over-the-ABI paths live in
// `busbar-store-sqlite-plugin`'s `tests/e2e.rs` and `tests/conformance.rs`.
#[cfg(test)]
#[path = "door/tests.rs"]
mod tests;
