// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **SQLite store as a droppable busbar plugin** — a `cdylib` that exports the store C ABI.
//! Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's plugins folder, and set
//! `store: { module: sqlite, settings: {...} }`; the engine loads it in-process at boot.
//!
//! This crate is deliberately tiny: all the SQLite logic lives in the `busbar-store-sqlite` `lib`
//! crate (which a custom build can also link statically). Here we only adapt the engine's JSON
//! config into a `SqliteStore` and hand the trait object to the SDK, which emits the six extern-C
//! symbols the loader resolves.

use busbar_api::Store;
use busbar_store_sqlite::SqliteStore;

/// Construct a SQLite store from the JSON config the engine passes through `open`. Shape (both keys
/// optional, sensible defaults so an empty `{}` works):
///
/// ```json
/// { "db_path": "busbar-governance.db", "busy_timeout_ms": 5000 }
/// ```
///
/// A key that is ABSENT falls back to its default (this plugin's whole design point — an empty
/// `{}` must work). A key that is PRESENT but the wrong JSON type (e.g. `db_path: 5` or
/// `busy_timeout_ms: "5000"`) is a config error, not silently defaulted: a template variable that
/// resolves to `null`/a number for `db_path` must never be swallowed into quietly opening the
/// default relative path — that reads as a healthy boot against an empty governance database
/// (data loss), not a config error.
fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
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
            n.as_i64().ok_or_else(|| {
                format!("invalid sqlite plugin config: `busy_timeout_ms` out of range, got {n}")
            })?
        }
        Some(other) => {
            return Err(format!(
                "invalid sqlite plugin config: `busy_timeout_ms` must be an integer, got {other}"
            ))
        }
    };
    let store = SqliteStore::open(path, busy_timeout_ms).map_err(|e| e.0)?;
    Ok(Box::new(store))
}

busbar_plugin_sdk::export_store_plugin!(open);

// ── unit tests for THIS crate's own responsibility: adapting the engine's JSON config into a real
// `SqliteStore`. Hermetic — every case uses `:memory:` or a scratch temp file, never the relative
// default path (which would write into the test's cwd). The underlying SQLite/governance logic is
// `busbar-store-sqlite`'s own job and is covered by that crate's own tests; these only cover what
// `open` itself does with the config before handing off. The real over-the-ABI, real-file success and
// failure paths live in THIS repo's own `tests/e2e.rs`.

#[cfg(test)]
mod tests;
