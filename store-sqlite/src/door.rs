// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door: [`door`], the store v3 table over [`SqliteStore`] (`store_door!`), and [`open`], the
//! settings parser its `open` slot runs. A build that links this crate registers `door`; the
//! `busbar-store-sqlite-plugin` cdylib exports the same one as `busbar_plugin_door`. The store
//! answers every call Ready: it is local-disk-bound and runs on the host's bounded disk lane.

use crate::SqliteStore;

/// The store's name, as its Statement states it and its signed manifest names it.
pub const NAME: &str = "busbar-store-sqlite";

/// The settings paths this store declares may hold a secret reference: `*`, every top-level key.
/// busbar 1.5.5 resolved a reference at any top-level store setting (a `license_key`, a `db_path`
/// read from the environment), and busbar now resolves one only where the Statement declares it,
/// refusing it anywhere else; declaring every key keeps each 1.5.5 config booting as it did.
const SECRET_REFS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str("*")];

busbar_contract::store_door!(
    SqliteStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    64,
    secret_refs: SECRET_REFS
);

/// Construct a SQLite store from the settings the host passes through `open`:
///
/// ```json
/// { "db_path": "busbar-governance.db", "busy_timeout_ms": 5000 }
/// ```
///
/// Both keys are optional, so `{}` works; any other top-level key, and an empty or blank `db_path`,
/// is refused. An absent key or an explicit `null` takes the default. A key of any other wrong JSON
/// type is a config error, never defaulted: a template variable resolving to a number for `db_path`
/// must not quietly open the default path, which reads as a healthy boot on an empty database.
pub fn open(cfg: &str) -> Result<SqliteStore, String> {
    let Settings {
        db_path,
        busy_timeout_ms,
    } = Settings::parse(cfg)?;
    SqliteStore::open(&db_path, busy_timeout_ms).map_err(|e| e.0)
}

/// The operator's settings, parsed and nothing more: `validate` runs this alone (`--validate` opens
/// and migrates no store), and [`open`] opens what it read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The database file (or an in-memory spelling).
    pub db_path: String,
    /// SQLite's busy timeout, in ms; never negative, at most `i32::MAX`.
    pub busy_timeout_ms: i64,
}

impl Settings {
    /// Parse the section's JSON exactly as [`open`] reads it.
    ///
    /// # Errors
    /// The refusal text [`open`] carries for the same settings.
    pub fn parse(cfg: &str) -> Result<Self, String> {
        const BAD: &str = "invalid sqlite plugin config";
        let v: serde_json::Value = if cfg.trim().is_empty() {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::from_str(cfg).map_err(|e| format!("invalid sqlite plugin config: {e}"))?
        };
        if let Some(obj) = v.as_object() {
            if let Some(unknown) = obj
                .keys()
                .find(|k| !matches!(k.as_str(), "db_path" | "busy_timeout_ms"))
            {
                return Err(format!(
                    "{BAD}: unknown setting `{unknown}` (accepted: db_path, busy_timeout_ms)"
                ));
            }
        }
        let path = match v.get("db_path") {
            None | Some(serde_json::Value::Null) => "busbar-governance.db".to_owned(),
            Some(serde_json::Value::String(s)) if s.trim().is_empty() => {
                return Err(format!(
                    "{BAD}: `db_path` must not be empty or blank (omit it for the default \
                     `busbar-governance.db`, or name a file, or `:memory:`)"
                ))
            }
            Some(serde_json::Value::String(s)) => s.clone(),
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
                // Negative is a config mistake and SQLite would silently disable the busy handler;
                // `0` is a legal, deliberate "never retry".
                if ms < 0 {
                    return Err(format!(
                        "{BAD}: `busy_timeout_ms` must not be negative, got {ms}"
                    ));
                }
                if ms > i64::from(i32::MAX) {
                    return Err(format!(
                        "{BAD}: `busy_timeout_ms` must be at most 2147483647 (SQLite's busy_timeout is a \
                         32-bit millisecond count; a larger value silently disables it), got {ms}"
                    ));
                }
                ms
            }
            Some(other) => {
                return Err(format!(
                    "{BAD}: `busy_timeout_ms` must be an integer, got {other}"
                ))
            }
        };
        Ok(Self {
            db_path: path,
            busy_timeout_ms,
        })
    }
}

#[cfg(test)]
#[path = "door/tests.rs"]
mod tests;
