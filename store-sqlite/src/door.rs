// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door: [`door`], the store v3 table over [`SqliteStore`] (`store_door!`), and [`open`], the
//! settings parser its `open` slot runs. A build that links this crate registers `door`; the
//! `busbar-store-sqlite-plugin` cdylib exports the same one as `busbar_plugin_door`. The store
//! answers every call Ready: it is local-disk-bound and runs on the host's bounded disk lane.

use crate::SqliteStore;

/// The store's name, as its Statement states it and its signed manifest names it.
pub const NAME: &str = "busbar-store-sqlite";

/// The settings paths this store declares may hold a secret reference (`secret_refs`): `license_key`,
/// the one secret-valued key a 1.5.5 sqlite config carried (busbar oracle BOOT-170). `db_path` and
/// `busy_timeout_ms` are not secrets. busbar resolves a reference only where the Statement declares
/// one and refuses it anywhere else (G14: each plugin declares its secret fields), so the store names
/// its field rather than `*`.
const SECRET_REFS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str("license_key")];

// `db_path` is reference-capable, not secret: a `{env:}`/`{file:}`/`{module:}` reference resolves in
// place (a 1.5.5 `db_path: {env: VAR}` keeps booting) and a literal passes as written.
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["db_path"]"#),
]);

/// The most ops the host may have in flight against this store at once. Every slot answers Ready
/// on the host's bounded disk lane, so this only caps the queue it feeds.
pub const MAX_INFLIGHT: u32 = 64;

busbar_contract::store_door!(
    SqliteStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    MAX_INFLIGHT,
    extensions: EXTENSIONS,
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
            serde_json::from_str(cfg).map_err(|e| format!("{BAD}: {e}"))?
        };
        let v = match v {
            serde_json::Value::Null => serde_json::Value::Object(Default::default()),
            serde_json::Value::Object(_) => v,
            other => {
                return Err(format!(
                    "{BAD}: expected a JSON object, got {}",
                    json_type(&other)
                ));
            }
        };
        // `license_key` is a declared secret ref a 1.5.5 config carried; accepted and ignored.
        if let Some(unknown) = v
            .as_object()
            .into_iter()
            .flat_map(|o| o.keys())
            .find(|k| !matches!(k.as_str(), "db_path" | "busy_timeout_ms" | "license_key"))
        {
            return Err(format!(
                "{BAD}: unknown setting `{unknown}` (accepted: db_path, busy_timeout_ms, license_key)"
            ));
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
                    "{BAD}: `db_path` must be a string, got {}",
                    json_type(other)
                ))
            }
        };
        let busy_timeout_ms = match v.get("busy_timeout_ms") {
            None | Some(serde_json::Value::Null) => 5000,
            Some(serde_json::Value::Number(n)) if n.is_i64() || n.is_u64() => {
                let ms = n
                    .as_i64()
                    .ok_or_else(|| format!("{BAD}: `busy_timeout_ms` out of range, got {n}"))?;
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
                    "{BAD}: `busy_timeout_ms` must be an integer, got {}",
                    json_type(other)
                ))
            }
        };
        Ok(Self {
            db_path: path,
            busy_timeout_ms,
        })
    }
}

/// The JSON type a refusal names in place of the value.
fn json_type(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

#[cfg(test)]
#[path = "door/tests.rs"]
mod tests;
