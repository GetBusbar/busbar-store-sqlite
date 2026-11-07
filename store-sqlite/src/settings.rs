// SPDX-License-Identifier: Apache-2.0
//! SQLite connection settings; validation never opens a database.

/// The operator's settings, parsed and nothing more: validation runs this alone, before any database is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The database file (or an in-memory spelling).
    pub db_path: String,
    /// SQLite's busy timeout, in ms; never negative, at most `i32::MAX`.
    pub busy_timeout_ms: i64,
}

/// Every top-level setting the parser accepts; any other key is refused, naming these.
const ACCEPTED: [&str; 2] = ["db_path", "busy_timeout_ms"];

impl Settings {
    /// Parse the section's JSON without opening a database.
    ///
    /// # Errors
    /// The refusal text for invalid settings.
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

        if let Some(unknown) = v
            .as_object()
            .into_iter()
            .flat_map(|o| o.keys())
            .find(|k| !ACCEPTED.contains(&k.as_str()))
        {
            return Err(format!(
                "{BAD}: unknown setting `{unknown}` (accepted: {})",
                ACCEPTED.join(", ")
            ));
        }
        let path = match v.get("db_path") {
            None | Some(serde_json::Value::Null) => "busbar-governance.db".to_owned(),
            Some(serde_json::Value::String(s)) if s.trim().is_empty() => {
                return Err(format!(
                    "{BAD}: `db_path` must not be empty or blank (omit it for the default \
                     `busbar-governance.db`, or name a file, or `:memory:`)"
                ));
            }
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(other) => {
                return Err(format!(
                    "{BAD}: `db_path` must be a string, got {}",
                    json_type(other)
                ));
            }
        };
        let busy_timeout_ms = match v.get("busy_timeout_ms") {
            None | Some(serde_json::Value::Null) => 5000,
            Some(serde_json::Value::Number(n)) if n.is_i64() || n.is_u64() => {
                let ms = n
                    .as_i64()
                    .ok_or_else(|| format!("{BAD}: `busy_timeout_ms` out of range, got {n}"))?;

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
            Some(serde_json::Value::Number(_)) => {
                return Err(format!(
                    "{BAD}: `busy_timeout_ms` must be a whole number of milliseconds, got a \
                     fractional or exponent number"
                ));
            }
            Some(other) => {
                return Err(format!(
                    "{BAD}: `busy_timeout_ms` must be an integer, got {}",
                    json_type(other)
                ));
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

/// One-shot settings conversion runs before secret resolution, without opening a store.
pub(crate) struct SettingsMigration;

impl busbar_contract::abi::sdk::migrate::Migrate for SettingsMigration {
    fn migrate(
        mut settings: serde_json::Value,
        _from: &str,
    ) -> busbar_contract::abi::sdk::migrate::Migrated {
        let removed = settings
            .as_object_mut()
            .is_some_and(|object| object.remove("license_key").is_some());
        let mut migrated = busbar_contract::abi::sdk::migrate::Migrated::unchanged(settings);
        if removed {
            migrated
                .report
                .push("Removed obsolete license_key; SQLite does not use this setting.".into());
        }
        migrated
    }
}
