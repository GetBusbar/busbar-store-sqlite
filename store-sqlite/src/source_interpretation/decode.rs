// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SQLite's admitted historical column/type/unit interpretation.
use busbar_contract::persistence::legacy_row::{Cell, Row};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, MeteringRow, ModelTokens, ScopeRef, SecretForm, UsageLedger,
    VirtualKey, RESERVED_UNITS,
};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Profile {
    Released6,
    Dev7,
    Dev8,
    Dev9,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Columns,
    Type,
    Range,
    Invalid,
    Unsupported,
}

/// Credential bytes remain borrowed from the reader's wiping custody. In
/// particular a revoked historical envelope is evidence, not a new live secret.
pub struct Credential<'a> {
    pub meta: CredentialMeta,
    pub envelope: Option<&'a [u8]>,
}

/// One admitted usage fragment with explicit request-counter semantics.
#[derive(Debug)]
pub struct UsageCell {
    pub bucket: String,
    pub window: u64,
    pub model: String,
    pub sum_requests: bool,
    pub ledger: UsageLedger,
}

pub enum HistoricalRow<'a> {
    Key {
        key: VirtualKey,
        updated_at: Option<u64>,
    },
    Credential(Credential<'a>),
    Denied {
        subject: String,
        reason: String,
        created_at: u64,
    },
    Revision(u64),
    ExactUsage {
        bucket: String,
        window: u64,
        ledger: UsageLedger,
    },
    /// Development candidates and old receipts cannot be submitted using a new
    /// execution identity. Preserve the original frame in a separate archive.
    Opaque {
        table: String,
        original: Row<'a>,
    },
    MeteringUnit {
        bucket: u64,
        key_id: String,
        provider: String,
        model: String,
        priced_from_ms: u64,
        key_group_at_use: Option<String>,
        pricing_version: Option<String>,
        unit: String,
        count: i128,
    },
    UsageUnit {
        bucket: String,
        window: u64,
        model: String,
        unit: String,
        count: i128,
    },
    Usage(UsageCell),
    Metering {
        bucket: u64,
        row: MeteringRow,
    },
    /// The original encoded physical row must also be retained as the immutable
    /// preimage. Parsing never recomputes its hash or signs a replacement event.
    Audit(AuditRecord),
    Meta {
        name: &'a [u8],
        value: &'a [u8],
    },
}

const KEYS: &[&str] = &[
    "id",
    "name",
    "key_group",
    "allowed_pools",
    "labels",
    "enabled",
    "generation_hash",
    "created_at",
    "updated_at",
    "expires_at",
    "deleted_at",
    "revision",
];
const CREDENTIALS: &[&str] = &[
    "id",
    "key_id",
    "kind",
    "slot",
    "public_id",
    "secret",
    "secret_form",
    "created_at",
    "updated_at",
    "expires_at",
    "revoked_at",
    "revoke_reason",
    "revision",
];
const USAGE: &[&str] = &[
    "window_start",
    "bucket_id",
    "model",
    "requests",
    "billable_requests",
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];
const METERING: &[&str] = &[
    "bucket",
    "key_id",
    "provider",
    "model",
    "key_group_at_use",
    "pricing_version",
    "requests",
    "billable_requests",
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];
const AUDIT: &[&str] = &[
    "seq",
    "ts",
    "action",
    "resource",
    "outcome",
    "principal",
    "prev_hash",
    "hash",
];

struct Columns<'a, 'b> {
    unsigned: bool,
    decimal: bool,
    names: &'b [&'b str],
    values: Vec<Cell<'a>>,
}
impl<'a, 'b> Columns<'a, 'b> {
    fn new(
        unsigned: bool,
        names: &'b [&'b str],
        row: Row<'a>,
        expected: &[&str],
    ) -> Result<Self, Error> {
        if names.len() != expected.len()
            || row.cells().len() != names.len()
            || names
                .iter()
                .enumerate()
                .any(|(i, n)| !expected.contains(n) || names[..i].contains(n))
        {
            return Err(Error::Columns);
        }
        Ok(Self {
            unsigned,
            decimal: false,
            names,
            values: row.cells().collect(),
        })
    }
    fn cell(&self, name: &str) -> Cell<'a> {
        self.values[self
            .names
            .iter()
            .position(|n| *n == name)
            .expect("validated columns")]
    }
    fn bytes(&self, name: &str) -> Result<&'a [u8], Error> {
        match self.cell(name) {
            Cell::Text(v) | Cell::Blob(v) => Ok(v),
            _ => Err(Error::Type),
        }
    }
    fn text(&self, name: &str) -> Result<String, Error> {
        std::str::from_utf8(self.bytes(name)?)
            .map(str::to_owned)
            .map_err(|_| Error::Type)
    }
    fn optional_text(&self, name: &str) -> Result<Option<String>, Error> {
        if self.cell(name) == Cell::Null {
            Ok(None)
        } else {
            self.text(name).map(Some)
        }
    }
    fn uint(&self, name: &str) -> Result<u64, Error> {
        match self.cell(name) {
            Cell::Integer(v) if self.unsigned => Ok(u64::from_le_bytes(v.to_le_bytes())),
            Cell::Integer(v) => v.try_into().map_err(|_| Error::Range),
            Cell::Text(v) if self.decimal => std::str::from_utf8(v)
                .map_err(|_| Error::Type)?
                .parse()
                .map_err(|_| Error::Range),
            _ => Err(Error::Type),
        }
    }
    fn quantity(&self, name: &str) -> Result<i128, Error> {
        let value = match self.cell(name) {
            Cell::Text(v) if self.decimal => std::str::from_utf8(v)
                .map_err(|_| Error::Type)?
                .parse()
                .map_err(|_| Error::Range)?,
            Cell::Integer(_) => i128::from(self.uint(name)?),
            _ => return Err(Error::Type),
        };
        if value < 0 {
            return Err(Error::Range);
        }
        Ok(value)
    }
    fn revision(&self) -> Result<u64, Error> {
        match self.cell("revision") {
            Cell::Integer(v) => u64::try_from(v).map_err(|_| Error::Range),
            _ => Err(Error::Type),
        }
    }
    fn timestamp(&self, name: &str) -> Result<u64, Error> {
        match self.cell(name) {
            Cell::Integer(v) => Ok(u64::from_le_bytes(v.to_le_bytes())),
            _ => Err(Error::Type),
        }
    }
    fn optional_timestamp(&self, name: &str) -> Result<Option<u64>, Error> {
        if self.cell(name) == Cell::Null {
            Ok(None)
        } else {
            self.timestamp(name).map(Some)
        }
    }
    fn boolean(&self, name: &str) -> Result<bool, Error> {
        match self.uint(name)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Invalid),
        }
    }
    fn tokens(&self) -> Result<BTreeMap<String, i128>, Error> {
        let mut values = BTreeMap::new();
        for (column, unit) in [
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_write",
        ]
        .into_iter()
        .zip(RESERVED_UNITS)
        {
            values.insert(unit.to_owned(), self.quantity(column)?);
        }
        Ok(values)
    }
}

pub fn decode<'a>(
    profile: Profile,
    table: &str,
    columns: &[&str],
    row: Row<'a>,
) -> Result<HistoricalRow<'a>, Error> {
    let key_table = "keys";
    let development = profile != Profile::Released6;
    let scale = if matches!(profile, Profile::Dev8 | Profile::Dev9) {
        6
    } else {
        0
    };
    if development
        && matches!(
            table,
            "store_ops" | "schema_records" | "plane_records" | "plane_tokens"
        )
    {
        let expected: &[&str] = match table {
            "store_ops" => &["op_id", "body", "answer", "recorded_at"],
            "schema_records" => &["schema", "record_key", "value"],
            "plane_tokens" => &["kind", "token", "expires_at"],
            _ => &[
                "kind",
                "identity",
                "seq",
                "id",
                "parent",
                "ts",
                "disposition",
                "body",
            ],
        };
        Columns::new(false, columns, row, expected)?;
        return Ok(HistoricalRow::Opaque {
            table: table.to_owned(),
            original: row,
        });
    }
    if development && matches!(table, "usage_window_exact" | "usage_metering_exact") {
        return exact_sqlite(profile, table, columns, row);
    }
    if matches!(profile, Profile::Dev7 | Profile::Dev8) && table == "usage_window_units" {
        let c = Columns::new(
            false,
            columns,
            row,
            &["window_start", "bucket_id", "model", "unit", "count"],
        )?;
        let count = busbar_contract::count::Count::from_stored(i128::from(c.uint("count")?), scale)
            .map_err(|_| Error::Range)?
            .micros();
        return Ok(HistoricalRow::UsageUnit {
            bucket: c.text("bucket_id")?,
            window: c.timestamp("window_start")?,
            model: c.text("model")?,
            unit: c.text("unit")?,
            count,
        });
    }
    if profile == Profile::Dev9
        && matches!(
            table,
            "usage_windows" | "usage_metering" | "usage_window_units" | "usage_metering_units"
        )
    {
        return Err(Error::Unsupported);
    }
    if matches!(profile, Profile::Dev7 | Profile::Dev8) && table == "usage_metering_units" {
        let c = Columns::new(
            false,
            columns,
            row,
            &[
                "bucket",
                "key_id",
                "provider",
                "model",
                "priced_from_ms",
                "key_group_at_use",
                "pricing_version",
                "unit",
                "count",
            ],
        )?;
        let count = busbar_contract::count::Count::from_stored(i128::from(c.uint("count")?), scale)
            .map_err(|_| Error::Range)?
            .micros();
        let bucket = std::str::from_utf8(c.bytes("bucket")?)
            .map_err(|_| Error::Type)?
            .parse()
            .map_err(|_| Error::Invalid)?;
        return Ok(HistoricalRow::MeteringUnit {
            bucket,
            key_id: c.text("key_id")?,
            provider: c.text("provider")?,
            model: c.text("model")?,
            priced_from_ms: c.timestamp("priced_from_ms")?,
            key_group_at_use: Some(c.text("key_group_at_use")?),
            pricing_version: Some(c.text("pricing_version")?),
            unit: c.text("unit")?,
            count,
        });
    }
    let dev = development;
    let mut expected = if table == key_table {
        KEYS
    } else {
        match table {
            "credentials" => CREDENTIALS,
            "usage_windows" => USAGE,
            "usage_metering" => METERING,
            "audit_log" => AUDIT,
            "denylist" => &["sub", "reason", "created_at"],
            "store_revision" => &["id", "revision"],
            "store_meta" => &["k", "v"],
            _ => return Err(Error::Unsupported),
        }
    };
    let adjusted;
    if dev && table == key_table {
        adjusted = KEYS
            .iter()
            .copied()
            .chain([
                "scope_grants",
                "idp_subject",
                "binding_mode",
                "minted_by",
                "idp_provider",
            ])
            .collect::<Vec<_>>();
        expected = &adjusted;
    } else if dev && table == "usage_metering" {
        adjusted = METERING
            .iter()
            .copied()
            .chain(["priced_from_ms"])
            .collect::<Vec<_>>();
        expected = &adjusted;
    }
    let c = Columns::new(false, columns, row, expected)?;
    if table == key_table {
        let group = c.optional_text("key_group")?;
        let pools: Option<Vec<String>> = if c.cell("allowed_pools") == Cell::Null {
            None
        } else {
            Some(serde_json::from_slice(c.bytes("allowed_pools")?).map_err(|_| Error::Invalid)?)
        };
        let mut key = VirtualKey {
            id: c.text("id")?,
            generation_hash: c.text("generation_hash")?,
            name: c.text("name")?,
            allowed_scopes: pools.map(|v| v.into_iter().map(ScopeRef::pool).collect()),
            enabled: c.boolean("enabled")?,
            created_at: c.timestamp("created_at")?,
            group,
            labels: serde_json::from_slice(c.bytes("labels")?).map_err(|_| Error::Invalid)?,
            expires_at: c.optional_timestamp("expires_at")?,
            deleted_at: c.optional_timestamp("deleted_at")?,
            revision: c.revision()?,
            idp_subject: None,
            binding_mode: None,
            minted_by: None,
            idp_provider: None,
        };
        if dev {
            key.idp_subject = c.optional_text("idp_subject")?;
            key.binding_mode = c.optional_text("binding_mode")?;
            key.minted_by = c.optional_text("minted_by")?;
            key.idp_provider = c.optional_text("idp_provider")?;
            let scope_column = "scope_grants";
            if c.cell(scope_column) != Cell::Null {
                let ext: BTreeMap<String, Vec<String>> =
                    serde_json::from_slice(c.bytes(scope_column)?).map_err(|_| Error::Invalid)?;
                let scopes = key.allowed_scopes.get_or_insert_with(Vec::new);
                for (kind, values) in ext {
                    if kind == "pool" {
                        return Err(Error::Invalid);
                    }
                    for value in values {
                        if scopes.iter().any(|s| s.kind == kind && s.value == value) {
                            return Err(Error::Invalid);
                        }
                        scopes.push(ScopeRef {
                            kind: kind.clone(),
                            value,
                        });
                    }
                }
            }
        }
        if key.deleted_at.is_some() && key.enabled
            || key.expires_at.is_some_and(|v| v <= key.created_at)
        {
            return Err(Error::Invalid);
        }
        return Ok(HistoricalRow::Key {
            key,
            updated_at: Some(c.timestamp("updated_at")?),
        });
    }
    Ok(match table {
        "credentials" => {
            let form = match c.bytes("secret_form")? {
                b"none" => SecretForm::None,
                b"recoverable" => SecretForm::Recoverable,
                b"digest" => SecretForm::Digest,
                _ => return Err(Error::Invalid),
            };
            let envelope = if c.cell("secret") == Cell::Null {
                None
            } else {
                Some(c.bytes("secret")?)
            };
            let meta = CredentialMeta {
                id: c.text("id")?,
                key_id: c.text("key_id")?,
                kind: c.text("kind")?,
                slot: c.uint("slot")?.try_into().map_err(|_| Error::Range)?,
                public_id: c.text("public_id")?,
                secret_form: form,
                created_at: c.timestamp("created_at")?,
                updated_at: c.timestamp("updated_at")?,
                expires_at: c.optional_timestamp("expires_at")?,
                revoked_at: c.optional_timestamp("revoked_at")?,
                revoke_reason: c.optional_text("revoke_reason")?,
                revision: c.revision()?,
            };
            if meta.slot > 1
                || (form == SecretForm::None && envelope.is_some())
                || (form != SecretForm::None
                    && envelope.is_none()
                    && !(dev && meta.revoked_at.is_some()))
                || meta.revoke_reason.is_some() && meta.revoked_at.is_none()
                || meta.expires_at.is_some_and(|v| v <= meta.created_at)
            {
                return Err(Error::Invalid);
            }
            HistoricalRow::Credential(Credential { meta, envelope })
        }
        "usage_windows" => {
            let model = c.text("model")?;
            let mut ledger = UsageLedger {
                requests: c.uint("requests")?,
                billable_requests: c.uint("billable_requests")?,
                models: vec![],
            };
            let tokens = c.tokens()?;
            if model.is_empty() {
                if tokens.values().any(|v| *v != 0) {
                    return Err(Error::Invalid);
                }
            } else {
                if ledger.requests != 0 || ledger.billable_requests != 0 {
                    return Err(Error::Invalid);
                }
                ledger.models.push(ModelTokens {
                    scale,
                    model: model.clone(),
                    usage_units: tokens,
                });
            }
            ledger.normalize_scale6().map_err(|_| Error::Range)?;
            HistoricalRow::Usage(UsageCell {
                sum_requests: false,
                bucket: c.text("bucket_id")?,
                window: c.timestamp("window_start")?,
                model,
                ledger,
            })
        }
        "usage_metering" => {
            let bucket = std::str::from_utf8(c.bytes("bucket")?)
                .map_err(|_| Error::Type)?
                .parse::<u64>()
                .map_err(|_| Error::Invalid)?;
            let mut row = MeteringRow {
                scale,
                key_id: c.text("key_id")?,
                model: c.text("model")?,
                provider: c.text("provider")?,
                tokens_input: c.quantity("tokens_input")?,
                tokens_output: c.quantity("tokens_output")?,
                tokens_cache_read: c.quantity("tokens_cache_read")?,
                tokens_cache_write: c.quantity("tokens_cache_write")?,
                requests: c.uint("requests")?,
                billable_requests: c.uint("billable_requests")?,
                key_group_at_use: c.text("key_group_at_use")?,
                pricing_version: c.text("pricing_version")?,
                priced_from_ms: if dev {
                    c.timestamp("priced_from_ms")?
                } else {
                    0
                },
                usage_units: BTreeMap::new(),
            };
            row.normalize_scale6().map_err(|_| Error::Range)?;
            HistoricalRow::Metering { bucket, row }
        }
        "denylist" => HistoricalRow::Denied {
            subject: c.text("sub")?,
            reason: c.text("reason")?,
            created_at: c.timestamp("created_at")?,
        },
        "store_revision" => {
            let valid = c.uint("id")? == 0;
            if !valid {
                return Err(Error::Invalid);
            }
            HistoricalRow::Revision(c.revision()?)
        }
        "store_meta" => HistoricalRow::Meta {
            name: c.bytes("k")?,
            value: c.bytes("v")?,
        },
        "audit_log" => HistoricalRow::Audit(AuditRecord {
            seq: c.uint("seq")?,
            ts: c.timestamp("ts")?,
            action: c.text("action")?,
            resource: c.text("resource")?,
            outcome: c.text("outcome")?,
            principal: c.text("principal")?,
            prev_hash: c.text("prev_hash")?,
            hash: c.text("hash")?,
        }),
        _ => return Err(Error::Unsupported),
    })
}

fn exact_sqlite<'a>(
    profile: Profile,
    table: &str,
    columns: &[&str],
    row: Row<'a>,
) -> Result<HistoricalRow<'a>, Error> {
    let metering = table == "usage_metering_exact";
    let expected: &[&str] = if metering {
        &[
            "bucket",
            "key_id",
            "provider",
            "model",
            "priced_from_ms",
            "key_group_at_use",
            "pricing_version",
            "ledger",
        ]
    } else {
        &["window_start", "bucket_id", "ledger"]
    };
    let c = Columns::new(false, columns, row, expected)?;
    let Cell::Blob(bytes) = c.cell("ledger") else {
        return Err(Error::Type);
    };
    // Inspect field names only. Domain decoding below reads original bytes, so
    // large signed i128 mantissas never pass through JSON floating point values.
    let fields: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    let object = fields.as_object().ok_or(Error::Invalid)?;
    let known: &[&str] = if metering {
        &[
            "scale",
            "key_id",
            "model",
            "provider",
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_write",
            "requests",
            "billable_requests",
            "key_group_at_use",
            "pricing_version",
            "priced_from_ms",
            "usage_units",
        ]
    } else {
        &["requests", "billable_requests", "models"]
    };
    if object.keys().any(|name| !known.contains(&name.as_str())) {
        return Err(Error::Columns);
    }
    if metering {
        let mut value: MeteringRow = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if value.key_id != c.text("key_id")?
            || value.provider != c.text("provider")?
            || value.model != c.text("model")?
            || value.priced_from_ms != c.timestamp("priced_from_ms")?
            || value.key_group_at_use != c.text("key_group_at_use")?
            || value.pricing_version != c.text("pricing_version")?
        {
            return Err(Error::Invalid);
        }
        if profile != Profile::Dev7 && value.scale != 6 {
            return Err(Error::Invalid);
        }
        value.normalize_scale6().map_err(|_| Error::Range)?;
        let bucket = std::str::from_utf8(c.bytes("bucket")?)
            .map_err(|_| Error::Type)?
            .parse()
            .map_err(|_| Error::Invalid)?;
        Ok(HistoricalRow::Metering { bucket, row: value })
    } else {
        let models = object
            .get("models")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::Invalid)?;
        for model in models {
            if model
                .as_object()
                .ok_or(Error::Invalid)?
                .keys()
                .any(|name| !["scale", "model", "usage_units"].contains(&name.as_str()))
            {
                return Err(Error::Columns);
            }
        }
        let mut ledger: UsageLedger = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        let mut seen = std::collections::BTreeSet::new();
        if ledger.models.iter().any(|m| !seen.insert(m.model.as_str())) {
            return Err(Error::Invalid);
        }
        if profile != Profile::Dev7 && ledger.models.iter().any(|m| m.scale != 6) {
            return Err(Error::Invalid);
        }
        ledger.normalize_scale6().map_err(|_| Error::Range)?;
        Ok(HistoricalRow::ExactUsage {
            bucket: c.text("bucket_id")?,
            window: c.timestamp("window_start")?,
            ledger,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::{
        persistence::{
            archive::{self, Table},
            legacy_row,
            lifecycle::{source::HistoricalFact, SourceRow},
        },
        Secret,
    };
    busbar_contract::own_seal!(Owner);
    #[test]
    fn published_source_rows_keep_quantities_audit_hashes_and_original_evidence() {
        let bytes = include_bytes!("fixtures/sqlite-1.5.5-rows.json");
        let digest = archive::digest(bytes)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        assert_eq!(
            digest,
            "690e23fe2f209e2aabd132fa3ff4c694f22d3fb7dddc5bdcbccc9bf81c253869"
        );
        let data: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            data["credentials"].as_array().unwrap().len(),
            0,
            "the published fixture is not a nonempty credential witness"
        );
        let owner = Owner::here();
        for (name, columns) in [
            ("usage_windows", USAGE),
            ("usage_metering", METERING),
            ("audit_log", AUDIT),
            ("keys", KEYS),
        ] {
            let table = Table {
                name: name.into(),
                columns: columns.iter().map(|v| (*v).to_owned()).collect(),
                native_layout: vec![1],
            };
            for (index, original) in data[name].as_array().unwrap().iter().enumerate() {
                let cells = columns
                    .iter()
                    .map(|column| match &original[*column] {
                        serde_json::Value::Null => Cell::Null,
                        serde_json::Value::String(value) => Cell::Text(value.as_bytes()),
                        serde_json::Value::Number(value) => Cell::Integer(value.as_i64().unwrap()),
                        _ => panic!("recorded native type"),
                    })
                    .collect::<Vec<_>>();
                let value = legacy_row::encode::<Owner>(&cells, 65536).unwrap();
                let expected = archive::digest(value.expose_own(&owner));
                let row = SourceRow {
                    table: 0,
                    native_key: Secret::held(index.to_le_bytes().to_vec()),
                    value,
                };
                let chunk = super::super::interpret(6, &table, &row, 1024 * 1024, &owner).unwrap();
                assert_eq!(chunk.evidence[0].value_digest, expected);
                assert_eq!(chunk.evidence[0].native_key, row.native_key);
                match &chunk.facts[0] {
                    HistoricalFact::Usage { ledger, model, .. } => {
                        assert_eq!(ledger.requests, original["requests"].as_u64().unwrap());
                        if !model.is_empty() {
                            assert_eq!(
                                ledger.total_input(),
                                i128::from(original["tokens_input"].as_i64().unwrap()) * 1_000_000
                            );
                        }
                    }
                    HistoricalFact::Metering { row, .. } => assert_eq!(
                        row.tokens_input,
                        i128::from(original["tokens_input"].as_i64().unwrap()) * 1_000_000
                    ),
                    HistoricalFact::Audit(row) => {
                        assert_eq!(row.hash, original["hash"].as_str().unwrap());
                        assert_eq!(row.prev_hash, original["prev_hash"].as_str().unwrap());
                    }
                    HistoricalFact::Key { value, .. } => assert_eq!(
                        value.generation_hash,
                        original["generation_hash"].as_str().unwrap()
                    ),
                    _ => panic!("logical fact"),
                }
            }
        }
    }
    #[test]
    fn native_versions_declare_document_semantics_and_refuse_unknown_versions() {
        use busbar_contract::persistence::lifecycle::DocumentSemantics;
        assert_eq!(
            super::super::descriptor(6).unwrap().documents(),
            DocumentSemantics::Historical
        );
        for version in 7..=9 {
            assert_eq!(
                super::super::descriptor(version).unwrap().documents(),
                DocumentSemantics::Current
            );
        }
        assert!(super::super::descriptor(10).is_err());
    }
}

#[cfg(test)]
mod physical_regressions {
    use super::*;
    use busbar_contract::persistence::legacy_row;
    busbar_contract::own_seal!(Own);
    // Synthetic units; published fixtures do not contain nonempty credentials.
    fn with_row<T>(cells: &[Cell<'_>], f: impl FnOnce(Row<'_>) -> T) -> T {
        let encoded = legacy_row::encode::<Own>(cells, 4096).unwrap();
        f(Row::decode(encoded.expose_own(&Own::here())).unwrap())
    }
    #[test]
    fn synthetic_revoked_credential_keeps_exact_envelope_and_aad_identity() {
        let cells = [
            Cell::Text(b"credential-id"),
            Cell::Text(b"key-id"),
            Cell::Text(b"sigv4"),
            Cell::Integer(1),
            Cell::Text(b"public-id"),
            Cell::Text(b"v1:aead:key:nonce:ciphertext"),
            Cell::Text(b"recoverable"),
            Cell::Integer(1),
            Cell::Integer(3),
            Cell::Null,
            Cell::Integer(3),
            Cell::Text(b"rotated"),
            Cell::Integer(9),
        ];
        with_row(&cells, |row| {
            let HistoricalRow::Credential(value) =
                decode(Profile::Released6, "credentials", CREDENTIALS, row).unwrap()
            else {
                panic!()
            };
            assert_eq!(
                value.envelope,
                Some(b"v1:aead:key:nonce:ciphertext".as_slice())
            );
            assert_eq!(
                (
                    value.meta.id.as_str(),
                    value.meta.key_id.as_str(),
                    value.meta.kind.as_str(),
                    value.meta.public_id.as_str()
                ),
                ("credential-id", "key-id", "sigv4", "public-id")
            );
            assert_eq!(
                (value.meta.slot, value.meta.revoked_at, value.meta.revision),
                (1, Some(3), 9)
            );
        });
    }

    #[test]
    fn synthetic_usage_whole_units_convert_once_and_requests_do_not_scale() {
        let cells = [
            Cell::Integer(0),
            Cell::Text(b"bucket"),
            Cell::Text(b"m"),
            Cell::Integer(0),
            Cell::Integer(0),
            Cell::Integer(7),
            Cell::Integer(11),
            Cell::Integer(4),
            Cell::Integer(0),
        ];
        with_row(&cells, |row| {
            let HistoricalRow::Usage(value) =
                decode(Profile::Released6, "usage_windows", USAGE, row).unwrap()
            else {
                panic!()
            };
            assert_eq!(value.ledger.models[0].scale, 6);
            assert_eq!(value.ledger.total_input(), 7_000_000);
            let mut count_cells = cells;
            count_cells[2] = Cell::Text(b"");
            count_cells[3] = Cell::Integer(4);
            count_cells[4] = Cell::Integer(3);
            count_cells[5..].fill(Cell::Integer(0));
            with_row(&count_cells, |row| {
                let HistoricalRow::Usage(counts) =
                    decode(Profile::Released6, "usage_windows", USAGE, row).unwrap()
                else {
                    panic!()
                };
                assert_eq!(
                    (counts.ledger.requests, counts.ledger.billable_requests),
                    (4, 3)
                );
                assert!(!value.sum_requests && !counts.sum_requests);
            });
        });
    }

    #[test]
    fn unknown_missing_duplicate_columns_and_negative_counts_are_errors() {
        let cells = [
            Cell::Integer(0),
            Cell::Text(b"bucket"),
            Cell::Text(b"m"),
            Cell::Integer(0),
            Cell::Integer(0),
            Cell::Integer(-1),
            Cell::Integer(0),
            Cell::Integer(0),
            Cell::Integer(0),
        ];
        with_row(&cells, |row| {
            assert!(matches!(
                decode(Profile::Released6, "usage_windows", USAGE, row),
                Err(Error::Range)
            ));
            let mut columns = USAGE.to_vec();
            columns[8] = "unknown_scale";
            assert!(matches!(
                decode(Profile::Released6, "usage_windows", &columns, row),
                Err(Error::Columns)
            ));
            columns[8] = "model";
            assert!(matches!(
                decode(Profile::Released6, "usage_windows", &columns, row),
                Err(Error::Columns)
            ));
            assert!(matches!(
                decode(Profile::Released6, "usage_windows", &USAGE[..8], row),
                Err(Error::Columns)
            ));
        });
    }

    #[test]
    fn synthetic_dev_micro_columns_are_not_scaled_twice() {
        let cells = [
            Cell::Integer(0),
            Cell::Text(b"bucket"),
            Cell::Text(b"m"),
            Cell::Integer(0),
            Cell::Integer(0),
            Cell::Integer(7_000_001),
            Cell::Integer(0),
            Cell::Integer(0),
            Cell::Integer(0),
        ];
        with_row(&cells, |row| {
            let HistoricalRow::Usage(value) =
                decode(Profile::Dev8, "usage_windows", USAGE, row).unwrap()
            else {
                panic!()
            };
            assert_eq!(value.ledger.total_input(), 7_000_001);
            assert!(matches!(
                decode(Profile::Dev9, "usage_windows", USAGE, row),
                Err(Error::Unsupported)
            ));
        });
    }

    #[test]
    fn synthetic_exact_ledger_rejects_unknown_scale_fields_and_mismatched_identity() {
        let columns = ["window_start", "bucket_id", "ledger"];
        for json in [
        br#"{"requests":1,"billable_requests":1,"models":[{"scale":5,"model":"m","usage_units":{"input":7}}]}"#.as_slice(),
        br#"{"requests":1,"billable_requests":1,"models":[{"scale":6,"model":"m","usage_units":{"input":7},"unknown":0}]}"#.as_slice(),
        br#"{"requests":1,"billable_requests":1,"models":[{"model":"m","usage_units":{"input":7}}]}"#.as_slice(),
    ] {
        with_row(&[Cell::Integer(0),Cell::Text(b"b"),Cell::Blob(json)], |row| assert!(decode(Profile::Dev9,"usage_window_exact",&columns,row).is_err()));
    }
        let json = br#"{"requests":1,"billable_requests":1,"models":[{"scale":6,"model":"m","usage_units":{"input":170141183460469231731687303715884105}}]}"#;
        with_row(
            &[Cell::Integer(0), Cell::Text(b"b"), Cell::Blob(json)],
            |row| {
                let HistoricalRow::ExactUsage { ledger, .. } =
                    decode(Profile::Dev9, "usage_window_exact", &columns, row).unwrap()
                else {
                    panic!()
                };
                assert_eq!(ledger.total_input(), 170141183460469231731687303715884105);
            },
        );
    }

    #[test]
    fn synthetic_dev_receipts_remain_opaque_original_bytes() {
        let columns = ["op_id", "body", "answer", "recorded_at"];
        with_row(
            &[
                Cell::Blob(b"original-op"),
                Cell::Text(b"old-uncertain-candidate"),
                Cell::Text(b"unknown"),
                Cell::Integer(1),
            ],
            |row| {
                let HistoricalRow::Opaque { original, .. } =
                    decode(Profile::Dev8, "store_ops", &columns, row).unwrap()
                else {
                    panic!()
                };
                assert_eq!(
                    original.cells().nth(1),
                    Some(Cell::Text(b"old-uncertain-candidate"))
                );
            },
        );
    }

    #[test]
    fn synthetic_open_units_keep_exact_fraction_and_attribution() {
        let columns = ["window_start", "bucket_id", "model", "unit", "count"];
        with_row(
            &[
                Cell::Integer(0),
                Cell::Text(b"bucket"),
                Cell::Text(b"model"),
                Cell::Text(b"seconds"),
                Cell::Integer(7),
            ],
            |row| {
                let unit = decode(Profile::Dev8, "usage_window_units", &columns, row).unwrap();
                let HistoricalRow::UsageUnit {
                    bucket,
                    window,
                    model,
                    unit,
                    count,
                } = unit
                else {
                    panic!()
                };
                assert_eq!(
                    (
                        bucket.as_str(),
                        window,
                        model.as_str(),
                        unit.as_str(),
                        count
                    ),
                    ("bucket", 0, "model", "seconds", 7)
                );
            },
        );
    }

    #[test]
    fn synthetic_wide_timestamp_bits_are_preserved_separately_from_counts() {
        let cells = [
            Cell::Text(b"id"),
            Cell::Text(b"key"),
            Cell::Text(b"sigv4"),
            Cell::Integer(0),
            Cell::Text(b"public"),
            Cell::Text(b"v1:plain:secret"),
            Cell::Text(b"recoverable"),
            Cell::Integer(i64::MIN),
            Cell::Integer(i64::MIN),
            Cell::Integer(i64::MIN + 1),
            Cell::Null,
            Cell::Null,
            Cell::Integer(1),
        ];
        with_row(&cells, |row| {
            let HistoricalRow::Credential(value) =
                decode(Profile::Released6, "credentials", CREDENTIALS, row).unwrap()
            else {
                panic!()
            };
            assert_eq!(value.meta.created_at, 1u64 << 63);
            assert_eq!(value.meta.expires_at, Some((1u64 << 63) + 1));
            assert_eq!(value.envelope, Some(b"v1:plain:secret".as_slice()));
        });
    }
}
