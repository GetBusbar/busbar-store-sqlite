// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native historical rows for automatic pre-open migration.
//! Source cells remain uninterpreted; core owns every logical transformation.

use busbar_contract::{
    persistence::legacy_row::{self, Cell},
    redacted::Secret,
};
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use std::path::Path;

busbar_contract::own_seal!(Own);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Sqlite,
    UnsupportedVersion,
    UnsupportedShape,
    InvalidLimits,
    InvalidCursor,
    RowTooLarge,
    Allocation,
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Sqlite
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Column {
    pub name: String,
    pub declared_type: String,
    pub not_null: bool,
    pub primary_key_ordinal: u32,
}
#[derive(Clone, Debug)]
pub(crate) struct Table {
    pub name: String,
    pub columns: Vec<Column>,
}
pub(crate) struct Limits {
    pub rows: usize,
    pub bytes: usize,
}
pub(crate) struct SourceRow {
    pub identity: Secret<Vec<u8>, Own>,
    pub value: Secret<Vec<u8>, Own>,
}
pub(crate) struct Page {
    pub rows: Vec<SourceRow>,
    pub exhausted: bool,
}
pub(crate) struct Snapshot {
    conn: Connection,
    version: i64,
    tables: Vec<Table>,
}

impl Snapshot {
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        Self::open_guarded(path, &[])
    }
    fn open_guarded(path: &Path, admitted_tables: &[&str]) -> Result<Self, Error> {
        // URI interpretation is disabled: a path cannot inject immutable=1.
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN DEFERRED;")?;
        // This first read pins the WAL snapshot before any metadata is inspected.
        let version = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 6..=9) {
            return Err(Error::UnsupportedVersion);
        }
        let expected = if version == 6 { V6 } else { DEV };
        let mut stmt = conn.prepare("SELECT name FROM sqlite_schema WHERE type IN ('table','view') AND name NOT GLOB 'sqlite_*' ORDER BY name LIMIT 33")?;
        let mut names = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        names.retain(|name| !admitted_tables.contains(&name.as_str()));
        if names.len() != expected.len() {
            return Err(Error::UnsupportedShape);
        }
        let mut tables = Vec::new();
        for (name, (expected_name, signature)) in names.into_iter().zip(expected) {
            if name != *expected_name {
                return Err(Error::UnsupportedShape);
            }
            let mut query = conn.prepare(&format!("PRAGMA table_xinfo({})", quote(&name)))?;
            let columns = query
                .query_map([], |r| {
                    Ok((
                        Column {
                            name: r.get(1)?,
                            declared_type: r.get(2)?,
                            not_null: r.get(3)?,
                            primary_key_ordinal: r.get(5)?,
                        },
                        r.get::<_, u32>(6)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if columns.len() > 32 || columns.iter().any(|(_, hidden)| *hidden != 0) {
                return Err(Error::UnsupportedShape);
            }
            let columns: Vec<_> = columns.into_iter().map(|(c, _)| c).collect();
            let actual = columns
                .iter()
                .map(|c| {
                    format!(
                        "{}:{}:{}:{}",
                        c.name,
                        c.declared_type,
                        u8::from(c.not_null),
                        c.primary_key_ordinal
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            if actual != *signature {
                return Err(Error::UnsupportedShape);
            }
            // Keyset comparisons use native PK order. Refuse alternate primary
            // collations/directions that would require a whole-table sort or
            // make an identity non-unique under our binary comparison.
            let mut indexes = conn.prepare(&format!("PRAGMA index_list({})", quote(&name)))?;
            let indexes = indexes
                .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(3)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            for (index, origin) in indexes {
                if origin != "pk" {
                    continue;
                }
                let mut info = conn.prepare(&format!("PRAGMA index_xinfo({})", quote(&index)))?;
                let mut info = info.query([])?;
                while let Some(row) = info.next()? {
                    let key: bool = row.get(5)?;
                    if key && (row.get::<_, bool>(3)? || row.get::<_, String>(4)? != "BINARY") {
                        return Err(Error::UnsupportedShape);
                    }
                }
            }
            tables.push(Table { name, columns });
        }
        drop(stmt);
        Ok(Self {
            conn,
            version,
            tables,
        })
    }
    pub(crate) fn source_version(&self) -> i64 {
        self.version
    }
    pub(crate) fn tables(&self) -> &[Table] {
        &self.tables
    }

    /// Caller-owned native PK cursor, valid within this retained snapshot. The
    /// coordinator must fence the source before resuming across opens. Both row
    /// values and identities count against the output byte budget.
    pub(crate) fn page(
        &self,
        table: usize,
        after: Option<&Secret<Vec<u8>, Own>>,
        limits: Limits,
    ) -> Result<Page, Error> {
        self.page_matching(table, after, limits, None, false)
    }
    fn page_matching(
        &self,
        table: usize,
        after: Option<&Secret<Vec<u8>, Own>>,
        limits: Limits,
        prefix: Option<&Secret<Vec<u8>, Own>>,
        exact: bool,
    ) -> Result<Page, Error> {
        if limits.rows == 0
            || limits.rows > 4096
            || limits.bytes == 0
            || limits.bytes > 64 * 1024 * 1024
        {
            return Err(Error::InvalidLimits);
        }
        let table_meta = self.tables.get(table).ok_or(Error::UnsupportedShape)?;
        let mut pk: Vec<_> = table_meta
            .columns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.primary_key_ordinal != 0)
            .collect();
        pk.sort_by_key(|(_, c)| c.primary_key_ordinal);
        let keys = pk
            .iter()
            .map(|(_, c)| format!("{} COLLATE BINARY", quote(&c.name)))
            .collect::<Vec<_>>()
            .join(",");
        let cursor = after
            .map(|c| {
                legacy_row::Row::decode(c.expose_own(&Own::here()))
                    .map_err(|_| Error::InvalidCursor)
            })
            .transpose()?;
        let mut bindings = cursor
            .map(|c| c.cells().map(value).collect::<Vec<_>>())
            .unwrap_or_default();
        if after.is_some()
            && (bindings.len() != pk.len()
                || bindings.iter().zip(&pk).any(|(v, (_, c))| {
                    !matches!(
                        (v, c.declared_type.as_str()),
                        (ValueRef::Integer(_), "INTEGER")
                            | (ValueRef::Text(_), "TEXT")
                            | (ValueRef::Blob(_), "BLOB")
                    )
                }))
        {
            return Err(Error::InvalidCursor);
        }
        let prefix_row = prefix
            .map(|p| {
                legacy_row::Row::decode(p.expose_own(&Own::here()))
                    .map_err(|_| Error::InvalidCursor)
            })
            .transpose()?;
        let prefix_bindings = prefix_row
            .map(|r| r.cells().map(value).collect::<Vec<_>>())
            .unwrap_or_default();
        if prefix.is_some()
            && (prefix_bindings.is_empty()
                || prefix_bindings.len() > pk.len()
                || (exact && prefix_bindings.len() != pk.len())
                || prefix_bindings.iter().zip(&pk).any(|(v, (_, c))| {
                    !matches!(
                        (v, c.declared_type.as_str()),
                        (ValueRef::Integer(_), "INTEGER")
                            | (ValueRef::Text(_), "TEXT")
                            | (ValueRef::Blob(_), "BLOB")
                    )
                }))
        {
            return Err(Error::InvalidCursor);
        }
        if after.is_some() && prefix_bindings.iter().zip(&bindings).any(|(a, b)| a != b) {
            return Err(Error::InvalidCursor);
        }
        let mut predicates = Vec::new();
        if !bindings.is_empty() {
            let placeholders = (0..pk.len()).map(|_| "?").collect::<Vec<_>>().join(",");
            predicates.push(format!("({keys}) > ({placeholders})"));
        }
        for (_, column) in pk.iter().take(prefix_bindings.len()) {
            predicates.push(format!("{} COLLATE BINARY IS ?", quote(&column.name)));
        }
        bindings.extend(prefix_bindings);
        let predicate = if predicates.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", predicates.join(" AND "))
        };
        let sql = format!(
            "SELECT {} FROM {}{predicate} ORDER BY {keys} LIMIT {}",
            table_meta
                .columns
                .iter()
                .map(|c| quote(&c.name))
                .collect::<Vec<_>>()
                .join(","),
            quote(&table_meta.name),
            limits.rows + 1
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut source = stmt.query(rusqlite::params_from_iter(
            bindings.into_iter().map(Binding),
        ))?;
        let mut rows = Vec::new();
        let mut remaining = limits.bytes;
        let mut exhausted = true;
        while let Some(row) = source.next()? {
            if rows.len() == limits.rows {
                exhausted = false;
                break;
            }
            let cells = (0..table_meta.columns.len())
                .map(|i| row.get_ref(i).map(cell))
                .collect::<Result<Vec<_>, _>>()?;
            let encoded = match legacy_row::encode::<Own>(&cells, remaining) {
                Ok(row) => row,
                Err(legacy_row::Error::Budget) if !rows.is_empty() => {
                    exhausted = false;
                    break;
                }
                Err(legacy_row::Error::Budget) => return Err(Error::RowTooLarge),
                Err(_) => return Err(Error::Allocation),
            };
            let key_cells = pk.iter().map(|(i, _)| cells[*i]).collect::<Vec<_>>();
            if key_cells.iter().any(|c| matches!(c, Cell::Null)) {
                return Err(Error::UnsupportedShape);
            }
            let value_len = encoded.expose_own(&Own::here()).len();
            let identity = match legacy_row::encode::<Own>(&key_cells, remaining - value_len) {
                Ok(identity) => identity,
                Err(legacy_row::Error::Budget) if !rows.is_empty() => {
                    exhausted = false;
                    break;
                }
                Err(legacy_row::Error::Budget) => return Err(Error::RowTooLarge),
                Err(_) => return Err(Error::Allocation),
            };
            remaining -= value_len + identity.expose_own(&Own::here()).len();
            rows.push(SourceRow {
                identity,
                value: encoded,
            });
        }
        Ok(Page { rows, exhausted })
    }
}
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
fn cell(value: ValueRef<'_>) -> Cell<'_> {
    match value {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(v) => Cell::Integer(v),
        ValueRef::Real(v) => Cell::RealBits(v.to_bits()),
        ValueRef::Text(v) => Cell::Text(v),
        ValueRef::Blob(v) => Cell::Blob(v),
    }
}
// Borrow guarded cursor bytes directly; Value would duplicate text/blob keys.
struct Binding<'a>(ValueRef<'a>);
impl rusqlite::ToSql for Binding<'_> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::Borrowed(self.0))
    }
}
fn value(cell: Cell<'_>) -> ValueRef<'_> {
    match cell {
        Cell::Null => ValueRef::Null,
        Cell::Integer(v) => ValueRef::Integer(v),
        Cell::RealBits(v) => ValueRef::Real(f64::from_bits(v)),
        Cell::Text(v) => ValueRef::Text(v),
        Cell::Blob(v) => ValueRef::Blob(v),
    }
}

// Names, ordinal types, nullability and PK order are the physical schema fence.
// v6 comes from the real 1.5.5 capture. v7/8/9 share physical columns; only core
// chooses the accounting decoder using the retained source_version.
const V6: &[(&str, &str)] = &[
    ("audit_log", "seq:INTEGER:0:1,ts:INTEGER:1:0,action:TEXT:1:0,resource:TEXT:1:0,outcome:TEXT:1:0,principal:TEXT:1:0,prev_hash:TEXT:1:0,hash:TEXT:1:0"),
    ("credentials", "id:TEXT:1:1,key_id:TEXT:1:0,kind:TEXT:1:0,slot:INTEGER:1:0,public_id:TEXT:1:0,secret:TEXT:0:0,secret_form:TEXT:1:0,created_at:INTEGER:1:0,updated_at:INTEGER:1:0,expires_at:INTEGER:0:0,revoked_at:INTEGER:0:0,revoke_reason:TEXT:0:0,revision:INTEGER:1:0"),
    ("denylist", "sub:TEXT:1:1,reason:TEXT:1:0,created_at:INTEGER:1:0"),
    ("keys", "id:TEXT:1:1,name:TEXT:1:0,key_group:TEXT:0:0,allowed_pools:TEXT:0:0,labels:TEXT:1:0,enabled:INTEGER:1:0,generation_hash:TEXT:1:0,created_at:INTEGER:1:0,updated_at:INTEGER:1:0,expires_at:INTEGER:0:0,deleted_at:INTEGER:0:0,revision:INTEGER:1:0"),
    ("store_meta", "k:TEXT:1:1,v:TEXT:1:0"),
    ("store_revision", "id:INTEGER:1:1,revision:INTEGER:1:0"),
    ("usage_metering", "bucket:TEXT:1:1,key_id:TEXT:1:2,provider:TEXT:1:3,model:TEXT:1:4,key_group_at_use:TEXT:1:0,pricing_version:TEXT:1:0,requests:INTEGER:1:0,billable_requests:INTEGER:1:0,tokens_input:INTEGER:1:0,tokens_output:INTEGER:1:0,tokens_cache_read:INTEGER:1:0,tokens_cache_write:INTEGER:1:0"),
    ("usage_windows", "window_start:INTEGER:1:1,bucket_id:TEXT:1:2,model:TEXT:1:3,requests:INTEGER:1:0,billable_requests:INTEGER:1:0,tokens_input:INTEGER:1:0,tokens_output:INTEGER:1:0,tokens_cache_read:INTEGER:1:0,tokens_cache_write:INTEGER:1:0"),
];
const DEV: &[(&str, &str)] = &[
    ("audit_log", "seq:INTEGER:0:1,ts:INTEGER:1:0,action:TEXT:1:0,resource:TEXT:1:0,outcome:TEXT:1:0,principal:TEXT:1:0,prev_hash:TEXT:1:0,hash:TEXT:1:0"),
    ("credentials", "id:TEXT:1:1,key_id:TEXT:1:0,kind:TEXT:1:0,slot:INTEGER:1:0,public_id:TEXT:1:0,secret:TEXT:0:0,secret_form:TEXT:1:0,created_at:INTEGER:1:0,updated_at:INTEGER:1:0,expires_at:INTEGER:0:0,revoked_at:INTEGER:0:0,revoke_reason:TEXT:0:0,revision:INTEGER:1:0"),
    ("denylist", "sub:TEXT:1:1,reason:TEXT:1:0,created_at:INTEGER:1:0"),
    ("keys", "id:TEXT:1:1,name:TEXT:1:0,key_group:TEXT:0:0,allowed_pools:TEXT:0:0,labels:TEXT:1:0,enabled:INTEGER:1:0,generation_hash:TEXT:1:0,created_at:INTEGER:1:0,updated_at:INTEGER:1:0,expires_at:INTEGER:0:0,deleted_at:INTEGER:0:0,revision:INTEGER:1:0,scope_grants:TEXT:0:0,idp_subject:TEXT:0:0,binding_mode:TEXT:0:0,minted_by:TEXT:0:0,idp_provider:TEXT:0:0"),
    ("plane_records", "kind:TEXT:1:1,identity:TEXT:1:2,seq:INTEGER:1:3,id:TEXT:1:0,parent:TEXT:0:0,ts:INTEGER:1:0,disposition:TEXT:1:0,body:BLOB:1:0"),
    ("plane_tokens", "kind:TEXT:1:1,token:TEXT:1:2,expires_at:INTEGER:1:0"),
    ("schema_records", "schema:TEXT:1:1,record_key:BLOB:1:2,value:BLOB:1:0"),
    ("store_meta", "k:TEXT:1:1,v:TEXT:1:0"),
    ("store_ops", "op_id:BLOB:1:1,body:TEXT:1:0,answer:TEXT:1:0,recorded_at:INTEGER:1:0"),
    ("store_revision", "id:INTEGER:1:1,revision:INTEGER:1:0"),
    ("usage_metering", "bucket:TEXT:1:1,key_id:TEXT:1:2,provider:TEXT:1:3,model:TEXT:1:4,key_group_at_use:TEXT:1:6,pricing_version:TEXT:1:7,requests:INTEGER:1:0,billable_requests:INTEGER:1:0,tokens_input:INTEGER:1:0,tokens_output:INTEGER:1:0,tokens_cache_read:INTEGER:1:0,tokens_cache_write:INTEGER:1:0,priced_from_ms:INTEGER:1:5"),
    ("usage_metering_exact", "bucket:TEXT:1:1,key_id:TEXT:1:2,provider:TEXT:1:3,model:TEXT:1:4,priced_from_ms:INTEGER:1:5,key_group_at_use:TEXT:1:6,pricing_version:TEXT:1:7,ledger:BLOB:1:0"),
    ("usage_metering_units", "bucket:TEXT:1:1,key_id:TEXT:1:2,provider:TEXT:1:3,model:TEXT:1:4,priced_from_ms:INTEGER:1:5,key_group_at_use:TEXT:1:6,pricing_version:TEXT:1:7,unit:TEXT:1:8,count:INTEGER:1:0"),
    ("usage_window_exact", "window_start:INTEGER:1:1,bucket_id:TEXT:1:2,ledger:BLOB:1:0"),
    ("usage_window_units", "window_start:INTEGER:1:1,bucket_id:TEXT:1:2,model:TEXT:1:3,unit:TEXT:1:4,count:INTEGER:1:0"),
    ("usage_windows", "window_start:INTEGER:1:1,bucket_id:TEXT:1:2,model:TEXT:1:3,requests:INTEGER:1:0,billable_requests:INTEGER:1:0,tokens_input:INTEGER:1:0,tokens_output:INTEGER:1:0,tokens_cache_read:INTEGER:1:0,tokens_cache_write:INTEGER:1:0"),
];

#[cfg(test)]
#[path = "tests/legacy_reader_tests.rs"]
mod tests;

#[path = "lifecycle_native.rs"]
pub(crate) mod native;
