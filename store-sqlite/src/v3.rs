// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the base op set ([`StoreSlots`]): the
//! `op_id`-carrying count batches and plane-record append, and a plane's kernel-held records. All
//! DURABLE on a file: the state lives in the tables `SCHEMA` creates (a `:memory:` store keeps it
//! only for the life of the process). It holds no money (counts x the rate
//! card, derived in busbar's core).
//!
//! DEDUPE (`abi::store` S1-S4, [`Dedupe`]): an `op_id` that APPLIED is recorded in `store_ops` with
//! the op's body, in the SAME `BEGIN IMMEDIATE` transaction as the op's effect: two racing calls
//! with one `op_id` apply once, and a replay after a restart answers done. A refusal rolls back and
//! records nothing. Records older than [`OP_ID_RETENTION_SECS`] are swept when a new one is recorded.

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::column::{prefix_end, storable_i64};
use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Request};
use busbar_contract::abi::sdk::store::correction;
use busbar_contract::abi::sdk::store::dedupe::Dedupe;
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult, Retention, UsageDelta,
    UsageLedger, VirtualKey,
};
use rusqlite::{params, Transaction};
use std::sync::atomic::Ordering;

use crate::{
    add_metering_in, add_usage_in, append_plane_record_in, exec, metering_in, now_secs,
    put_usage_in, query_all, query_one, usage_in, verify_usage_in, SqliteStore,
    RESERVED_USAGE_REFUSAL,
};

fn failed(e: RecordStoreError) -> OpRefused {
    if e.0.starts_with("exact count: ") {
        OpRefused::Refused(e.0)
    } else {
        OpRefused::Failed(e.0)
    }
}

/// A value the columns cannot hold: nothing applied, the host may split or re-send.
fn refused(e: RecordStoreError) -> OpRefused {
    OpRefused::Refused(e.0)
}

/// The body recorded under `op` inside its retention, read inside `tx`.
fn recorded(tx: &Transaction<'_>, op: OpId) -> OpResult<Option<String>> {
    query_one(
        tx,
        "SELECT body FROM store_ops WHERE op_id=?1 AND recorded_at >= ?2",
        params![op.0.as_slice(), retention_cutoff(now_secs())],
        |r| r.get(0),
    )
    .map_err(failed)
}

/// A row recorded before this is past its retention: never honoured, swept in time. Both stamps are
/// whole seconds, so a row stamped exactly at the cutoff may be up to a second younger than
/// [`OP_ID_RETENTION_SECS`] and is still honoured: an `op_id` is remembered AT LEAST that long (S4).
fn retention_cutoff(now: i64) -> i64 {
    now.saturating_sub(OP_ID_RETENTION_SECS as i64)
}

/// Ops recorded between retention sweeps.
const SWEEP_EVERY: u64 = 256;

/// Remember an APPLIED op's body ([`Dedupe::body_hex`]: the column is TEXT); every [`SWEEP_EVERY`]th one also
/// forgets the ops past their retention (`recorded` already ignores them, so the sweep only
/// reclaims space). `answer` is written as the one answer older builds read back (`"Done"`).
fn record(tx: &Transaction<'_>, op: OpId, body: &str, sweep: bool) -> RecordStoreResult<()> {
    let now = now_secs();
    if sweep {
        exec(
            tx,
            "DELETE FROM store_ops WHERE recorded_at < ?1",
            params![retention_cutoff(now)],
        )?;
    }
    let changed = exec(
        tx,
        "INSERT INTO store_ops (op_id, body, answer, recorded_at) VALUES (?1, ?2, '\"Done\"', ?3) \
         ON CONFLICT(op_id) DO UPDATE SET body=excluded.body, recorded_at=excluded.recorded_at",
        params![op.0.as_slice(), body, now],
    )?;
    let receipt: Option<(String, String, i64)> = query_one(
        tx,
        "SELECT body, answer, recorded_at FROM store_ops WHERE op_id=?1",
        params![op.0.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if changed != 1
        || receipt
            .as_ref()
            .is_none_or(|(saved, answer, at)| saved != body || answer != "\"Done\"" || *at != now)
    {
        return Err(RecordStoreError(
            "sqlite: applied operation receipt was not recorded".into(),
        ));
    }
    Ok(())
}

impl SqliteStore {
    /// Run one `op_id`-carrying write deduped ([`Dedupe::run`]) in ONE `BEGIN IMMEDIATE`
    /// transaction at FULL sync. A refusal rolls the transaction back.
    fn op(
        &self,
        op: OpId,
        dedupe: Dedupe,
        apply: impl FnOnce(&Transaction<'_>) -> RecordStoreResult<()>,
    ) -> OpResult<()> {
        let mut refusal = None;
        let ran = self.write(true, |tx| {
            let mut tx = tx;
            dedupe
                .run(
                    &mut tx,
                    |tx| recorded(tx, op),
                    |tx, _| {
                        apply(tx).map_err(failed)?;
                        let n = self.ops_recorded.fetch_add(1, Ordering::Relaxed);
                        record(tx, op, &dedupe.body_hex(), n.is_multiple_of(SWEEP_EVERY))
                            .map_err(failed)
                    },
                )
                .map_err(|e| {
                    refusal = Some(e);
                    RecordStoreError("op refused".into())
                })
        });
        ran.map_err(|e| refusal.unwrap_or_else(|| failed(e)))
    }
}

/// An opaque record's exact optional BLOB value, read on the transaction's snapshot.
fn record_value(
    conn: &rusqlite::Connection,
    schema: &str,
    key: &[u8],
) -> RecordStoreResult<Option<Vec<u8>>> {
    query_one(
        conn,
        "SELECT value FROM schema_records WHERE schema=?1 AND record_key=?2",
        params![schema, key],
        |row| row.get(0),
    )
}

/// The legacy record PUT spelling: an empty value deletes; a nonempty value upserts.
fn put_record_in(
    tx: &Transaction<'_>,
    schema: &str,
    key: &[u8],
    value: &[u8],
) -> RecordStoreResult<()> {
    (if value.is_empty() {
        exec(
            tx,
            "DELETE FROM schema_records WHERE schema=?1 AND record_key=?2",
            params![schema, key],
        )
    } else {
        exec(
            tx,
            "INSERT INTO schema_records (schema, record_key, value) VALUES (?1, ?2, ?3) \
             ON CONFLICT(schema, record_key) DO UPDATE SET value=excluded.value",
            params![schema, key, value],
        )
    })
    .map(drop)
}

/// A raw BLOB-prefix selector with an exact byte length. SQLite lengths are nonnegative i64:
/// a larger checked platform length cannot match any row and is a legal empty range.
fn record_range(
    tx: &Transaction<'_>,
    schema: &str,
    prefix: &[u8],
    exact_key_length: u64,
    delete: bool,
) -> RecordStoreResult<bool> {
    let Ok(length) = i64::try_from(exact_key_length) else {
        return Ok(false);
    };
    let end = prefix_end(prefix);
    let upper = if end.is_some() {
        " AND record_key < ?4"
    } else {
        ""
    };
    let predicate = format!("schema=?1 AND length(record_key)=?2 AND record_key >= ?3{upper}");
    let sql = if delete {
        format!("DELETE FROM schema_records WHERE {predicate}")
    } else {
        format!("SELECT EXISTS(SELECT 1 FROM schema_records WHERE {predicate})")
    };
    let run = |values: &[&dyn rusqlite::ToSql]| {
        if delete {
            exec(tx, &sql, values).map(|changed| changed != 0)
        } else {
            query_one(tx, &sql, values, |row| row.get::<_, bool>(0))
                .map(|found| found.unwrap_or(false))
        }
    };
    match end {
        Some(end) => run(params![schema, length, prefix, end]),
        None => run(params![schema, length, prefix]),
    }
}

/// The slots' own bodies, answered Ready: the store is local-disk-bound and never pends.
impl SqliteStore {
    pub(crate) fn v3_append_plane_record_op(
        &self,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> OpResult<()> {
        storable_i64("append_plane_record", "seq", record.seq).map_err(refused)?;
        storable_i64("append_plane_record", "ts", record.ts).map_err(refused)?;
        self.op(op, Dedupe::append(record), |tx| {
            append_plane_record_in(tx, record)
        })
    }

    /// An upsert on `(schema, key)`; an EMPTY value removes the row (the host's strike), and
    /// removing a row that is not there is `Ok`.
    pub(crate) fn v3_record_put(
        &self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        self.write(false, |tx| put_record_in(tx, schema, key, value))
            .map_err(|e| e.0)
    }

    pub(crate) fn v3_record_get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        let value = record_value(&self.lock_reader(), schema, key).map_err(|e| e.0)?;
        value.map(|v| record_bytes(schema, v)).transpose()
    }

    /// Compare the complete pre-state, then commit every effect and the applied-only receipt in
    /// the existing FULL-sync BEGIN IMMEDIATE operation. A predicate miss forces rollback, but is
    /// a definitive decision rather than an operation-id body conflict. SQL/commit errors retain
    /// their ambiguous failure semantics: callers must replay this exact id and body.
    pub(crate) fn v3_record_transaction(&self, request: &Request) -> OpResult<Decision> {
        request
            .validate()
            .map_err(|reason| OpRefused::Refused(reason.into()))?;
        let mut condition_conflict = false;
        let result = self.op(request.op_id, Dedupe::record_transaction(request), |tx| {
            for predicate in &request.predicates {
                let actual = record_value(tx, &predicate.schema, &predicate.key)?;
                let matches = match &predicate.expected {
                    Expected::Absent => actual.is_none(),
                    Expected::Bytes(expected) => actual.as_ref() == Some(expected),
                };
                if !matches {
                    condition_conflict = true;

                    return Err(RecordStoreError(
                        "record transaction predicate conflict".into(),
                    ));
                }
            }
            for mutation in &request.mutations {
                match mutation {
                    Mutation::Put { schema, key, value } => put_record_in(tx, schema, key, value)?,
                    Mutation::Delete { schema, key } => put_record_in(tx, schema, key, &[])?,
                    Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => {
                        record_range(tx, schema, prefix, *exact_key_length, true)?;
                    }
                }
            }

            for mutation in &request.mutations {
                let applied = match mutation {
                    Mutation::Put { schema, key, value } => {
                        record_value(tx, schema, key)?.as_ref() == Some(value)
                    }
                    Mutation::Delete { schema, key } => record_value(tx, schema, key)?.is_none(),
                    Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => !record_range(tx, schema, prefix, *exact_key_length, false)?,
                };
                if !applied {
                    return Err(RecordStoreError(
                        "record transaction mutation was not applied".into(),
                    ));
                }
            }
            Ok(())
        });
        if condition_conflict {
            Ok(Decision::ConditionConflict)
        } else {
            result.map(|()| Decision::Applied)
        }
    }

    pub(crate) fn v3_record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let conn = self.lock_reader();
        let row = |r: &rusqlite::Row| Ok((r.get(0)?, r.get(1)?));
        let rows: Vec<(Vec<u8>, Vec<u8>)> = match prefix_end(prefix) {
            Some(end) => query_all(
                &conn,
                "SELECT record_key, value FROM schema_records WHERE schema=?1 AND record_key >= ?2 \
                 AND record_key < ?3 ORDER BY record_key LIMIT ?4",
                params![schema, prefix, end, i64::from(limit)],
                row,
            ),
            None => query_all(
                &conn,
                "SELECT record_key, value FROM schema_records WHERE schema=?1 AND record_key >= ?2 \
                 ORDER BY record_key LIMIT ?3",
                params![schema, prefix, i64::from(limit)],
                row,
            ),
        }
        .map_err(|e| e.0)?;
        rows.into_iter()
            .map(|(k, v)| Ok((k, record_bytes(schema, v)?)))
            .collect()
    }

    pub(crate) fn v3_purge_usage_before(&self, before: u64) -> RecordStoreResult<u64> {
        if before == 0 {
            return Ok(0);
        }

        // `window_start` is a `u64` stored by bit pattern: a cutoff inside the signed range is a
        // plain range seek on the `window_start`-led primary keys; one past it (stored negative)
        // takes every positive window and the negatives below it, in unsigned order.
        const OLD_SIGNED: &str = "window_start > 0 AND window_start < ?1";
        const OLD_WRAPPED: &str = "(window_start > 0 AND (?1 < 0 OR window_start < ?1)) \
            OR (window_start < 0 AND ?1 < 0 AND window_start < ?1)";
        let old = if i64::try_from(before).is_ok() {
            OLD_SIGNED
        } else {
            OLD_WRAPPED
        };
        self.write(true, |tx| {
            let count: Option<i64> = query_one(
                tx,
                &format!(
                    "SELECT count(*) FROM (SELECT window_start, bucket_id \
                    FROM usage_windows WHERE {old} UNION SELECT window_start, bucket_id \
                    FROM usage_window_exact WHERE {old})"
                ),
                params![before as i64],
                |r| r.get(0),
            )?;
            for table in ["usage_windows", "usage_window_units", "usage_window_exact"] {
                exec(
                    tx,
                    &format!("DELETE FROM {table} WHERE {old}"),
                    params![before as i64],
                )?;
            }
            Ok(count.unwrap_or(0) as u64)
        })
    }

    pub(crate) fn v3_add_usage_batch(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> OpResult<()> {
        let mut reserved = false;
        let result = self.op(op, Dedupe::usage(cells), |tx| {
            if cells
                .iter()
                .any(|(bucket, _, _)| correction::reserved_bucket(bucket))
            {
                reserved = true;
                return Err(RecordStoreError(RESERVED_USAGE_REFUSAL.into()));
            }
            cells
                .iter()
                .try_for_each(|(bucket, window, delta)| add_usage_in(tx, bucket, *window, delta))
        });
        if reserved {
            Err(OpRefused::Refused(RESERVED_USAGE_REFUSAL.into()))
        } else {
            result
        }
    }

    /// One serialized pre-state and one FULL-sync commit for all rows and the applied receipt.
    /// A lost commit answer is Failed: retain the immutable request and replay its id/body.
    pub(crate) fn v3_apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> OpResult<correction::Decision> {
        request
            .validate()
            .map_err(|reason| OpRefused::Refused(reason.into()))?;
        let dedupe = Dedupe::usage_correction(request);
        let mut normalized_request = request.clone();
        for row in &mut normalized_request.metering {
            row.normalize_scale6()
                .map_err(|e| OpRefused::Refused(e.to_string()))?;
        }
        for change in &mut normalized_request.usage {
            change
                .expected
                .normalize_scale6()
                .map_err(|e| OpRefused::Refused(e.to_string()))?;
            change
                .replacement
                .normalize_scale6()
                .map_err(|e| OpRefused::Refused(e.to_string()))?;
        }
        let request = &normalized_request;
        let mut conflict = false;
        let result = self.op(request.op_id, dedupe, |tx| {
            let live = query_one(
                tx,
                "SELECT EXISTS(SELECT 1 FROM keys WHERE id=?1 AND deleted_at IS NULL)",
                params![request.key_id],
                |row| row.get::<_, bool>(0),
            )?
            .unwrap_or(false);
            let mut metering = metering_in(tx, request.day_start)?;
            metering.retain(|row| row.key_id == request.key_id);
            correction::canonical_metering(&mut metering);
            let mut matches = live && metering == request.metering;
            for change in &request.usage {
                let mut actual =
                    usage_in(tx, &change.address.bucket_id, change.address.window_start)?;
                correction::canonical_ledger(&mut actual)
                    .map_err(|reason| RecordStoreError(reason.into()))?;
                matches &= actual == change.expected;
            }
            if !matches {
                conflict = true;
                return Err(RecordStoreError(
                    "usage correction condition conflict".into(),
                ));
            }
            for change in &request.usage {
                put_usage_in(
                    tx,
                    &change.address.bucket_id,
                    change.address.window_start,
                    &change.replacement,
                )?;
            }
            for change in &request.usage {
                verify_usage_in(
                    tx,
                    &change.address.bucket_id,
                    change.address.window_start,
                    &change.replacement,
                )?;
            }
            Ok(())
        });
        if conflict {
            Ok(correction::Decision::ConditionConflict)
        } else {
            result.map(|()| correction::Decision::Applied)
        }
    }

    pub(crate) fn v3_add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        for d in deltas {
            storable_i64("add_metering", "priced_from_ms", d.priced_from_ms).map_err(refused)?;
        }
        self.op(op, Dedupe::metering(deltas), |tx| {
            deltas.iter().try_for_each(|d| add_metering_in(tx, d))
        })
    }
}

/// Each listed slot answers `Step::Ready` over the body named before its argument list.
macro_rules! ready {
    ($($name:ident => $via:ident::$body:ident ($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {$(
        fn $name(&self, _: &mut Op<'_>, $($arg: $ty),*) -> Step<$ret> {
            Step::Ready($via::$body(self, $($arg),*))
        }
    )*};
}

/// The store v3 table over this store. The store never touches [`Op`]; the host runs it on its
/// bounded disk lane. The base op set is the [`RecordStore`] impl, one body each.
impl StoreSlots for SqliteStore {
    fn ephemeral(&self) -> Option<bool> {
        // Ask the actual opened connection, including temporary and memory URI databases.
        Some(self.lock_writer().path().is_none_or(str::is_empty))
    }

    const RECORD_TRANSACTION: bool = true;
    const USAGE_CORRECTION: bool = true;

    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    fn validate(settings: &[u8]) -> Result<(), String> {
        crate::door::Settings::parse(settings_str(settings)?).map(drop)
    }

    fn open_with_secrets(
        settings: &[u8],
        _secrets: &[&[u8]],
        _host: Option<Host>,
    ) -> Result<Self, String> {
        crate::door::open(settings_str(settings)?)
    }

    ready! {
        apply_usage_correction => Self::v3_apply_usage_correction(request: &correction::Request) -> OpResult<correction::Decision>;
        record_transaction => Self::v3_record_transaction(request: &Request) -> OpResult<Decision>;
        append_plane_record_op => Self::v3_append_plane_record_op(op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()>;
        record_put => Self::v3_record_put(schema: &str, key: &[u8], value: &[u8]) -> Result<(), String>;
        record_get => Self::v3_record_get(schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String>;
        record_scan => Self::v3_record_scan(schema: &str, prefix: &[u8], limit: u32) -> Result<Scanned, String>;
        add_usage_batch => Self::v3_add_usage_batch(op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;
        add_metering_batch => Self::v3_add_metering_batch(op: OpId, deltas: &[MeteringDelta]) -> OpResult<()>;
        put_key => RecordStore::put_key(key: &VirtualKey) -> RecordStoreResult<()>;
        get_key => RecordStore::get_key(id: &str) -> RecordStoreResult<Option<VirtualKey>>;
        list_keys => RecordStore::list_keys() -> RecordStoreResult<Vec<VirtualKey>>;
        delete_key => RecordStore::delete_key(id: &str) -> RecordStoreResult<()>;
        list_keys_since => RecordStore::list_keys_since(since: u64) -> RecordStoreResult<Vec<VirtualKey>>;
        get_usage => RecordStore::get_usage(bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger>;
        put_usage => RecordStore::put_usage(bucket_id: &str, window_start: u64, ledger: &UsageLedger) -> RecordStoreResult<()>;
        purge_usage_before => Self::v3_purge_usage_before(before: u64) -> RecordStoreResult<u64>;
        list_metering => RecordStore::list_metering(bucket: u64) -> RecordStoreResult<Vec<MeteringRow>>;
        put_credential => RecordStore::put_credential(secret: &CredentialSecret) -> RecordStoreResult<()>;
        rewrap_credential => RecordStore::rewrap_credential(expected: &CredentialSecret, replacement: &str) -> RecordStoreResult<bool>;
        put_key_with_credential => RecordStore::put_key_with_credential(key: &VirtualKey, secret: &CredentialSecret) -> RecordStoreResult<()>;
        list_credentials => RecordStore::list_credentials(key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>>;
        revoke_credential => RecordStore::revoke_credential(id: &str, reason: &str) -> RecordStoreResult<()>;
        list_credentials_since => RecordStore::list_credentials_since(since: u64) -> RecordStoreResult<Vec<CredentialSecret>>;
        list_audit => RecordStore::list_audit() -> RecordStoreResult<Vec<AuditRecord>>;
        add_denylist => RecordStore::add_denylist(sub: &str, reason: &str) -> RecordStoreResult<()>;
        list_denylist => RecordStore::list_denylist() -> RecordStoreResult<Vec<String>>;
        list_audit_tail => RecordStore::list_audit_tail(limit: u64) -> RecordStoreResult<Vec<AuditRecord>>;
        upsert_plane_record => RecordStore::upsert_plane_record(record: PlaneRecordRef<'_>) -> RecordStoreResult<()>;
        get_plane_record => RecordStore::get_plane_record(kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>>;
        list_plane_records => RecordStore::list_plane_records(kind: &str, selector: &PlaneSelector<'_>) -> RecordStoreResult<Vec<Vec<u8>>>;
        list_plane_record_parents => RecordStore::list_plane_record_parents(kind: &str) -> RecordStoreResult<Vec<String>>;
        purge_plane_records_before => RecordStore::purge_plane_records_before(kind: &str, before: u64) -> RecordStoreResult<u64>;
        purge_plane_records => RecordStore::purge_plane_records(kind: &str, before: u64, retention: Retention) -> RecordStoreResult<u64>;
        delete_plane_record => RecordStore::delete_plane_record(kind: &str, id: &str) -> RecordStoreResult<()>;
        redeem_plane_token => RecordStore::redeem_plane_token(kind: &str, token: &str, expires_at: u64, now: u64) -> RecordStoreResult<bool>;
        plane_token_live => RecordStore::plane_token_live(kind: &str, token: &str, expires_at: u64, now: u64) -> RecordStoreResult<bool>;
    }
}

/// The operator's settings as the text the door's parser reads.
fn settings_str(settings: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(settings)
        .map_err(|e| format!("invalid sqlite plugin config: not UTF-8: {e}"))
}

/// A stored record's bytes as the contract's bounded record. The refusal names the schema and the
/// size, which find the row (`length(value)`) without echoing its key or value.
fn record_bytes(schema: &str, v: Vec<u8>) -> Result<RecordBytes, String> {
    RecordBytes::new(v).map_err(|n| {
        format!("sqlite: a stored record of {n} bytes in schema '{schema}' is over the ceiling")
    })
}

#[cfg(test)]
#[path = "tests/v3_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/conditional_records.rs"]
mod conditional_tests;

#[cfg(test)]
#[path = "tests/usage_correction.rs"]
mod correction_tests;
