// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the base op set ([`StoreSlots`]): the
//! `op_id`-carrying count batches and plane-record append, and a plane's kernel-held records. All
//! DURABLE: the state lives in the tables `SCHEMA` creates. It holds no money (counts x the rate
//! card, derived in busbar's core).
//!
//! DEDUPE (`abi::store` S1-S4): an `op_id` that APPLIED is recorded in `store_ops` with the op's
//! value fields and its answer, in the SAME `BEGIN IMMEDIATE` transaction as the op's effect: two
//! racing calls with one `op_id` apply once, and a replay after a restart answers the original. The
//! same value fields apply nothing; different ones are a conflict; a refusal rolls back and records
//! nothing. Records older than [`OP_ID_RETENTION_SECS`] are swept when a new one is recorded.

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult, Retention, UsageDelta,
    UsageLedger, VirtualKey,
};
use rusqlite::{params, Transaction};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

use crate::{
    add_metering_in, add_usage_in, append_plane_record_in, exec, now_secs, query_all, query_one,
    SqliteStore,
};

/// What an applied op answered, stored with it and replayed verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Answer {
    Done,
}

fn failed(e: RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

/// Whether `op` is new, a replay (its original answer), or a conflict, read inside `tx`.
enum Seen {
    New,
    Replay(Answer),
    Conflict,
}

fn seen(tx: &Transaction<'_>, op: OpId, body: &str) -> Result<Seen, RecordStoreError> {
    let row: Option<(String, String)> = query_one(
        tx,
        "SELECT body, answer FROM store_ops WHERE op_id=?1 AND recorded_at > ?2",
        params![op.0.as_slice(), retention_cutoff(now_secs())],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(match row {
        None => Seen::New,
        Some((b, answer)) if b == body => Seen::Replay(
            serde_json::from_str(&answer)
                .map_err(|e| RecordStoreError(format!("store_ops: unreadable answer: {e}")))?,
        ),
        Some(_) => Seen::Conflict,
    })
}

/// A row recorded at or before this is past its retention: never honoured, swept in time.
fn retention_cutoff(now: i64) -> i64 {
    now.saturating_sub(OP_ID_RETENTION_SECS as i64)
}

/// Ops recorded between retention sweeps.
const SWEEP_EVERY: u64 = 256;

/// Remember an APPLIED op; every [`SWEEP_EVERY`]th one also forgets the ops past their retention
/// (`seen` already ignores them, so the sweep only reclaims space).
fn record(
    tx: &Transaction<'_>,
    op: OpId,
    body: &str,
    answer: &Answer,
    sweep: bool,
) -> Result<(), RecordStoreError> {
    let now = now_secs();
    if sweep {
        exec(
            tx,
            "DELETE FROM store_ops WHERE recorded_at <= ?1",
            params![retention_cutoff(now)],
        )?;
    }
    let answer =
        serde_json::to_string(answer).map_err(|e| RecordStoreError(format!("store_ops: {e}")))?;
    exec(
        tx,
        "INSERT INTO store_ops (op_id, body, answer, recorded_at) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(op_id) DO UPDATE SET body=excluded.body, answer=excluded.answer, \
         recorded_at=excluded.recorded_at",
        params![op.0.as_slice(), body, answer, now],
    )
    .map(drop)
}

impl SqliteStore {
    /// Run one `op_id`-carrying write in ONE `BEGIN IMMEDIATE` transaction at FULL sync: a replay
    /// answers the original, a conflict applies nothing, and a new op runs `apply` and is recorded
    /// only if it applied. A refusal from `apply` rolls the transaction back.
    fn op(
        &self,
        op: OpId,
        body: &str,
        apply: impl FnOnce(&Transaction<'_>) -> OpResult<Answer>,
    ) -> OpResult<Answer> {
        let mut refusal = None;
        let ran = self.write(true, |tx| {
            match seen(tx, op, body)? {
                Seen::Replay(a) => return Ok(a),
                Seen::Conflict => refusal = Some(OpRefused::Conflict),
                Seen::New => match apply(tx) {
                    Ok(a) => {
                        let n = self.ops_recorded.fetch_add(1, Ordering::Relaxed);
                        record(tx, op, body, &a, n.is_multiple_of(SWEEP_EVERY))?;
                        return Ok(a);
                    }
                    Err(e) => refusal = Some(e),
                },
            }
            Err(RecordStoreError("op refused".into()))
        });
        ran.map_err(|e| refusal.unwrap_or_else(|| failed(e)))
    }
}

/// The slots' own bodies, answered Ready: the store is local-disk-bound and never pends.
impl SqliteStore {
    pub(crate) fn v3_append_plane_record_op(
        &self,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> OpResult<()> {
        let body = format!("append_plane_record:{record:?}");
        self.op(op, &body, |tx| {
            append_plane_record_in(tx, record).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    /// An upsert on `(schema, key)`; an EMPTY value removes the row (the host's strike), and
    /// removing a row that is not there is `Ok`.
    pub(crate) fn v3_record_put(
        &self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        self.write(false, |tx| {
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
        })
        .map_err(|e| e.0)
    }

    pub(crate) fn v3_record_get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        let value: Option<Vec<u8>> = query_one(
            &self.lock_reader(),
            "SELECT value FROM schema_records WHERE schema=?1 AND record_key=?2",
            params![schema, key],
            |r| r.get(0),
        )
        .map_err(|e| e.0)?;
        value.map(record_bytes).transpose()
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
        // A BLOB compares as memcmp, so a prefix is the key range [prefix, successor); a NULL end
        // (every byte `0xff`, or empty) is unbounded above.
        let rows: Vec<(Vec<u8>, Vec<u8>)> = query_all(
            &self.lock_reader(),
            "SELECT record_key, value FROM schema_records WHERE schema=?1 AND record_key >= ?2 \
             AND (?3 IS NULL OR record_key < ?3) ORDER BY record_key LIMIT ?4",
            params![schema, prefix, prefix_successor(prefix), i64::from(limit)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| e.0)?;
        rows.into_iter()
            .map(|(k, v)| Ok((k, record_bytes(v)?)))
            .collect()
    }

    pub(crate) fn v3_add_usage_batch(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> OpResult<()> {
        let body = format!("add_usage_batch:{cells:?}");
        self.op(op, &body, |tx| {
            for (bucket, window, delta) in cells {
                add_usage_in(tx, bucket, *window, delta).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        self.op(op, &body, |tx| {
            for d in deltas {
                add_metering_in(tx, d).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
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
    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    fn validate(settings: &[u8]) -> Result<(), String> {
        crate::door::Settings::parse(settings_str(settings)?).map(drop)
    }

    fn open(settings: &[u8], _host: Option<Host>) -> Result<Self, String> {
        crate::door::open(settings_str(settings)?)
    }

    ready! {
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
        list_metering => RecordStore::list_metering(bucket: u64) -> RecordStoreResult<Vec<MeteringRow>>;
        put_credential => RecordStore::put_credential(secret: &CredentialSecret) -> RecordStoreResult<()>;
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

/// A stored record's bytes as the contract's bounded record.
fn record_bytes(v: Vec<u8>) -> Result<RecordBytes, String> {
    RecordBytes::new(v).map_err(|n| format!("a stored record of {n} bytes is over the ceiling"))
}

/// The smallest byte string greater than every string `prefix` starts: the last byte that is not
/// `0xff` incremented, the rest dropped. `None` when there is none (every byte `0xff`, or empty).
fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let i = prefix.iter().rposition(|&b| b != 0xff)?;
    let mut end = prefix[..=i].to_vec();
    end[i] += 1;
    Some(end)
}

#[cfg(test)]
#[path = "tests/v3_tests.rs"]
mod tests;
