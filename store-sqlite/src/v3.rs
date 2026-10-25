// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the 1.5.5 op set ([`StoreSlots`]): the
//! `op_id`-carrying count batches and plane-record append, and a plane's kernel-held records. Every
//! one is DURABLE: its state lives in the tables `SCHEMA` creates, on the writer connection. It
//! holds no money: money is counts x the rate card, derived in busbar's core.
//!
//! DEDUPE (`abi::store` S1-S4): an `op_id` that APPLIED is recorded in `store_ops` with the op's
//! value fields and its answer, in the SAME `BEGIN IMMEDIATE` transaction as the op's effect, so
//! the check, the effect and the record are one atomic step: two racing calls with one `op_id`
//! apply once, a crash between the effect and the record cannot happen, and a replay after a
//! restart answers the original. A replay with the same value fields applies nothing; different
//! value fields are a conflict; a refusal or a failure rolls back and records nothing. Records
//! older than [`OP_ID_RETENTION_SECS`] are swept when a new one is recorded.

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger,
    VirtualKey,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::{
    add_metering_in, add_usage_in, append_plane_record_in, now_secs, with_full_sync,
    IntoStoreResult, SqliteStore,
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
    let row: Option<(String, String)> = tx
        .query_row(
            "SELECT body, answer FROM store_ops WHERE op_id=?1",
            params![op.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .store()?;
    Ok(match row {
        None => Seen::New,
        Some((b, answer)) if b == body => Seen::Replay(
            serde_json::from_str(&answer)
                .map_err(|e| RecordStoreError(format!("store_ops: unreadable answer: {e}")))?,
        ),
        Some(_) => Seen::Conflict,
    })
}

/// Remember an APPLIED op, and forget every op past its retention.
fn record(
    tx: &Transaction<'_>,
    op: OpId,
    body: &str,
    answer: &Answer,
) -> Result<(), RecordStoreError> {
    let now = now_secs();
    tx.execute(
        "DELETE FROM store_ops WHERE recorded_at <= ?1",
        params![now.saturating_sub(OP_ID_RETENTION_SECS as i64)],
    )
    .store()?;
    let answer =
        serde_json::to_string(answer).map_err(|e| RecordStoreError(format!("store_ops: {e}")))?;
    tx.execute(
        "INSERT INTO store_ops (op_id, body, answer, recorded_at) VALUES (?1, ?2, ?3, ?4)",
        params![op.0.as_slice(), body, answer, now],
    )
    .store()
    .map(drop)
}

impl SqliteStore {
    /// Run one `op_id`-carrying write in ONE `BEGIN IMMEDIATE` transaction at FULL sync: a replay
    /// answers the original, a conflict is `conflict`, and a new op runs `apply` and is recorded
    /// with its answer only if it applied. A refusal from `apply` rolls the transaction back; a
    /// backend error is `fail`ed.
    fn deduped<E>(
        &self,
        op: OpId,
        body: &str,
        conflict: E,
        fail: fn(RecordStoreError) -> E,
        apply: impl FnOnce(&Transaction<'_>) -> Result<Answer, E>,
    ) -> Result<Answer, E> {
        let mut conn = self.lock_writer();
        let mut conflict = Some(conflict);
        let ran = with_full_sync(&mut conn, |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .store()?;
            let answer = match seen(&tx, op, body)? {
                Seen::Replay(a) => Ok(a),
                Seen::Conflict => Err(conflict.take().expect("taken once")),
                Seen::New => match apply(&tx) {
                    Ok(a) => {
                        record(&tx, op, body, &a)?;
                        tx.commit().store()?;
                        Ok(a)
                    }
                    Err(e) => Err(e),
                },
            };
            Ok(answer)
        });
        ran.unwrap_or_else(|e| Err(fail(e)))
    }

    /// [`Self::deduped`] for a slot whose refusal is [`OpRefused`].
    fn op(
        &self,
        op: OpId,
        body: &str,
        apply: impl FnOnce(&Transaction<'_>) -> OpResult<Answer>,
    ) -> OpResult<Answer> {
        self.deduped(op, body, OpRefused::Conflict, failed, apply)
    }
}

/// The store v3 slots' own bodies: each op's ONE body, which the table's slot answers Ready (the
/// store is local-disk-bound and never pends).
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

    /// `record_put` (slot 40): an upsert on `(schema, key)`. An EMPTY value removes the row
    /// (ARCHITECT 2026-10-21): it is the host's strike, so `record_get` then answers `None` and
    /// `record_scan` never returns it. Removing a row that is not there is `Ok`.
    pub(crate) fn v3_record_put(
        &self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        if value.is_empty() {
            return self
                .lock_writer()
                .execute(
                    "DELETE FROM schema_records WHERE schema=?1 AND record_key=?2",
                    params![schema, key],
                )
                .map(drop)
                .map_err(|e| e.to_string());
        }
        self.lock_writer()
            .execute(
                "INSERT INTO schema_records (schema, record_key, value) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(schema, record_key) DO UPDATE SET value=excluded.value",
                params![schema, key, value],
            )
            .map(drop)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn v3_record_get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        let value: Option<Vec<u8>> = self
            .lock_reader()
            .query_row(
                "SELECT value FROM schema_records WHERE schema=?1 AND record_key=?2",
                params![schema, key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
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
        // A BLOB compares as memcmp, so a prefix is the key range [prefix, successor).
        let conn = self.lock_reader();
        let rows: Vec<(Vec<u8>, Vec<u8>)> = match prefix_successor(prefix) {
            Some(end) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT record_key, value FROM schema_records WHERE schema=?1 \
                         AND record_key >= ?2 AND record_key < ?3 ORDER BY record_key LIMIT ?4",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![schema, prefix, end, i64::from(limit)], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .map_err(|e| e.to_string())?
                    .collect::<Result<_, _>>();
                rows
            }
            None => {
                let mut stmt = conn
                    .prepare(
                        "SELECT record_key, value FROM schema_records WHERE schema=?1 \
                         AND record_key >= ?2 ORDER BY record_key LIMIT ?3",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![schema, prefix, i64::from(limit)], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .map_err(|e| e.to_string())?
                    .collect::<Result<_, _>>();
                rows
            }
        }
        .map_err(|e| e.to_string())?;
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

/// THE STORE v3 TABLE over this store (`abi::sdk::store::StoreSlots`): every slot answers
/// [`Step::Ready`]. The store is local-disk-bound and never pends, so it makes no connector service
/// and never touches [`Op`]; the host runs it on its bounded disk lane (THE DESIGN §11.11 R4,
/// Q-DISK). The 1.5.5 op set (slots 0-32) is ONE body each, the store's [`RecordStore`] impl, which
/// is exactly the code v1.0.6 shipped.
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

    fn append_plane_record_op(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_append_plane_record_op(op, record))
    }

    fn record_put(
        &self,
        _: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        Step::Ready(self.v3_record_put(schema, key, value))
    }

    fn record_get(
        &self,
        _: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>> {
        Step::Ready(self.v3_record_get(schema, key))
    }

    fn record_scan(
        &self,
        _: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>> {
        Step::Ready(self.v3_record_scan(schema, prefix, limit))
    }

    fn add_usage_batch(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_add_usage_batch(op, cells))
    }

    fn add_metering_batch(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_add_metering_batch(op, deltas))
    }

    // ── the 1.5.5 op set (slots 0-32): the RecordStore impl, one body each ───────────────────────

    fn put_key(&self, _: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::put_key(self, key))
    }

    fn get_key(&self, _: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        Step::Ready(RecordStore::get_key(self, id))
    }

    fn list_keys(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        Step::Ready(RecordStore::list_keys(self))
    }

    fn delete_key(&self, _: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::delete_key(self, id))
    }

    fn list_keys_since(
        &self,
        _: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        Step::Ready(RecordStore::list_keys_since(self, since))
    }

    fn get_usage(
        &self,
        _: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>> {
        Step::Ready(RecordStore::get_usage(self, bucket_id, window_start))
    }

    fn put_usage(
        &self,
        _: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::put_usage(
            self,
            bucket_id,
            window_start,
            ledger,
        ))
    }

    fn list_metering(
        &self,
        _: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        Step::Ready(RecordStore::list_metering(self, bucket))
    }

    fn put_credential(
        &self,
        _: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::put_credential(self, secret))
    }

    fn put_key_with_credential(
        &self,
        _: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::put_key_with_credential(self, key, secret))
    }

    fn list_credentials(
        &self,
        _: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        Step::Ready(RecordStore::list_credentials(self, key_id))
    }

    fn revoke_credential(
        &self,
        _: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::revoke_credential(self, id, reason))
    }

    fn list_credentials_since(
        &self,
        _: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        Step::Ready(RecordStore::list_credentials_since(self, since))
    }

    fn list_audit(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        Step::Ready(RecordStore::list_audit(self))
    }

    fn add_denylist(&self, _: &mut Op<'_>, sub: &str, reason: &str) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::add_denylist(self, sub, reason))
    }

    fn list_denylist(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        Step::Ready(RecordStore::list_denylist(self))
    }

    fn list_audit_tail(
        &self,
        _: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        Step::Ready(RecordStore::list_audit_tail(self, limit))
    }

    fn upsert_plane_record(
        &self,
        _: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::upsert_plane_record(self, record))
    }

    fn get_plane_record(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        Step::Ready(RecordStore::get_plane_record(self, kind, id))
    }

    fn list_plane_records(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        Step::Ready(RecordStore::list_plane_records(self, kind, selector))
    }

    fn list_plane_record_parents(
        &self,
        _: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        Step::Ready(RecordStore::list_plane_record_parents(self, kind))
    }

    fn purge_plane_records_before(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        Step::Ready(RecordStore::purge_plane_records_before(self, kind, before))
    }

    fn delete_plane_record(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::delete_plane_record(self, kind, id))
    }

    fn redeem_plane_token(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        Step::Ready(RecordStore::redeem_plane_token(
            self, kind, token, expires_at, now,
        ))
    }

    fn plane_token_live(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        Step::Ready(RecordStore::plane_token_live(
            self, kind, token, expires_at, now,
        ))
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
/// `0xff` incremented, the rest dropped. `None` when there is none (every byte `0xff`, or empty):
/// the range is then unbounded above.
fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let i = prefix.iter().rposition(|&b| b != 0xff)?;
    let mut end = prefix[..=i].to_vec();
    end[i] += 1;
    Some(end)
}

#[cfg(test)]
#[path = "tests/v3_tests.rs"]
mod tests;
