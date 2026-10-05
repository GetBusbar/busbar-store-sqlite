// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the 1.5.5 op set ([`StoreSlots`]): the
//! `op_id`-carrying writes, the ledger streams, the session directory, a plane's kernel-held
//! records, the money slots and `window_caps`. Every one is DURABLE: its state lives in the v11
//! tables (`SCHEMA`), on the writer connection.
//!
//! DEDUPE (`abi::store` S1-S4): an `op_id` that APPLIED is recorded in `store_ops` with the op's
//! value fields and its answer, in the SAME `BEGIN IMMEDIATE` transaction as the op's effect, so
//! the check, the effect and the record are one atomic step: two racing calls with one `op_id`
//! apply once, a crash between the effect and the record cannot happen, and a replay after a
//! restart answers the original. A replay with the same value fields applies nothing; different
//! value fields are a conflict; a refusal or a failure rolls back and records nothing. Records
//! older than [`OP_ID_RETENTION_SECS`] are swept when a new one is recorded.
//!
//! EPOCH AND SLICE LIFE (`abi::store::SLICE_TTL_MS` (a)-(c)): this store is durable (no
//! `MARK_EPHEMERAL`) and every node that shares the file draws against the same rows, so it is a
//! store a FLEET shares. It persists ONE epoch (`money_epoch`), raised only by a reserve presenting
//! a higher one, atomically with its draw; a reserve below it is `StaleEpoch` and applies nothing.
//! Every slice is valid until `now + SLICE_TTL_MS` on this store's clock; past that it is EXPIRED
//! and its unreturned remainder goes back to its window's headroom (applied lazily, inside the next
//! reserve or release that touches it, under the write lock). `slice_release` always applies,
//! whatever the epoch, capped at what the slice has left; a closed slice stays a row, so any
//! further release of it answers 0.
//!
//! GRANT SIZE: a cell grants its whole `amount` or the reserve fails; the per-dimension test is
//! 1.5.5's, cited on `abi::store::ReserveIn`.

use std::collections::HashMap;

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, Op, OpRefused, OpResult, ReserveRefused,
    Scanned, Step, StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS, SLICE_TTL_MS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger,
    VirtualKey,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::{
    add_metering_in, add_usage_in, append_audit_in, append_plane_record_in, now_secs,
    with_full_sync, IntoStoreResult, SqliteStore,
};

/// What an applied op answered, stored with it and replayed verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Answer {
    Done,
    Head {
        seq: u64,
        epoch: u64,
    },
    /// `(slice_id, granted, valid_until_ms)` per cell, in order.
    Grants(Vec<(u64, u64, u64)>),
    Released(Vec<u64>),
}

/// The slot a cell draws from and a cap bounds, as its stored key: the JSON array
/// `[bucket, pool, dimension, class_key, window_start]` (`pool` stays `null` apart from `""`).
fn slot_of(k: &CellKey<'_>) -> (String, u32) {
    let (dimension, class_key) = match k.dimension {
        Dimension::NanoUnits => (0, ""),
        Dimension::Requests => (1, ""),
        Dimension::Concurrency => (2, ""),
        Dimension::Class(c) => (3, c),
    };
    let key = serde_json::json!([k.bucket, k.pool, dimension, class_key, k.window_start]);
    (key.to_string(), dimension)
}

/// The 1.5.5 admission test for one cell (`abi::store::ReserveIn`, GRANT SIZE): whether drawing
/// `amount` onto `used` under `cap` is refused. `used + amount` is checked: an overflow refuses.
fn exhausted(dimension: u32, used: u64, amount: u64, cap: u64) -> bool {
    let Some(after) = used.checked_add(amount) else {
        return true;
    };
    match dimension {
        // DIM_CLASS: `tokens >= cap` — the draw that crosses the cap is granted whole.
        3 => used >= cap,
        // DIM_NANO_UNITS: `derived >= cap || derived + fee > cap`.
        0 => used >= cap || after > cap,
        // DIM_REQUESTS / DIM_CONCURRENCY: `used + amount > cap`.
        _ => after > cap,
    }
}

/// A `u64` amount or id kept bit-for-bit in SQLite's signed column (and back).
fn to_db(v: u64) -> i64 {
    v as i64
}
fn from_db(v: i64) -> u64 {
    v as u64
}

fn failed(e: RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

/// `(cap, config_gen)` stored for `slot`.
fn stored_cap(tx: &Transaction<'_>, slot: &str) -> Result<Option<(u64, u64)>, RecordStoreError> {
    tx.query_row(
        "SELECT cap, config_gen FROM money_caps WHERE slot=?1",
        [slot],
        |r| Ok((from_db(r.get(0)?), from_db(r.get(1)?))),
    )
    .optional()
    .store()
}

/// What is drawn and not released on `slot`.
fn stored_used(tx: &Transaction<'_>, slot: &str) -> Result<u64, RecordStoreError> {
    tx.query_row("SELECT used FROM money_used WHERE slot=?1", [slot], |r| {
        r.get::<_, i64>(0)
    })
    .optional()
    .store()
    .map(|u| u.map_or(0, from_db))
}

/// Return every EXPIRED slice's unreturned remainder on `slot` to its headroom (`SLICE_TTL_MS` (c)):
/// each such slice closes (`remaining` 0) and `used` drops by what it still held. A slice granted
/// `u64::MAX` (stored `-1`, a v11 grant) never expires.
fn expire(tx: &Transaction<'_>, slot: &str, now_ms: u64) -> Result<(), RecordStoreError> {
    let back: i64 = tx
        .query_row(
            "SELECT COALESCE(SUM(remaining), 0) FROM money_slices WHERE slot=?1 AND remaining > 0 \
             AND valid_until_ms >= 0 AND valid_until_ms < ?2",
            params![slot, to_db(now_ms)],
            |r| r.get(0),
        )
        .store()?;
    if back == 0 {
        return Ok(());
    }
    tx.execute(
        "UPDATE money_slices SET remaining=0 WHERE slot=?1 AND remaining > 0 \
         AND valid_until_ms >= 0 AND valid_until_ms < ?2",
        params![slot, to_db(now_ms)],
    )
    .store()?;
    let used = stored_used(tx, slot)?;
    set_used(tx, slot, used.saturating_sub(from_db(back)))
}

/// Forget closed slices whose validity ended more than `OP_ID_RETENTION_SECS` ago: past that a
/// release of one is a replay the dedupe log has forgotten too.
fn sweep_closed(tx: &Transaction<'_>, now_ms: u64) -> Result<(), RecordStoreError> {
    let horizon = now_ms.saturating_sub(OP_ID_RETENTION_SECS.saturating_mul(1000));
    tx.execute(
        "DELETE FROM money_slices WHERE remaining = 0 AND valid_until_ms >= 0 \
         AND valid_until_ms < ?1",
        params![to_db(horizon)],
    )
    .store()
    .map(drop)
}

/// The persisted fleet epoch (`SLICE_TTL_MS` (a)): 0 before any reserve.
fn stored_epoch(tx: &Transaction<'_>) -> Result<u64, RecordStoreError> {
    tx.query_row("SELECT epoch FROM money_epoch WHERE id=0", [], |r| {
        r.get::<_, i64>(0)
    })
    .optional()
    .store()
    .map(|e| e.map_or(0, from_db))
}

fn set_used(tx: &Transaction<'_>, slot: &str, used: u64) -> Result<(), RecordStoreError> {
    tx.execute(
        "INSERT INTO money_used (slot, used) VALUES (?1, ?2) \
         ON CONFLICT(slot) DO UPDATE SET used=excluded.used",
        params![slot, to_db(used)],
    )
    .store()
    .map(drop)
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
    pub(crate) fn v3_add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> OpResult<()> {
        let body = format!("add_usage:{bucket:?}:{window_start}:{delta:?}");
        self.op(op, &body, |tx| {
            add_usage_in(tx, bucket, window_start, delta).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        let body = format!("add_metering:{delta:?}");
        self.op(op, &body, |tx| {
            add_metering_in(tx, delta).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        let body = format!("append_audit:{entry:?}");
        self.op(op, &body, |tx| {
            append_audit_in(tx, entry).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

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

    pub(crate) fn v3_append_batch(
        &self,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> OpResult<Head> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let answer = self.op(op, &body, |tx| {
            let mut seq: u64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(seq), 0) FROM journal WHERE stream=?1",
                    [stream],
                    |r| r.get::<_, i64>(0),
                )
                .store()
                .map(from_db)
                .map_err(failed)?;
            for r in records {
                seq += 1;
                tx.execute(
                    "INSERT INTO journal (stream, seq, record) VALUES (?1, ?2, ?3)",
                    params![stream, to_db(seq), r.as_slice()],
                )
                .store()
                .map_err(failed)?;
            }
            Ok(Answer::Head { seq, epoch: 0 })
        })?;
        match answer {
            Answer::Head { seq, epoch } => Ok(Head { seq, epoch }),
            _ => Err(OpRefused::Conflict),
        }
    }

    pub(crate) fn v3_heads(&self) -> Result<Vec<(String, Head)>, String> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare("SELECT stream, MAX(seq) FROM journal GROUP BY stream ORDER BY stream")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    Head {
                        seq: from_db(r.get(1)?),
                        epoch: 0,
                    },
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    pub(crate) fn v3_session_put(
        &self,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Result<(), String> {
        self.lock_writer()
            .execute(
                "INSERT INTO sessions (session, node, principal) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(session) DO UPDATE SET node=excluded.node, principal=excluded.principal",
                params![to_db(session), node, principal],
            )
            .map(drop)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn v3_session_remove(&self, session: u64) -> Result<(), String> {
        self.lock_writer()
            .execute(
                "DELETE FROM sessions WHERE session=?1",
                params![to_db(session)],
            )
            .map(drop)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn v3_sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        let conn = self.lock_reader();
        let mut stmt = conn
            .prepare("SELECT session, node FROM sessions WHERE principal=?1")
            .map_err(|e| e.to_string())?;
        let mut rows: Vec<(u64, String)> = stmt
            .query_map([principal], |r| Ok((from_db(r.get(0)?), r.get(1)?)))
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        rows.sort_unstable();
        Ok(rows)
    }

    pub(crate) fn v3_record_put(
        &self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
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

    pub(crate) fn v3_reserve<'c>(
        &self,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused> {
        let cells: Vec<Cell<'_>> = cells.collect();
        let body = format!("reserve:{epoch}:{cells:?}");
        let answer = self.deduped(
            op,
            &body,
            ReserveRefused::Conflict,
            |_| ReserveRefused::Unavailable,
            |tx| {
                let unavailable = |_: RecordStoreError| ReserveRefused::Unavailable;
                let now = self.now_ms();
                // The epoch fences the draw (`SLICE_TTL_MS` (b)): below the stored one applies
                // nothing; above it raises the stored one, in this same transaction.
                let fleet = stored_epoch(tx).map_err(unavailable)?;
                if epoch < fleet {
                    return Err(ReserveRefused::StaleEpoch);
                }
                // The chain draw is all or nothing: test every cell against what the cells before
                // it in THIS draw add, and apply only when every cell passes. Each slot's expired
                // slices go back to its headroom first (`SLICE_TTL_MS` (c)).
                let mut drawn: HashMap<String, u64> = HashMap::new();
                let mut slots = Vec::with_capacity(cells.len());
                for (i, c) in cells.iter().enumerate() {
                    let (slot, dimension) = slot_of(&c.key);
                    expire(tx, &slot, now).map_err(unavailable)?;
                    let Some((cap, _)) = stored_cap(tx, &slot).map_err(unavailable)? else {
                        return Err(ReserveRefused::NoCap { cell: i as u32 });
                    };
                    let used = stored_used(tx, &slot).map_err(unavailable)?;
                    let used = used.saturating_add(drawn.get(&slot).copied().unwrap_or(0));
                    if exhausted(dimension, used, c.amount, cap) {
                        return Err(ReserveRefused::Exhausted { cell: i as u32 });
                    }
                    *drawn.entry(slot.clone()).or_default() += c.amount;
                    slots.push(slot);
                }
                if epoch > fleet {
                    tx.execute(
                        "INSERT INTO money_epoch (id, epoch) VALUES (0, ?1) \
                         ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch",
                        params![to_db(epoch)],
                    )
                    .store()
                    .map_err(unavailable)?;
                }
                sweep_closed(tx, now).map_err(unavailable)?;
                let valid_until_ms = now.saturating_add(SLICE_TTL_MS);
                let mut granted = Vec::with_capacity(cells.len());
                for (c, slot) in cells.iter().zip(slots) {
                    let used = stored_used(tx, &slot).map_err(unavailable)?;
                    set_used(tx, &slot, used.saturating_add(c.amount)).map_err(unavailable)?;
                    let slice_id: i64 = tx
                        .query_row(
                            "INSERT INTO money_slices (slot, remaining, valid_until_ms) \
                             VALUES (?1, ?2, ?3) RETURNING slice_id",
                            params![slot, to_db(c.amount), to_db(valid_until_ms)],
                            |r| r.get(0),
                        )
                        .store()
                        .map_err(unavailable)?;
                    granted.push((from_db(slice_id), c.amount, valid_until_ms));
                }
                Ok(Answer::Grants(granted))
            },
        )?;
        match answer {
            Answer::Grants(g) => {
                grants.extend(
                    g.into_iter()
                        .map(|(slice_id, granted, valid_until_ms)| Grant {
                            slice_id,
                            granted,
                            valid_until_ms,
                        }),
                );
                Ok(())
            }
            _ => Err(ReserveRefused::Conflict),
        }
    }

    pub(crate) fn v3_slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        let answer = self.op(op, &body, |tx| {
            let now = self.now_ms();
            let held = |id: u64| -> OpResult<Option<(String, u64)>> {
                tx.query_row(
                    "SELECT slot, remaining FROM money_slices WHERE slice_id=?1",
                    params![to_db(id)],
                    |r| Ok((r.get(0)?, from_db(r.get(1)?))),
                )
                .optional()
                .store()
                .map_err(failed)
            };
            for &(id, _) in &items {
                if held(id)?.is_none() {
                    return Err(OpRefused::Failed(format!(
                        "slice_release: slice {id} was never granted"
                    )));
                }
            }
            let mut back_all = Vec::with_capacity(items.len());
            for &(id, unspent) in &items {
                let gone =
                    || OpRefused::Failed(format!("slice_release: slice {id} was never granted"));
                let (slot, _) = held(id)?.ok_or_else(gone)?;
                // An expired slice's remainder went back to its headroom at expiry, so a release
                // after it returns nothing more (`SLICE_TTL_MS`: each unit at most once).
                expire(tx, &slot, now).map_err(failed)?;
                let (_, left) = held(id)?.ok_or_else(gone)?;
                let back = unspent.min(left);
                tx.execute(
                    "UPDATE money_slices SET remaining=?2 WHERE slice_id=?1",
                    params![to_db(id), to_db(left - back)],
                )
                .store()
                .map_err(failed)?;
                let used = stored_used(tx, &slot).map_err(failed)?;
                set_used(tx, &slot, used.saturating_sub(back)).map_err(failed)?;
                back_all.push(back);
            }
            Ok(Answer::Released(back_all))
        })?;
        match answer {
            Answer::Released(r) => {
                released.extend(r);
                Ok(())
            }
            _ => Err(OpRefused::Conflict),
        }
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

    pub(crate) fn v3_append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
        let body = format!("append_audit_batch:{entries:?}");
        // One transaction: a fork anywhere (against the log, or inside the batch, which the fork
        // check sees because the earlier entries are already written in it) rolls back the whole.
        self.op(op, &body, |tx| {
            for e in entries {
                append_audit_in(tx, e).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        let body = format!("window_caps:{caps:?}");
        self.deduped(
            op,
            &body,
            CapsRefused::Conflict,
            |e| CapsRefused::Failed(e.0),
            |tx| {
                let fail = |e: RecordStoreError| CapsRefused::Failed(e.0);
                // Atomic per push: find the first conflict before applying any cap.
                let mut pushed: HashMap<String, (u64, u64)> = HashMap::new();
                for (index, c) in caps.iter().enumerate() {
                    let (slot, _) = slot_of(&c.key);
                    let stored = match pushed.get(&slot) {
                        Some(p) => Some(*p),
                        None => stored_cap(tx, &slot).map_err(fail)?,
                    };
                    match stored {
                        Some((cap, gen)) if gen == c.config_gen && cap != c.cap => {
                            return Err(CapsRefused::CapConflict { index });
                        }
                        Some((_, gen)) if gen >= c.config_gen => {}
                        _ => {
                            pushed.insert(slot, (c.cap, c.config_gen));
                        }
                    }
                }
                for (slot, (cap, gen)) in &pushed {
                    tx.execute(
                        "INSERT INTO money_caps (slot, cap, config_gen) VALUES (?1, ?2, ?3) \
                         ON CONFLICT(slot) DO UPDATE SET cap=excluded.cap, config_gen=excluded.config_gen",
                        params![slot, to_db(*cap), to_db(*gen)],
                    )
                    .store()
                    .map_err(fail)?;
                }
                Ok(Answer::Done)
            },
        )
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

    fn add_usage_op(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_add_usage_op(op, bucket, window_start, delta))
    }

    fn add_metering_op(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        delta: &MeteringDelta,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_add_metering_op(op, delta))
    }

    fn append_audit_op(&self, _: &mut Op<'_>, op: OpId, entry: &AuditRecord) -> Step<OpResult<()>> {
        Step::Ready(self.v3_append_audit_op(op, entry))
    }

    fn append_plane_record_op(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_append_plane_record_op(op, record))
    }

    fn append_batch(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Step<OpResult<Head>> {
        Step::Ready(self.v3_append_batch(op, stream, records))
    }

    fn heads(&self, _: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
        Step::Ready(self.v3_heads())
    }

    fn session_put(
        &self,
        _: &mut Op<'_>,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Step<Result<(), String>> {
        Step::Ready(self.v3_session_put(session, node, principal))
    }

    fn session_remove(&self, _: &mut Op<'_>, session: u64) -> Step<Result<(), String>> {
        Step::Ready(self.v3_session_remove(session))
    }

    fn sessions_for(
        &self,
        _: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>> {
        Step::Ready(self.v3_sessions_for(principal))
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

    fn reserve<'c>(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        Step::Ready(self.v3_reserve(op, epoch, cells, grants))
    }

    fn slice_release(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_slice_release(op, epoch, items, released))
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

    fn append_audit_batch(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_append_audit_batch(op, entries))
    }

    fn window_caps(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>> {
        Step::Ready(self.v3_window_caps(op, caps))
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

    fn scrub_key(&self, _: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::scrub_key(self, id))
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

    fn purge_windows_before(&self, _: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        Step::Ready(RecordStore::purge_windows_before(self, before))
    }

    fn purge_metering_before(&self, _: &mut Op<'_>, bucket: &str) -> Step<RecordStoreResult<u64>> {
        Step::Ready(RecordStore::purge_metering_before(self, bucket))
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

    fn lookup_credential_secret(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        public_id: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
        Step::Ready(RecordStore::lookup_credential_secret(self, kind, public_id))
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
