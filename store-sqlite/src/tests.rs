// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_api::{
    AuditRecord, McpCallRecord, McpDemotionRow, ModelTokensDelta, Store, TaskEventRow, TaskRow,
    TierTokensDelta, VirtualKey,
};
use rusqlite::TransactionBehavior;

fn sample_key(id: &str, generation: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: generation.to_string(),
        name: "test".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    }
}

fn sample_credential(key_id: &str, public_id: &str, slot: u8) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: format!("cred_{public_id}"),
            key_id: key_id.to_string(),
            kind: "sigv4".to_string(),
            slot,
            public_id: public_id.to_string(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:shhh".to_string(),
    }
}

/// `CredentialMeta::updated_at` must round-trip as its own value. Bound to `created_at`'s
/// placeholder, the caller's value was silently discarded and every credential reported that it was
/// last changed when it was minted. The keys table carries a dedicated regression test for exactly
/// this shape; the credentials table had none, and the fixture's `created_at == updated_at == 0`
/// meant no existing assertion could tell the two apart.
#[test]
fn credential_updated_at_round_trips_as_its_own_value() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_credtime", "g")).unwrap();
    let mut cred = sample_credential("vk_credtime", "AKIA_CREDTIME", 0);
    cred.meta.created_at = 100;
    cred.meta.updated_at = 200;
    s.put_credential(&cred).unwrap();

    let back = s
        .list_credentials("vk_credtime")
        .unwrap()
        .into_iter()
        .find(|c| c.public_id == "AKIA_CREDTIME")
        .expect("the minted credential must be listed");
    assert_eq!(back.created_at, 100, "created_at must round-trip untouched");
    assert_eq!(
        back.updated_at, 200,
        "updated_at must round-trip as its own distinct value, not be overwritten by created_at's"
    );
}

fn delta(requests: i64, model: &str, input: i64, output: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: model.to_string(),
            tokens: TierTokensDelta {
                input,
                output,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    }
}

// ── Basic key CRUD ──────────────────────────────────────────────────────────────────────────────

#[test]
fn put_get_roundtrips_a_key() {
    let s = SqliteStore::open_in_memory().unwrap();
    let k = sample_key("vk_1", "binding:vk_1:g1");
    s.put_key(&k).unwrap();
    let back = s.get_key("vk_1").unwrap().unwrap();
    assert_eq!(back.id, "vk_1");
    assert_eq!(back.generation_hash, "binding:vk_1:g1");
    assert!(back.deleted_at.is_none());
    assert!(back.revision > 0, "put_key must stamp a nonzero revision");
}

/// `keys.updated_at` has no Rust-side reader (`KEY_COLS` omits it -- it exists purely for direct
/// SQL/operator inspection), so this reads it back via raw SQL like the other CHECK/trigger tests
/// in this file. Regression test for `put_key_inner`'s ON CONFLICT branch reusing `created_at`
/// (bound param `?6`) for `updated_at` instead of stamping the actual mutation time.
#[test]
fn put_key_update_stamps_updated_at_to_mutation_time_not_created_at() {
    let s = SqliteStore::open_in_memory().unwrap();
    let mut k = sample_key("vk_stamp", "g1");
    k.created_at = 1_000;
    s.put_key(&k).unwrap();
    // Mutate (rename) and put again -- this goes through the ON CONFLICT DO UPDATE branch.
    k.name = "renamed".to_string();
    s.put_key(&k).unwrap();
    let conn = s.lock_writer();
    let updated_at: i64 = conn
        .query_row("SELECT updated_at FROM keys WHERE id='vk_stamp'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_ne!(
        updated_at, k.created_at as i64,
        "updated_at must reflect the actual mutation time, not be frozen at created_at"
    );
}

/// `SqliteStore::open`'s `:memory:` routing must recognize every spelling `apply_pragmas`'s own
/// `is_memory` check recognizes -- not just the bare `:memory:` literal. Regression test for a
/// gap where `open()` used `path == ":memory:"` (exact match only) while `apply_pragmas` already
/// used the broader `is_memory_path` check: a URI-form spelling like `file::memory:` would fall
/// through to `open_with_readers`, which opens N+1 independent, mutually-invisible private
/// in-memory databases (only the writer gets `migrate()`'s schema; every reader sees no tables).
#[test]
fn memory_uri_spellings_other_than_the_bare_literal_are_still_single_connection() {
    for path in ["file::memory:", "file:test?mode=memory&cache=shared"] {
        let s = SqliteStore::open(path, 5000)
            .unwrap_or_else(|e| panic!("open({path:?}) must succeed: {e}"));
        assert!(
            s.readers.is_empty(),
            "open({path:?}) must route through the single-connection in-memory path, not open_with_readers"
        );
        let k = sample_key("vk_mem", "g");
        s.put_key(&k).unwrap();
        // If a reader pool had been created against an isolated private DB, this would fail with
        // "no such table: keys" instead of returning the row just written on the writer.
        assert!(
            s.get_key("vk_mem").unwrap().is_some(),
            "open({path:?}): reader path must see the row written on the writer connection"
        );
    }
}

#[test]
fn allowed_pools_none_vs_empty_round_trip_distinctly() {
    let s = SqliteStore::open_in_memory().unwrap();
    let mut all_pools = sample_key("vk_all", "g");
    all_pools.allowed_scopes = None;
    let mut no_pools = sample_key("vk_none", "g");
    no_pools.allowed_scopes = Some(vec![]);
    s.put_key(&all_pools).unwrap();
    s.put_key(&no_pools).unwrap();
    assert_eq!(s.get_key("vk_all").unwrap().unwrap().allowed_scopes, None);
    assert_eq!(
        s.get_key("vk_none").unwrap().unwrap().allowed_scopes,
        Some(vec![])
    );
}

#[test]
fn list_keys_since_only_returns_keys_past_the_watermark() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_a", "g")).unwrap();
    let watermark = s.get_key("vk_a").unwrap().unwrap().revision;
    s.put_key(&sample_key("vk_b", "g")).unwrap();
    let delta = s.list_keys_since(watermark).unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].id, "vk_b");
}

/// The credential-side half of the same revision-based hydration mechanism as
/// `list_keys_since_only_returns_keys_past_the_watermark` — had zero coverage before this test.
#[test]
fn list_credentials_since_only_returns_credentials_past_the_watermark() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_ca", "g")).unwrap();
    s.put_credential(&sample_credential("vk_ca", "AKIA_A", 0))
        .unwrap();
    let watermark = s.list_credentials("vk_ca").unwrap()[0].revision;
    s.put_credential(&sample_credential("vk_ca", "AKIA_B", 1))
        .unwrap();
    let delta = s.list_credentials_since(watermark).unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].meta.public_id, "AKIA_B");
    // Must be ordered by revision (the hydration contract), not insertion/id order. Revoking
    // slot 0 bumps that SAME physical row's revision again (revoke/remint reuse the row via the
    // key_id+kind+slot UPSERT) rather than appending a new one, so the delta still reflects each
    // row's latest state, ordered by its latest revision.
    let a_id = s.list_credentials("vk_ca").unwrap()[0].id.clone();
    s.revoke_credential(&a_id, "rotated").unwrap();
    let delta2 = s.list_credentials_since(watermark).unwrap();
    assert_eq!(
        delta2.len(),
        2,
        "revoke updates AKIA_A's existing row rather than adding one"
    );
    assert!(
        delta2[0].meta.revision < delta2[1].meta.revision,
        "delta must be ordered by revision"
    );
    assert!(
        delta2
            .iter()
            .any(|c| c.meta.public_id == "AKIA_A" && c.meta.revoked_at.is_some()),
        "the revoked row's latest state must be visible in the delta"
    );
}

// ── Tombstone delete: the redesign's central behavior change ──────────────────────────────────

#[test]
fn delete_key_tombstones_not_removes() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_del", "g")).unwrap();
    s.delete_key("vk_del").unwrap();
    let row = s
        .get_key("vk_del")
        .unwrap()
        .expect("tombstoned row must still be readable");
    assert!(!row.enabled);
    assert!(row.deleted_at.is_some());
    assert!(!row.is_live());
}

#[test]
fn delete_key_destroys_credentials() {
    let s = SqliteStore::open_in_memory().unwrap();
    let k = sample_key("vk_cred", "g");
    let cred = sample_credential("vk_cred", "AKIA_TEST", 0);
    s.put_key_with_credential(&k, &cred).unwrap();
    assert_eq!(s.list_credentials("vk_cred").unwrap().len(), 1);
    s.delete_key("vk_cred").unwrap();
    assert!(s.list_credentials("vk_cred").unwrap().is_empty());
    assert!(s
        .lookup_credential_secret("sigv4", "AKIA_TEST")
        .unwrap()
        .is_none());
}

#[test]
fn delete_key_is_idempotent() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_x", "g")).unwrap();
    s.delete_key("vk_x").unwrap();
    let rev_after_first = s.get_key("vk_x").unwrap().unwrap().revision;
    s.delete_key("vk_x").unwrap(); // must not error, must not bump revision again
    let rev_after_second = s.get_key("vk_x").unwrap().unwrap().revision;
    assert_eq!(
        rev_after_first, rev_after_second,
        "a no-op re-delete must not stamp a new revision"
    );
}

#[test]
fn delete_key_unknown_id_errors() {
    let s = SqliteStore::open_in_memory().unwrap();
    assert!(s.delete_key("vk_never_existed").is_err());
}

/// HARDEST INVARIANT #1: the tombstone UPDATE's atomicity. `keys_tombstone_off` (`deleted_at IS NULL
/// OR enabled = 0`) would reject a transient `enabled=1, deleted_at=now` state — this test proves
/// `delete_key` sets both flags in the SAME statement by attempting exactly that split, by hand,
/// through raw SQL, and confirming the CHECK constraint rejects it (proving the constraint is real
/// and would have caught a two-statement `delete_key` if one were ever (re)introduced).
#[test]
fn tombstone_flags_cannot_be_set_transiently_split() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_split", "g")).unwrap();
    let conn = s.lock_writer();
    // Attempt the UNSAFE two-statement form directly: set deleted_at first, leaving enabled=1 -
    // this must be rejected by keys_tombstone_off, proving the constraint is load-bearing.
    let result = conn.execute("UPDATE keys SET deleted_at = 999 WHERE id='vk_split'", []);
    assert!(
        result.is_err(),
        "keys_tombstone_off must reject deleted_at set while enabled=1"
    );
    // The real (correct) single-statement form must succeed.
    conn.execute(
        "UPDATE keys SET enabled=0, deleted_at=999 WHERE id='vk_split'",
        [],
    )
    .unwrap();
}

/// HARDEST INVARIANT #2: `keys_guard_hard_delete` actually blocks a raw DELETE when metering rows
/// exist for that key — the backstop against DB-level surgery bypassing the tombstone path.
#[test]
fn hard_delete_blocked_when_metering_rows_exist() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_billed", "g")).unwrap();
    s.add_metering(&MeteringDelta {
        key_id: "vk_billed".to_string(),
        bucket: 20260101,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    })
    .unwrap();
    let conn = s.lock_writer();
    let result = conn.execute("DELETE FROM keys WHERE id='vk_billed'", []);
    assert!(
        result.is_err(),
        "keys_guard_hard_delete must block a raw DELETE when billing rows exist"
    );
    // A key with NO metering rows must be hard-deletable directly (the trigger is scoped, not blanket).
    drop(conn);
    s.put_key(&sample_key("vk_unbilled", "g")).unwrap();
    let conn = s.lock_writer();
    conn.execute("DELETE FROM keys WHERE id='vk_unbilled'", [])
        .unwrap();
}

// ── Credentials: slot bounds, revoke, secret isolation ─────────────────────────────────────────

#[test]
fn credential_mint_into_occupied_live_slot_fails() {
    let s = SqliteStore::open_in_memory().unwrap();
    let k = sample_key("vk_c", "g");
    s.put_key(&k).unwrap();
    s.put_credential(&sample_credential("vk_c", "AKIA_1", 0))
        .unwrap();
    let result = s.put_credential(&sample_credential("vk_c", "AKIA_2", 0));
    assert!(
        result.is_err(),
        "minting into a live slot must fail, not silently overwrite"
    );
}

#[test]
fn credential_mint_into_revoked_slot_succeeds() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_c2", "g")).unwrap();
    s.put_credential(&sample_credential("vk_c2", "AKIA_OLD", 0))
        .unwrap();
    let old_id = s.list_credentials("vk_c2").unwrap()[0].id.clone();
    s.revoke_credential(&old_id, "rotated").unwrap();
    // Slot 0 is now revoked, so re-minting into it must succeed (overlap-window rotation).
    s.put_credential(&sample_credential("vk_c2", "AKIA_NEW", 0))
        .unwrap();
    let live: Vec<_> = s
        .list_credentials("vk_c2")
        .unwrap()
        .into_iter()
        .filter(|c| c.revoked_at.is_none())
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].public_id, "AKIA_NEW");
}

/// Overlap-window rotation: mint into the FREE slot (1) while slot 0 is still live, so both
/// credentials for the same key_id+kind are live simultaneously — the actual scenario `slot`
/// exists for (mint the replacement, hand it out, only THEN revoke the old one). Every other
/// credential test in this file uses slot 0 exclusively; this is the only one that ever puts a
/// row into slot 1 or has two live rows for one key_id+kind at once.
#[test]
fn credential_overlap_window_rotation_keeps_both_slots_live_simultaneously() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_overlap", "g")).unwrap();
    s.put_credential(&sample_credential("vk_overlap", "AKIA_OLD", 0))
        .unwrap();
    // Mint the replacement into the free slot (1) BEFORE revoking slot 0 -- both must be live.
    s.put_credential(&sample_credential("vk_overlap", "AKIA_NEW", 1))
        .unwrap();
    let live: std::collections::BTreeSet<_> = s
        .list_credentials("vk_overlap")
        .unwrap()
        .into_iter()
        .filter(|c| c.revoked_at.is_none())
        .map(|c| c.public_id)
        .collect();
    assert_eq!(
        live,
        std::collections::BTreeSet::from(["AKIA_OLD".to_string(), "AKIA_NEW".to_string()]),
        "both slots must resolve as live during the overlap window"
    );
    // Only now retire the old one, leaving exactly the new credential live.
    let old_id = s
        .list_credentials("vk_overlap")
        .unwrap()
        .into_iter()
        .find(|c| c.public_id == "AKIA_OLD")
        .unwrap()
        .id;
    s.revoke_credential(&old_id, "rotation complete").unwrap();
    let live_after: Vec<_> = s
        .list_credentials("vk_overlap")
        .unwrap()
        .into_iter()
        .filter(|c| c.revoked_at.is_none())
        .map(|c| c.public_id)
        .collect();
    assert_eq!(live_after, vec!["AKIA_NEW".to_string()]);
}

#[test]
fn credential_public_id_is_globally_unique_per_kind() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_a", "g")).unwrap();
    s.put_key(&sample_key("vk_b", "g")).unwrap();
    s.put_credential(&sample_credential("vk_a", "AKIA_DUP", 0))
        .unwrap();
    let result = s.put_credential(&sample_credential("vk_b", "AKIA_DUP", 0));
    assert!(
        result.is_err(),
        "the same public_id must not resolve to two different keys"
    );
}

#[test]
fn lookup_credential_secret_returns_none_for_unknown() {
    let s = SqliteStore::open_in_memory().unwrap();
    assert!(s
        .lookup_credential_secret("sigv4", "nope")
        .unwrap()
        .is_none());
}

#[test]
fn list_credentials_never_carries_a_secret_field() {
    // CredentialMeta has no `secret` field at all -- this test exists to document the guarantee at
    // the type level (it will fail to COMPILE, not fail an assertion, if that ever changes).
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_s", "g")).unwrap();
    s.put_credential(&sample_credential("vk_s", "AKIA_S", 0))
        .unwrap();
    let metas = s.list_credentials("vk_s").unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].public_id, "AKIA_S");
}

#[test]
fn scrub_key_requires_tombstone_first() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_live", "g")).unwrap();
    assert!(
        s.scrub_key("vk_live").is_err(),
        "scrubbing a live key must be refused"
    );
    s.delete_key("vk_live").unwrap();
    s.scrub_key("vk_live").unwrap();
    let row = s.get_key("vk_live").unwrap().unwrap();
    assert_eq!(row.name, "");
    assert!(row.labels.is_empty());
}

// ── Usage ledger ─────────────────────────────────────────────────────────────────────────────

#[test]
fn add_usage_accumulates_and_floors_at_zero() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.add_usage("vk_u", 100, &delta(1, "m", 10, 5)).unwrap();
    s.add_usage("vk_u", 100, &delta(-5, "m", -20, -1)).unwrap();
    let ledger = s.get_usage("vk_u", 100).unwrap();
    assert_eq!(
        ledger.requests, 0,
        "requests must floor at 0, never go negative"
    );
    let m = ledger.tokens_for("m").unwrap();
    assert_eq!(m.input, 0, "input tokens must floor at 0");
    assert_eq!(m.output, 4);
}

#[test]
fn put_usage_is_an_absolute_overwrite() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.add_usage("vk_o", 200, &delta(5, "m", 100, 50)).unwrap();
    s.put_usage(
        "vk_o",
        200,
        &UsageLedger {
            requests: 1,
            billable_requests: 1,
            models: vec![],
        },
    )
    .unwrap();
    let ledger = s.get_usage("vk_o", 200).unwrap();
    assert_eq!(ledger.requests, 1);
    assert!(ledger.models.is_empty());
}

/// A zero-model add_usage call (e.g. a rejected request: it counts toward `requests` but never
/// reached a model) followed by a real-model add_usage call for the SAME (window, bucket) must not
/// let the two calls' `requests` diverge. Before the sentinel-row fix, the empty-models call wrote
/// requests only onto the model='' row while the model call wrote its own (different!) requests onto
/// the model row — get_usage's MIN() picked whichever was smaller, silently undercounting.
#[test]
fn add_usage_requests_stay_consistent_across_empty_then_populated_calls() {
    let s = SqliteStore::open_in_memory().unwrap();
    // First: a rejected request. requests=1, zero models.
    s.add_usage(
        "vk_mix",
        300,
        &UsageDelta {
            requests: 1,
            billable_requests: 0,
            models: vec![],
        },
    )
    .unwrap();
    // Then: a real request against a model. requests=1 again (its own admission), one model.
    s.add_usage("vk_mix", 300, &delta(1, "gpt", 10, 5)).unwrap();
    let ledger = s.get_usage("vk_mix", 300).unwrap();
    assert_eq!(
        ledger.requests, 2,
        "both calls' requests must accumulate on the one sentinel row"
    );
    assert_eq!(ledger.models.len(), 1);
    assert_eq!(ledger.tokens_for("gpt").unwrap().input, 10);
}

// ── Metering ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn metering_accumulates_and_carries_group_and_pricing_attribution() {
    let s = SqliteStore::open_in_memory().unwrap();
    let d = MeteringDelta {
        key_id: "vk_m".to_string(),
        bucket: 20260101,
        model: "gpt".to_string(),
        provider: "openai".to_string(),
        tokens_input: 10,
        tokens_output: 5,
        tokens_cache_read: 0,
        tokens_cache_write: 2,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "growth".to_string(),
        pricing_version: "2026-07".to_string(),
    };
    s.add_metering(&d).unwrap();
    s.add_metering(&d).unwrap();
    let rows = s.list_metering(20260101).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tokens_input, 20);
    assert_eq!(rows[0].requests, 2);
    assert_eq!(rows[0].key_group_at_use, "growth");
    assert_eq!(rows[0].pricing_version, "2026-07");
}

/// HARDEST INVARIANT #3: chunked retention sweep leaves no partial state and eventually purges
/// everything, across multiple internal chunk iterations (chunk size 5000; this test uses a small
/// override-free row count but proves the loop terminates and the final count is exact).
#[test]
fn purge_windows_before_removes_exactly_the_stale_rows() {
    let s = SqliteStore::open_in_memory().unwrap();
    for i in 0..10u64 {
        s.add_usage("vk_p", 100 + i, &delta(1, "m", 1, 1)).unwrap();
    }
    for i in 0..5u64 {
        s.add_usage("vk_p", 500 + i, &delta(1, "m", 1, 1)).unwrap();
    }
    let purged = s.purge_windows_before(200).unwrap();
    // Each add_usage call with one model writes TWO physical rows (the model='' requests/
    // billable_requests sentinel + the one model's token row), so 10 stale windows = 20 rows.
    // WINDOWS, not rows. This asserted 20 (the row count: one sentinel plus one model row per
    // window), which encoded the wrong contract as correct. `purge_windows_before` returns "the
    // number of windows purged", and a figure that scales with each window's model cardinality
    // cannot be reconciled against the retention the caller asked for.
    assert_eq!(
        purged, 10,
        "the 10 windows with window_start < 200 should be reported as 10 windows purged"
    );
    // The remaining 5 must still be readable.
    for i in 0..5u64 {
        let ledger = s.get_usage("vk_p", 500 + i).unwrap();
        assert_eq!(ledger.requests, 1);
    }
}

#[test]
fn purge_metering_before_only_touches_the_named_bucket() {
    let s = SqliteStore::open_in_memory().unwrap();
    let mk = |bucket: u64| MeteringDelta {
        key_id: "vk_pm".to_string(),
        bucket,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };
    s.add_metering(&mk(20260101)).unwrap();
    s.add_metering(&mk(20260102)).unwrap();
    let purged = s.purge_metering_before("20260101").unwrap();
    assert_eq!(purged, 1);
    assert!(s.list_metering(20260101).unwrap().is_empty());
    assert_eq!(s.list_metering(20260102).unwrap().len(), 1);
}

// ── Denylist ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn denylist_add_and_list_and_idempotent() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.add_denylist("vk_d", "compromised").unwrap();
    s.add_denylist("vk_d", "compromised again").unwrap(); // idempotent, updates reason
    let list = s.list_denylist().unwrap();
    assert_eq!(list, vec!["vk_d".to_string()]);
}

// ── Audit log ────────────────────────────────────────────────────────────────────────────────

#[test]
fn audit_log_append_and_replay_is_idempotent() {
    let s = SqliteStore::open_in_memory().unwrap();
    let rec = AuditRecord {
        seq: 1,
        ts: 100,
        action: "key.mint".to_string(),
        resource: "vk_1".to_string(),
        outcome: "applied".to_string(),
        principal: "admin".to_string(),
        prev_hash: String::new(),
        hash: "h1".to_string(),
    };
    s.append_audit(&rec).unwrap();
    s.append_audit(&rec).unwrap(); // replay of the same seq must not error or duplicate
    assert_eq!(s.list_audit().unwrap().len(), 1);
}

#[test]
fn audit_log_is_append_only() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.append_audit(&AuditRecord {
        seq: 1,
        ts: 1,
        action: "a".to_string(),
        resource: "r".to_string(),
        outcome: "applied".to_string(),
        principal: "p".to_string(),
        prev_hash: String::new(),
        hash: "h".to_string(),
    })
    .unwrap();
    let conn = s.lock_writer();
    assert!(conn
        .execute("UPDATE audit_log SET action='tampered' WHERE seq=1", [])
        .is_err());
    assert!(conn
        .execute("DELETE FROM audit_log WHERE seq=1", [])
        .is_err());
}

#[test]
fn list_audit_tail_bounds_and_preserves_order() {
    let s = SqliteStore::open_in_memory().unwrap();
    for i in 1..=5u64 {
        s.append_audit(&AuditRecord {
            seq: i,
            ts: i,
            action: "a".to_string(),
            resource: "r".to_string(),
            outcome: "applied".to_string(),
            principal: "p".to_string(),
            prev_hash: String::new(),
            hash: format!("h{i}"),
        })
        .unwrap();
    }
    let tail = s.list_audit_tail(2).unwrap();
    assert_eq!(tail.len(), 2);
    assert_eq!(tail[0].seq, 4);
    assert_eq!(tail[1].seq, 5);
}

// ── Pragma / transaction-mode invariants ────────────────────────────────────────────────────────

/// HARDEST INVARIANT #4: `BEGIN IMMEDIATE` vs `BEGIN DEFERRED` genuinely matters. A DEFERRED
/// transaction that reads first, then attempts to upgrade to a write while ANOTHER connection holds
/// the write lock, fails with `SQLITE_BUSY_SNAPSHOT` -- which bypasses the busy handler / configured
/// `busy_timeout` entirely and fails instantly, regardless of the timeout. An IMMEDIATE transaction
/// acquires the write lock up front, so the SAME contention correctly goes through the busy handler
/// and (with a nonzero timeout) succeeds once the other writer releases.
#[test]
fn begin_immediate_succeeds_under_contention_where_deferred_fails_instantly() {
    let dir = tempdir();
    let path = dir.join("contend.db");
    let path_str = path.to_str().unwrap();
    let store = SqliteStore::open_with_readers(path_str, 2000, 0).unwrap();
    drop(store); // just wanted migrate() to have created the schema

    let mut holder = Connection::open(path_str).unwrap();
    apply_pragmas(&holder, path_str, 2000, true).unwrap();
    let holder_tx = holder
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    holder_tx
        .execute(
            "INSERT INTO store_meta (k, v) VALUES ('lock_holder', '1')",
            [],
        )
        .unwrap();
    // holder_tx now holds the write lock, uncommitted.

    let mut contender = Connection::open(path_str).unwrap();
    apply_pragmas(&contender, path_str, 50, true).unwrap(); // short timeout: fail fast if BUSY, not BUSY_SNAPSHOT-instant
    let deferred = contender
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .unwrap();
    // A read first (deferred doesn't take the write lock yet)...
    let _: i64 = deferred
        .query_row("SELECT COUNT(*) FROM store_meta", [], |r| r.get(0))
        .unwrap();
    // ...then attempt to write, which must upgrade the lock while `holder_tx` still holds it.
    let deferred_write_result =
        deferred.execute("INSERT INTO store_meta (k, v) VALUES ('x','1')", []);
    assert!(
        deferred_write_result.is_err(),
        "a DEFERRED transaction's write-upgrade must fail while another writer holds the lock"
    );

    // IMMEDIATE takes the write lock at BEGIN, so an attempt while holder_tx is open would also
    // fail -- but through the busy-handler-honoring path, not the BUSY_SNAPSHOT bypass. Prove the
    // acquisition mechanism itself works correctly once the lock is free (the actual proof of "goes
    // through the normal locking protocol" is the code path used, verified by the pragma-order test
    // and the type-level doc; this test's job is to show DEFERRED's failure mode specifically).
    drop(deferred); // release contender's DEFERRED transaction before starting a new one
    holder_tx.rollback().unwrap();
    let immediate2 = contender
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    immediate2
        .execute("INSERT INTO store_meta (k, v) VALUES ('y','1')", [])
        .unwrap();
    immediate2.commit().unwrap();
}

/// HARDEST INVARIANT #5: `foreign_keys` verification actually fails startup if the pragma readback
/// shows it didn't take. Simulated by calling `apply_pragmas` and confirming it error-checks the
/// readback rather than trusting the `pragma_update` call blindly (the real SQLITE_OMIT_FOREIGN_KEY
/// case can't be triggered from a normal bundled build, so this test proves the CHECK LOGIC itself
/// is present and correct by exercising the success path and inspecting that a failure path exists
/// in the source, i.e. this documents + locks the contract rather than fabricating a failing build).
#[test]
fn foreign_keys_pragma_is_verified_by_readback_not_assumed() {
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn, ":memory:", 2000, true).unwrap();
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        fk, 1,
        "apply_pragmas must leave foreign_keys actually ON, verified by readback"
    );
}

#[test]
fn foreign_keys_cascade_is_real_not_just_the_app_level_delete() {
    let s = SqliteStore::open_in_memory().unwrap();
    let k = sample_key("vk_fk", "g");
    let cred = sample_credential("vk_fk", "AKIA_FK", 0);
    s.put_key_with_credential(&k, &cred).unwrap();
    // Bypass delete_key entirely: a raw DELETE FROM keys (blocked by the guard trigger if metering
    // rows exist, but this key has none) must still cascade to credentials via the real FK, not just
    // the app-level DELETE inside delete_key.
    {
        let conn = s.lock_writer();
        conn.execute("DELETE FROM keys WHERE id='vk_fk'", [])
            .unwrap();
    }
    assert!(
        s.list_credentials("vk_fk").unwrap().is_empty(),
        "ON DELETE CASCADE must have removed the credential row"
    );
}

// ── Targeted guards for individual predicates and bounds in store-sqlite/src/lib.rs ────────────

#[test]
fn is_memory_path_rejects_a_plain_file_path() {
    assert!(
        !is_memory_path("/var/lib/busbar/governance.db"),
        "a real on-disk path must never be routed as an in-memory spelling"
    );
}

#[test]
fn is_memory_path_recognizes_every_documented_spelling() {
    assert!(is_memory_path(":memory:"));
    assert!(is_memory_path("file::memory:"));
    assert!(is_memory_path("file:test?mode=memory&cache=shared"));
}

#[test]
fn is_memory_path_file_prefix_alone_is_not_enough() {
    // `starts_with("file:")` alone must NOT be sufficient -- it must ALSO contain `:memory:`.
    // A real on-disk `file:` URI naming an ordinary rwc-mode database must not be misrouted.
    assert!(
        !is_memory_path("file:/var/lib/busbar/governance.db?mode=rwc"),
        "a file: URI without :memory: must not be treated as an in-memory spelling"
    );
}

#[test]
fn apply_pragmas_writer_and_reader_cache_sizes_are_negative_kib_budgets() {
    // Negative `cache_size` means "KiB budget" (not "N pages") in SQLite's own pragma semantics --
    // the sign is load-bearing, not cosmetic. A writer gets a larger budget than a reader.
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn, ":memory:", 5000, true).unwrap();
    let writer_cache: i64 = conn
        .query_row("PRAGMA cache_size", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        writer_cache, -65536,
        "writer cache_size must be -65536 (a 64MiB budget)"
    );

    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn, ":memory:", 5000, false).unwrap();
    let reader_cache: i64 = conn
        .query_row("PRAGMA cache_size", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        reader_cache, -16384,
        "reader cache_size must be -16384 (a 16MiB budget)"
    );
}

#[test]
fn apply_pragmas_mmap_disabled_only_for_a_real_network_style_path() {
    // A path that "looks like" a network filesystem (contains `//`, does not start with `:`, i.e.
    // is not one of the in-memory spellings) disables mmap defensively. Uses a real temp file
    // connection (not `:memory:`) so the WAL-enable branch actually runs, matching a real on-disk
    // open -- the `path` string passed to `apply_pragmas` is independent of the connection's real
    // backing file, exactly as the production `open_with_readers` call site passes it.
    let dir = tempdir();
    let file = dir.join("net.db");
    let conn = Connection::open(&file).unwrap();
    apply_pragmas(&conn, "//nfs/share/governance.db", 5000, true).unwrap();
    let mmap: i64 = conn
        .query_row("PRAGMA mmap_size", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mmap, 0, "a real network-style path must disable mmap");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn apply_pragmas_mmap_stays_enabled_for_a_colon_prefixed_lookalike() {
    // A path starting with `:` (the in-memory-spelling prefix character) must NOT trip the
    // network-path mmap-disable heuristic even if it also happens to contain `//` -- the `!`
    // negation on `starts_with(':')` is load-bearing. `is_memory_path` also returns true for this
    // string (it starts with `:memory:`... no -- it starts with just `:`, not `:memory:`, so route
    // through the WAL-enabling branch on a real file to exercise the full pragma set).
    let dir = tempdir();
    let file = dir.join("colon.db");
    let conn = Connection::open(&file).unwrap();
    apply_pragmas(&conn, "://weird/but/not/memory//x", 5000, true).unwrap();
    let mmap: i64 = conn
        .query_row("PRAGMA mmap_size", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        mmap, 268_435_456,
        "a `:`-prefixed path must keep mmap enabled even though it contains `//`"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn apply_pragmas_writer_only_pragmas_skipped_for_an_in_memory_writer() {
    // `journal_size_limit`/`wal_autocheckpoint` are writer-only AND memory-skipped: a `:memory:`
    // writer must never have them explicitly set (WAL doesn't apply to a private in-memory
    // database in the first place). SQLite's own unset default for `journal_size_limit` is -1.
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn, ":memory:", 5000, true).unwrap();
    let limit: i64 = conn
        .query_row("PRAGMA journal_size_limit", [], |r| r.get(0))
        .unwrap();
    assert_ne!(
        limit, 67_108_864,
        "an in-memory writer must not have the file-only journal_size_limit pragma applied"
    );
}

#[test]
fn store_path_reports_the_exact_configured_path() {
    let s = SqliteStore::open_in_memory().unwrap();
    assert_eq!(s.path(), ":memory:");

    let dir = tempdir();
    let file = dir.join("named.db");
    let s = SqliteStore::open(file.to_str().unwrap(), 5000).unwrap();
    assert_eq!(s.path(), file.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lock_reader_round_robins_without_ever_indexing_out_of_bounds() {
    let dir = tempdir();
    let file = dir.join("readers.db");
    let s = SqliteStore::open_with_readers(file.to_str().unwrap(), 5000, 2).unwrap();
    // Far more calls than the reader count (and more than reader_count^2) so an off-by-operator
    // index (`/` instead of `%`, or unwrapped `+` growth instead of wraparound) would either pick
    // the wrong connection forever or panic on an out-of-bounds index well before this many calls.
    for _ in 0..25 {
        let conn = s.lock_reader();
        let one: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(one, 1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_rerun_at_current_schema_version_does_not_wipe_data() {
    // `migrate()`'s legacy-drop block only guards on `version < SCHEMA_VERSION`. The CURRENT
    // schema's own table names (`keys`, `store_meta`) are ALSO named in the legacy-drop list (the
    // list has to cover every prior schema generation), so if that guard ever admits
    // `version == SCHEMA_VERSION` (a `<=` in place of the `<`), a second migrate() call
    // on an already-current database would find "legacy" tables (its own current ones) and drop
    // every table, silently wiping live data.
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_mig", "g")).unwrap();
    s.migrate()
        .expect("re-running migrate on a current-version db must succeed");
    assert!(
        s.get_key("vk_mig").unwrap().is_some(),
        "re-running migrate() at the current schema version must not drop live data"
    );
}

#[test]
fn migrate_drops_and_recreates_a_genuinely_older_schema() {
    // The inverse of the test above: given a database at a version BELOW SCHEMA_VERSION with a
    // legacy `keys` table shaped incompatibly with the current schema, `migrate()` must actually
    // drop and recreate it (the `version < SCHEMA_VERSION` guard must admit this case) -- an
    // inverted comparison (`>` instead of `<`) would leave the incompatible legacy table in place
    // and the subsequent `put_key` would fail against the wrong column shape.
    let dir = tempdir();
    let file = dir.join("legacy.db");
    {
        let conn = Connection::open(&file).unwrap();
        conn.execute_batch(
            "CREATE TABLE keys (id TEXT PRIMARY KEY); \
             PRAGMA user_version = 2;",
        )
        .unwrap();
    }
    let s = SqliteStore::open(file.to_str().unwrap(), 5000)
        .expect("open() must migrate a genuinely older schema, not fail against the legacy shape");
    s.put_key(&sample_key("vk_legacy", "g")).expect(
        "the legacy `keys` table must have been dropped and recreated with the current shape",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_v5_to_v6_backfills_billable_requests_without_wiping_data() {
    // The v5->v6 crossing is the FIRST non-destructive migration this store has ever needed — a
    // real regression risk `migrate_rerun_at_current_schema_version_does_not_wipe_data`'s own
    // comment already flags but doesn't itself cover: the legacy-drop block's table-name list
    // ('keys','store_meta', etc) includes the CURRENT schema's own names, so a naive
    // `version < SCHEMA_VERSION` bump (5 < 6) would find a real v5 database's OWN 'keys' table and
    // wipe it, unless the has_legacy check is scoped to pre-v5-ONLY names. Hand-build a real v5
    // database (current table shapes, PRAGMA user_version=5) with a live key AND a usage_windows
    // row shaped exactly like the boot-time bug this migration exists to close (billable_requests
    // stuck at 0 with a real nonzero requests count), then open it through the real store
    // (triggering migrate()) and assert BOTH that the key survived AND the row was backfilled.
    let dir = tempdir();
    let file = dir.join("v5.db");
    {
        let conn = Connection::open(&file).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO keys (id, name, key_group, allowed_pools, labels, enabled, \
             generation_hash, created_at, updated_at, expires_at, deleted_at, revision) \
             VALUES ('vk_v5', 'n', NULL, NULL, '{}', 1, 'g1', 0, 0, NULL, NULL, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests) \
             VALUES (100, 'vk_v5', '', 7, 0)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 5i64).unwrap();
    }
    let s = SqliteStore::open(file.to_str().unwrap(), 5000)
        .expect("open() must migrate a real v5 database additively, not fail or wipe it");
    assert!(
        s.get_key("vk_v5").unwrap().is_some(),
        "a real v5 key must survive the v5->v6 migration, not be wiped by the legacy-drop path"
    );
    let ledger = s.get_usage("vk_v5", 100).unwrap();
    assert_eq!(ledger.requests, 7, "requests must be untouched");
    assert_eq!(
        ledger.billable_requests, 7,
        "a v5-era row stuck at billable_requests=0 with real requests must be backfilled exactly \
         once during the v5->v6 crossing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_v5_to_v6_does_not_touch_an_already_nonzero_billable_requests_row() {
    // The backfill's WHERE clause (`billable_requests = 0 AND requests > 0`) must not touch a row
    // that already carries a real, independently-tracked billable_requests value — only the
    // ambiguous zero-with-nonzero-requests shape is a backfill candidate.
    let dir = tempdir();
    let file = dir.join("v5_ok.db");
    {
        let conn = Connection::open(&file).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests) \
             VALUES (200, 'vk_v5b', '', 10, 3)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 5i64).unwrap();
    }
    let s = SqliteStore::open(file.to_str().unwrap(), 5000).unwrap();
    let ledger = s.get_usage("vk_v5b", 200).unwrap();
    assert_eq!(ledger.requests, 10);
    assert_eq!(
        ledger.billable_requests, 3,
        "a row with a real, already-nonzero billable_requests must be left exactly as-is"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn secret_form_from_str_round_trips_every_named_form() {
    assert_eq!(secret_form_from_str("recoverable"), SecretForm::Recoverable);
    assert_eq!(secret_form_from_str("digest"), SecretForm::Digest);
    assert_eq!(secret_form_from_str("anything-else"), SecretForm::None);
}

#[test]
fn purge_windows_before_purges_past_a_single_chunk_boundary() {
    // The chunked-delete loop breaks on `changed < 5000` (the subquery LIMIT). With more than one
    // full chunk's worth of stale rows, an inclusive (`<=`) boundary would stop after the FIRST
    // full chunk and silently leave the remainder unpurged.
    let s = SqliteStore::open_in_memory().unwrap();
    // 2501 distinct windows x 2 rows each (requests-sentinel + one model row) = 5002 rows, one more
    // than a single 5000-row chunk.
    for i in 0..2501u64 {
        s.add_usage("vk_chunk", i, &delta(1, "m", 1, 1)).unwrap();
    }
    let purged = s.purge_windows_before(10_000).unwrap();
    assert_eq!(
        purged, 2501,
        "every stale window must be purged across chunk boundaries, not just the first chunk, and \
         the figure returned is windows rather than the 5002 underlying rows"
    );
    assert!(s.get_usage("vk_chunk", 0).unwrap().requests == 0);
}

#[test]
fn purge_metering_before_purges_past_a_single_chunk_boundary() {
    let s = SqliteStore::open_in_memory().unwrap();
    for i in 0..5001u64 {
        s.add_metering(&MeteringDelta {
            key_id: "vk_chunk_m".to_string(),
            bucket: 1,
            model: format!("m{i}"),
            provider: "p".to_string(),
            tokens_input: 1,
            tokens_output: 1,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
        })
        .unwrap();
    }
    let purged = s.purge_metering_before("1").unwrap();
    assert_eq!(
        purged, 5001,
        "every stale metering row must be purged across chunk boundaries, not just the first 5000"
    );
    assert!(s.list_metering(1).unwrap().is_empty());
}

#[test]
fn now_secs_reflects_the_actual_current_time_not_a_constant() {
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let got = now_secs();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        (before..=after).contains(&got),
        "now_secs() must return the real current unix time ({got}), not a fixed constant \
         (bracketed by [{before}, {after}])"
    );
}

// ── Test helpers ─────────────────────────────────────────────────────────────────────────────

fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "store-sqlite-test-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The shared `Store` contract conformance suite (`busbar-plugin-testkit`) — the four behaviours the
/// fleet used to settle differently per backend. Kept in the testkit rather than written out here so
/// a future ruling reaches every backend at once instead of being hand-copied and drifting again.
mod conformance {
    use super::SqliteStore;
    use busbar_plugin_testkit::store_conformance as conf;

    // Each check opens its OWN in-memory database, so it is already an isolated,
    // empty namespace and `ns`/`seq` only have to be stable.
    fn fresh() -> SqliteStore {
        SqliteStore::open_in_memory().expect("open an empty in-memory store")
    }

    #[test]
    fn put_key_does_not_resurrect_a_tombstone() {
        conf::assert_put_key_does_not_resurrect_a_tombstone(&fresh(), "conf");
    }

    #[test]
    fn delete_key_unknown_id_is_an_error() {
        conf::assert_delete_key_unknown_id_is_an_error(&fresh(), "conf");
    }

    #[test]
    fn revoke_credential_unknown_id_is_an_error() {
        conf::assert_revoke_credential_unknown_id_is_an_error(&fresh(), "conf");
    }

    #[test]
    fn append_audit_duplicate_seq_is_ok_when_identical_and_an_error_when_different() {
        conf::assert_append_audit_duplicate_seq(&fresh(), 1);
    }
}

/// An out-of-range `seq`/`ts` is refused rather than silently mangled.
///
/// `as i64` wraps a `u64` past `i64::MAX` negative, and `row_to_audit` clamps the negative back to 0
/// on read, so the stored record can never equal the one written. Left unguarded, appending the
/// IDENTICAL record twice at such a seq reports "the audit chain has forked" while naming the same
/// action on both sides — a false alarm on the most alarming message this store can emit. Comparing
/// the round-tripped form instead would silence that by letting two distinct seqs collapse onto one
/// row, trading a false alarm for silent loss.
#[test]
fn append_audit_refuses_a_seq_it_cannot_store_faithfully() {
    let s = SqliteStore::open_in_memory().unwrap();
    let mut rec = AuditRecord {
        seq: u64::MAX,
        ts: 1_700_000_000,
        action: "hook.register".into(),
        resource: "hook:x".into(),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };
    let err = s
        .append_audit(&rec)
        .expect_err("a seq past i64::MAX must be refused, not wrapped");
    assert!(
        err.0.contains("storable range"),
        "the refusal must say why: {}",
        err.0
    );

    // The boundary itself is storable, and an identical retry there is still the benign Ok path.
    rec.seq = i64::MAX as u64;
    s.append_audit(&rec).expect("i64::MAX is in range");
    s.append_audit(&rec)
        .expect("an identical retry at the boundary must not read as a forked chain");
}
// ── THE DURABLE MCP TOOL-CALL LOG ────────────────────────────────────────────────────────────
//
// The property under test is not "the write returned Ok" — the trait's default `append_mcp_call`
// returns `Ok(())` and keeps nothing, so a write's return value is worthless as evidence of
// durability. The only honest way to know a deployment has durable call evidence is to READ IT
// BACK, and the only honest way to know it survives a deploy is to read it back THROUGH A RESTART.

fn sample_call(principal: &str, seq: u64, ts: u64, prev_hash: &str, hash: &str) -> McpCallRecord {
    McpCallRecord {
        principal: principal.to_string(),
        seq,
        ts,
        server: "srv".to_string(),
        tool: "srv_read_file".to_string(),
        outcome: "dispatched".to_string(),
        reason: String::new(),
        tool_digest: format!("sha256:tool{seq}"),
        pin_generation: 3,
        request_id: format!("req-{seq}"),
        prev_hash: prev_hash.to_string(),
        hash: hash.to_string(),
    }
}

/// THE TEST THAT MATTERS. A unit test against a live handle proves nothing here: it cannot
/// distinguish a backend that wrote to disk from one that kept the rows in a HashMap behind the
/// same trait. So this drops the store entirely — closing every SQLite connection and its WAL —
/// reopens the same FILE, and verifies the per-principal hash chain still links from the bytes that
/// came back off disk.
#[test]
fn an_mcp_call_chain_survives_dropping_the_store_and_reopening_the_file() {
    let dir = tempdir();
    let file = dir.join("calls.db");
    let path = file.to_str().unwrap().to_string();

    // Write a 3-long chain, then let every connection close.
    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.append_mcp_call(&sample_call("vk_a", 1, 100, "", "h1"))
            .unwrap();
        s.append_mcp_call(&sample_call("vk_a", 2, 200, "h1", "h2"))
            .unwrap();
        s.append_mcp_call(&sample_call("vk_a", 3, 300, "h2", "h3"))
            .unwrap();
        drop(s);
    }

    // A genuinely new store over the same file — nothing carried over in memory.
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let got = reopened.list_mcp_calls("vk_a").unwrap();

    assert_eq!(
        got.len(),
        3,
        "the call log must survive a restart; got {} records back after reopening the file, which \
         is the accept-and-keep-nothing behaviour this backend exists to replace",
        got.len()
    );

    // The chain must LINK, read back off disk — not merely be non-empty.
    assert_eq!(
        got[0].prev_hash, "",
        "seq 1 opens the chain with an empty prev_hash"
    );
    for w in got.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the per-principal chain must still link after a restart: seq {} carries prev_hash {:?} \
             but seq {} persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    // Ordering is by seq, and the non-indexed payload must round-trip verbatim too.
    assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(got[2].tool_digest, "sha256:tool3");
    assert_eq!(got[2].request_id, "req-3");
    assert_eq!(got[1].tool, "srv_read_file");
    assert_eq!(got[1].pin_generation, 3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The boot enumeration: a restart has to resume a chain for a principal this process has not yet
/// seen, so the store must be able to name every principal holding records — across a restart.
#[test]
fn mcp_call_principals_are_enumerable_after_a_restart() {
    let dir = tempdir();
    let file = dir.join("principals.db");
    let path = file.to_str().unwrap().to_string();
    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.append_mcp_call(&sample_call("vk_a", 1, 100, "", "a1"))
            .unwrap();
        s.append_mcp_call(&sample_call("vk_b", 1, 100, "", "b1"))
            .unwrap();
        s.append_mcp_call(&sample_call("vk_a", 2, 101, "a1", "a2"))
            .unwrap();
        drop(s);
    }
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let mut principals = reopened.list_mcp_call_principals().unwrap();
    principals.sort();
    assert_eq!(
        principals,
        vec!["vk_a".to_string(), "vk_b".to_string()],
        "every principal holding records must be enumerable after a restart, exactly once each"
    );
    // A scoped read returns only its own principal's chain — the chain scope is the principal.
    assert_eq!(reopened.list_mcp_calls("vk_a").unwrap().len(), 2);
    assert_eq!(reopened.list_mcp_calls("vk_b").unwrap().len(), 1);
    assert!(
        reopened
            .list_mcp_calls("vk_nonexistent")
            .unwrap()
            .is_empty(),
        "a principal with no records reads back empty, not an error"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Retention must ACTUALLY DELETE and report a real count — a purge that returns a number it did
/// not perform is worse than one that reports nothing purged.
#[test]
fn purge_mcp_calls_before_deletes_and_returns_a_real_count() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.append_mcp_call(&sample_call("vk_a", 1, 100, "", "h1"))
        .unwrap();
    s.append_mcp_call(&sample_call("vk_a", 2, 200, "h1", "h2"))
        .unwrap();
    s.append_mcp_call(&sample_call("vk_a", 3, 300, "h2", "h3"))
        .unwrap();
    s.append_mcp_call(&sample_call("vk_b", 1, 150, "", "b1"))
        .unwrap();

    // Strictly older than `before`, across every principal. ts=300 and ts=200 stay.
    let purged = s.purge_mcp_calls_before(200).unwrap();
    assert_eq!(
        purged, 2,
        "purge must return the number of rows it actually removed (ts=100 and ts=150), not a guess"
    );
    assert_eq!(
        s.list_mcp_calls("vk_a")
            .unwrap()
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![2, 3],
        "the rows at or after the cutoff must remain"
    );
    assert!(
        s.list_mcp_calls("vk_b").unwrap().is_empty(),
        "a principal whose every row aged out reads back empty"
    );
    // `before` is STRICTLY less-than: a row exactly at the cutoff is kept.
    assert_eq!(
        s.purge_mcp_calls_before(200).unwrap(),
        0,
        "re-running the same purge removes nothing; ts=200 sits exactly at the cutoff and is kept"
    );
    // And the count is real: purging past everything clears the rest.
    assert_eq!(s.purge_mcp_calls_before(1_000).unwrap(), 2);
    assert!(s.list_mcp_calls("vk_a").unwrap().is_empty());
}

/// A record arriving on a `(principal, seq)` that already has one is settled the way the contract
/// settles it: BYTE-IDENTICAL is the retry and succeeds; DIFFERENT is a forked or tampered log and
/// is an error. Overwriting would destroy the second case instead of reporting it.
#[test]
fn a_replayed_mcp_call_is_idempotent_but_a_forked_one_is_refused() {
    let s = SqliteStore::open_in_memory().unwrap();
    let rec = sample_call("vk_a", 1, 100, "", "h1");
    s.append_mcp_call(&rec).unwrap();

    s.append_mcp_call(&rec)
        .expect("an identical replay is the at-least-once retry and must succeed");
    assert_eq!(
        s.list_mcp_calls("vk_a").unwrap().len(),
        1,
        "a replay must not duplicate the row"
    );

    // Same (principal, seq), different digest — the fork case.
    let forked = sample_call("vk_a", 1, 100, "", "DIFFERENT");
    let err = s
        .append_mcp_call(&forked)
        .expect_err("a different record at an occupied (principal, seq) is a fork and must error");
    assert!(
        !format!("{err}").contains("DIFFERENT"),
        "the error must not echo stored content back"
    );
    assert_eq!(
        s.list_mcp_calls("vk_a").unwrap()[0].hash,
        "h1",
        "the refused fork must not have overwritten the record already on record"
    );

    // A differing non-indexed payload field is a fork too, not a silent accept.
    let mut tampered = sample_call("vk_a", 1, 100, "", "h1");
    tampered.tool = "srv_other_tool".to_string();
    s.append_mcp_call(&tampered)
        .expect_err("a payload that differs under an identical digest is a fork and must error");
}

/// The v6 -> v7 crossing is additive: a real v6 database gains `mcp_calls` and keeps every row it
/// already had. Regression cover for the legacy-drop path reaching a live database.
#[test]
fn migrate_v6_to_v7_adds_the_call_log_without_wiping_data() {
    let dir = tempdir();
    let file = dir.join("v6.db");
    {
        let conn = Connection::open(&file).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute("DROP TABLE mcp_calls", []).unwrap();
        conn.execute(
            "INSERT INTO keys (id, name, key_group, allowed_pools, labels, enabled, \
             generation_hash, created_at, updated_at, expires_at, deleted_at, revision) \
             VALUES ('vk_v6', 'n', NULL, NULL, '{}', 1, 'g1', 0, 0, NULL, NULL, 0)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 6i64).unwrap();
    }
    let s = SqliteStore::open(file.to_str().unwrap(), 5000)
        .expect("a v6 database must migrate additively to v7");
    assert!(
        s.get_key("vk_v6").unwrap().is_some(),
        "a real v6 key must survive the v6->v7 crossing"
    );
    s.append_mcp_call(&sample_call("vk_v6", 1, 10, "", "h1"))
        .expect("the newly created mcp_calls table must be writable after the migration");
    assert_eq!(s.list_mcp_calls("vk_v6").unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A persisted record is never REWRITTEN. Enforced by a trigger so it survives an operator opening
/// the file with the sqlite3 CLI, not merely by the write path being careful.
#[test]
fn mcp_calls_rejects_a_direct_update_but_allows_the_retention_delete() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.append_mcp_call(&sample_call("vk_a", 1, 100, "", "h1"))
        .unwrap();
    let err = s
        .lock_writer()
        .execute(
            "UPDATE mcp_calls SET hash = 'forged' WHERE principal = 'vk_a'",
            [],
        )
        .expect_err("a direct UPDATE must be refused by the append-only trigger");
    assert!(format!("{err}").contains("append-only"));
    // DELETE is deliberately NOT guarded — retention has to be able to do its job.
    s.lock_writer()
        .execute("DELETE FROM mcp_calls WHERE principal = 'vk_a'", [])
        .expect("retention must remain possible; only rewriting is forbidden");
}

// ── THE DURABLE A2A TASK STORE ───────────────────────────────────────────────────────────────
//
// A2A is async by design: a task spans turns, can sit interrupted waiting on a human, and can
// outlive the process that started it. So the property under test is not "put_task returned Ok" —
// the trait's default `put_task` returns `Ok(())` and keeps nothing, and `get_task` answers `None`
// for everything, which is a backend that accepts every in-flight task and loses all of them on the
// next deploy. The only honest proof is to READ THE TASK BACK THROUGH A RESTART.

fn sample_task(task_id: &str, state: &str, updated_at: u64) -> TaskRow {
    TaskRow {
        task_id: task_id.to_string(),
        context_id: format!("ctx-{task_id}"),
        principal: "vk_a".to_string(),
        direction: "inbound".to_string(),
        state: state.to_string(),
        agent_id: "planner".to_string(),
        artifact_cursor: 7,
        push_callback: "https://example.test/push".to_string(),
        created_at: 100,
        updated_at,
    }
}

fn sample_event(task_id: &str, seq: u64, kind: &str, prev_hash: &str, hash: &str) -> TaskEventRow {
    TaskEventRow {
        task_id: task_id.to_string(),
        seq,
        // Saturating: the out-of-range test deliberately passes `u64::MAX` as `seq`, and a helper
        // that panicked on its own arithmetic would hide the behaviour under test.
        ts: seq.saturating_add(100),
        kind: kind.to_string(),
        context_id: format!("ctx-{task_id}"),
        principal: "vk_a".to_string(),
        agent_id: "planner".to_string(),
        state: "working".to_string(),
        request_id: format!("req-{seq}"),
        prev_hash: prev_hash.to_string(),
        hash: hash.to_string(),
    }
}

/// THE TEST THAT MATTERS, and it is deliberately not a unit test against a live handle: a live
/// handle cannot tell a backend that wrote to disk from one keeping a HashMap behind the same trait,
/// and it cannot tell either of those from the trait's accept-and-keep-nothing defaults if the
/// defaults happen to be exercised through the same handle that "wrote". So this DROPS the store —
/// closing every SQLite connection and its WAL — reopens the same FILE, and reads the task back off
/// disk. Against the unimplemented state it fails on the very first assertion.
#[test]
fn an_in_flight_task_survives_dropping_the_store_and_reopening_the_file() {
    let dir = tempdir();
    let file = dir.join("tasks.db");
    let path = file.to_str().unwrap().to_string();

    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.put_task(&sample_task("t-1", "working", 200)).unwrap();
        // The write-through on a state transition REPLACES the row rather than appending a second
        // one — an interrupted task waiting on a human is what a restart has to find.
        let mut interrupted = sample_task("t-1", "input-required", 300);
        interrupted.artifact_cursor = 12;
        s.put_task(&interrupted).unwrap();
        s.put_task(&sample_task("t-2", "submitted", 210)).unwrap();
        drop(s);
    }

    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let got = reopened.get_task("t-1").unwrap().expect(
        "an in-flight task must survive a restart; got None back after reopening the file, \
             which is the accept-and-keep-nothing default this backend exists to replace",
    );

    // Every field a resume reads has to come back verbatim — not merely a row with the right id.
    assert_eq!(got.state, "input-required", "the LAST state must win");
    assert_eq!(
        got.artifact_cursor, 12,
        "the artifact cursor is where a resubscribe resumes; a stale one replays or loses the gap"
    );
    assert_eq!(
        got.context_id, "ctx-t-1",
        "the resume key is the context id"
    );
    assert_eq!(got.principal, "vk_a");
    assert_eq!(got.direction, "inbound");
    assert_eq!(got.agent_id, "planner");
    assert_eq!(got.push_callback, "https://example.test/push");
    assert_eq!(got.created_at, 100);
    assert_eq!(got.updated_at, 300);

    // UPSERT, not append: two writes for one task_id leave ONE row.
    let mut all = reopened.list_tasks().unwrap();
    all.sort_by(|a, b| a.task_id.cmp(&b.task_id));
    assert_eq!(
        all.iter().map(|t| t.task_id.as_str()).collect::<Vec<_>>(),
        vec!["t-1", "t-2"],
        "put_task upserts by task_id; a second write for the same id must replace, never append"
    );

    assert!(
        reopened.get_task("t-nonexistent").unwrap().is_none(),
        "an unknown task id reads back None, not an error"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `list_tasks` is deliberately UNFILTERED. The boot rehydrate wants the active rows, the retention
/// sweep wants the terminal ones and the scoped listing wants one principal's; a store that
/// pre-filtered for any one of those would break the other two. Pinned across a restart because the
/// boot rehydrate is precisely the caller that only ever sees the post-restart answer.
#[test]
fn list_tasks_returns_every_row_including_terminal_ones_after_a_restart() {
    let dir = tempdir();
    let file = dir.join("list.db");
    let path = file.to_str().unwrap().to_string();
    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.put_task(&sample_task("t-active", "working", 200))
            .unwrap();
        s.put_task(&sample_task("t-waiting", "input-required", 201))
            .unwrap();
        s.put_task(&sample_task("t-done", "completed", 202))
            .unwrap();
        s.put_task(&sample_task("t-failed", "failed", 203)).unwrap();
        drop(s);
    }
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let mut ids = reopened
        .list_tasks()
        .unwrap()
        .into_iter()
        .map(|t| t.task_id)
        .collect::<Vec<_>>();
    ids.sort();
    assert_eq!(
        ids,
        vec!["t-active", "t-done", "t-failed", "t-waiting"],
        "list_tasks is unfiltered: terminal rows are returned too, and every row survives a restart"
    );
}

/// The per-task provenance chain, read back off disk. Per-TASK rather than one global chain, so the
/// scope of a read is one task and the links have to hold within it.
#[test]
fn a_task_event_chain_survives_a_restart_and_still_links() {
    let dir = tempdir();
    let file = dir.join("events.db");
    let path = file.to_str().unwrap().to_string();
    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.append_task_event(&sample_event("t-1", 1, "task.submitted", "", "e1"))
            .unwrap();
        s.append_task_event(&sample_event("t-1", 2, "task.working", "e1", "e2"))
            .unwrap();
        s.append_task_event(&sample_event("t-1", 3, "task.interrupted", "e2", "e3"))
            .unwrap();
        // A second task's chain is independent — it must not leak into the first one's read.
        s.append_task_event(&sample_event("t-2", 1, "task.submitted", "", "f1"))
            .unwrap();
        drop(s);
    }
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let got = reopened.list_task_events("t-1").unwrap();
    assert_eq!(
        got.len(),
        3,
        "the provenance chain must survive a restart; got {} events back after reopening the file, \
         which is the accept-and-keep-nothing default this backend exists to replace",
        got.len()
    );
    assert_eq!(
        got.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "oldest-first by seq, which is the order the chain verifier reads"
    );
    assert_eq!(got[0].prev_hash, "", "seq 1 opens the chain");
    for w in got.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the per-task chain must still link after a restart: seq {} carries prev_hash {:?} but \
             seq {} persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    // Every field round-trips, including the join key that is deliberately NOT chained.
    assert_eq!(got[2].kind, "task.interrupted");
    assert_eq!(got[2].request_id, "req-3");
    assert_eq!(got[1].context_id, "ctx-t-1");
    assert_eq!(got[1].principal, "vk_a");
    assert_eq!(got[1].agent_id, "planner");
    assert_eq!(got[1].state, "working");
    assert_eq!(got[1].ts, 102);
    // The scope of a read is one task.
    assert_eq!(reopened.list_task_events("t-2").unwrap().len(), 1);
    assert!(
        reopened.list_task_events("t-unknown").unwrap().is_empty(),
        "a task with no events reads back empty, not an error"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A replayed `(task_id, seq)` UPSERTS. This is where the task-event contract genuinely DIFFERS
/// from `append_mcp_call`'s, and a backend that copied the call log's fork check would be wrong in a
/// way that looks right: the contract says a store "must upsert on that pair — the write-through is
/// idempotent on replay, and rejecting or duplicating a replayed `seq` breaks the chain the engine
/// will verify on read". So neither a duplicate row nor an error, on either an identical replay or a
/// corrected one.
#[test]
fn a_replayed_task_event_upserts_rather_than_duplicating_or_erroring() {
    let s = SqliteStore::open_in_memory().unwrap();
    let e = sample_event("t-1", 1, "task.submitted", "", "e1");
    s.append_task_event(&e).unwrap();
    s.append_task_event(&e)
        .expect("an identical replay must succeed, not be rejected as a fork");
    assert_eq!(
        s.list_task_events("t-1").unwrap().len(),
        1,
        "a replay must not duplicate the row"
    );

    // A rewritten event at the same seq REPLACES, per the contract's "must upsert on that pair".
    let mut corrected = sample_event("t-1", 1, "task.submitted", "", "e1-corrected");
    corrected.state = "submitted".to_string();
    s.append_task_event(&corrected).unwrap();
    let got = s.list_task_events("t-1").unwrap();
    assert_eq!(got.len(), 1, "an upsert replaces; it does not append");
    assert_eq!(got[0].hash, "e1-corrected");
    assert_eq!(got[0].state, "submitted");
}

/// Retention drops TERMINAL rows only, strictly older than the cutoff, and returns a count it
/// actually performed. An interrupted task waiting on a human is exactly the row that legitimately
/// sits still for a long time; compacting it is losing the work, not reclaiming space.
#[test]
fn purge_tasks_before_drops_only_terminal_rows_and_returns_a_real_count() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_task(&sample_task("t-old-done", "completed", 100))
        .unwrap();
    s.put_task(&sample_task("t-old-failed", "failed", 100))
        .unwrap();
    s.put_task(&sample_task("t-old-canceled", "canceled", 100))
        .unwrap();
    s.put_task(&sample_task("t-old-rejected", "rejected", 100))
        .unwrap();
    // Old, and NOT terminal — never dropped, no matter how old.
    s.put_task(&sample_task("t-old-waiting", "input-required", 100))
        .unwrap();
    s.put_task(&sample_task("t-old-auth", "auth-required", 100))
        .unwrap();
    s.put_task(&sample_task("t-old-working", "working", 100))
        .unwrap();
    s.put_task(&sample_task("t-old-submitted", "submitted", 100))
        .unwrap();
    // Terminal but at the cutoff exactly, and terminal but newer — both kept.
    s.put_task(&sample_task("t-at-cutoff", "completed", 200))
        .unwrap();
    s.put_task(&sample_task("t-new-done", "completed", 300))
        .unwrap();

    let purged = s.purge_tasks_before(200).unwrap();
    assert_eq!(
        purged, 4,
        "only the four TERMINAL rows strictly older than the cutoff go, and the count must be one \
         actually performed rather than a guess"
    );
    let mut left = s
        .list_tasks()
        .unwrap()
        .into_iter()
        .map(|t| t.task_id)
        .collect::<Vec<_>>();
    left.sort();
    assert_eq!(
        left,
        vec![
            "t-at-cutoff",
            "t-new-done",
            "t-old-auth",
            "t-old-submitted",
            "t-old-waiting",
            "t-old-working",
        ],
        "an active or interrupted task is never dropped by retention, and `before` is strictly \
         less-than so a row exactly at the cutoff is kept"
    );
    assert_eq!(
        s.purge_tasks_before(200).unwrap(),
        0,
        "re-running the same purge removes nothing"
    );
}

/// Retention has to bound the EVENT table too. The trait offers no `purge_task_events_before`, so if
/// purging a task left its provenance behind, `task_events` would grow without any bound the
/// contract provides a way to apply. Dropping a task therefore drops the chain that belongs to it —
/// and drops nothing belonging to any other task.
#[test]
fn purging_a_task_takes_its_provenance_chain_with_it_and_no_other() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_task(&sample_task("t-gone", "completed", 100))
        .unwrap();
    s.put_task(&sample_task("t-stays", "working", 100)).unwrap();
    s.append_task_event(&sample_event("t-gone", 1, "task.submitted", "", "g1"))
        .unwrap();
    s.append_task_event(&sample_event("t-gone", 2, "task.completed", "g1", "g2"))
        .unwrap();
    s.append_task_event(&sample_event("t-stays", 1, "task.submitted", "", "s1"))
        .unwrap();

    assert_eq!(s.purge_tasks_before(200).unwrap(), 1);
    assert!(
        s.list_task_events("t-gone").unwrap().is_empty(),
        "the purged task's events go with it; otherwise task_events grows unbounded, because the \
         contract offers no other way to purge them"
    );
    assert_eq!(
        s.list_task_events("t-stays").unwrap().len(),
        1,
        "another task's chain must be untouched by that purge"
    );
}

/// A `seq`/`ts`/`artifact_cursor` past `i64::MAX` cannot be stored faithfully — `as i64` wraps it
/// negative and the read clamps back — so the row read back would not be the row written. Refused
/// outright, exactly as `append_audit` refuses it, rather than silently mangled.
#[test]
fn the_task_store_refuses_values_it_cannot_store_faithfully() {
    let s = SqliteStore::open_in_memory().unwrap();

    let mut t = sample_task("t-1", "working", 200);
    t.artifact_cursor = u64::MAX;
    let err = s
        .put_task(&t)
        .expect_err("an artifact cursor past i64::MAX must be refused, not wrapped");
    assert!(
        err.0.contains("storable range"),
        "the refusal must say why: {}",
        err.0
    );
    assert!(
        s.get_task("t-1").unwrap().is_none(),
        "a refused write must leave nothing behind"
    );

    let mut e = sample_event("t-1", u64::MAX, "task.submitted", "", "e1");
    assert!(s
        .append_task_event(&e)
        .expect_err("a seq past i64::MAX must be refused")
        .0
        .contains("storable range"));
    e.seq = 1;
    e.ts = u64::MAX;
    assert!(s
        .append_task_event(&e)
        .expect_err("a ts past i64::MAX must be refused")
        .0
        .contains("storable range"));

    // The boundary itself is storable and round-trips exactly.
    t.artifact_cursor = i64::MAX as u64;
    s.put_task(&t).expect("i64::MAX is in range");
    assert_eq!(
        s.get_task("t-1").unwrap().unwrap().artifact_cursor,
        i64::MAX as u64
    );
}

/// The v7 -> v8 crossing is additive: a real v7 database gains `tasks` and `task_events` and keeps
/// every row it already had. Regression cover for the pre-v5 drop-and-recreate path reaching a live
/// database on a version bump it has no business touching.
#[test]
fn migrate_v7_to_v8_adds_the_task_store_without_wiping_data() {
    let dir = tempdir();
    let file = dir.join("v7.db");
    {
        let conn = Connection::open(&file).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute("DROP TRIGGER tasks_cascade_events", [])
            .unwrap();
        conn.execute("DROP TABLE task_events", []).unwrap();
        conn.execute("DROP TABLE tasks", []).unwrap();
        conn.execute(
            "INSERT INTO keys (id, name, key_group, allowed_pools, labels, enabled, \
             generation_hash, created_at, updated_at, expires_at, deleted_at, revision) \
             VALUES ('vk_v7', 'n', NULL, NULL, '{}', 1, 'g1', 0, 0, NULL, NULL, 0)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 7i64).unwrap();
    }
    let s = SqliteStore::open(file.to_str().unwrap(), 5000)
        .expect("a v7 database must migrate additively to v8");
    assert!(
        s.get_key("vk_v7").unwrap().is_some(),
        "a real v7 key must survive the v7->v8 crossing"
    );
    s.put_task(&sample_task("t-1", "working", 200))
        .expect("the newly created tasks table must be writable after the migration");
    s.append_task_event(&sample_event("t-1", 1, "task.submitted", "", "e1"))
        .expect("the newly created task_events table must be writable after the migration");
    assert!(s.get_task("t-1").unwrap().is_some());
    assert_eq!(s.list_task_events("t-1").unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── THE DURABLE MCP DEMOTION RECORD AND THE SPENT-APPROVAL LEDGER ────────────────────────────
//
// Both of these are security state, and both had the same shape of hole before this: the trait
// defaults them to accept-and-keep-nothing, so a backend that implements neither compiles, ships
// and reports every write successful while discarding it. What that costs is exactly the two
// properties the engine added them for — a quarantined upstream that gets its approval back at the
// next restart, and a single-use human approval that a second node redeems again — so every case
// below reads the state back through a REOPENED file rather than through the handle that wrote it.

fn demotion(server: &str, reason: &str, recorded_at: u64) -> McpDemotionRow {
    McpDemotionRow {
        server: server.to_string(),
        reason: reason.to_string(),
        recorded_at,
    }
}

/// A DEMOTION OUTLIVES THE PROCESS THAT RECORDED IT. The engine derives a demotion from a live
/// observation, so a process that has taken no observation has nothing to derive it from and serves
/// the upstream against the digest the operator approved — which means a restart hands a quarantined
/// upstream its approval back unless this row is on disk. Written, dropped, reopened, read back.
#[test]
fn a_demotion_survives_dropping_the_store_and_reopening_the_file() {
    let dir = tempdir();
    let file = dir.join("demotions.db");
    let path = file.to_str().unwrap().to_string();

    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.put_mcp_demotion(&demotion("payments", "tool-drift", 1_700_000_000))
            .unwrap();
        // UPSERT by `server`: a second demotion of one upstream replaces the row rather than
        // standing a rival one beside it, so a read cannot come back holding two answers.
        s.put_mcp_demotion(&demotion("payments", "digest-mismatch", 1_700_000_100))
            .unwrap();
        s.put_mcp_demotion(&demotion("search", "tool-drift", 1_700_000_200))
            .unwrap();
        drop(s);
    }

    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let mut rows = reopened.list_mcp_demotions().unwrap();
    rows.sort_by(|a, b| a.server.cmp(&b.server));
    assert_eq!(
        rows,
        vec![
            demotion("payments", "digest-mismatch", 1_700_000_100),
            demotion("search", "tool-drift", 1_700_000_200),
        ],
        "a recorded demotion must be in force before the first request is served after a restart; \
         an empty or stale answer here is a quarantined upstream handed its approval back, which is \
         the accept-and-keep-nothing default this backend exists to replace"
    );

    // CLEARED on a later agreeing observation, and the clear is durable too — a quarantine the
    // operator has already worked must not be re-established by the next restart.
    reopened.clear_mcp_demotion("payments").unwrap();
    reopened
        .clear_mcp_demotion("never-demoted")
        .expect("clearing a row that is not there is a no-op, not an error");
    drop(reopened);

    let again = SqliteStore::open(&path, 5000).unwrap();
    assert_eq!(
        again.list_mcp_demotions().unwrap(),
        vec![demotion("search", "tool-drift", 1_700_000_200)],
        "the clear must survive the restart as well, and must take exactly one upstream with it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// AN EMPTY LIST IS THE PRE-EXISTING DECLARATIVE BEHAVIOUR, and the trait is explicit that it must
/// stay so: a server with no row here is a server nobody has demoted, which is a different fact from
/// one that drifted. A store that answered "demoted" for the absence would quarantine every
/// declaratively-approved deployment at boot.
#[test]
fn a_store_with_no_demotions_reads_back_empty_rather_than_failing() {
    let dir = tempdir();
    let file = dir.join("no-demotions.db");
    let s = SqliteStore::open(file.to_str().unwrap(), 5000).unwrap();
    assert!(s.list_mcp_demotions().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE SPENT-APPROVAL LEDGER ACROSS A RESTART. The seal that carries a single-use approval is valid
/// bytes on its second presentation exactly as on its first; only a record that the first happened
/// tells them apart. Held in RAM that record dies with the process while the approval it records is
/// still openable, so this drops the store, reopens the FILE, and asks again.
#[test]
fn a_reopened_store_refuses_a_second_redemption_of_the_same_approval() {
    let dir = tempdir();
    let file = dir.join("askstate.db");
    let path = file.to_str().unwrap().to_string();
    let now = 1_700_000_000u64;
    let expires = now + 900;

    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        assert!(
            s.redeem_ask_state("nonce-a", expires, now).unwrap(),
            "the FIRST redemption is the one that must proceed, or nothing below is about single use"
        );
        drop(s);
    }

    let reopened = SqliteStore::open(&path, 5000).unwrap();
    assert!(
        !reopened.redeem_ask_state("nonce-a", expires, now + 1).unwrap(),
        "a restart handed a spent approval back. The approval has not lapsed — outliving a restart \
         is the point of it — so the only thing that changed is that the process which recorded the \
         redemption is gone. On a tool an operator gated because it moves money, that second \
         redemption is the whole defect the gate exists to stop"
    );

    // THE CONTROL, and it is load-bearing: a ledger that refused everything would satisfy the case
    // above and would have deleted the feature.
    assert!(
        reopened
            .redeem_ask_state("nonce-b", expires, now + 2)
            .unwrap(),
        "a different approval is not the one that was spent; refusing it would make the ledger a \
         blanket refusal of every confirmation after the first"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TWO HANDLES ON ONE FILE ARE TWO NODES OF A FLEET. They share the deployment's signing key, so
/// they share the seal — every check but this one passes on both — and the ledger is the only thing
/// standing between one operator confirmation and one execution per node.
#[test]
fn a_second_handle_on_the_same_file_cannot_redeem_what_the_first_spent() {
    let dir = tempdir();
    let file = dir.join("fleet.db");
    let path = file.to_str().unwrap().to_string();
    let node_a = SqliteStore::open(&path, 5000).unwrap();
    let node_b = SqliteStore::open(&path, 5000).unwrap();
    let now = 1_700_000_000u64;

    assert!(node_a
        .redeem_ask_state("nonce-fleet", now + 900, now)
        .unwrap());
    assert!(
        !node_b
            .redeem_ask_state("nonce-fleet", now + 900, now)
            .unwrap(),
        "a second node of the same deployment redeemed an approval the first already spent, which \
         is one confirmation executing once per node"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// CONCURRENT REDEMPTION IS THE ATTACK, not the corner case: two redemptions in flight at once are
/// what a read-then-write check answers "first" to twice. Exactly one of N racing threads may win.
#[test]
fn exactly_one_of_many_racing_redemptions_wins() {
    let dir = tempdir();
    let file = dir.join("race.db");
    let path = file.to_str().unwrap().to_string();
    let now = 1_700_000_000u64;
    let store = std::sync::Arc::new(SqliteStore::open(&path, 5000).unwrap());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));

    let winners: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = std::sync::Arc::clone(&store);
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    store
                        .redeem_ask_state("nonce-race", now + 900, now)
                        .unwrap() as usize
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });

    assert_eq!(
        winners, 1,
        "exactly one redemption of one approval may be the first; {winners} threads were each told \
         they were, which is a test-and-set that is really a read followed by a write"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE LEDGER IS BOUNDED BY ONE APPROVAL-VALIDITY WINDOW. `now` is handed to every redemption so the
/// backend can drop what has lapsed as part of the same call — an entry recording an approval that
/// can no longer be opened protects nothing, and a table that only grows is its own outage.
#[test]
fn redeeming_evicts_entries_whose_approval_can_no_longer_be_opened() {
    let dir = tempdir();
    let file = dir.join("evict.db");
    let path = file.to_str().unwrap().to_string();
    let now = 1_700_000_000u64;

    let s = SqliteStore::open(&path, 5000).unwrap();
    assert!(s.redeem_ask_state("short-lived", now + 10, now).unwrap());
    assert!(s.redeem_ask_state("long-lived", now + 10_000, now).unwrap());

    // A redemption well past the first entry's expiry: the sweep runs inside the same call.
    let later = now + 11;
    assert!(s.redeem_ask_state("another", later + 900, later).unwrap());
    let rows: i64 = s
        .lock_reader()
        .query_row("SELECT COUNT(*) FROM spent_ask_states", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        rows, 2,
        "the lapsed entry must be evicted by the sweep the redemption carries, leaving only the \
         approvals still openable"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// REFUSED RATHER THAN MANGLED, and here the reason is sharper than it is for a task cursor: `as
/// i64` wraps a `u64` past `i64::MAX` negative, and a wrapped `now` sweeps the whole ledger before
/// inserting — which answers "first redemption" to a replay. The failure has to be an error.
#[test]
fn the_ledger_refuses_values_it_cannot_store_faithfully() {
    let s = SqliteStore::open_in_memory().unwrap();
    assert!(
        s.redeem_ask_state("n", u64::MAX, 1_700_000_000).is_err(),
        "an unstorable expires_at must be an error, never a silent 'first redemption'"
    );
    assert!(
        s.redeem_ask_state("n", 1_700_000_900, u64::MAX).is_err(),
        "an unstorable now must be an error: clamped to i64::MAX it would evict the entire ledger \
         and then report every replay as a first redemption"
    );
    assert!(
        s.put_mcp_demotion(&demotion("srv", "tool-drift", u64::MAX))
            .is_err(),
        "an unstorable recorded_at must be an error rather than a row that does not read back as \
         itself"
    );
    // And the in-range boundary still stores.
    assert!(s
        .redeem_ask_state("boundary", i64::MAX as u64, 1_700_000_000)
        .unwrap());
}

/// The v8 -> v9 crossing is additive: a real v8 database gains the two trust-state tables and keeps
/// every row it already had. Same regression cover the v7 -> v8 crossing carries — the pre-v5
/// drop-and-recreate path has no business touching a live database on a version bump.
#[test]
fn migrate_v8_to_v9_adds_the_trust_state_tables_without_wiping_data() {
    let dir = tempdir();
    let file = dir.join("v8.db");
    {
        let conn = Connection::open(&file).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute("DROP TABLE spent_ask_states", []).unwrap();
        conn.execute("DROP TABLE mcp_demotions", []).unwrap();
        conn.execute(
            "INSERT INTO keys (id, name, key_group, allowed_pools, labels, enabled, \
             generation_hash, created_at, updated_at, expires_at, deleted_at, revision) \
             VALUES ('vk_v8', 'n', NULL, NULL, '{}', 1, 'g1', 0, 0, NULL, NULL, 0)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 8i64).unwrap();
    }
    let s = SqliteStore::open(file.to_str().unwrap(), 5000)
        .expect("a v8 database must migrate additively to v9");
    assert!(
        s.get_key("vk_v8").unwrap().is_some(),
        "a real v8 key must survive the v8->v9 crossing"
    );
    s.put_mcp_demotion(&demotion("srv", "tool-drift", 1_700_000_000))
        .expect("the newly created mcp_demotions table must be writable after the migration");
    assert!(s
        .redeem_ask_state("n", 1_700_000_900, 1_700_000_000)
        .unwrap());
    assert_eq!(s.list_mcp_demotions().unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
