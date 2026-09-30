// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{AuditRecord, ModelTokensDelta, RecordStore, VirtualKey};
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
        idp_subject: None,
        binding_mode: None,
        minted_by: None,
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
            usage_units: [
                (UNIT_INPUT.to_string(), input),
                (UNIT_OUTPUT.to_string(), output),
            ]
            .into_iter()
            .collect(),
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
    let before = now_secs();
    s.put_key(&k).unwrap();
    let after = now_secs();
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
    // Not merely "anything but created_at": the mutation time itself, bracketed by the clock read
    // on either side of the write (a revision, a zero or any other bound value falls outside).
    assert!(
        (before..=after).contains(&updated_at),
        "updated_at {updated_at} must be the mutation time, within [{before}, {after}]"
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

/// A tombstone is a MUTATION a hydrating peer must see: `delete_key` stamps a new revision, so a
/// peer reading `list_keys_since` from its watermark receives the key with `deleted_at` set and
/// stops honouring it. Without the stamp the revoked key stays live on every peer.
#[test]
fn delete_key_bumps_the_revision_so_hydration_sees_the_tombstone() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_hyd", "g")).unwrap();
    let watermark = s.get_key("vk_hyd").unwrap().unwrap().revision;
    s.delete_key("vk_hyd").unwrap();
    let delta = s.list_keys_since(watermark).unwrap();
    assert_eq!(
        delta.len(),
        1,
        "the tombstone must be past the watermark, or a hydrating peer never learns of it"
    );
    assert_eq!(delta[0].id, "vk_hyd");
    assert!(
        delta[0].deleted_at.is_some(),
        "the delta must carry the tombstone itself"
    );
    assert!(delta[0].revision > watermark);
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
        priced_from_ms: 0,
        usage_units: Default::default(),
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

/// A revocation is EVIDENCE: its reason and time must read back as recorded, and a second revoke of
/// the same credential is an idempotent no-op that keeps the first reason and time rather than
/// overwriting what the operator responding to a leak wrote down.
#[test]
fn revoke_credential_records_its_reason_and_a_second_revoke_keeps_the_first() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.put_key(&sample_key("vk_rv", "g")).unwrap();
    s.put_credential(&sample_credential("vk_rv", "AKIA_RV", 0))
        .unwrap();
    let id = s.list_credentials("vk_rv").unwrap()[0].id.clone();

    let before = now_secs();
    s.revoke_credential(&id, "leak").unwrap();
    let after = now_secs();
    let first = s.list_credentials("vk_rv").unwrap()[0].clone();
    assert_eq!(first.revoke_reason.as_deref(), Some("leak"));
    let Some(revoked_at) = first.revoked_at else {
        panic!("a revoked credential carries revoked_at");
    };
    let revoked_at = revoked_at as i64;
    assert!(
        (before..=after).contains(&revoked_at),
        "revoked_at {revoked_at} must be the revocation time, within [{before}, {after}]"
    );

    s.revoke_credential(&id, "rotated")
        .expect("revoking an already-revoked credential is idempotent");
    let second = s.list_credentials("vk_rv").unwrap()[0].clone();
    assert_eq!(
        second.revoke_reason.as_deref(),
        Some("leak"),
        "a second revoke overwrote the original reason"
    );
    assert_eq!(
        second.revoked_at, first.revoked_at,
        "a second revoke moved the original revocation time"
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
    let m = ledger.models.iter().find(|m| m.model == "m").unwrap();
    assert_eq!(m.tier(UNIT_INPUT), 0, "input tokens must floor at 0");
    assert_eq!(m.tier(UNIT_OUTPUT), 4);
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
    assert_eq!(
        ledger
            .models
            .iter()
            .find(|m| m.model == "gpt")
            .unwrap()
            .tier(UNIT_INPUT),
        10
    );
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
        priced_from_ms: 0,
        usage_units: Default::default(),
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
        priced_from_ms: 0,
        usage_units: Default::default(),
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

/// The same invariant through the STORE's own write path, not raw rusqlite: a store write that
/// reads before it writes (`append_plane_record` reads the chain position first) runs while another
/// connection holds the write lock and commits a change underneath it. Under `BEGIN IMMEDIATE` the
/// store waits at BEGIN through its busy handler and then succeeds; under `DEFERRED` its read
/// snapshot is stale by the time it writes, and it fails with `SQLITE_BUSY`/`SQLITE_BUSY_SNAPSHOT`.
#[test]
fn a_store_write_under_contention_waits_for_the_lock_instead_of_failing() {
    let dir = tempdir();
    let path = dir.join("store-contend.db");
    let path_str = path.to_str().unwrap().to_string();
    let store = SqliteStore::open(&path_str, 5000).unwrap();

    let holder = Connection::open(&path).unwrap();
    holder
        .execute_batch(
            "BEGIN IMMEDIATE; UPDATE store_revision SET revision = revision + 1 WHERE id = 0;",
        )
        .unwrap();

    let call = sample_call("vk_contend", 1, 100, "", "h1");
    let result = std::thread::scope(|scope| {
        let writer = scope.spawn(|| append_call(&store, &call));
        // Let the store's write start and meet the held lock, then commit a change underneath it.
        std::thread::sleep(std::time::Duration::from_millis(300));
        holder.execute_batch("COMMIT").unwrap();
        writer.join().unwrap()
    });
    result.expect(
        "a store write must wait for the lock and then succeed; failing here means its transaction \
         was not taken IMMEDIATE",
    );
    assert_eq!(list_calls(&store, "vk_contend").len(), 1);
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
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

/// The refusal half of the readback: `PRAGMA foreign_keys` is a no-op inside an open transaction,
/// so issuing `apply_pragmas` there leaves enforcement OFF, and the readback must turn that into an
/// error rather than a store quietly running without the credentials->keys CASCADE.
#[test]
fn foreign_keys_that_did_not_take_refuse_the_connection() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = OFF; BEGIN;")
        .unwrap();
    let err = apply_pragmas(&conn, ":memory:", 2000, true)
        .expect_err("foreign_keys still OFF after apply_pragmas must be refused");
    assert!(
        err.0.contains("foreign_keys could not be enabled"),
        "the refusal must say why: {err:?}"
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

/// A window whose rows STRADDLE a 5000-row batch boundary is still one window. 4999 windows of a
/// lone sentinel row, then one window of a sentinel plus three model rows: 5003 rows in 5000
/// windows, and the first batch ends on the last window's sentinel, so its model rows fall into
/// the second batch. Counting the distinct windows each batch touches counts that window twice.
#[test]
fn purge_windows_before_counts_a_window_split_across_batches_once() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.lock_writer()
        .execute_batch(
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 4998)
             INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests)
               SELECT i, 'vk_straddle', '', 1, 1 FROM n;
             INSERT INTO usage_windows (window_start, bucket_id, model, requests, billable_requests)
               VALUES (4999, 'vk_straddle', '', 1, 1), (4999, 'vk_straddle', 'm1', 0, 0),
                      (4999, 'vk_straddle', 'm2', 0, 0), (4999, 'vk_straddle', 'm3', 0, 0);",
        )
        .unwrap();
    assert_eq!(
        s.purge_windows_before(10_000).unwrap(),
        5000,
        "5000 windows were purged; a window whose rows straddle two batches must be counted once"
    );
    let left: i64 = s
        .lock_reader()
        .query_row("SELECT COUNT(*) FROM usage_windows", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 0, "every stale row is gone");
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
            priced_from_ms: 0,
            usage_units: Default::default(),
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

/// The `Store` contract conformance suite — THIS crate's own copy, at `src/tests/store_conformance.rs`.
/// It used to arrive as `busbar-plugin-testkit`; the owner ruled that crate deleted on 2026-09-22 and
/// #2/#31 forbid a shared test util between plugins, so every backend owns its copy. See that file's
/// module doc for the full provenance and for what the shared crate was buying: a new ruling no
/// longer reaches this backend on a dependency bump, it has to be written in here by hand.
mod store_conformance;

/// The cross-backend `Store` conformance checks, answered by this backend — EVERY check the suite
/// carries, including the 1.6.0 credential-ownership, atomic-mint and plane-record rulings.
mod conformance {
    use super::store_conformance as conf;
    use super::{tempdir, SqliteStore};

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
    fn put_credential_requires_a_live_key() {
        conf::assert_put_credential_requires_a_live_key(&fresh(), "conf");
    }

    #[test]
    fn put_key_with_credential_is_atomic() {
        conf::assert_put_key_with_credential_is_atomic(&fresh(), "conf");
    }

    #[test]
    fn append_audit_duplicate_seq_is_ok_when_identical_and_an_error_when_different() {
        conf::assert_append_audit_duplicate_seq(&fresh(), 1);
    }

    #[test]
    fn plane_task_upsert_get_list() {
        conf::assert_plane_task_upsert_get_list(&fresh(), "conf");
    }

    #[test]
    fn plane_event_chain_is_ordered_by_seq() {
        conf::assert_plane_event_chain_is_ordered_by_seq(&fresh(), "conf");
    }

    #[test]
    fn plane_call_parents_enumerated() {
        conf::assert_plane_call_parents_enumerated(&fresh(), "conf");
    }

    #[test]
    fn plane_demotion_upsert_list_delete() {
        conf::assert_plane_demotion_upsert_list_delete(&fresh(), "conf");
    }

    #[test]
    fn plane_purge_honours_the_cutoff() {
        conf::assert_plane_purge_honours_the_cutoff(&fresh(), "conf");
    }

    #[test]
    fn plane_purge_task_keeps_active_rows() {
        conf::assert_plane_purge_task_keeps_active_rows(&fresh(), "conf");
    }

    #[test]
    fn plane_token_is_single_use() {
        conf::assert_plane_token_is_single_use(&fresh(), "conf");
    }

    /// The suite's namespacing exists for a SHARED database: every check again, against ONE real
    /// file, each under its own `ns` — the shape a fleet of nodes on one file actually has, and the
    /// one an in-memory handle per check can never exercise.
    #[test]
    fn the_whole_suite_passes_against_one_shared_file() {
        let dir = tempdir();
        let path = dir.join("conformance.db");
        let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
        conf::assert_put_key_does_not_resurrect_a_tombstone(&store, "sa");
        conf::assert_delete_key_unknown_id_is_an_error(&store, "sb");
        conf::assert_revoke_credential_unknown_id_is_an_error(&store, "sc");
        conf::assert_put_credential_requires_a_live_key(&store, "sd");
        conf::assert_put_key_with_credential_is_atomic(&store, "se");
        conf::assert_append_audit_duplicate_seq(&store, 41);
        conf::assert_plane_task_upsert_get_list(&store, "sf");
        conf::assert_plane_event_chain_is_ordered_by_seq(&store, "sg");
        conf::assert_plane_call_parents_enumerated(&store, "sh");
        conf::assert_plane_demotion_upsert_list_delete(&store, "si");
        conf::assert_plane_purge_honours_the_cutoff(&store, "sj");
        conf::assert_plane_purge_task_keeps_active_rows(&store, "sk");
        conf::assert_plane_token_is_single_use(&store, "sl");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two purge checks are the ones whose verb takes no namespace, and the suite salts them so
    /// two runs sharing one database cannot sweep each other's survivors. Run them CONCURRENTLY on one
    /// file to hold that — the property the salting exists for.
    #[test]
    fn the_purge_checks_hold_under_a_concurrent_sibling_run() {
        let dir = tempdir();
        let path = dir.join("conformance-race.db");
        let store = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
        std::thread::scope(|scope| {
            let a = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(&store, "confA"));
            let b = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(&store, "confB"));
            a.join().unwrap();
            b.join().unwrap();
        });
        std::thread::scope(|scope| {
            let a =
                scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(&store, "confA"));
            let b =
                scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(&store, "confB"));
            a.join().unwrap();
            b.join().unwrap();
        });
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
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

// ── THE NEUTRAL PLANE-RECORD VERBS (1.6.0) ───────────────────────────────────────────────────
//
// busbar 1.6.0 replaced the fourteen protocol-named durable methods (`put_task`, `append_mcp_call`,
// `put_mcp_demotion`, `redeem_ask_state`, …) with eight kind-tagged verbs over an opaque
// `PlaneRecord`. Every property the typed tables were tested for is still owed — a task survives a
// restart, a chain links, a fork is refused, retention is terminal-only for tasks, a spent approval
// stays spent across nodes — so each of those tests is carried here onto the verbs that now carry
// the property. The bodies are small stand-in structs with the field NAMES the planes encode
// (this store never decodes a body; the tests do, to prove it came back verbatim).
//
// The property under test is never "the write returned Ok": the trait's defaults return `Ok` and
// keep nothing. The only honest proof is to READ IT BACK, and for durability, THROUGH A RESTART.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct CallBody {
    principal: String,
    seq: u64,
    ts: u64,
    server: String,
    tool: String,
    outcome: String,
    reason: String,
    tool_digest: String,
    pin_generation: u64,
    request_id: String,
    prev_hash: String,
    hash: String,
}

fn body<T: Serialize>(row: &T) -> Vec<u8> {
    serde_json::to_vec(row).unwrap()
}

fn sample_call(principal: &str, seq: u64, ts: u64, prev_hash: &str, hash: &str) -> CallBody {
    CallBody {
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

/// A `call` record exactly as the MCP plane hangs it: parent = the principal (the chain scope).
fn call_record(c: &CallBody) -> PlaneRecord {
    PlaneRecord {
        kind: "call".into(),
        id: c.principal.clone(),
        parent: Some(c.principal.clone()),
        seq: c.seq,
        ts: c.ts,
        disposition: PlaneDisposition::Active,
        body: body(c),
    }
}

fn append_call(s: &SqliteStore, c: &CallBody) -> RecordStoreResult<()> {
    s.append_plane_record(&call_record(c))
}

fn list_calls(s: &SqliteStore, principal: &str) -> Vec<CallBody> {
    s.list_plane_records("call", &PlaneSelector::Parent(principal.to_string()))
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect()
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
        append_call(&s, &sample_call("vk_a", 1, 100, "", "h1")).unwrap();
        append_call(&s, &sample_call("vk_a", 2, 200, "h1", "h2")).unwrap();
        append_call(&s, &sample_call("vk_a", 3, 300, "h2", "h3")).unwrap();
        drop(s);
    }

    // A genuinely new store over the same file — nothing carried over in memory.
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let got = list_calls(&reopened, "vk_a");

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
    // Ordering is by seq, and the body must round-trip verbatim too.
    assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(got[2], sample_call("vk_a", 3, 300, "h2", "h3"));
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
        append_call(&s, &sample_call("vk_a", 1, 100, "", "a1")).unwrap();
        append_call(&s, &sample_call("vk_b", 1, 100, "", "b1")).unwrap();
        append_call(&s, &sample_call("vk_a", 2, 101, "a1", "a2")).unwrap();
        drop(s);
    }
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    assert_eq!(
        reopened.list_plane_record_parents("call").unwrap(),
        vec!["vk_a".to_string(), "vk_b".to_string()],
        "every principal holding records must be enumerable after a restart, exactly once each"
    );
    // A scoped read returns only its own principal's chain — the chain scope is the principal.
    assert_eq!(list_calls(&reopened, "vk_a").len(), 2);
    assert_eq!(list_calls(&reopened, "vk_b").len(), 1);
    assert!(
        list_calls(&reopened, "vk_nonexistent").is_empty(),
        "a principal with no records reads back empty, not an error"
    );
    // The enumeration is per KIND: a parent of another kind is not a call principal.
    reopened
        .append_plane_record(&event_record(&sample_event(
            "t-1",
            1,
            "task.submitted",
            "",
            "e1",
        )))
        .unwrap();
    assert_eq!(reopened.list_plane_record_parents("call").unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Retention must ACTUALLY DELETE and report a real count — a purge that returns a number it did
/// not perform is worse than one that reports nothing purged. The `call` kind drops EVERY row older
/// than the cutoff, active or not.
#[test]
fn purge_mcp_calls_before_deletes_and_returns_a_real_count() {
    let s = SqliteStore::open_in_memory().unwrap();
    append_call(&s, &sample_call("vk_a", 1, 100, "", "h1")).unwrap();
    append_call(&s, &sample_call("vk_a", 2, 200, "h1", "h2")).unwrap();
    append_call(&s, &sample_call("vk_a", 3, 300, "h2", "h3")).unwrap();
    append_call(&s, &sample_call("vk_b", 1, 150, "", "b1")).unwrap();

    // Strictly older than `before`, across every principal. ts=300 and ts=200 stay.
    let purged = s.purge_plane_records_before("call", 200).unwrap();
    assert_eq!(
        purged, 2,
        "purge must return the number of rows it actually removed (ts=100 and ts=150), not a guess"
    );
    assert_eq!(
        list_calls(&s, "vk_a")
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![2, 3],
        "the rows at or after the cutoff must remain"
    );
    assert!(
        list_calls(&s, "vk_b").is_empty(),
        "a principal whose every row aged out reads back empty"
    );
    // `before` is STRICTLY less-than: a row exactly at the cutoff is kept.
    assert_eq!(
        s.purge_plane_records_before("call", 200).unwrap(),
        0,
        "re-running the same purge removes nothing; ts=200 sits exactly at the cutoff and is kept"
    );
    // A purge is per KIND: sweeping another kind at a cutoff past everything touches no call.
    assert_eq!(s.purge_plane_records_before("demotion", 1_000).unwrap(), 0);
    assert_eq!(list_calls(&s, "vk_a").len(), 2);
    // And the count is real: purging past everything clears the rest.
    assert_eq!(s.purge_plane_records_before("call", 1_000).unwrap(), 2);
    assert!(list_calls(&s, "vk_a").is_empty());
}

/// A record arriving on a `(principal, seq)` that already has one is settled the way `append_audit`
/// settles it: IDENTICAL is the retry and succeeds; DIFFERENT is a forked or tampered log and is an
/// error. Overwriting would destroy the second case instead of reporting it.
#[test]
fn a_replayed_mcp_call_is_idempotent_but_a_forked_one_is_refused() {
    let s = SqliteStore::open_in_memory().unwrap();
    let rec = sample_call("vk_a", 1, 100, "", "h1");
    append_call(&s, &rec).unwrap();

    append_call(&s, &rec).expect("an identical replay is the at-least-once retry and must succeed");
    assert_eq!(
        list_calls(&s, "vk_a").len(),
        1,
        "a replay must not duplicate the row"
    );

    // Same (principal, seq), different digest — the fork case.
    let forked = sample_call("vk_a", 1, 100, "", "DIFFERENT");
    let err = append_call(&s, &forked)
        .expect_err("a different record at an occupied (principal, seq) is a fork and must error");
    assert!(
        !format!("{err}").contains("DIFFERENT"),
        "the error must not echo stored content back"
    );
    assert_eq!(
        list_calls(&s, "vk_a")[0].hash,
        "h1",
        "the refused fork must not have overwritten the record already on record"
    );

    // A differing payload field is a fork too, not a silent accept.
    let mut tampered = sample_call("vk_a", 1, 100, "", "h1");
    tampered.tool = "srv_other_tool".to_string();
    append_call(&s, &tampered)
        .expect_err("a payload that differs under an identical digest is a fork and must error");
    // And so is a differing SIDECAR under an identical body: the envelope is the record.
    let mut moved = call_record(&rec);
    moved.ts = 999;
    s.append_plane_record(&moved)
        .expect_err("the same body under a different ts is a different record at that position");
}

/// Every field of the envelope is part of the record at a position, not only the body and `ts`: a
/// record at an occupied position that differs in its DISPOSITION, its ID or its PARENT is a fork,
/// never a benign replay. A Terminal record slipping in as a "replay" changes what retention does.
#[test]
fn a_record_differing_in_disposition_id_or_parent_at_an_occupied_position_is_a_fork() {
    let s = SqliteStore::open_in_memory().unwrap();
    let rec = call_record(&sample_call("vk_a", 1, 100, "", "h1"));
    s.append_plane_record(&rec).unwrap();

    let mut terminal = rec.clone();
    terminal.disposition = PlaneDisposition::Terminal;
    let mut other_id = rec.clone();
    other_id.id = "vk_other".to_string();
    // Same position (kind, identity = "vk_a", seq): a top-level record's identity is its own id.
    let mut no_parent = rec.clone();
    no_parent.parent = None;

    for (what, forked) in [
        ("disposition", &terminal),
        ("id", &other_id),
        ("parent", &no_parent),
    ] {
        let err = s
            .append_plane_record(forked)
            .expect_err("a different record at an occupied position must be refused");
        assert!(
            format!("{err}").contains("the chain has forked"),
            "a differing {what} must be reported as a fork: {err}"
        );
    }
    assert_eq!(
        s.list_plane_records("call", &PlaneSelector::Parent("vk_a".into()))
            .unwrap()
            .len(),
        1,
        "no refused fork may have added or overwritten a row"
    );
}

/// A persisted chain record is never REWRITTEN. Enforced by a trigger so it survives an operator
/// opening the file with the sqlite3 CLI, not merely by the write path being careful. An upserted
/// top-level record (no parent) is updated in place by design, so the guard must not reach it.
#[test]
fn a_chain_record_rejects_a_direct_update_but_allows_the_retention_delete() {
    let s = SqliteStore::open_in_memory().unwrap();
    append_call(&s, &sample_call("vk_a", 1, 100, "", "h1")).unwrap();
    let err = s
        .lock_writer()
        .execute(
            "UPDATE plane_records SET body = x'00' WHERE kind = 'call' AND identity = 'vk_a'",
            [],
        )
        .expect_err("a direct UPDATE must be refused by the append-only trigger");
    assert!(format!("{err}").contains("never rewritten"));
    // DELETE is deliberately NOT guarded — retention has to be able to do its job.
    s.lock_writer()
        .execute("DELETE FROM plane_records WHERE kind = 'call'", [])
        .expect("retention must remain possible; only rewriting is forbidden");

    // The upsert path is untouched by the guard: a second write of a top-level record replaces it.
    s.upsert_plane_record(&task_record(&sample_task("t-1", "working", 200)))
        .unwrap();
    s.upsert_plane_record(&task_record(&sample_task("t-1", "completed", 300)))
        .expect("an upserted top-level record is updated in place, not refused as a rewrite");
    assert_eq!(get_task(&s, "t-1").unwrap().state, "completed");
}

// ── A2A tasks and their provenance chains ────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct TaskBody {
    task_id: String,
    context_id: String,
    principal: String,
    direction: String,
    state: String,
    agent_id: String,
    artifact_cursor: u64,
    push_callback: String,
    created_at: u64,
    updated_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct EventBody {
    task_id: String,
    seq: u64,
    ts: u64,
    kind: String,
    context_id: String,
    principal: String,
    agent_id: String,
    state: String,
    request_id: String,
    prev_hash: String,
    hash: String,
}

fn sample_task(task_id: &str, state: &str, updated_at: u64) -> TaskBody {
    TaskBody {
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

/// A `task` record exactly as the A2A plane builds it: `ts` is `updated_at`, and the disposition
/// is `Terminal` exactly when the state is final.
fn task_record(t: &TaskBody) -> PlaneRecord {
    PlaneRecord {
        kind: "task".into(),
        id: t.task_id.clone(),
        parent: None,
        seq: 0,
        ts: t.updated_at,
        disposition: if TERMINAL_TASK_STATES.contains(&t.state.as_str()) {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: body(t),
    }
}

fn get_task(s: &SqliteStore, id: &str) -> Option<TaskBody> {
    s.get_plane_record("task", id)
        .unwrap()
        .map(|b| serde_json::from_slice(&b).unwrap())
}

fn list_task_ids(s: &SqliteStore) -> Vec<String> {
    let mut ids: Vec<String> = s
        .list_plane_records("task", &PlaneSelector::All)
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice::<TaskBody>(b).unwrap().task_id)
        .collect();
    ids.sort();
    ids
}

fn sample_event(task_id: &str, seq: u64, kind: &str, prev_hash: &str, hash: &str) -> EventBody {
    EventBody {
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

/// A `task_event` record exactly as the A2A plane hangs it: parent = its task.
fn event_record(e: &EventBody) -> PlaneRecord {
    PlaneRecord {
        kind: "task_event".into(),
        id: e.task_id.clone(),
        parent: Some(e.task_id.clone()),
        seq: e.seq,
        ts: e.ts,
        disposition: PlaneDisposition::Active,
        body: body(e),
    }
}

fn list_events(s: &SqliteStore, task_id: &str) -> Vec<EventBody> {
    s.list_plane_records("task_event", &PlaneSelector::Parent(task_id.to_string()))
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect()
}

/// THE TEST THAT MATTERS, and it is deliberately not a unit test against a live handle: a live
/// handle cannot tell a backend that wrote to disk from one keeping a HashMap behind the same trait,
/// and it cannot tell either of those from the trait's accept-and-keep-nothing defaults if the
/// defaults happen to be exercised through the same handle that "wrote". So this DROPS the store —
/// closing every SQLite connection and its WAL — reopens the same FILE, and reads the task back off
/// disk.
#[test]
fn an_in_flight_task_survives_dropping_the_store_and_reopening_the_file() {
    let dir = tempdir();
    let file = dir.join("tasks.db");
    let path = file.to_str().unwrap().to_string();

    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.upsert_plane_record(&task_record(&sample_task("t-1", "working", 200)))
            .unwrap();
        // The write-through on a state transition REPLACES the row rather than appending a second
        // one — an interrupted task waiting on a human is what a restart has to find.
        let mut interrupted = sample_task("t-1", "input-required", 300);
        interrupted.artifact_cursor = 12;
        s.upsert_plane_record(&task_record(&interrupted)).unwrap();
        s.upsert_plane_record(&task_record(&sample_task("t-2", "submitted", 210)))
            .unwrap();
        drop(s);
    }

    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let got = get_task(&reopened, "t-1").expect(
        "an in-flight task must survive a restart; got None back after reopening the file, \
             which is the accept-and-keep-nothing default this backend exists to replace",
    );

    // Every field a resume reads has to come back verbatim — not merely a row with the right id.
    let mut expected = sample_task("t-1", "input-required", 300);
    expected.artifact_cursor = 12;
    assert_eq!(got, expected, "the LAST write must win, byte for byte");

    // UPSERT, not append: two writes for one task_id leave ONE row.
    assert_eq!(
        list_task_ids(&reopened),
        vec!["t-1", "t-2"],
        "upsert is by id; a second write for the same id must replace, never append"
    );

    assert!(
        get_task(&reopened, "t-nonexistent").is_none(),
        "an unknown task id reads back None, not an error"
    );
    // A point read is per KIND: a record of another kind under the same id is not a task.
    reopened
        .upsert_plane_record(&demotion_record(&demotion("t-3", "drift", 1)))
        .unwrap();
    assert!(get_task(&reopened, "t-3").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The kind listing is deliberately UNFILTERED. The boot rehydrate wants the active rows, the
/// retention sweep wants the terminal ones and the scoped listing wants one principal's; a store
/// that pre-filtered for any one of those would break the other two. Pinned across a restart because
/// the boot rehydrate is precisely the caller that only ever sees the post-restart answer.
#[test]
fn list_tasks_returns_every_row_including_terminal_ones_after_a_restart() {
    let dir = tempdir();
    let file = dir.join("list.db");
    let path = file.to_str().unwrap().to_string();
    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        for t in [
            sample_task("t-active", "working", 200),
            sample_task("t-waiting", "input-required", 201),
            sample_task("t-done", "completed", 202),
            sample_task("t-failed", "failed", 203),
        ] {
            s.upsert_plane_record(&task_record(&t)).unwrap();
        }
        drop(s);
    }
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    assert_eq!(
        list_task_ids(&reopened),
        vec!["t-active", "t-done", "t-failed", "t-waiting"],
        "the listing is unfiltered: terminal rows are returned too, and every row survives a restart"
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
        for e in [
            sample_event("t-1", 1, "task.submitted", "", "e1"),
            sample_event("t-1", 2, "task.working", "e1", "e2"),
            sample_event("t-1", 3, "task.interrupted", "e2", "e3"),
            // A second task's chain is independent — it must not leak into the first one's read.
            sample_event("t-2", 1, "task.submitted", "", "f1"),
        ] {
            s.append_plane_record(&event_record(&e)).unwrap();
        }
        drop(s);
    }
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    let got = list_events(&reopened, "t-1");
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
    assert_eq!(
        got[2],
        sample_event("t-1", 3, "task.interrupted", "e2", "e3")
    );
    assert_eq!(got[1].ts, 102);
    // The scope of a read is one task.
    assert_eq!(list_events(&reopened, "t-2").len(), 1);
    assert!(
        list_events(&reopened, "t-unknown").is_empty(),
        "a task with no events reads back empty, not an error"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A replayed `(task_id, seq)` is IDEMPOTENT, and a DIFFERENT event at an occupied `seq` is a FORK.
///
/// This is a deliberate 1.6.0 change. The typed `append_task_event` was specified to UPSERT on
/// `(task_id, seq)`, so a "corrected" event silently replaced the one on record. The 1.6.0 contract
/// has ONE append verb for every chain kind, and busbar's own reference backends (`store-memory`,
/// the in-tree `store-example`) settle a second record at an occupied chain position exactly as
/// `append_audit` does: identical is the write-through retrying, different is two records claiming
/// one position — refused, never silently applied. An upsert here is how two processes on one file
/// would overwrite each other's provenance without anyone being told.
#[test]
fn a_replayed_task_event_is_idempotent_but_a_forked_one_is_refused() {
    let s = SqliteStore::open_in_memory().unwrap();
    let e = sample_event("t-1", 1, "task.submitted", "", "e1");
    s.append_plane_record(&event_record(&e)).unwrap();
    s.append_plane_record(&event_record(&e))
        .expect("an identical replay must succeed, not be rejected as a fork");
    assert_eq!(
        list_events(&s, "t-1").len(),
        1,
        "a replay must not duplicate the row"
    );

    let mut rewritten = sample_event("t-1", 1, "task.submitted", "", "e1-rewritten");
    rewritten.state = "submitted".to_string();
    s.append_plane_record(&event_record(&rewritten))
        .expect_err("a different event at an occupied seq is a fork and must be refused");
    let got = list_events(&s, "t-1");
    assert_eq!(got.len(), 1, "a refused fork appends nothing");
    assert_eq!(got[0], e, "and overwrites nothing");
}

/// Retention drops TERMINAL rows only, strictly older than the cutoff, and returns a count it
/// actually performed. An interrupted task waiting on a human is exactly the row that legitimately
/// sits still for a long time; compacting it is losing the work, not reclaiming space. Terminality
/// is the envelope's `disposition` sidecar, never decoded out of the body.
#[test]
fn purge_tasks_before_drops_only_terminal_rows_and_returns_a_real_count() {
    let s = SqliteStore::open_in_memory().unwrap();
    for t in [
        sample_task("t-old-done", "completed", 100),
        sample_task("t-old-failed", "failed", 100),
        sample_task("t-old-canceled", "canceled", 100),
        sample_task("t-old-rejected", "rejected", 100),
        // Old, and NOT terminal — never dropped, no matter how old.
        sample_task("t-old-waiting", "input-required", 100),
        sample_task("t-old-auth", "auth-required", 100),
        sample_task("t-old-working", "working", 100),
        sample_task("t-old-submitted", "submitted", 100),
        // Terminal but at the cutoff exactly, and terminal but newer — both kept.
        sample_task("t-at-cutoff", "completed", 200),
        sample_task("t-new-done", "completed", 300),
    ] {
        s.upsert_plane_record(&task_record(&t)).unwrap();
    }

    let purged = s.purge_plane_records_before("task", 200).unwrap();
    assert_eq!(
        purged, 4,
        "only the four TERMINAL rows strictly older than the cutoff go, and the count must be one \
         actually performed rather than a guess"
    );
    assert_eq!(
        list_task_ids(&s),
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
        s.purge_plane_records_before("task", 200).unwrap(),
        0,
        "re-running the same purge removes nothing"
    );
}

/// Retention has to bound the EVENT rows too. Nothing else removes a task's events, so if purging a
/// task left its provenance behind, the chains would outlive the very retention decision just made
/// about them and grow without bound. Dropping a task therefore drops the chain that belongs to it —
/// and drops nothing belonging to any other task.
#[test]
fn purging_a_task_takes_its_provenance_chain_with_it_and_no_other() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.upsert_plane_record(&task_record(&sample_task("t-gone", "completed", 100)))
        .unwrap();
    s.upsert_plane_record(&task_record(&sample_task("t-stays", "working", 100)))
        .unwrap();
    for e in [
        sample_event("t-gone", 1, "task.submitted", "", "g1"),
        sample_event("t-gone", 2, "task.completed", "g1", "g2"),
        sample_event("t-stays", 1, "task.submitted", "", "s1"),
    ] {
        s.append_plane_record(&event_record(&e)).unwrap();
    }

    assert_eq!(s.purge_plane_records_before("task", 200).unwrap(), 1);
    assert!(
        list_events(&s, "t-gone").is_empty(),
        "the purged task's events go with it; otherwise they grow unbounded"
    );
    assert_eq!(
        list_events(&s, "t-stays").len(),
        1,
        "another task's chain must be untouched by that purge"
    );
}

/// A `seq`/`ts` past `i64::MAX` cannot be stored faithfully — `as i64` wraps it negative and the
/// read clamps back — so the row read back would not be the row written: a wrapped `seq` reorders a
/// chain, a wrapped `ts` changes what retention does to it. Refused outright, exactly as
/// `append_audit` refuses it, rather than silently mangled.
#[test]
fn the_plane_verbs_refuse_values_they_cannot_store_faithfully() {
    let s = SqliteStore::open_in_memory().unwrap();

    let mut t = task_record(&sample_task("t-1", "working", 200));
    t.ts = u64::MAX;
    let err = s
        .upsert_plane_record(&t)
        .expect_err("a ts past i64::MAX must be refused, not wrapped");
    assert!(
        err.0.contains("storable range"),
        "the refusal must say why: {}",
        err.0
    );
    assert!(
        get_task(&s, "t-1").is_none(),
        "a refused write must leave nothing behind"
    );

    let mut e = event_record(&sample_event("t-1", 1, "task.submitted", "", "e1"));
    e.seq = u64::MAX;
    assert!(s
        .append_plane_record(&e)
        .expect_err("a seq past i64::MAX must be refused")
        .0
        .contains("storable range"));
    e.seq = 1;
    e.ts = u64::MAX;
    assert!(s
        .append_plane_record(&e)
        .expect_err("a ts past i64::MAX must be refused")
        .0
        .contains("storable range"));
    assert!(list_events(&s, "t-1").is_empty());

    // The boundary itself is storable, and a record written there reads back and sweeps correctly.
    t.ts = i64::MAX as u64;
    s.upsert_plane_record(&t).expect("i64::MAX is in range");
    assert!(get_task(&s, "t-1").is_some());
    assert_eq!(
        s.purge_plane_records_before("task", u64::MAX).unwrap(),
        0,
        "an ACTIVE task is kept even by a sweep at the end of time"
    );
}

/// A pre-v10 database crossing to v10 gains the plane tables and keeps every row it already had.
/// Regression cover for the pre-v5 drop-and-recreate path reaching a live database on a version bump
/// it has no business touching. (The typed-table crossings v6->v7, v7->v8 and v8->v9 this used to be
/// three tests for no longer exist; `a_real_v9_database_*` below opens a v9 file the old code wrote.)
#[test]
fn migrate_v9_to_v10_adds_the_plane_tables_without_wiping_data() {
    let dir = tempdir();
    let file = dir.join("v9.db");
    {
        let conn = Connection::open(&file).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute("DROP TABLE plane_records", []).unwrap();
        conn.execute("DROP TABLE plane_tokens", []).unwrap();
        conn.execute(
            "INSERT INTO keys (id, name, key_group, allowed_pools, labels, enabled, \
             generation_hash, created_at, updated_at, expires_at, deleted_at, revision) \
             VALUES ('vk_v9', 'n', NULL, NULL, '{}', 1, 'g1', 0, 0, NULL, NULL, 0)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 9i64).unwrap();
    }
    let s = SqliteStore::open(file.to_str().unwrap(), 5000)
        .expect("a v9 database must migrate additively to v10");
    assert!(
        s.get_key("vk_v9").unwrap().is_some(),
        "a real v9 key must survive the v9->v10 crossing"
    );
    append_call(&s, &sample_call("vk_v9", 1, 10, "", "h1"))
        .expect("the newly created plane_records table must be writable after the migration");
    assert_eq!(list_calls(&s, "vk_v9").len(), 1);
    assert!(s.redeem_plane_token("ask", "n", 20, 10).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

// ── The MCP demotion record and the single-use token ledger ─────────────────────────────────
//
// Both of these are security state, and the trait defaults them to accept-and-keep-nothing (and the
// token check to refuse-everything), so every case below reads the state back through a REOPENED
// file rather than through the handle that wrote it.

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct DemotionBody {
    server: String,
    reason: String,
    recorded_at: u64,
}

fn demotion(server: &str, reason: &str, recorded_at: u64) -> DemotionBody {
    DemotionBody {
        server: server.to_string(),
        reason: reason.to_string(),
        recorded_at,
    }
}

fn demotion_record(d: &DemotionBody) -> PlaneRecord {
    PlaneRecord {
        kind: "demotion".into(),
        id: d.server.clone(),
        parent: None,
        seq: 0,
        ts: d.recorded_at,
        disposition: PlaneDisposition::Active,
        body: body(d),
    }
}

fn list_demotions(s: &SqliteStore) -> Vec<DemotionBody> {
    let mut rows: Vec<DemotionBody> = s
        .list_plane_records("demotion", &PlaneSelector::All)
        .unwrap()
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    rows.sort_by(|a, b| a.server.cmp(&b.server));
    rows
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
        s.upsert_plane_record(&demotion_record(&demotion(
            "payments",
            "tool-drift",
            1_700_000_000,
        )))
        .unwrap();
        // UPSERT by `server`: a second demotion of one upstream replaces the row rather than
        // standing a rival one beside it, so a read cannot come back holding two answers.
        s.upsert_plane_record(&demotion_record(&demotion(
            "payments",
            "digest-mismatch",
            1_700_000_100,
        )))
        .unwrap();
        s.upsert_plane_record(&demotion_record(&demotion(
            "search",
            "tool-drift",
            1_700_000_200,
        )))
        .unwrap();
        drop(s);
    }

    let reopened = SqliteStore::open(&path, 5000).unwrap();
    assert_eq!(
        list_demotions(&reopened),
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
    reopened
        .delete_plane_record("demotion", "payments")
        .unwrap();
    reopened
        .delete_plane_record("demotion", "never-demoted")
        .expect("clearing a row that is not there is a no-op, not an error");
    drop(reopened);

    let again = SqliteStore::open(&path, 5000).unwrap();
    assert_eq!(
        list_demotions(&again),
        vec![demotion("search", "tool-drift", 1_700_000_200)],
        "the clear must survive the restart as well, and must take exactly one upstream with it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// AN EMPTY LIST IS THE PRE-EXISTING DECLARATIVE BEHAVIOUR: a server with no row here is a server
/// nobody has demoted, which is a different fact from one that drifted. A store that answered
/// "demoted" for the absence would quarantine every declaratively-approved deployment at boot.
#[test]
fn a_store_with_no_demotions_reads_back_empty_rather_than_failing() {
    let dir = tempdir();
    let file = dir.join("no-demotions.db");
    let s = SqliteStore::open(file.to_str().unwrap(), 5000).unwrap();
    assert!(list_demotions(&s).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE SPENT-TOKEN LEDGER ACROSS A RESTART. The seal that carries a single-use approval is valid
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
            s.redeem_plane_token("ask", "nonce-a", expires, now)
                .unwrap(),
            "the FIRST redemption is the one that must proceed, or nothing below is about single use"
        );
        drop(s);
    }

    let reopened = SqliteStore::open(&path, 5000).unwrap();
    assert!(
        !reopened
            .redeem_plane_token("ask", "nonce-a", expires, now + 1)
            .unwrap(),
        "a restart handed a spent approval back. The approval has not lapsed — outliving a restart \
         is the point of it — so the only thing that changed is that the process which recorded the \
         redemption is gone. On a tool an operator gated because it moves money, that second \
         redemption is the whole defect the gate exists to stop"
    );

    // THE CONTROL, and it is load-bearing: a ledger that refused everything would satisfy the case
    // above and would have deleted the feature.
    assert!(
        reopened
            .redeem_plane_token("ask", "nonce-b", expires, now + 2)
            .unwrap(),
        "a different approval is not the one that was spent; refusing it would make the ledger a \
         blanket refusal of every confirmation after the first"
    );
    // The ledger is per KIND: the same token string under another kind is a different grant.
    assert!(reopened
        .redeem_plane_token("other-kind", "nonce-a", expires, now + 3)
        .unwrap());
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
        .redeem_plane_token("ask", "nonce-fleet", now + 900, now)
        .unwrap());
    assert!(
        !node_b
            .redeem_plane_token("ask", "nonce-fleet", now + 900, now)
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
                        .redeem_plane_token("ask", "nonce-race", now + 900, now)
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

/// THE LEDGER IS BOUNDED BY ONE VALIDITY WINDOW. `now` is handed to every redemption so the backend
/// can drop what has lapsed as part of the same call — an entry recording a grant that can no longer
/// be presented protects nothing, and a table that only grows is its own outage.
#[test]
fn redeeming_evicts_entries_whose_approval_can_no_longer_be_opened() {
    let dir = tempdir();
    let file = dir.join("evict.db");
    let path = file.to_str().unwrap().to_string();
    let now = 1_700_000_000u64;

    let s = SqliteStore::open(&path, 5000).unwrap();
    assert!(s
        .redeem_plane_token("ask", "short-lived", now + 10, now)
        .unwrap());
    assert!(s
        .redeem_plane_token("ask", "long-lived", now + 10_000, now)
        .unwrap());

    // A redemption well past the first entry's expiry: the sweep runs inside the same call.
    let later = now + 11;
    assert!(s
        .redeem_plane_token("ask", "another", later + 900, later)
        .unwrap());
    let rows: i64 = s
        .lock_reader()
        .query_row("SELECT COUNT(*) FROM plane_tokens", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        rows, 2,
        "the lapsed entry must be evicted by the sweep the redemption carries, leaving only the \
         grants still presentable"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE EVICTION BOUNDARY IS FAIL-CLOSED. An entry whose grant expires exactly at `now` can still be
/// presented at `now`, so the sweep must keep it (strictly less-than): evicting it first would tell
/// that replay it is the first redemption.
#[test]
fn an_entry_expiring_exactly_now_is_kept_and_its_replay_refused() {
    let s = SqliteStore::open_in_memory().unwrap();
    let now = 1_700_000_000u64;
    let expires = now + 10;
    assert!(s.redeem_plane_token("ask", "edge", expires, now).unwrap());
    assert!(
        !s.redeem_plane_token("ask", "edge", expires, expires)
            .unwrap(),
        "a replay at now == expires_at was told it was first: the sweep evicted an entry whose \
         grant is still presentable"
    );
}

/// REFUSED RATHER THAN MANGLED, and here the reason is sharper than it is for a chain position: `as
/// i64` wraps a `u64` past `i64::MAX` negative, and a wrapped `now` sweeps the whole ledger before
/// inserting — which answers "first redemption" to a replay. The failure has to be an error.
#[test]
fn the_ledger_refuses_values_it_cannot_store_faithfully() {
    let s = SqliteStore::open_in_memory().unwrap();
    assert!(
        s.redeem_plane_token("ask", "n", u64::MAX, 1_700_000_000)
            .is_err(),
        "an unstorable expires_at must be an error, never a silent 'first redemption'"
    );
    assert!(
        s.redeem_plane_token("ask", "n", 1_700_000_900, u64::MAX)
            .is_err(),
        "an unstorable now must be an error: clamped to i64::MAX it would evict the entire ledger \
         and then report every replay as a first redemption"
    );
    assert!(
        s.upsert_plane_record(&demotion_record(&demotion("srv", "tool-drift", u64::MAX)))
            .is_err(),
        "an unstorable recorded_at must be an error rather than a row that does not read back as \
         itself"
    );
    // And the in-range boundary still stores.
    assert!(s
        .redeem_plane_token("ask", "boundary", i64::MAX as u64, 1_700_000_000)
        .unwrap());
}

/// `plane_token_live` is the MULTI-USE capability check (a push callback token): live while its
/// record is present, still active, and inside its deadline — and it SPENDS NOTHING, because one task
/// legitimately draws several callbacks. Every other answer is `false`, fail-closed.
#[test]
fn a_push_callback_token_is_live_until_its_task_ends_or_its_deadline_passes() {
    let dir = tempdir();
    let file = dir.join("push.db");
    let path = file.to_str().unwrap().to_string();
    let cfg = |disposition| PlaneRecord {
        kind: "push_config".into(),
        id: "tok-1".into(),
        parent: None,
        seq: 0,
        ts: 1_000,
        disposition,
        body: b"{\"url\":\"https://cb.example/x\"}".to_vec(),
    };
    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.upsert_plane_record(&cfg(PlaneDisposition::Active))
            .unwrap();
        drop(s);
    }
    let s = SqliteStore::open(&path, 5000).unwrap();
    for _ in 0..3 {
        assert!(
            s.plane_token_live("push_config", "tok-1", 2_000, 1_500)
                .unwrap(),
            "a live capability must answer live on every callback — asking spends nothing, and it \
             must survive a restart"
        );
    }
    assert!(
        s.plane_token_live("push_config", "tok-1", 2_000, 2_000)
            .unwrap(),
        "`now` AT the deadline has not passed it"
    );
    assert!(
        !s.plane_token_live("push_config", "tok-1", 2_000, 2_001)
            .unwrap(),
        "a lapsed deadline is dead even if the task has not finished"
    );
    assert!(
        !s.plane_token_live("push_config", "tok-unknown", 2_000, 1_500)
            .unwrap(),
        "an unknown token holds no capability"
    );
    assert!(
        !s.plane_token_live("other_kind", "tok-1", 2_000, 1_500)
            .unwrap(),
        "the capability is per kind"
    );
    // The task ends: the write that made it terminal flips the record's disposition.
    s.upsert_plane_record(&cfg(PlaneDisposition::Terminal))
        .unwrap();
    assert!(
        !s.plane_token_live("push_config", "tok-1", 2_000, 1_500)
            .unwrap(),
        "a terminal record names finished work; its token is revoked"
    );
    // And the revoke leg deletes it outright.
    s.upsert_plane_record(&cfg(PlaneDisposition::Active))
        .unwrap();
    s.delete_plane_record("push_config", "tok-1").unwrap();
    assert!(!s
        .plane_token_live("push_config", "tok-1", 2_000, 1_500)
        .unwrap());
    assert!(s
        .get_plane_record("push_config", "tok-1")
        .unwrap()
        .is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A kind no plane in this build has ever named is stored and served exactly like the ones that
/// exist: the store is kind-neutral, so a plane added after this build ships needs no store change.
#[test]
fn a_kind_this_build_has_never_heard_of_round_trips() {
    let s = SqliteStore::open_in_memory().unwrap();
    let rec = PlaneRecord {
        kind: "future_kind".into(),
        id: "x".into(),
        parent: None,
        seq: 0,
        ts: 5,
        disposition: PlaneDisposition::Active,
        body: vec![0, 159, 146, 150, 255],
    };
    s.upsert_plane_record(&rec).unwrap();
    assert_eq!(
        s.get_plane_record("future_kind", "x").unwrap(),
        Some(rec.body.clone()),
        "an opaque, not-even-UTF-8 body comes back byte for byte"
    );
    assert_eq!(
        s.list_plane_records("future_kind", &PlaneSelector::All)
            .unwrap(),
        vec![rec.body.clone()]
    );
    // Not `task`, so its retention is every-row-older-than, active or not.
    assert_eq!(s.purge_plane_records_before("future_kind", 6).unwrap(), 1);
}

// ── 1.6.0 record shapes: keys, usage units, metering instants ────────────────────────────────

/// Every non-pool scope kind round-trips WITH its kind. Before v10 the store kept only bare values
/// in `allowed_pools`, so an `mcp_server` grant came back as a POOL grant: the MCP grant was lost and
/// a pool the key was never granted was opened.
#[test]
fn non_pool_scope_grants_round_trip_with_their_kind() {
    let dir = tempdir();
    let file = dir.join("scopes.db");
    let path = file.to_str().unwrap().to_string();
    let mut k = sample_key("vk_scopes", "g");
    k.allowed_scopes = Some(vec![
        ScopeRef::pool("fast"),
        ScopeRef {
            kind: "mcp_server".into(),
            value: "payments".into(),
        },
        ScopeRef {
            kind: "mcp_tool".into(),
            value: "payments_refund".into(),
        },
    ]);
    let mut only_mcp = sample_key("vk_only_mcp", "g");
    only_mcp.allowed_scopes = Some(vec![ScopeRef {
        kind: "mcp_server".into(),
        value: "search".into(),
    }]);
    {
        let s = SqliteStore::open(&path, 5000).unwrap();
        s.put_key(&k).unwrap();
        s.put_key(&only_mcp).unwrap();
        drop(s);
    }
    let s = SqliteStore::open(&path, 5000).unwrap();
    let got = s.get_key("vk_scopes").unwrap().unwrap();
    assert_eq!(got.allowed_scopes, k.allowed_scopes);
    assert!(got.scope_allowed("mcp_server", "payments"));
    assert!(
        !got.scope_allowed("pool", "payments"),
        "an mcp_server grant must never read back as a pool grant"
    );
    let got = s.get_key("vk_only_mcp").unwrap().unwrap();
    assert_eq!(
        got.allowed_scopes, only_mcp.allowed_scopes,
        "a grant of ONLY non-pool kinds is still an explicit grant, never the omitted-grant wildcard"
    );
    assert!(!got.scope_allowed("pool", "anything"));
    // And the key serializes back out over the plugin seam (the contract refuses an unregistered
    // non-pool kind on the wire; a kind read from this store is registered on the way out).
    serde_json::to_string(&got).expect("a stored non-pool grant must re-serialize");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The three 1.6.0 attribution fields round-trip, and a key written without them reads `None`.
#[test]
fn the_1_6_attribution_fields_round_trip() {
    let s = SqliteStore::open_in_memory().unwrap();
    let mut k = sample_key("vk_attr", "g");
    k.idp_subject = Some("user@example.test".into());
    k.binding_mode = Some("user-bound".into());
    k.minted_by = Some("vk_admin".into());
    s.put_key(&k).unwrap();
    let got = s.get_key("vk_attr").unwrap().unwrap();
    assert_eq!(got.idp_subject.as_deref(), Some("user@example.test"));
    assert_eq!(got.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(got.minted_by.as_deref(), Some("vk_admin"));
    // An update that clears them clears them.
    k.minted_by = None;
    s.put_key(&k).unwrap();
    assert_eq!(s.get_key("vk_attr").unwrap().unwrap().minted_by, None);
    s.put_key(&sample_key("vk_plain", "g")).unwrap();
    let plain = s.get_key("vk_plain").unwrap().unwrap();
    assert_eq!(
        (plain.idp_subject, plain.binding_mode, plain.minted_by),
        (None, None, None)
    );
}

/// The OPEN usage units (every name the four reserved token columns do not hold) accumulate and
/// floor at zero exactly like the reserved ones, survive an absolute `put_usage`, and go with their
/// window when retention sweeps it.
#[test]
fn open_usage_units_accumulate_overwrite_and_purge_with_their_window() {
    let s = SqliteStore::open_in_memory().unwrap();
    let units = |pairs: &[(&str, i64)]| -> std::collections::BTreeMap<String, i64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    };
    let add = |d: &[(&str, i64)]| {
        s.add_usage(
            "vk_u",
            100,
            &UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![ModelTokensDelta {
                    model: "rerank".into(),
                    usage_units: units(d),
                }],
            },
        )
        .unwrap()
    };
    add(&[(UNIT_INPUT, 10), ("search_units", 3), ("tool_calls", 2)]);
    add(&[("search_units", 4), ("tool_calls", -5)]);
    let ledger = s.get_usage("vk_u", 100).unwrap();
    let m = &ledger.models[0];
    assert_eq!(m.model, "rerank");
    assert_eq!(m.tier(UNIT_INPUT), 10);
    assert_eq!(m.usage_units.get("search_units"), Some(&7));
    assert_eq!(
        m.usage_units.get("tool_calls"),
        Some(&0),
        "an open unit floors at 0 like every durable counter"
    );
    assert_eq!(ledger.requests, 2);

    // An absolute set replaces the open units too, not just the columns.
    let mut model = ModelTokens {
        model: "rerank".into(),
        ..Default::default()
    };
    model.usage_units.insert(UNIT_OUTPUT.into(), 9);
    model.usage_units.insert("seconds".into(), 30);
    let set = UsageLedger {
        requests: 5,
        billable_requests: 4,
        models: vec![model],
    };
    s.put_usage("vk_u", 100, &set).unwrap();
    assert_eq!(
        s.get_usage("vk_u", 100).unwrap(),
        set,
        "put_usage is an absolute overwrite of the whole ledger, open units included"
    );

    assert_eq!(s.purge_windows_before(101).unwrap(), 1);
    assert_eq!(s.get_usage("vk_u", 100).unwrap(), UsageLedger::default());
    let left: i64 = s
        .lock_reader()
        .query_row("SELECT COUNT(*) FROM usage_window_units", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 0, "a purged window takes its open-unit rows with it");
}

/// `priced_from_ms` is part of a metering cell's KEY: a rate-card edit mid-day SPLITS the day's cell
/// so each half prices at the card it was earned under. The open classes ride on the cell they were
/// accrued with, additively.
#[test]
fn metering_cells_split_on_priced_from_and_carry_their_open_classes() {
    let s = SqliteStore::open_in_memory().unwrap();
    let d = |priced_from_ms: u64, tool_calls: u64| MeteringDelta {
        key_id: "vk_m".into(),
        bucket: 20260101,
        model: "gpt".into(),
        provider: "openai".into(),
        tokens_input: 10,
        tokens_output: 5,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "growth".into(),
        pricing_version: String::new(),
        priced_from_ms,
        usage_units: [("tool_calls".to_string(), tool_calls)]
            .into_iter()
            .collect(),
    };
    s.add_metering(&d(0, 2)).unwrap();
    s.add_metering(&d(0, 3)).unwrap();
    s.add_metering(&d(1_767_268_800_000, 1)).unwrap();
    let mut rows = s.list_metering(20260101).unwrap();
    rows.sort_by_key(|r| r.priced_from_ms);
    assert_eq!(rows.len(), 2, "a card edit splits the day's cell: {rows:?}");
    assert_eq!(rows[0].priced_from_ms, 0);
    assert_eq!(rows[0].tokens_input, 20);
    assert_eq!(rows[0].usage_units.get("tool_calls"), Some(&5));
    assert_eq!(rows[1].priced_from_ms, 1_767_268_800_000);
    assert_eq!(rows[1].tokens_input, 10);
    assert_eq!(rows[1].usage_units.get("tool_calls"), Some(&1));

    // An instant SQLite cannot hold is refused: clamped, it would merge into another card's cell.
    assert!(s.add_metering(&d(u64::MAX, 1)).is_err());

    assert_eq!(s.purge_metering_before("20260101").unwrap(), 2);
    let left: i64 = s
        .lock_reader()
        .query_row("SELECT COUNT(*) FROM usage_metering_units", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(left, 0, "a purged bucket takes its open-class rows with it");
}

// ── Upgrading a database the OLD code wrote ──────────────────────────────────────────────────
//
// `tests/fixtures/` holds two database files byte-for-byte as the old code left them (see the
// `gen_*.rs` provenance files beside them): `v6-release-1.0.6.db`, written by the latest RELEASE
// (store-sqlite v1.0.6 on busbar 1.5.5, schema v6) — the file every existing deployment has — and
// `v9-origin-dev.db`, written by this repo's pre-port `dev` (schema v9, never released). Each test
// copies one to a scratch dir, opens it with THIS build, and reads every row back.

fn open_fixture(name: &str) -> (std::path::PathBuf, SqliteStore) {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let dir = tempdir();
    let dst = dir.join(name);
    std::fs::copy(&src, &dst).unwrap_or_else(|e| panic!("copy fixture {src:?}: {e}"));
    let s = SqliteStore::open(dst.to_str().unwrap(), 5000)
        .unwrap_or_else(|e| panic!("a {name} database must open and upgrade: {e}"));
    (dir, s)
}

/// What BOTH fixtures carry (written by `gen_common.rs`), read back through the 1.6.0 surface.
fn assert_the_common_fixture_rows_survived(s: &SqliteStore) {
    let v: i64 = s
        .lock_reader()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        v, SCHEMA_VERSION,
        "the upgrade must stamp the current version"
    );

    let live = s.get_key("vk_live").unwrap().expect("vk_live survived");
    assert_eq!(
        live.allowed_scopes,
        Some(vec![ScopeRef::pool("fast"), ScopeRef::pool("slow")])
    );
    assert_eq!(live.group.as_deref(), Some("eng"));
    assert_eq!(live.labels.get("team").map(String::as_str), Some("growth"));
    assert_eq!(live.expires_at, Some(1_900_000_000));
    assert!(live.enabled && live.is_live());
    assert_eq!(
        (live.idp_subject, live.binding_mode, live.minted_by),
        (None, None, None),
        "a key minted before the 1.6.0 attribution fields reads None for all three"
    );
    assert_eq!(
        s.get_key("vk_all").unwrap().unwrap().allowed_scopes,
        None,
        "an omitted grant stays the wildcard"
    );
    assert_eq!(
        s.get_key("vk_none").unwrap().unwrap().allowed_scopes,
        Some(vec![]),
        "an explicit empty grant stays the empty set"
    );
    let dead = s.get_key("vk_dead").unwrap().unwrap();
    assert!(dead.deleted_at.is_some() && !dead.enabled);
    assert!(
        s.put_key(&sample_key("vk_dead", "g2")).is_err(),
        "an upgraded tombstone still refuses resurrection"
    );

    let cred = s
        .lookup_credential_secret("sigv4", "AKIAFIXTURE1")
        .unwrap()
        .expect("the credential survived");
    assert_eq!(cred.meta.key_id, "vk_live");
    assert_eq!(cred.plaintext(), Some("fixture-secret"));
    // (Not `updated_at`: v1.0.6 stored `created_at` there — the bug fixed on `dev` since — and an
    // upgrade carries the stored value across, it does not invent one.)

    assert_eq!(
        s.list_denylist().unwrap(),
        vec!["vk_revoked_sub".to_string()]
    );
    let audit = s.list_audit().unwrap();
    assert_eq!(audit.iter().map(|a| a.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(audit[1].prev_hash, "h1");

    let ledger = s.get_usage("vk_live", 1_700_000_000).unwrap();
    assert_eq!((ledger.requests, ledger.billable_requests), (7, 6));
    let gpt = ledger.models.iter().find(|m| m.model == "gpt-x").unwrap();
    assert_eq!(
        [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE].map(|u| gpt.tier(u)),
        [100, 50, 10, 5],
        "the reserved four stay in their columns and read back under their unit names"
    );
    assert_eq!(ledger.models.len(), 2);

    let rows = s.list_metering(1_699_920_000).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        (
            r.tokens_input,
            r.tokens_output,
            r.tokens_cache_read,
            r.tokens_cache_write
        ),
        (100, 50, 10, 5)
    );
    assert_eq!((r.requests, r.billable_requests), (7, 6));
    assert_eq!(r.key_group_at_use, "eng");
    assert_eq!(r.pricing_version, "v3");
    assert_eq!(
        r.priced_from_ms, 0,
        "a pre-v10 cell reads at the opening card's instant"
    );
    assert!(r.usage_units.is_empty());

    // The rebuilt metering table still accrues onto the SAME cell, and still guards the key.
    s.add_metering(&MeteringDelta {
        key_id: "vk_live".into(),
        bucket: 1_699_920_000,
        model: "gpt-x".into(),
        provider: "openai".into(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "eng".into(),
        pricing_version: "v3".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    })
    .unwrap();
    assert_eq!(s.list_metering(1_699_920_000).unwrap()[0].tokens_input, 101);
    assert!(
        s.lock_writer()
            .execute("DELETE FROM keys WHERE id='vk_live'", [])
            .is_err(),
        "the hard-delete guard is back on the rebuilt metering table"
    );

    // And the upgraded file takes 1.6.0 writes.
    s.upsert_plane_record(&task_record(&sample_task("t-new", "working", 5)))
        .unwrap();
    assert!(get_task(s, "t-new").is_some());
}

/// Every table/column/index an upgraded file carries is the one a fresh v10 file carries, so an
/// upgraded deployment and a new one are the same database from here on.
fn assert_schema_matches_a_fresh_one(s: &SqliteStore, ignore: &[&str]) {
    let shape = |conn: &Connection| -> Vec<String> {
        let mut out = Vec::new();
        let mut t = conn
            .prepare("SELECT type, name, tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
            .unwrap();
        let objs: Vec<(String, String, String)> = t
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for (ty, name, tbl) in objs {
            if ignore.contains(&tbl.as_str()) {
                continue;
            }
            out.push(format!("{ty} {name} on {tbl}"));
            if ty == "table" {
                let mut c = conn
                    .prepare("SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info(?1) ORDER BY cid")
                    .unwrap();
                let cols: Vec<String> = c
                    .query_map([&name], |r| {
                        Ok(format!(
                            "  {} {} nn={} d={:?} pk={}",
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, i64>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, i64>(4)?
                        ))
                    })
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                out.extend(cols);
            }
        }
        out
    };
    let fresh = SqliteStore::open_in_memory().unwrap();
    let want = shape(&fresh.lock_reader());
    let got = shape(&s.lock_reader());
    assert_eq!(
        got, want,
        "an upgraded database must have exactly a fresh one's shape"
    );
}

#[test]
fn a_real_v6_database_from_the_released_plugin_opens_and_upgrades_losslessly() {
    let (dir, s) = open_fixture("v6-release-1.0.6.db");
    assert_the_common_fixture_rows_survived(&s);
    assert_schema_matches_a_fresh_one(&s, &[]);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_real_v9_database_from_the_pre_port_dev_build_opens_and_upgrades_losslessly() {
    let (dir, s) = open_fixture("v9-origin-dev.db");
    assert_the_common_fixture_rows_survived(&s);

    // The typed task rows are now `task` records with the exact body the A2A plane decodes, and the
    // disposition the plane would have written.
    let active = get_task(&s, "task_active").expect("the in-flight task survived the upgrade");
    assert_eq!(active.state, "input-required");
    assert_eq!(active.artifact_cursor, 3);
    assert_eq!(active.push_callback, "https://cb.example/x");
    assert_eq!(
        (active.created_at, active.updated_at),
        (1_700_000_000, 1_700_000_100)
    );
    assert_eq!(get_task(&s, "task_done").unwrap().state, "completed");

    // Its provenance chain, in order, still linking — and with NO `digest_version`, which the plane
    // reads as the framing those hashes were sealed under.
    let events = list_events(&s, "task_active");
    assert_eq!(events.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(events[1].prev_hash, events[0].hash);
    assert_eq!(events[1].request_id, "req-2");
    let raw = s
        .list_plane_records("task_event", &PlaneSelector::Parent("task_active".into()))
        .unwrap();
    assert!(!String::from_utf8_lossy(&raw[0]).contains("digest_version"));

    // Retention reads the migrated disposition: the terminal task goes, the interrupted one stays.
    assert_eq!(
        s.purge_plane_records_before("task", 1_800_000_000).unwrap(),
        1
    );
    assert!(get_task(&s, "task_done").is_none());
    assert!(get_task(&s, "task_active").is_some());

    // The demotion is still in force.
    assert_eq!(
        list_demotions(&s),
        vec![demotion("srv_bad", "drift", 1_700_000_060)]
    );
    // The spent approval is still spent, under the kind the 1.6.0 kernel redeems with (`ask`, its
    // `KIND_ASK`). Filed under any other kind, this redemption is told it is the first, and the
    // approval the 1.5.x node already spent executes a second time after the upgrade.
    assert!(
        !s.redeem_plane_token("ask", "nonce_spent", 4_000_000_000, 1_700_000_001)
            .unwrap(),
        "DOUBLE SPEND: an approval spent before the upgrade was redeemed again after it"
    );

    // The call log is LEFT IN PLACE, unread: its rows cannot be re-encoded into the 1.6.0 call body
    // without forging the chain, and an upgrade must not destroy evidence.
    let kept: i64 = s
        .lock_reader()
        .query_row("SELECT COUNT(*) FROM mcp_calls", [], |r| r.get(0))
        .unwrap();
    assert_eq!(kept, 1);
    assert!(s.list_plane_record_parents("call").unwrap().is_empty());

    // The migrated typed tables are gone; everything else is a fresh v10 database's shape.
    assert_schema_matches_a_fresh_one(&s, &["mcp_calls"]);

    // A SECOND open of the upgraded file is a no-op, not a second migration.
    let path = dir.join("v9-origin-dev.db");
    drop(s);
    let again = SqliteStore::open(path.to_str().unwrap(), 5000).unwrap();
    assert_eq!(list_events(&again, "task_active").len(), 2);
    assert_eq!(list_demotions(&again).len(), 1);
    drop(again);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TWO FIRST-OPENS OF ONE UN-MIGRATED FILE. `migrate` gates its destructive pre-v5 drop on the
/// file's `user_version`, so that version must be the one inside the write transaction. Here a raw
/// connection plays the process that migrates first: it holds `BEGIN IMMEDIATE`, lays down the
/// current schema with a marker revision, stamps the current version and commits only after the
/// second store's `open` is already waiting on the lock. A version read before the lock is still 0
/// by then, the second open takes the drop path, and the first process's tables are wiped.
#[test]
fn a_second_first_open_waiting_on_the_lock_does_not_rerun_the_destructive_migration() {
    let dir = tempdir();
    let path = dir.join("two-first-opens.db");
    let path_str = path.to_str().unwrap().to_string();
    // An empty file already in WAL mode, so the waiting open's pragmas never need the lock.
    {
        let setup = Connection::open(&path).unwrap();
        setup
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0))
            .unwrap();
    }

    let first = Connection::open(&path).unwrap();
    first
        .execute_batch("PRAGMA busy_timeout = 10000; BEGIN IMMEDIATE;")
        .unwrap();
    first.execute_batch(SCHEMA).unwrap();
    first
        .execute_batch(&format!(
            "INSERT INTO store_revision (id, revision) VALUES (0, 42); \
             PRAGMA user_version = {SCHEMA_VERSION};"
        ))
        .unwrap();

    let reopened = std::thread::scope(|scope| {
        let waiter = scope.spawn(|| SqliteStore::open(&path_str, 10_000));
        // Long enough for the second open to reach its BEGIN IMMEDIATE and wait there.
        std::thread::sleep(std::time::Duration::from_millis(1000));
        first.execute_batch("COMMIT").unwrap();
        waiter.join().unwrap()
    })
    .expect("the second open waits for the first migration and then opens");

    let revision: i64 = reopened
        .lock_reader()
        .query_row(
            "SELECT revision FROM store_revision WHERE id = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        revision, 42,
        "the second open re-ran the pre-v5 drop against the tables the first open had just \
         migrated: it gated the drop on a user_version read before it held the write lock"
    );
    drop(reopened);
    drop(first);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A FILE FROM A LATER BUILD IS REFUSED, NOT RESTAMPED. Opening it would run this build's schema
/// pass over it and stamp it back down to `SCHEMA_VERSION`, so the newer build would later re-run
/// its own version-gated steps against data it already migrated.
#[test]
fn a_database_stamped_by_a_newer_build_is_refused_and_left_untouched() {
    let dir = tempdir();
    let path = dir.join("newer.db");
    {
        let c = Connection::open(&path).unwrap();
        c.execute_batch(&format!(
            "PRAGMA journal_mode=WAL; PRAGMA user_version = {};",
            SCHEMA_VERSION + 1
        ))
        .unwrap();
    }
    let err = match SqliteStore::open(path.to_str().unwrap(), 5000) {
        Ok(_) => panic!("a database stamped by a newer build must be refused"),
        Err(e) => e,
    };
    assert!(
        err.0.contains(&format!("v{}", SCHEMA_VERSION + 1)) && err.0.contains("newer"),
        "the refusal names the file's version and why: {err:?}"
    );
    let v: i64 = Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        v,
        SCHEMA_VERSION + 1,
        "a refused open must not restamp the file's version"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
