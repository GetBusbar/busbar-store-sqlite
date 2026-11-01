// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::{Arc, Barrier};

fn row(store: &SqliteStore) -> CredentialSecret {
    store
        .lookup_credential_secret("sigv4", "public")
        .unwrap()
        .unwrap()
}

fn revision(store: &SqliteStore) -> i64 {
    store
        .lock_reader()
        .query_row("SELECT revision FROM store_revision WHERE id=0", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn independent_connections_rewrap_once_and_keep_the_committed_envelope_after_reopen() {
    let dir = tempdir();
    let path = dir.join("rewrap.db").display().to_string();
    let store = SqliteStore::open(&path, 5000).unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    store
        .put_credential(&sample_credential("owner", "public", 0))
        .unwrap();
    let expected = row(&store);
    let before = revision(&store);
    assert!(!store
        .rewrap_credential(&expected, &expected.secret)
        .unwrap());
    let mut altered = expected.clone();
    altered.meta.updated_at += 1;
    assert!(!store
        .rewrap_credential(&altered, "v1:test:altered-metadata")
        .unwrap());
    assert_eq!(revision(&store), before);
    let gate = Arc::new(Barrier::new(3));
    let connections = [
        SqliteStore::open(&path, 5000).unwrap(),
        SqliteStore::open(&path, 5000).unwrap(),
    ];
    let writers: Vec<_> = connections
        .into_iter()
        .zip(["v1:test:envelope-a", "v1:test:envelope-b"])
        .map(|(connection, envelope)| {
            let gate = Arc::clone(&gate);
            let expected = expected.clone();
            std::thread::spawn(move || {
                gate.wait();
                (
                    envelope,
                    connection.rewrap_credential(&expected, envelope).unwrap(),
                )
            })
        })
        .collect();
    gate.wait();
    let outcomes: Vec<_> = writers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|(_, applied)| *applied).count(), 1);
    let winner = outcomes.iter().find(|(_, applied)| *applied).unwrap().0;
    let current = row(&store);
    let mut wanted = expected.clone();
    wanted.secret = winner.into();
    wanted.meta.revision = current.meta.revision;
    assert!(current == wanted);
    assert_eq!(current.meta.revision, expected.meta.revision + 1);
    assert_eq!(revision(&store), before + 1);
    assert!(!store.rewrap_credential(&expected, "v1:test:stale").unwrap());
    assert!(!store.rewrap_credential(&current, &current.secret).unwrap());
    let mut ordinary = current.clone();
    ordinary.secret = "v1:test:ordinary-put-must-not-rotate".into();
    assert!(store.put_credential(&ordinary).is_err());
    assert!(row(&store) == current);
    assert_eq!(revision(&store), before + 1);
    drop(store);
    let reopened = SqliteStore::open(&path, 5000).unwrap();
    assert!(row(&reopened) == current);
}

#[test]
fn rewrap_cannot_resurrect_revoked_deleted_or_reclaimed_rows() {
    for delete in [false, true] {
        let store = SqliteStore::open_in_memory().unwrap();
        store.put_key(&sample_key("owner", "hash")).unwrap();
        store
            .put_credential(&sample_credential("owner", "public", 0))
            .unwrap();
        let expected = row(&store);
        if delete {
            store.delete_key("owner").unwrap();
        } else {
            store
                .revoke_credential(&expected.meta.id, "revoked")
                .unwrap();
        }
        let retired = store.list_credentials_since(0).unwrap();
        let before = revision(&store);
        assert!(!store
            .rewrap_credential(&expected, "v1:test:resurrection")
            .unwrap());
        assert!(store.list_credentials_since(0).unwrap() == retired);
        assert_eq!(revision(&store), before);
        if !delete {
            store
                .put_credential(&sample_credential("owner", "reclaimed", 0))
                .unwrap();
            let reclaimed = store.list_credentials_since(0).unwrap();
            let before = revision(&store);
            assert!(!store
                .rewrap_credential(&expected, "v1:test:resurrection")
                .unwrap());
            assert!(store.list_credentials_since(0).unwrap() == reclaimed);
            assert_eq!(revision(&store), before);
        }
    }
}

#[test]
fn a_failed_rewrap_rolls_back_its_revision_and_envelope_together() {
    for phase in ["BEFORE", "AFTER"] {
        let store = SqliteStore::open_in_memory().unwrap();
        store.put_key(&sample_key("owner", "hash")).unwrap();
        store
            .put_credential(&sample_credential("owner", "public", 0))
            .unwrap();
        let expected = row(&store);
        let before = revision(&store);
        store.lock_writer().execute_batch(&format!("CREATE TRIGGER refuse_rewrap {phase} UPDATE OF secret ON credentials BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;")).unwrap();
        assert!(store
            .rewrap_credential(&expected, "v1:test:replacement")
            .is_err());
        assert!(row(&store) == expected);
        assert_eq!(revision(&store), before);
        store
            .lock_writer()
            .execute_batch("DROP TRIGGER refuse_rewrap")
            .unwrap();
        assert!(store
            .rewrap_credential(&expected, "v1:test:replacement")
            .unwrap());
        assert_eq!(revision(&store), before + 1);
    }
}

#[test]
fn every_expected_field_participates_in_cas_and_success_preserves_metadata() {
    let store = SqliteStore::open_in_memory().unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    let mut credential = sample_credential("owner", "public", 0);
    credential.meta.created_at = 9_007_199_254_740_993;
    credential.meta.updated_at = 9_007_199_254_740_995;
    credential.meta.expires_at = Some(9_007_199_254_740_997);
    store.put_credential(&credential).unwrap();
    let expected = row(&store);
    let before = revision(&store);
    let mut variants = Vec::new();
    macro_rules! altered {
        ($field:ident, $value:expr) => {{
            let mut candidate = expected.clone();
            candidate.meta.$field = $value;
            variants.push(candidate);
        }};
    }
    altered!(id, "another-id".into());
    altered!(key_id, "another-owner".into());
    altered!(kind, "another-kind".into());
    altered!(slot, 1);
    altered!(public_id, "another-public-id".into());
    altered!(secret_form, SecretForm::None);
    altered!(created_at, expected.meta.created_at - 1);
    altered!(updated_at, expected.meta.updated_at - 1);
    altered!(expires_at, None);
    altered!(revoked_at, Some(1));
    altered!(revoke_reason, Some("another-reason".into()));
    altered!(revision, expected.meta.revision + 1);
    let mut wrong_envelope = expected.clone();
    wrong_envelope.secret = "v1:test:wrong-envelope".into();
    variants.push(wrong_envelope);
    for candidate in variants {
        assert!(!store
            .rewrap_credential(&candidate, "v1:test:replacement")
            .unwrap());
        assert!(row(&store) == expected);
        assert_eq!(revision(&store), before);
    }
    assert!(store
        .rewrap_credential(&expected, "v1:test:replacement")
        .unwrap());
    let mut wanted = expected;
    wanted.secret = "v1:test:replacement".into();
    wanted.meta.revision += 1;
    assert!(row(&store) == wanted);
    assert_eq!(revision(&store), before + 1);
}

#[test]
fn an_exact_credential_cannot_be_rewrapped_under_a_tombstoned_owner() {
    let store = SqliteStore::open_in_memory().unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    store
        .put_credential(&sample_credential("owner", "public", 0))
        .unwrap();
    let expected = row(&store);
    store
        .lock_writer()
        .execute(
            "UPDATE keys SET enabled=0, deleted_at=1 WHERE id='owner'",
            [],
        )
        .unwrap();
    let before = revision(&store);
    assert!(!store
        .rewrap_credential(&expected, "v1:test:replacement")
        .unwrap());
    assert!(row(&store) == expected);
    assert_eq!(revision(&store), before);
}

#[test]
fn rewrap_does_not_insert_a_missing_credential_for_a_live_owner() {
    let store = SqliteStore::open_in_memory().unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    store
        .put_credential(&sample_credential("owner", "public", 0))
        .unwrap();
    let expected = row(&store);
    store
        .lock_writer()
        .execute(
            "DELETE FROM credentials WHERE id=?1",
            params![expected.meta.id],
        )
        .unwrap();
    let before = revision(&store);
    assert!(!store
        .rewrap_credential(&expected, "v1:test:replacement")
        .unwrap());
    assert!(store
        .get_key("owner")
        .unwrap()
        .unwrap()
        .deleted_at
        .is_none());
    assert!(store.list_credentials_since(0).unwrap().is_empty());
    assert_eq!(revision(&store), before);
}
