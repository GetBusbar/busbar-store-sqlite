// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut, ReleaseIn};
use busbar_contract::abi::sdk::store::rewrap;
use busbar_contract::abi::store::{records::BlobIn, slot};
use busbar_contract::records::{CredentialMeta, CredentialSecret, SecretForm};

const RAW_SQLITE_TEST: &str =
    "credential_rewrap::linked_rewrap_reconciles_a_cancelled_commit_reply_once";
const RAW_SQLITE_OPERATION: &str = "BUSBAR_SQLITE_REWRAP_RAW_OPERATION";
const RAW_SQLITE_PATH: &str = "BUSBAR_SQLITE_REWRAP_RAW_PATH";
const RAW_SQLITE_RESULT: &str = "BUSBAR_SQLITE_REWRAP_RAW_RESULT:";
const IGNORE_REWRAP_TRIGGER: &str =
    "CREATE TRIGGER ignore_rewrap BEFORE UPDATE OF secret ON credentials
     WHEN NEW.revision = OLD.revision + 1
       AND (SELECT revision FROM store_revision WHERE id=0) = NEW.revision
     BEGIN SELECT RAISE(IGNORE); END;";

/// The executable and cdylib each bundle SQLite. Their process-local VFS lock tables are
/// independent, while POSIX locks belong to the process. Keep raw observers in another process
/// so closing one engine's connection cannot interfere with the live dropped provider's WAL.
/// The parent keeps its Store open: this still witnesses the commit immediately after READY.
fn raw_sqlite(path: &std::path::Path, operation: &str) -> Option<i64> {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", RAW_SQLITE_TEST, "--nocapture", "--color=never"])
        .env(RAW_SQLITE_OPERATION, operation)
        .env(RAW_SQLITE_PATH, path)
        .output()
        .expect("run the Rust SQLite witness process");
    let stdout = String::from_utf8(output.stdout).expect("the witness prints UTF-8 JSON");
    assert!(
        output.status.success(),
        "raw SQLite witness failed: status={} stdout={} stderr={}",
        output.status,
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("1 passed; 0 failed;"),
        "the exact existing fixture test must execute once: {stdout}"
    );
    let results: Vec<serde_json::Value> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(RAW_SQLITE_RESULT))
        .map(|json| serde_json::from_str(json).expect("the witness returns structured JSON"))
        .collect();
    assert_eq!(results.len(), 1, "one SQLite witness result: {stdout}");
    assert_eq!(results[0]["test"], RAW_SQLITE_TEST);
    assert_eq!(results[0]["operation"], operation);
    let revision = results[0]
        .get("revision")
        .expect("the witness result contains its revision field");
    if revision.is_null() {
        None
    } else {
        Some(
            revision
                .as_i64()
                .expect("the witness revision is an exact i64"),
        )
    }
}

/// Entered only by raw_sqlite's scoped child environment, before either scenario opens a Store.
/// No new ignored test or external SQL interpreter is needed; SQL failures fail the child test.
fn raw_sqlite_helper_mode() -> bool {
    let Some(operation) = std::env::var_os(RAW_SQLITE_OPERATION) else {
        return false;
    };
    let operation = operation.to_str().expect("the witness operation is UTF-8");
    let path = std::env::var_os(RAW_SQLITE_PATH).expect("the witness names its database");
    let path = std::path::PathBuf::from(path);
    let revision = match operation {
        "revision" => {
            let conn = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("open the committed database read-only");
            Some(
                conn.query_row(
                    "SELECT revision FROM store_revision WHERE id=0",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("read the committed global revision"),
            )
        }
        "create-ignore-trigger" => {
            rusqlite::Connection::open(&path)
                .unwrap()
                .execute_batch(IGNORE_REWRAP_TRIGGER)
                .expect("create the real ignored-update trigger");
            None
        }
        "drop-ignore-trigger" => {
            rusqlite::Connection::open(&path)
                .unwrap()
                .execute_batch("DROP TRIGGER ignore_rewrap")
                .expect("drop the real ignored-update trigger");
            None
        }
        other => panic!("unknown raw SQLite witness operation: {other}"),
    };
    println!(
        "\n{RAW_SQLITE_RESULT}{}",
        serde_json::json!({"test": RAW_SQLITE_TEST, "operation": operation, "revision": revision})
    );
    true
}

fn revision(path: &std::path::Path) -> i64 {
    raw_sqlite(path, "revision").expect("the revision witness returns the exact global counter")
}

fn row(store: &LoadedStore) -> CredentialSecret {
    store
        .list_credentials_since(0)
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
}

fn scenario(by: Door, tag: &str) {
    if raw_sqlite_helper_mode() {
        return;
    }
    let dir = scratch(tag);
    let path = dir.join("rewrap.db");
    let cfg = serde_json::json!({"db_path": path}).to_string();
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load::<Store>(by, &dispatcher).unwrap();
    let store = LoadedStore::open(plugin, Arc::clone(&dispatcher), cfg.as_bytes(), mint).unwrap();
    assert!(store.facts().credential_rewrap);
    store.put_key(&key("owner")).unwrap();
    store
        .put_credential(&CredentialSecret {
            meta: CredentialMeta {
                id: "credential".into(),
                key_id: "owner".into(),
                kind: "sigv4".into(),
                slot: 0,
                public_id: "public".into(),
                secret_form: SecretForm::Recoverable,
                created_at: 9_007_199_254_740_993,
                updated_at: 9_007_199_254_740_995,
                expires_at: Some(9_007_199_254_740_997),
                revoked_at: None,
                revoke_reason: None,
                revision: 0,
            },
            secret: "v1:test:old-envelope".into(),
        })
        .unwrap();
    let expected = row(&store);
    let before = revision(&path);

    // The database commits through the real slot, but the caller loses the result before it
    // consumes the leased extension. Cancelling that ticket cannot undo a completed transaction.
    let request = rewrap::Request::new(&expected, "v1:test:new-envelope");
    let payload = serde_json::to_vec(&request).unwrap();
    let intent = extensions::encode(&[(rewrap::INTENT, b"1")]);
    let mut head = in_head();
    // SAFETY: both input buffers remain alive and immutable through the synchronous crossing.
    head.extensions =
        unsafe { Blob::from_raw_parts(intent.as_ptr(), intent.len(), BLOB_OCTETS, 0) };
    // SAFETY: the request payload remains alive and immutable through the synchronous crossing.
    let record =
        unsafe { Blob::from_raw_parts(payload.as_ptr(), payload.len(), BLOB_JSON, BLOB_SECRET) };
    let mut frame = Frame::new(BlobIn { head, record }, out_head());
    let held = dispatcher
        .inline_ticket()
        .expect("the dispatcher mints a real ticket");
    let ticket = held.ticket();
    let called = store
        .plugin()
        .call_inline(ticket, false, slot::PUT_CREDENTIAL, &mut frame);
    assert_eq!(called.outcome, Outcome::Ready);
    let mut cancel = Frame::new(
        CancelIn {
            head: in_head(),
            ticket,
        },
        CancelOut {
            head: out_head(),
            disposition: 0,
            _reserved: 0,
        },
    );
    assert_eq!(
        store.plugin().call(lc::CANCEL, &mut cancel).outcome,
        Outcome::Ready
    );
    let mut release = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease: called.lease,
        },
        out_head(),
    );
    assert_eq!(
        store.plugin().call(lc::RELEASE, &mut release).outcome,
        Outcome::Ready
    );
    drop(held);
    close(store);

    let store = open(by, &cfg).unwrap();
    let current = row(&store);
    let mut wanted = expected.clone();
    wanted.secret = "v1:test:new-envelope".into();
    wanted.meta.revision += 1;
    assert!(current == wanted);
    assert_eq!(revision(&path), before + 1);
    assert!(!store
        .rewrap_credential(&expected, "v1:test:new-envelope")
        .unwrap());
    assert!(!store
        .rewrap_credential(&current, "v1:test:new-envelope")
        .unwrap());
    let mut ordinary = current.clone();
    ordinary.secret = "v1:test:ordinary-put".into();
    assert!(store.put_credential(&ordinary).is_err());
    assert!(row(&store) == current);
    assert_eq!(revision(&path), before + 1);

    assert!(store
        .rewrap_credential(&current, "v1:test:third-envelope")
        .unwrap());
    assert_eq!(revision(&path), before + 2);
    let current = row(&store);
    store
        .revoke_credential(&current.meta.id, "operator-revoked")
        .unwrap();
    let revoked = row(&store);
    let revoked_revision = revision(&path);
    assert!(!store
        .rewrap_credential(&current, "v1:test:resurrection")
        .unwrap());
    assert!(row(&store) == revoked);
    assert!(revoked.secret.is_empty());
    assert_eq!(revision(&path), revoked_revision);
    close(store);
    let store = open(by, &cfg).unwrap();
    assert!(row(&store) == revoked);
    close(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn linked_rewrap_reconciles_a_cancelled_commit_reply_once() {
    scenario(Door::Linked, "linked-rewrap");
}

#[test]
fn dropped_rewrap_reconciles_a_cancelled_commit_reply_once() {
    scenario(Door::Dropped, "dropped-rewrap");
}

fn ignored_update_rolls_back(by: Door, tag: &str) {
    if raw_sqlite_helper_mode() {
        return;
    }
    let dir = scratch(tag);
    let path = dir.join("rewrap.db");
    let cfg = serde_json::json!({"db_path": path}).to_string();
    let store = open(by, &cfg).unwrap();
    assert!(store.facts().credential_rewrap);
    store.put_key(&key("owner")).unwrap();
    store
        .put_credential(&CredentialSecret {
            meta: CredentialMeta {
                id: "credential".into(),
                key_id: "owner".into(),
                kind: "sigv4".into(),
                slot: 0,
                public_id: "public".into(),
                secret_form: SecretForm::Recoverable,
                created_at: 9_007_199_254_740_993,
                updated_at: 9_007_199_254_740_995,
                expires_at: Some(9_007_199_254_740_997),
                revoked_at: None,
                revoke_reason: None,
                revision: 0,
            },
            secret: "v1:test:old-envelope".into(),
        })
        .unwrap();
    let expected = row(&store);
    let owner = store.get_key("owner").unwrap().unwrap();
    let before = revision(&path);
    // Suppress the actual credential UPDATE only after the same transaction allocated its next
    // revision. SQLite reports zero changed rows without raising a SQL error.
    assert!(raw_sqlite(&path, "create-ignore-trigger").is_none());
    let error = store
        .rewrap_credential(&expected, "v1:test:replacement")
        .expect_err("a suppressed update must refuse rather than commit its allocated revision");
    assert!(error.0.contains("credential rewrap lost its locked row"));
    assert!(row(&store) == expected);
    assert!(store.get_key("owner").unwrap().unwrap() == owner);
    assert_eq!(revision(&path), before);
    close(store);

    let store = open(by, &cfg).unwrap();
    assert!(
        row(&store) == expected,
        "the unchanged full row must survive reopen"
    );
    assert!(store.get_key("owner").unwrap().unwrap() == owner);
    assert_eq!(revision(&path), before);
    assert!(raw_sqlite(&path, "drop-ignore-trigger").is_none());
    assert!(store
        .rewrap_credential(&expected, "v1:test:replacement")
        .unwrap());
    let mut wanted = expected.clone();
    wanted.secret = "v1:test:replacement".into();
    wanted.meta.revision += 1;
    assert!(row(&store) == wanted);
    assert_eq!(revision(&path), before + 1);
    assert!(!store
        .rewrap_credential(&expected, "v1:test:replacement")
        .unwrap());
    assert!(!store.rewrap_credential(&wanted, &wanted.secret).unwrap());
    assert_eq!(revision(&path), before + 1);
    close(store);
    let store = open(by, &cfg).unwrap();
    assert!(row(&store) == wanted);
    assert_eq!(revision(&path), before + 1);
    close(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn linked_rewrap_rolls_back_a_trigger_ignored_update_and_recovers_once() {
    ignored_update_rolls_back(Door::Linked, "linked-rewrap-ignore");
}

#[test]
fn dropped_rewrap_rolls_back_a_trigger_ignored_update_and_recovers_once() {
    ignored_update_rolls_back(Door::Dropped, "dropped-rewrap-ignore");
}
