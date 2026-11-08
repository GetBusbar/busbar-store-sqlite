// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
const NS: [u8; 16] = [9; 16];
const WRITER: [u8; 16] = [2; 16];
fn address(key: &[u8]) -> Address {
    Address {
        namespace: NS,
        key: key.to_vec(),
    }
}
pub(super) fn put(key: &[u8], value: &[u8]) -> Mutation<Own> {
    Mutation::Put {
        address: address(key),
        value: Secret::held(value.to_vec()),
    }
}
fn opened(
    settings: &[u8],
    secrets: &[&[u8]],
    host: Option<Host<busbar_contract::plugin::markers::StoreKind>>,
) -> Result<SqliteV4, String> {
    let store = SqliteV4::open(settings, secrets, host)?;
    store.connect_now()?;
    Ok(store)
}
fn store() -> SqliteV4 {
    opened(br#"{"db_path":":memory:"}"#, &[], None).unwrap()
}
pub(super) fn candidate(s: &SqliteV4, op: u128, mutations: Vec<Mutation<Own>>) -> Candidate<Own> {
    Candidate {
        id: AttemptId {
            dataset: s.facts().dataset,
            writer_epoch: 1,
            writer: WRITER,
            execution_epoch: 1,
            operation: op.to_le_bytes(),
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations,
        time: None,
        result: Secret::held(b"result".to_vec()),
    }
}
pub(super) fn prepared(c: Candidate<Own>) -> PreparedCandidate<Own> {
    PreparedCandidate::new(c).unwrap()
}
fn initialization(s: &SqliteV4) -> Candidate<Own> {
    let root = Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    };
    let writer = Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key(WRITER).to_vec(),
    };
    Candidate {
        id: AttemptId {
            dataset: s.facts().dataset,
            writer_epoch: 1,
            writer: WRITER,
            execution_epoch: 1,
            operation: 1u128.to_le_bytes(),
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![
            Predicate {
                address: root.clone(),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: writer.clone(),
                expected: ExpectedValue::Absent,
            },
        ],
        mutations: vec![
            Mutation::Put {
                address: root,
                value: Secret::held(
                    control::Dataset {
                        id: s.facts().dataset,
                        writer_epoch: 1,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            },
            Mutation::Put {
                address: writer,
                value: Secret::held(
                    control::Writer {
                        retired_through: 0,
                        admitted_through: 1,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            },
        ],
        time: None,
        result: Secret::held(vec![]),
    }
}
pub(super) fn bootstrap(s: &SqliteV4) {
    assert!(matches!(
        s.commit_now(&prepared(initialization(s))).unwrap().decision,
        Decision::Applied(_)
    ));
}
fn read_key(s: &SqliteV4, key: &[u8]) -> Option<Vec<u8>> {
    match s
        .read_now(&Read {
            dataset: s.facts().dataset,
            addresses: vec![address(key)],
            time: None,
        })
        .unwrap()
    {
        ReadResult::Values { values, .. } => {
            values[0].as_ref().map(|v| v.expose_own(&s.owner).clone())
        }
        _ => panic!(),
    }
}
fn scan(s: &SqliteV4) -> Scan {
    Scan {
        dataset: s.facts().dataset,
        namespace: NamespaceId(NS),
        prefix: vec![],
        after: None,
        generation: None,
        allow_change: false,
        max_items: 2,
        max_bytes: 1024 * 1024,
    }
}

fn file_settings() -> (std::path::PathBuf, Vec<u8>) {
    let dir = std::env::temp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!(
        "sqlite-target-test-{:032x}.db",
        u128::from_le_bytes(random().unwrap())
    ));
    let settings = serde_json::to_vec(&serde_json::json!({"db_path":path})).unwrap();
    (path, settings)
}
fn close_file(path: &std::path::Path) {
    std::fs::remove_file(path).unwrap();
}
fn applied(s: &SqliteV4, c: Candidate<Own>) {
    assert!(matches!(
        s.commit_now(&prepared(c)).unwrap().decision,
        Decision::Applied(_)
    ))
}
#[test]
fn restart_preserves_identity_receipt_and_original_result() {
    let (path, cfg) = file_settings();
    let s = opened(&cfg, &[], None).unwrap();
    let info = s.facts();
    assert_eq!(info.durability, Durability::Local);
    bootstrap(&s);
    let p = prepared(candidate(&s, 2, vec![put(b"key", b"secret")]));
    let first = s.commit_now(&p).unwrap();
    drop(s);
    let s = opened(&cfg, &[], None).unwrap();
    assert_eq!(s.facts(), info);
    assert_eq!(read_key(&s, b"key"), Some(b"secret".to_vec()));
    let again = s.commit_now(&p).unwrap();
    assert_eq!(again.observed_at, first.observed_at);
    let Decision::Applied(v) = again.decision else {
        panic!()
    };
    assert_eq!(v.expose_own(&s.owner), b"result");
    let conflict = prepared(candidate(&s, 2, vec![put(b"key", b"other")]));
    assert!(matches!(
        s.commit_now(&conflict).unwrap().decision,
        Decision::OpIdConflict
    ));
    drop(s);
    close_file(&path);
}
#[test]
fn uninitialized_and_nonempty_missing_root_never_grant_authority() {
    let s = store();
    assert!(matches!(
        s.commit_now(&prepared(candidate(&s, 2, vec![put(b"a", b"b")])))
            .unwrap()
            .decision,
        Decision::ExpiredUnknown
    ));
    {
        let c = s.guard().unwrap();
        super::put(&c, NS, b"preexisting", b"x").unwrap();
    }
    assert!(matches!(
        s.commit_now(&prepared(initialization(&s)))
            .unwrap()
            .decision,
        Decision::ExpiredUnknown
    ));
    assert_eq!(read_key(&s, b"preexisting"), Some(b"x".to_vec()));
}
#[test]
fn exact_predicates_and_generations_prevent_races() {
    let (path, cfg) = file_settings();
    let a = opened(&cfg, &[], None).unwrap();
    bootstrap(&a);
    let b = opened(&cfg, &[], None).unwrap();
    let mut ca = candidate(&a, 2, vec![put(b"k", b"first")]);
    ca.predicates.push(Predicate {
        address: address(b"k"),
        expected: ExpectedValue::Absent,
    });
    let mut cb = candidate(&b, 3, vec![put(b"k", b"second")]);
    cb.predicates.push(Predicate {
        address: address(b"k"),
        expected: ExpectedValue::Absent,
    });
    let pa = prepared(ca);
    let pb = prepared(cb);
    std::thread::scope(|scope| {
        let one = scope.spawn(|| a.commit_now(&pa).unwrap());
        let two = scope.spawn(|| b.commit_now(&pb).unwrap());
        let decisions = [one.join().unwrap().decision, two.join().unwrap().decision];
        assert_eq!(
            decisions
                .iter()
                .filter(|d| matches!(d, Decision::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            decisions
                .iter()
                .filter(|d| matches!(d, Decision::ConditionConflict))
                .count(),
            1
        );
    });
    applied(&a, candidate(&a, 4, vec![put(b"z", b"z")]));
    let mut r = scan(&a);
    r.max_items = 1;
    let page = a.scan_now(&r).unwrap();
    assert!(page.next.is_some());
    r.after = page.next;
    r.generation = Some(page.generation);
    applied(&b, candidate(&b, 5, vec![put(b"new", b"new")]));
    assert_eq!(a.scan_now(&r).unwrap_err(), Failure::StaleScan);
    drop(a);
    drop(b);
    close_file(&path);
}
#[test]
fn serialization_time_bounds_and_coherent_read() {
    let s = store();
    bootstrap(&s);
    let now = {
        let c = s.guard().unwrap();
        s.observation(&c).unwrap().unix_seconds
    };
    let mut c = candidate(&s, 2, vec![put(b"k", b"value")]);
    c.time = Some(TimeGuard {
        not_before: None,
        before: Some(now),
    });
    assert!(matches!(
        s.commit_now(&prepared(c)).unwrap().decision,
        Decision::TimeGuardFailed { .. }
    ));
    assert_eq!(read_key(&s, b"k"), None);
    let r = Read {
        dataset: s.facts().dataset,
        addresses: vec![address(b"k")],
        time: Some(TimeGuard {
            not_before: Some(u64::MAX),
            before: None,
        }),
    };
    assert!(matches!(
        s.read_now(&r).unwrap(),
        ReadResult::TimeGuardFailed { .. }
    ));
    let mut c = candidate(&s, 3, vec![put(b"k", b"value")]);
    c.time = Some(TimeGuard {
        not_before: Some(now),
        before: None,
    });
    applied(&s, c);
}
#[test]
fn raw_order_range_exact_lengths_large_values_and_large_batch() {
    let s = store();
    bootstrap(&s);
    let big = vec![42; 17 * 1024 * 1024];
    let mut mutations: Vec<_> = (0..1200u32).map(|i| put(&i.to_be_bytes(), b"v")).collect();
    mutations.extend([
        put(b"\xff\0", b"x"),
        put(b"\xff\0\0", b"keep"),
        put(b"\xff\x01", b"x"),
        put(b"large", &big),
    ]);
    applied(&s, candidate(&s, 2, mutations));
    assert_eq!(read_key(&s, b"large").unwrap(), big);
    let mut r = scan(&s);
    r.prefix = vec![255];
    r.max_items = 10;
    let page = s.scan_now(&r).unwrap();
    assert_eq!(
        page.rows
            .iter()
            .map(|r| r.0.key.as_slice())
            .collect::<Vec<_>>(),
        vec![b"\xff\0".as_slice(), b"\xff\0\0", b"\xff\x01"]
    );
    applied(
        &s,
        candidate(
            &s,
            3,
            vec![Mutation::DeleteRange {
                namespace: NamespaceId(NS),
                prefix: vec![255],
                exact_key_length: 2,
            }],
        ),
    );
    assert_eq!(read_key(&s, b"\xff\0"), None);
    assert_eq!(read_key(&s, b"\xff\x01"), None);
    assert!(read_key(&s, b"\xff\0\0").is_some());
    let c = s.guard().unwrap();
    assert_eq!(generation(&c, NS, &s.owner).unwrap(), 2);
}
#[test]
fn closed_authority_replays_but_new_attempts_expire_and_malformed_fences_corrupt() {
    let s = store();
    bootstrap(&s);
    let p = prepared(candidate(&s, 2, vec![put(b"k", b"v")]));
    s.commit_now(&p).unwrap();
    let at = Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key(WRITER).to_vec(),
    };
    let previous = {
        let c = s.guard().unwrap();
        super::get(&c, at.namespace, &at.key).unwrap().unwrap()
    };
    let mut c = candidate(
        &s,
        3,
        vec![Mutation::Put {
            address: at.clone(),
            value: Secret::held(
                control::Writer {
                    retired_through: 1,
                    admitted_through: 1,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
        }],
    );
    c.predicates.push(Predicate {
        address: at.clone(),
        expected: ExpectedValue::Exact(previous),
    });
    applied(&s, c);
    assert!(matches!(
        s.commit_now(&p).unwrap().decision,
        Decision::Applied(_)
    ));
    assert!(matches!(
        s.commit_now(&prepared(candidate(&s, 4, vec![put(b"x", b"v")])))
            .unwrap()
            .decision,
        Decision::ExpiredUnknown
    ));
    {
        let c = s.guard().unwrap();
        super::put(&c, at.namespace, &at.key, b"broken").unwrap();
    }
    assert_eq!(
        s.commit_now(&prepared(candidate(&s, 5, vec![put(b"x", b"v")])))
            .unwrap_err(),
        Failure::Corrupt
    );
    assert!(matches!(
        s.commit_now(&p).unwrap().decision,
        Decision::Applied(_)
    ));
}
#[test]
fn forbidden_control_mutations_and_generation_overflow_are_atomic() {
    let s = store();
    bootstrap(&s);
    let c = candidate(
        &s,
        2,
        vec![Mutation::Delete(Address {
            namespace: control::NAMESPACE.0,
            key: control::DATASET_KEY.to_vec(),
        })],
    );
    assert_eq!(s.commit_now(&prepared(c)).unwrap_err(), Failure::Refused);
    let c = candidate(
        &s,
        3,
        vec![Mutation::Put {
            address: Address {
                namespace: control::GENERATION_NAMESPACE.0,
                key: NS.to_vec(),
            },
            value: Secret::held(1u64.to_le_bytes().to_vec()),
        }],
    );
    assert_eq!(s.commit_now(&prepared(c)).unwrap_err(), Failure::Refused);
    {
        let c = s.guard().unwrap();
        super::put(
            &c,
            control::GENERATION_NAMESPACE.0,
            &NS,
            &u64::MAX.to_le_bytes(),
        )
        .unwrap();
    }
    assert_eq!(
        s.commit_now(&prepared(candidate(&s, 4, vec![put(b"k", b"v")])))
            .unwrap_err(),
        Failure::Refused
    );
    assert_eq!(read_key(&s, b"k"), None);
}
#[test]
fn legacy_unknown_partial_and_unmarked_databases_are_not_modified() {
    for ddl in ["CREATE TABLE keys(id TEXT PRIMARY KEY, secret BLOB); INSERT INTO keys VALUES('old',x'736563726574')", "CREATE TABLE records(namespace BLOB,key BLOB,value BLOB)", "CREATE TABLE meta(key TEXT PRIMARY KEY,value BLOB); INSERT INTO meta VALUES('physical_format',x'01000000')"] {
        let (path,cfg)=file_settings();let c=Connection::open(&path).unwrap();c.execute_batch(ddl).unwrap();drop(c);
        let before=std::fs::read(&path).unwrap();assert!(opened(&cfg,&[],None).is_err());
        assert_eq!(std::fs::read(&path).unwrap(),before);close_file(&path);
    }
}

#[test]
fn receipt_gc_requires_durable_retirement_and_full_monotonic_horizon_after_restart() {
    use busbar_contract::abi::sdk::store::v4::retirement::MIN_RETENTION;
    let (path, cfg) = file_settings();
    let s = opened(&cfg, &[], None).unwrap();
    bootstrap(&s);
    let p = prepared(candidate(&s, 2, vec![put(b"k", b"v")]));
    s.commit_now(&p).unwrap();
    let at = Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key(WRITER).to_vec(),
    };
    let previous = {
        let c = s.guard().unwrap();
        super::get(&c, at.namespace, &at.key).unwrap().unwrap()
    };
    let mut close = candidate(
        &s,
        3,
        vec![Mutation::Put {
            address: at.clone(),
            value: Secret::held(
                control::Writer {
                    retired_through: 1,
                    admitted_through: 1,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
        }],
    );
    close.predicates.push(Predicate {
        address: at,
        expected: ExpectedValue::Exact(previous),
    });
    applied(&s, close);
    let start = Instant::now();
    s.horizons.lock().unwrap().clear();
    {
        let mut c = s.guard().unwrap();
        s.collect_receipts(&mut c, start).unwrap();
        s.collect_receipts(
            &mut c,
            start + MIN_RETENTION - std::time::Duration::from_nanos(1),
        )
        .unwrap();
    }
    assert!(matches!(
        s.commit_now(&p).unwrap().decision,
        Decision::Applied(_)
    ));
    drop(s);
    // Restart discards any old grace; even a large absolute wall time proves nothing.
    let s = opened(&cfg, &[], None).unwrap();
    let new_start = start + MIN_RETENTION;
    {
        let mut c = s.guard().unwrap();
        s.collect_receipts(&mut c, new_start).unwrap();
    }
    assert!(matches!(
        s.commit_now(&p).unwrap().decision,
        Decision::Applied(_)
    ));
    {
        let mut c = s.guard().unwrap();
        s.collect_receipts(&mut c, new_start + MIN_RETENTION)
            .unwrap();
    }
    assert!(matches!(
        s.commit_now(&p).unwrap().decision,
        Decision::ExpiredUnknown
    ));
    assert_eq!(read_key(&s, b"k"), Some(b"v".to_vec()));
    drop(s);
    close_file(&path);
}

#[test]
fn published_legacy_fixture_copy_refuses_without_data_change() {
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/1.5.5/governance.db");
    let original = std::fs::read(&source).unwrap();
    let (path, cfg) = file_settings();
    std::fs::write(&path, &original).unwrap();
    assert!(opened(&cfg, &[], None).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    close_file(&path);
    // Read-only WAL inspection may create locking sidecars on the disposable copy.
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
#[test]
fn instance_budget_is_explicitly_configurable_and_validated_without_opening() {
    assert!(SqliteV4::validate(br#"{"input_budget_bytes":0}"#).is_err());
    let s = opened(
        br#"{"db_path":":memory:","input_budget_bytes":12345}"#,
        &[],
        None,
    )
    .unwrap();
    assert_eq!(s.input_budget(), 12345);
    assert_eq!(s.facts().durability, Durability::Ephemeral);
}

#[test]
fn present_bad_root_is_corrupt_and_commit_failure_is_unknown_without_partial_effects() {
    let s = store();
    bootstrap(&s);
    let p = prepared(candidate(&s, 2, vec![put(b"k", b"v")]));
    s.guard().unwrap().commit_hook(Some(|| true)).unwrap();
    assert_eq!(s.commit_now(&p).unwrap_err(), Failure::Unknown);
    s.guard()
        .unwrap()
        .commit_hook(None::<fn() -> bool>)
        .unwrap();
    assert_eq!(read_key(&s, b"k"), None);
    assert!(matches!(
        s.commit_now(&p).unwrap().decision,
        Decision::Applied(_)
    ));
    {
        let c = s.guard().unwrap();
        super::put(&c, control::NAMESPACE.0, control::DATASET_KEY, b"bad root").unwrap();
    }
    assert_eq!(
        s.commit_now(&prepared(candidate(&s, 3, vec![put(b"other", b"v")])))
            .unwrap_err(),
        Failure::Corrupt
    );
    assert!(matches!(
        s.commit_now(&p).unwrap().decision,
        Decision::Applied(_)
    ));
}

#[test]
fn settings_schema_matches_native_validation_without_opening() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("../settings.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for (text, accepted) in [
        (r#"{}"#, true),
        (r#"null"#, true),
        (r#"{"db_path":null,"busy_timeout_ms":null}"#, true),
        (
            r#"{"db_path":":memory:","busy_timeout_ms":0,"input_budget_bytes":1024}"#,
            true,
        ),
        (r#"{"db_path":" "}"#, false),
        (r#"{"db_path":1}"#, false),
        (r#"{"busy_timeout_ms":-1}"#, false),
        (r#"{"busy_timeout_ms":2147483648}"#, false),
        (r#"{"busy_timeout_ms":1.5}"#, false),
        (r#"{"input_budget_bytes":0}"#, false),
        (r#"{"unknown":0}"#, false),
        (r#"[]"#, false),
    ] {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(validator.is_valid(&value), accepted, "schema {text}");
        assert_eq!(
            SqliteV4::validate(text.as_bytes()).is_ok(),
            accepted,
            "native validation {text}"
        );
    }
    assert!(SqliteV4::validate(b"").is_ok());
    assert!(SqliteV4::validate(br#"{"busy_timeout_ms":1e3}"#).is_err());
}
