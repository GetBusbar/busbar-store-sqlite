// SPDX-License-Identifier: Apache-2.0
//! Typed automatic native lifecycle crossing; core owns all logical transforms.
use super::*;
use crate::legacy::native::{Error as NativeError, Inspection, Session, Upgrade};
use lifecycle::{CompletionPhase, Error, Request, Response};
fn native(error: NativeError) -> Error {
    match error {
        NativeError::Busy => Error::Busy,
        NativeError::Unsupported => Error::UnsupportedFormat,
        NativeError::MissingCapability => Error::MissingCapability,
        NativeError::Changed => Error::SourceChanged,
        NativeError::Corrupt => Error::Corrupt,
        NativeError::Bounds => Error::Bounds,
        NativeError::Unavailable => Error::Unavailable,
        NativeError::Pending => Error::Unknown,
        NativeError::Refused => Error::Refused,
    }
}
fn facts(upgrade: &Upgrade) -> BackendInfo {
    BackendInfo {
        dataset: DatasetId(upgrade.target),
        atomic_domain: upgrade.atomic_domain,
        clock_authority: upgrade.clock_authority,
        physical_version: 1,
        durability: Durability::Local,
    }
}
fn bounds(bounds: lifecycle::Bounds) -> Result<(), Error> {
    if bounds.items == 0
        || bounds.items > 4096
        || bounds.bytes < 256
        || bounds.bytes > 64 * 1024 * 1024
    {
        Err(Error::Bounds)
    } else {
        Ok(())
    }
}
fn ready_state(session: &Session) -> lifecycle::InspectionState {
    match session.inspection {
        Inspection::Empty => lifecycle::InspectionState::Empty,
        Inspection::Current => lifecycle::InspectionState::Current,
        Inspection::Legacy { .. } => lifecycle::InspectionState::Legacy,
        Inspection::InProgress(Upgrade { phase: 2, .. }) => lifecycle::InspectionState::Current,
        Inspection::InProgress(_) => lifecycle::InspectionState::InProgress,
    }
}
pub(super) fn run(store: &SqliteV4, request: &Request<Own>) -> Result<Response<Own>, Error> {
    let mut session = store.native.lock().map_err(|_| Error::Unavailable)?;
    match request {
        Request::Inspect { bounds: limit } => {
            bounds(*limit)?;
            session.refresh_inspection().map_err(native)?;
            let (source, catalogue) = if matches!(session.inspection, Inspection::Empty) {
                (None, Vec::new())
            } else {
                let (source, tables) = session.view().map_err(native)?;
                (Some(source), tables)
            };
            let used = catalogue.iter().try_fold(0usize, |total, t| {
                total
                    .checked_add(
                        t.name.len()
                            + t.columns.iter().map(String::len).sum::<usize>()
                            + t.native_layout.len(),
                    )
                    .ok_or(Error::Bounds)
            })?;
            if catalogue.len() > limit.items as usize || used > limit.bytes as usize {
                return Err(Error::Bounds);
            }
            let marker = session.admission().map_err(native)?.map(Secret::held);
            Ok(Response::Inspected(lifecycle::Inspection {
                state: ready_state(&session),
                source,
                admission_marker: marker,
                catalogue,
                capabilities: if session.may_write() {
                    vec![
                        lifecycle::NativeCapability::Snapshot,
                        lifecycle::NativeCapability::PersistentFence,
                        lifecycle::NativeCapability::Resume,
                        lifecycle::NativeCapability::InactiveTarget,
                        lifecycle::NativeCapability::CurrentOpen,
                    ]
                } else {
                    vec![lifecycle::NativeCapability::Snapshot]
                },
            }))
        }
        Request::BeginOrResume {
            expected_source,
            route_digest,
            target_format,
            operation_id,
        } => {
            if *target_format != lifecycle::CORE_FORMAT {
                return Err(Error::UnsupportedFormat);
            }
            if session.view().map_err(native)?.0 != *expected_source {
                return Err(Error::SourceChanged);
            }
            let upgrade = session
                .begin(
                    expected_source.native_anchor,
                    *route_digest,
                    target_format.physical,
                    *operation_id,
                )
                .map_err(native)?;
            let (source, catalogue) = session.view().map_err(native)?;
            Ok(Response::Begun(lifecycle::Upgrade {
                reference: lifecycle::UpgradeRef {
                    id: upgrade.upgrade,
                    authority: protected(session.authority().map_err(native)?)
                        .map_err(|_| Error::Bounds)?,
                },
                source,
                snapshot: upgrade.frozen_digest[..16]
                    .try_into()
                    .map_err(|_| Error::Corrupt)?,
                target: facts(&upgrade),
                native_step: upgrade.phase as u64,
                catalogue,
            }))
        }
        Request::SourcePage { upgrade, .. } => {
            session
                .authenticate(upgrade.id, upgrade.authority.expose_own(&store.owner))
                .map_err(native)?;
            Ok(Response::SourcePage(
                session.page(request, &store.owner).map_err(native)?,
            ))
        }

        Request::Target { upgrade } => {
            session
                .authenticate(upgrade.id, upgrade.authority.expose_own(&store.owner))
                .map_err(native)?;
            let (connection, target) = session.target(upgrade.id).map_err(native)?;
            let info = facts(&target);
            *store.connection.lock().map_err(|_| Error::Unavailable)? = connection;
            *store.info.lock().map_err(|_| Error::Unavailable)? = info;
            store.enabled.store(true, Ordering::Release);
            Ok(Response::Target(lifecycle::TargetBinding {
                upgrade: upgrade.id,
                info,
                binding: protected(session.authority().map_err(native)?)
                    .map_err(|_| Error::Bounds)?,
            }))
        }
        Request::CheckFence { upgrade } => {
            let actual = session
                .authenticate(upgrade.id, upgrade.authority.expose_own(&store.owner))
                .map_err(native)?;
            let (source, _) = session.frozen_view().map_err(native)?;
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
            let mut observation = actual.frozen_digest.to_vec();
            observation.extend_from_slice(&source.native_anchor);
            observation.extend_from_slice(&nonce);
            Ok(Response::Fence(lifecycle::Fence {
                upgrade: upgrade.id,
                source,
                enforcement_digest: session.enforcement(upgrade.id).map_err(native)?,
                observation_digest: busbar_contract::persistence::archive::digest(&observation),
                snapshot: actual.frozen_digest[..16]
                    .try_into()
                    .map_err(|_| Error::Corrupt)?,
            }))
        }
        Request::Finish {
            upgrade,
            activation_receipt: proof,
        } => {
            let target = session
                .authenticate(upgrade.id, upgrade.authority.expose_own(&store.owner))
                .map_err(native)?;
            let proof_digest = proof_digest(proof, &store.owner)?;
            let complete = proof.phase == CompletionPhase::Complete;
            session
                .finish(upgrade.id, &proof_digest, complete, |c, target, _| {
                    verify_receipt(c, target, proof, &store.owner)
                })
                .map_err(native)?;
            let recovery = session.ready().map_err(native)?;
            if recovery.target != DatasetId(target.target) {
                return Err(Error::SourceChanged);
            }
            if complete {
                Ok(Response::ServingReady(lifecycle::ServingReady {
                    recovery,
                    completed_checkpoint_digest: proof.checkpoint_value_digest,
                }))
            } else {
                Ok(Response::RecoveryReady(recovery))
            }
        }
    }
}
fn proof_digest(proof: &lifecycle::ActivationReceipt<Own>, owner: &Own) -> Result<[u8; 32], Error> {
    let mut bytes = b"SQLite activation proof/1\0".to_vec();
    bytes.extend_from_slice(&proof.attempt.dataset.0);
    bytes.extend_from_slice(&proof.attempt.writer_epoch.to_le_bytes());
    bytes.extend_from_slice(&proof.attempt.writer);
    bytes.extend_from_slice(&proof.attempt.execution_epoch.to_le_bytes());
    bytes.extend_from_slice(&proof.attempt.operation);
    bytes.extend_from_slice(&proof.candidate_fingerprint);
    bytes.extend_from_slice(&busbar_contract::persistence::archive::digest(
        proof.original_result.expose_own(owner),
    ));
    bytes.extend_from_slice(&proof.checkpoint_address.namespace);
    bytes.extend_from_slice(&(proof.checkpoint_address.key.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&proof.checkpoint_address.key);
    bytes.extend_from_slice(&proof.checkpoint_value_digest);
    bytes.push(if proof.phase == CompletionPhase::Activation {
        0
    } else {
        1
    });
    Ok(busbar_contract::persistence::archive::digest(&bytes))
}
fn verify_receipt(
    c: &Connection,
    target: &Upgrade,
    proof: &lifecycle::ActivationReceipt<Own>,
    owner: &Own,
) -> Result<(), NativeError> {
    if proof.attempt.dataset != DatasetId(target.target)
        || proof.attempt.writer_epoch == 0
        || proof.attempt.execution_epoch == 0
    {
        return Err(NativeError::Refused);
    }
    let (fingerprint,epoch,result):(Vec<u8>,Vec<u8>,Vec<u8>)=c.query_row("SELECT fingerprint,execution_epoch,result FROM receipts WHERE writer=?1 AND operation=?2 AND length(result)=?3",params![proof.attempt.writer.as_slice(),proof.attempt.operation.as_slice(),proof.original_result.expose_own(owner).len() as i64],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|NativeError::Refused)?;
    let result = zeroize::Zeroizing::new(result);
    if fingerprint != proof.candidate_fingerprint
        || epoch != proof.attempt.execution_epoch.to_le_bytes()
        || result.as_slice() != proof.original_result.expose_own(owner).as_slice()
    {
        return Err(NativeError::Refused);
    }
    let checkpoint: Vec<u8> = c
        .query_row(
            "SELECT value FROM records WHERE namespace=?1 AND key=?2 AND length(value)<=67108864",
            params![
                proof.checkpoint_address.namespace.as_slice(),
                proof.checkpoint_address.key
            ],
            |r| r.get(0),
        )
        .map_err(|_| NativeError::Refused)?;
    let checkpoint = zeroize::Zeroizing::new(checkpoint);
    if busbar_contract::persistence::archive::digest(&checkpoint) != proof.checkpoint_value_digest {
        return Err(NativeError::Refused);
    }
    // The native target must also carry the core admission locator. Its opaque
    // content is interpreted by core; this layer only requires durable presence.
    let marker: Vec<u8> = c
        .query_row(
            "SELECT value FROM records WHERE namespace=?1 AND key=?2 AND length(value)<=67108864",
            params![
                lifecycle::ADMISSION_NAMESPACE.as_slice(),
                lifecycle::ADMISSION_KEY
            ],
            |r| r.get(0),
        )
        .map_err(|_| NativeError::Refused)?;
    if marker.is_empty() {
        return Err(NativeError::Refused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_lifecycle_exact_receipt_independent_reopen_and_same_backend_serving() {
        let root = std::env::temp_dir().join(format!(
            "sqlite-lifecycle-receipt-{}",
            crate::v4::random()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source.db");
        std::fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/1.5.5/governance.db"),
            &source,
        )
        .unwrap();
        let config = serde_json::to_vec(&serde_json::json!({"db_path":source})).unwrap();
        {
            let store = SqliteV4::open(&config, &[], None).unwrap();
            assert!(store.connect_now().is_err());
            let limit = lifecycle::Bounds {
                items: 64,
                bytes: 4 * 1024 * 1024,
            };
            let Response::Inspected(inspected) =
                run(&store, &Request::Inspect { bounds: limit }).unwrap()
            else {
                panic!("inspection")
            };
            assert_eq!(inspected.state, lifecycle::InspectionState::Legacy);
            let Response::Begun(upgrade) = run(
                &store,
                &Request::BeginOrResume {
                    expected_source: inspected.source.unwrap(),
                    route_digest: [4; 32],
                    target_format: lifecycle::CORE_FORMAT,
                    operation_id: [3; 16],
                },
            )
            .unwrap() else {
                panic!("upgrade")
            };
            let key_table = upgrade
                .catalogue
                .iter()
                .position(|t| t.name == "keys")
                .unwrap() as u32;
            let request = Request::SourcePage {
                upgrade: upgrade.reference.clone(),
                snapshot: upgrade.snapshot,
                family: lifecycle::SQLITE_SOURCE_OWNER,
                selector: lifecycle::SourceSelector::Scan { table: key_table },
                cursor: None,
                bounds: limit,
            };
            let Response::SourcePage(page) = run(&store, &request).unwrap() else {
                panic!("source page")
            };
            assert!(!page.rows.is_empty());
            let request = Request::SourcePage {
                upgrade: upgrade.reference.clone(),
                snapshot: upgrade.snapshot,
                family: lifecycle::SQLITE_SOURCE_OWNER,
                selector: lifecycle::SourceSelector::Exact {
                    table: key_table,
                    key: page.rows[0].native_key.clone(),
                },
                cursor: None,
                bounds: limit,
            };
            let Response::SourcePage(exact) = run(&store, &request).unwrap() else {
                panic!("exact source")
            };
            assert_eq!(exact.rows.len(), 1);
            assert_eq!(
                exact.rows[0].value.expose_own(&store.owner),
                page.rows[0].value.expose_own(&store.owner)
            );
            let Response::Target(target) = run(
                &store,
                &Request::Target {
                    upgrade: upgrade.reference.clone(),
                },
            )
            .unwrap() else {
                panic!("target")
            };
            assert_eq!(target.info, upgrade.target);
            crate::v4::tests::bootstrap(&store);
            let checkpoint = Address {
                namespace: [9; 16],
                key: b"upgrade checkpoint".to_vec(),
            };
            let apply = |op: u128, value: &[u8]| {
                let candidate = crate::v4::tests::candidate(
                    &store,
                    op,
                    vec![
                        Mutation::Put {
                            address: checkpoint.clone(),
                            value: Secret::held(value.to_vec()),
                        },
                        Mutation::Put {
                            address: Address {
                                namespace: lifecycle::ADMISSION_NAMESPACE,
                                key: lifecycle::ADMISSION_KEY.to_vec(),
                            },
                            value: Secret::held(value.to_vec()),
                        },
                    ],
                );
                let attempt = candidate.id;
                let prepared = PreparedCandidate::new(candidate).unwrap();
                let fingerprint = prepared.fingerprint();
                assert!(matches!(
                    store.commit_now(&prepared).unwrap().decision,
                    Decision::Applied(_)
                ));
                (attempt, fingerprint)
            };
            let (attempt, fp) = apply(2, b"activation pending");
            let mut proof = lifecycle::ActivationReceipt {
                attempt,
                candidate_fingerprint: [0; 32],
                original_result: Secret::held(b"result".to_vec()),
                checkpoint_address: checkpoint.clone(),
                checkpoint_value_digest: busbar_contract::persistence::archive::digest(
                    b"activation pending",
                ),
                phase: CompletionPhase::Activation,
            };
            assert!(matches!(
                run(
                    &store,
                    &Request::Finish {
                        upgrade: upgrade.reference.clone(),
                        activation_receipt: proof.clone()
                    }
                ),
                Err(Error::Refused)
            ));
            proof.candidate_fingerprint = fp;
            let Response::RecoveryReady(recovery) = run(
                &store,
                &Request::Finish {
                    upgrade: upgrade.reference.clone(),
                    activation_receipt: proof,
                },
            )
            .unwrap() else {
                panic!("recovery ready")
            };
            store
                .connect_binding(&lifecycle::OpenBinding::Recovery(recovery.clone()))
                .unwrap();
            assert_eq!(store.facts(), target.info);
            let (attempt, fp) = apply(3, b"complete");
            let proof = lifecycle::ActivationReceipt {
                attempt,
                candidate_fingerprint: fp,
                original_result: Secret::held(b"result".to_vec()),
                checkpoint_address: checkpoint,
                checkpoint_value_digest: busbar_contract::persistence::archive::digest(b"complete"),
                phase: CompletionPhase::Complete,
            };
            let Response::ServingReady(ready) = run(
                &store,
                &Request::Finish {
                    upgrade: upgrade.reference.clone(),
                    activation_receipt: proof,
                },
            )
            .unwrap() else {
                panic!("serving ready")
            };
            assert_eq!(ready.recovery, recovery);
            // The same connected native backend and original writer accept the
            // first serving mutation without a shutdown/reopen/reset.
            let candidate = crate::v4::tests::candidate(
                &store,
                4,
                vec![crate::v4::tests::put(b"serving", b"first")],
            );
            assert!(matches!(
                store
                    .commit_now(&PreparedCandidate::new(candidate).unwrap())
                    .unwrap()
                    .decision,
                Decision::Applied(_)
            ));
            assert!(store.native.lock().unwrap().snapshot.is_none());
            let busy: i64 = store
                .connection
                .lock()
                .unwrap()
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
                .unwrap();
            assert_eq!(busy, 0, "completed source capture must not pin serving WAL");
            let Response::Fence(fence) = run(
                &store,
                &Request::CheckFence {
                    upgrade: upgrade.reference.clone(),
                },
            )
            .unwrap() else {
                panic!("retained fence")
            };
            assert_eq!(fence.source, upgrade.source);
            let Response::SourcePage(retained) = run(&store, &request).unwrap() else {
                panic!("retained source")
            };
            assert_eq!(
                retained.rows[0].value.expose_own(&store.owner),
                page.rows[0].value.expose_own(&store.owner)
            );
            let reopened = SqliteV4::open(&config, &[], None).unwrap();
            let Response::Inspected(current) =
                run(&reopened, &Request::Inspect { bounds: limit }).unwrap()
            else {
                panic!("current")
            };
            assert_eq!(current.state, lifecycle::InspectionState::Current);
            reopened
                .connect_binding(&lifecycle::OpenBinding::Current {
                    source: current.source.unwrap(),
                    admission_marker_digest: busbar_contract::persistence::archive::digest(
                        current
                            .admission_marker
                            .as_ref()
                            .unwrap()
                            .expose_own(&reopened.owner),
                    ),
                })
                .unwrap();
            assert_eq!(reopened.facts(), target.info);
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    use std::path::PathBuf;
    #[test]
    fn fresh_empty_origin_blocks_exact_released_startup_and_resumes_same_native_ids() {
        let root = std::env::temp_dir().join(format!(
            "sqlite-empty-origin-{}",
            crate::v4::random()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("fresh.db");
        let config = serde_json::to_vec(&serde_json::json!({"db_path":path})).unwrap();
        let facts;
        {
            let store = SqliteV4::open(&config, &[], None).unwrap();
            assert!(!path.exists());
            store
                .connect_binding(&lifecycle::OpenBinding::Empty)
                .unwrap();
            facts = store.facts();
        }
        let old = Connection::open(&path).unwrap();
        old.execute_batch("BEGIN IMMEDIATE").unwrap();
        old.execute_batch(include_str!("../tests/fixtures/released-1.0.6.sql"))
            .unwrap();
        assert!(old
            .execute(
                "INSERT INTO store_revision(id,revision) VALUES(0,0) ON CONFLICT(id) DO NOTHING",
                []
            )
            .unwrap_err()
            .to_string()
            .contains("Busbar legacy source is frozen"));
        old.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            old.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='keys'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        drop(old);
        {
            let reopened = SqliteV4::open(&config, &[], None).unwrap();
            let Response::Inspected(inspection) = run(
                &reopened,
                &Request::Inspect {
                    bounds: lifecycle::Bounds {
                        items: 32,
                        bytes: 1024 * 1024,
                    },
                },
            )
            .unwrap() else {
                panic!("inspection")
            };
            assert_eq!(inspection.state, lifecycle::InspectionState::Empty);
            assert!(inspection.source.is_none());
            reopened
                .connect_binding(&lifecycle::OpenBinding::Empty)
                .unwrap();
            assert_eq!(reopened.facts(), facts);
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
