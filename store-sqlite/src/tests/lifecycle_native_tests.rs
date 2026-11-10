// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn source() -> Self {
        let root = std::env::temp_dir();
        let path = root.join(format!(
            "sqlite-native-upgrade-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/1.5.5");
        for suffix in ["", "-wal", "-shm"] {
            let name = format!("governance.db{suffix}");
            if fixtures.join(&name).exists() {
                std::fs::copy(fixtures.join(&name), path.join(&name)).unwrap();
            }
        }
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("governance.db")
    }
    fn inspect(&self) -> Session {
        Session::inspect(&self.path(), 0, 1024 * 1024).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn source(session: &Session) -> [u8; 32] {
    match session.inspection {
        Inspection::Legacy { descriptor, .. } => descriptor,
        _ => panic!("recognized original source"),
    }
}
fn start(session: &mut Session, expected: [u8; 32]) -> Upgrade {
    session.begin(expected, [7; 32], 1, [8; 16]).unwrap()
}
#[test]
fn native_guards_block_cached_reconnect_and_released_startup_mutations() {
    let scratch = Scratch::source();
    let old = Connection::open(scratch.path()).unwrap();
    let mut cached = old
        .prepare("INSERT INTO store_meta(k,v) VALUES('queued','writer')")
        .unwrap();
    let mut session = scratch.inspect();
    let expected = source(&session);
    let upgrade = start(&mut session, expected);
    assert!(cached
        .execute([])
        .unwrap_err()
        .to_string()
        .contains("Busbar legacy source is frozen"));
    let reconnect = Connection::open(scratch.path()).unwrap();
    for statement in [
        "INSERT INTO store_revision(id,revision) VALUES(0,0) ON CONFLICT(id) DO NOTHING",
        "UPDATE keys SET enabled=enabled",
        "DELETE FROM keys",
    ] {
        assert!(reconnect
            .execute(statement, [])
            .unwrap_err()
            .to_string()
            .contains("Busbar legacy source is frozen"));
    }
    // Exact old startup stamps user_version only after its guarded insert; its
    // transaction cannot return native success or alter source rows.
    reconnect.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(reconnect
        .execute(
            "INSERT INTO store_revision(id,revision) VALUES(0,0) ON CONFLICT(id) DO NOTHING",
            []
        )
        .is_err());
    reconnect.execute_batch("ROLLBACK").unwrap();
    session.check(upgrade.upgrade).unwrap();
    let (target, info) = session.target(upgrade.upgrade).unwrap();
    target
        .execute(
            "INSERT INTO records VALUES(?1,?2,?3)",
            params![[9u8; 16].as_slice(), b"key", b"value"],
        )
        .unwrap();
    assert_eq!(info.target, upgrade.target);
}
#[test]
fn preceding_writer_is_drained_and_second_starter_cannot_claim_parallel_target() {
    let scratch = Scratch::source();
    let writer = Connection::open(scratch.path()).unwrap();
    let mut session = scratch.inspect();
    let expected = source(&session);
    writer
        .execute_batch(
            "BEGIN IMMEDIATE; INSERT INTO store_meta VALUES('before-cut','acknowledged')",
        )
        .unwrap();
    assert_eq!(
        session.begin(expected, [7; 32], 1, [8; 16]),
        Err(Error::Busy)
    );
    writer.execute_batch("COMMIT").unwrap();
    let upgrade = start(&mut session, expected);
    assert_eq!(
        session
            .snapshot
            .as_ref()
            .unwrap()
            .conn
            .query_row("SELECT v FROM store_meta WHERE k='before-cut'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
        "acknowledged"
    );
    let mut competitor = scratch.inspect();
    assert_eq!(
        competitor.begin(expected, [7; 32], 1, [9; 16]),
        Err(Error::Busy)
    );
    drop(session);
    let resumed = competitor.begin(expected, [7; 32], 1, [9; 16]).unwrap();
    assert_eq!(resumed, upgrade);
    assert_eq!(
        competitor.begin(expected, [6; 32], 1, [9; 16]),
        Err(Error::Refused)
    );
}
#[test]
fn resume_accepts_only_the_exact_recorded_catalogue_delta() {
    let scratch = Scratch::source();
    let mut first = scratch.inspect();
    let expected = source(&first);
    let upgrade = start(&mut first, expected);
    drop(first);
    let mut resumed = scratch.inspect();
    assert_eq!(start(&mut resumed, expected), upgrade);
    drop(resumed);
    let outsider = Connection::open(scratch.path()).unwrap();
    outsider
        .execute_batch(
            "CREATE TRIGGER unexpected_guard AFTER UPDATE ON store_meta BEGIN SELECT 1; END",
        )
        .unwrap();
    assert!(matches!(
        Session::inspect(&scratch.path(), 0, 1024 * 1024),
        Err(Error::Changed)
    ));
}
#[test]
fn rollback_source_transitions_under_guards_and_preserves_original_rows() {
    let scratch = Scratch::source();
    let native = Connection::open(scratch.path()).unwrap();
    native.execute_batch("PRAGMA journal_mode=DELETE").unwrap();
    drop(native);
    let mut session = scratch.inspect();
    let expected = source(&session);
    let upgrade = start(&mut session, expected);
    let (target, _) = session.target(upgrade.upgrade).unwrap();
    assert_eq!(
        target
            .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    assert_eq!(
        target
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert!(
        target
            .query_row("SELECT count(*) FROM keys", [], |r| r.get::<_, i64>(0))
            .unwrap()
            > 0
    );
}

#[test]
fn uri_inspection_resolves_existing_source_and_refuses_locking_overrides() {
    let scratch = Scratch::source();
    let uri = PathBuf::from(format!("file:{}?mode=rw", scratch.path().display()));
    let session = Session::inspect(&uri, 0, 1024 * 1024).unwrap();
    assert!(matches!(
        session.inspection,
        Inspection::Legacy { physical: 6, .. }
    ));
    for query in ["immutable=1", "nolock=1", "cache=shared", "vfs=unix-none"] {
        let uri = PathBuf::from(format!("file:{}?{query}", scratch.path().display()));
        assert!(matches!(
            Session::inspect(&uri, 0, 1024 * 1024),
            Err(Error::Unsupported)
        ));
    }
    let missing = PathBuf::from(format!(
        "file:{}?mode=rw",
        scratch.0.join("missing.db").display()
    ));
    assert!(matches!(
        Session::inspect(&missing, 0, 1024 * 1024),
        Err(Error::Unavailable)
    ));
    assert!(!scratch.0.join("missing.db").exists());
}
#[cfg(unix)]
#[test]
fn hardlink_alias_refuses_before_mutation_and_lock_replacement_revokes_capability() {
    let scratch = Scratch::source();
    let alias = scratch.0.join("alias.db");
    std::fs::hard_link(scratch.path(), &alias).unwrap();
    assert!(matches!(
        Session::inspect(&scratch.path(), 0, 1024 * 1024),
        Err(Error::Refused)
    ));
    std::fs::remove_file(alias).unwrap();
    let mut session = scratch.inspect();
    let expected = source(&session);
    let upgrade = start(&mut session, expected);
    let lock = session.coordination.as_ref().unwrap().path.clone();
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&lock, b"").unwrap();
    assert_eq!(session.check(upgrade.upgrade), Err(Error::Changed));
}
#[test]
fn memory_uri_with_rw_mode_resolves_to_in_memory() {
    let session = Session::inspect(Path::new("file::memory:?mode=rw"), 0, 1024 * 1024).unwrap();
    assert_eq!(session.inspection, Inspection::Empty);
    assert_eq!(session.database_name(), Path::new(":memory:"));
    assert!(session.may_write());
}
#[test]
fn memory_uri_with_ro_mode_resolves_to_in_memory() {
    let session = Session::inspect(Path::new("file::memory:?mode=ro"), 0, 1024 * 1024).unwrap();
    assert_eq!(session.inspection, Inspection::Empty);
    assert_eq!(session.database_name(), Path::new(":memory:"));
    assert!(!session.may_write());
}
