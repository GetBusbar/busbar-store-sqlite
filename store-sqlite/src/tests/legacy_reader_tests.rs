// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir();
        let path = root.join(format!(
            "sqlite-legacy-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn fixture(&self) -> PathBuf {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/1.5.5");
        for suffix in ["", "-wal", "-shm"] {
            let name = format!("governance.db{suffix}");
            if source.join(&name).exists() {
                std::fs::copy(source.join(&name), self.0.join(&name)).unwrap();
            }
        }
        self.0.join("governance.db")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn limits() -> Limits {
    Limits {
        rows: 1,
        bytes: 1024 * 1024,
    }
}
fn fixture_bytes() -> Vec<Option<Vec<u8>>> {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/1.5.5");
    [
        "MANIFEST.tsv",
        "governance.db",
        "governance.db-wal",
        "governance.db-shm",
    ]
    .iter()
    .map(|n| match std::fs::read(source.join(n)) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("fixture read: {error}"),
    })
    .collect()
}

#[test]
fn released_capture_is_read_without_migration_and_original_is_untouched() {
    let original = fixture_bytes();
    let scratch = Scratch::new();
    let path = scratch.fixture();
    let reader = Snapshot::open(&path).unwrap();
    assert_eq!(reader.source_version(), 6);
    assert_eq!(reader.tables().len(), 8);
    let native = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    for index in 0..reader.tables().len() {
        let table = &reader.tables()[index];
        let expected: i64 = native
            .query_row(
                &format!("SELECT count(*) FROM {}", quote(&table.name)),
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut count = 0;
        let mut after = None;
        loop {
            let page = reader.page(index, after.as_ref(), limits()).unwrap();
            assert!(page.rows.len() <= 1);
            count += page.rows.len();
            for row in page.rows {
                legacy_row::Row::decode(row.value.expose_own(&Own::here())).unwrap();
                after = Some(row.identity);
            }
            if page.exhausted {
                break;
            }
        }
        assert_eq!(count as i64, expected);
        assert!(
            reader
                .page(index, after.as_ref(), limits())
                .unwrap()
                .exhausted
        );
    }
    assert_eq!(
        native
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert_eq!(fixture_bytes(), original);
}

#[test]
fn schema_fence_refuses_unknown_versions_and_changed_shapes() {
    for sql in [
        "PRAGMA user_version=10",
        "ALTER TABLE keys ADD COLUMN unknown TEXT",
        "CREATE TABLE unknown(x)",
        "CREATE TABLE sqliteXunknown(x)",
        "DROP TABLE denylist",
    ] {
        let scratch = Scratch::new();
        let path = scratch.fixture();
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        assert!(matches!(
            Snapshot::open(&path),
            Err(Error::UnsupportedVersion | Error::UnsupportedShape)
        ));
    }
    let scratch = Scratch::new();
    assert!(matches!(
        Snapshot::open(&scratch.0.join("absent.db")),
        Err(Error::Sqlite)
    ));
    assert!(!scratch.0.join("absent.db").exists());
}

#[test]
fn wal_snapshot_stays_stable_across_pages_and_later_commits() {
    let scratch = Scratch::new();
    let path = scratch.fixture();
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; INSERT INTO denylist(sub) VALUES('wal-before');").unwrap();
    let reader = Snapshot::open(&path).unwrap();
    let table = reader
        .tables()
        .iter()
        .position(|t| t.name == "denylist")
        .unwrap();
    writer
        .execute("INSERT INTO denylist(sub) VALUES('wal-after')", [])
        .unwrap();
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = reader.page(table, after.as_ref(), limits()).unwrap();
        for row in page.rows {
            let decoded = legacy_row::Row::decode(row.value.expose_own(&Own::here())).unwrap();
            if let Cell::Text(name) = decoded.cells().next().unwrap() {
                seen.push(name.to_vec());
            }
            after = Some(row.identity);
        }
        if page.exhausted {
            break;
        }
    }
    assert!(seen.iter().any(|s| s == b"wal-before"));
    assert!(!seen.iter().any(|s| s == b"wal-after"));
    assert!(reader.conn.execute("DELETE FROM denylist", []).is_err());
}

#[test]
fn native_cells_and_oversize_retry_preserve_types_bits_and_cursor() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE native(id INTEGER PRIMARY KEY, a, b, c, d, e, f, g); INSERT INTO native VALUES(1,NULL,'',x'',-9223372036854775808,-1,-0.0,CAST(x'ff00' AS TEXT)); INSERT INTO native VALUES(2,NULL,'',x'',0,0,1.25,x'ff00'); BEGIN;").unwrap();
    let reader = Snapshot {
        conn,
        version: 6,
        tables: vec![Table {
            name: "native".into(),
            columns: (0..8)
                .map(|i| Column {
                    name: ["id", "a", "b", "c", "d", "e", "f", "g"][i].into(),
                    declared_type: if i == 0 {
                        "INTEGER".into()
                    } else {
                        String::new()
                    },
                    not_null: false,
                    primary_key_ordinal: u32::from(i == 0),
                })
                .collect(),
        }],
    };
    assert!(matches!(
        reader.page(0, None, Limits { rows: 1, bytes: 12 }),
        Err(Error::RowTooLarge)
    ));
    let page = reader.page(0, None, limits()).unwrap();
    assert!(!page.exhausted);
    let cells = legacy_row::Row::decode(page.rows[0].value.expose_own(&Own::here()))
        .unwrap()
        .cells()
        .collect::<Vec<_>>();
    assert_eq!(
        cells,
        [
            Cell::Integer(1),
            Cell::Null,
            Cell::Text(b""),
            Cell::Blob(b""),
            Cell::Integer(i64::MIN),
            Cell::Integer(-1),
            Cell::RealBits((-0.0f64).to_bits()),
            Cell::Text(&[255, 0])
        ]
    );
    let page = reader
        .page(0, Some(&page.rows[0].identity), limits())
        .unwrap();
    assert!(page.exhausted);
    assert_eq!(
        legacy_row::Row::decode(page.rows[0].value.expose_own(&Own::here()))
            .unwrap()
            .cells()
            .next(),
        Some(Cell::Integer(2))
    );
}

#[test]
fn current_development_physical_versions_are_identified_without_writes() {
    for version in [7, 8, 9] {
        let scratch = Scratch::new();
        let path = scratch.0.join("dev.db");
        // Build only physical DDL; this test never invokes the runtime opener.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(include_str!("../../tests/fixtures/dev-physical-9.sql"))
            .unwrap();
        conn.pragma_update(None, "user_version", version).unwrap();
        drop(conn);
        let reader = Snapshot::open(&path).unwrap();
        assert_eq!(reader.source_version(), version);
        assert_eq!(reader.tables().len(), 16);
    }
}

#[test]
fn caller_checkpoint_replays_and_budget_counts_identity_and_value() {
    let scratch = Scratch::new();
    let path = scratch.fixture();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("DELETE FROM denylist; INSERT INTO denylist(sub) VALUES('a'),('b');")
        .unwrap();
    let reader = Snapshot::open(&path).unwrap();
    let table = reader
        .tables()
        .iter()
        .position(|t| t.name == "denylist")
        .unwrap();
    let first = reader.page(table, None, limits()).unwrap();
    let bytes = first.rows[0].identity.expose_own(&Own::here()).len()
        + first.rows[0].value.expose_own(&Own::here()).len();
    let bounded = reader.page(table, None, Limits { rows: 4, bytes }).unwrap();
    assert_eq!(bounded.rows.len(), 1);
    assert!(!bounded.exhausted);
    assert!(matches!(
        reader.page(
            table,
            None,
            Limits {
                rows: 1,
                bytes: bytes - 1
            }
        ),
        Err(Error::RowTooLarge)
    ));
    let last = reader
        .page(table, Some(&bounded.rows[0].identity), limits())
        .unwrap();
    assert!(last.exhausted);
    assert_eq!(last.rows.len(), 1);
    let replay = reader
        .page(table, Some(&bounded.rows[0].identity), limits())
        .unwrap();
    assert_eq!(
        last.rows[0].value.expose_own(&Own::here()),
        replay.rows[0].value.expose_own(&Own::here())
    );
    let invalid = legacy_row::encode::<Own>(&[Cell::Integer(0)], 1024).unwrap();
    assert!(matches!(
        reader.page(table, Some(&invalid), limits()),
        Err(Error::InvalidCursor)
    ));
}
