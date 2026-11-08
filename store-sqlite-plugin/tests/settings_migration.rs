// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercise the actual linked and dropped cold migration entries, without opening a store.

use busbar_contract::abi::sdk::migrate::Migrated;
use busbar_plugin_loader::dispatch::{load::raw, migrate};
use serde_json::{json, Value};
use std::path::PathBuf;

fn cdylib() -> PathBuf {
    if let Some(path) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        let path = PathBuf::from(path);
        assert!(
            path.is_absolute() && path.is_file(),
            "missing SQLite cdylib"
        );
        return path;
    }
    let exe = std::env::current_exe().unwrap();
    let profile = exe.parent().and_then(|dir| dir.parent()).unwrap();
    let path = profile.join(busbar_plugin_loader::plugin_library_filename(
        "busbar_store_sqlite_plugin",
    ));
    assert!(
        path.is_file(),
        "build busbar-store-sqlite-plugin --lib first"
    );
    path
}

fn assert_migration(migrate: impl Fn(&Value) -> Migrated, tag: &str) {
    let root = std::env::temp_dir().join(format!(
        "sqlite-settings-migration-{}-{tag}",
        std::process::id()
    ));
    assert!(!root.exists(), "migration fixture must start absent");
    let path = root.join("missing-parent/database.db");
    let settings = json!({
        "db_path": path,
        "busy_timeout_ms": 731,
        "license_key": {"env": "SQLITE_OBSOLETE_LICENSE_SENTINEL"}
    });
    let answer = migrate(&settings);
    assert_eq!(
        answer.settings,
        json!({"db_path": path, "busy_timeout_ms": 731})
    );
    assert_eq!(
        answer.report,
        ["Removed obsolete license_key; SQLite does not use this setting."]
    );
    assert!(answer.needs.is_empty());
    assert!(!root.exists(), "cold migration must not open a database");
    let again = migrate(&answer.settings);
    assert_eq!(again, Migrated::unchanged(answer.settings));

    // Only this obsolete field is removed. References, unknown future settings and every
    // untouched JSON shape survive exactly; validation and reference resolution run later.
    let settings = json!({"db_path": {"env": "SQLITE_DB_SENTINEL"},
        "busy_timeout_ms": null, "future": [1, {"nested": true}], "license_key": null});
    let mut expected = settings.clone();
    expected.as_object_mut().unwrap().remove("license_key");
    let answer = migrate(&settings);
    assert_eq!(answer.settings, expected);
    assert_eq!(answer.report.len(), 1);
    assert!(!answer.report[0].contains("SENTINEL"));
    for unchanged in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"busy_timeout_ms": 0}),
    ] {
        assert_eq!(migrate(&unchanged), Migrated::unchanged(unchanged));
    }
}

#[test]
fn linked_migration_removes_ignored_license_before_resolution_without_open() {
    assert_migration(
        |settings| {
            migrate::migrate_door(raw(busbar_store_sqlite::door), settings, "1.5.5")
                .unwrap()
                .expect("SQLite declares its migration")
        },
        "linked",
    );
}

#[test]
fn dropped_migration_removes_ignored_license_before_resolution_without_open() {
    let bytes = std::fs::read(cdylib()).unwrap();
    assert_migration(
        |settings| {
            migrate::migrate_library(&bytes, "busbar-store-sqlite", settings, "1.5.5")
                .unwrap()
                .expect("SQLite declares its migration")
        },
        "dropped",
    );
}
