// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A damaged exact metering ledger, or one whose column mirror is gone, fails the read or the
//! accrual that meets it, naming the cell; it is never read as an empty or default count.

use super::*;

fn delta(tokens: i128) -> MeteringDelta {
    MeteringDelta {
        scale: 6,
        key_id: "damaged-key".into(),
        bucket: 20_000,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: tokens,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    }
}

fn store_with_one_cell() -> SqliteStore {
    let store = SqliteStore::open_in_memory().unwrap();
    store.add_metering(&delta(5)).unwrap();
    assert_eq!(store.list_metering(20_000).unwrap()[0].tokens_input, 5);
    store
}

#[test]
fn an_unreadable_exact_metering_ledger_fails_the_read_naming_its_bucket() {
    let store = store_with_one_cell();
    store
        .lock_writer()
        .execute("UPDATE usage_metering_exact SET ledger = x'7b'", [])
        .unwrap();
    let err = store.list_metering(20_000).unwrap_err().0;
    assert!(
        err.starts_with("sqlite: an exact metering cell of bucket 20000 is unreadable"),
        "{err}"
    );
}

#[test]
fn an_unreadable_exact_metering_ledger_refuses_the_next_accrual() {
    let store = store_with_one_cell();
    store
        .lock_writer()
        .execute("UPDATE usage_metering_exact SET ledger = x'7b'", [])
        .unwrap();
    let err = store.add_metering(&delta(3)).unwrap_err().0;
    assert!(
        err.starts_with(
            "sqlite: exact metering cell of key 'damaged-key' model 'm' in bucket 20000 is unreadable"
        ),
        "{err}"
    );
    // Nothing was added on top of the damaged cell.
    let mirror: i64 = store
        .lock_reader()
        .query_row("SELECT tokens_input FROM usage_metering", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mirror, 5);
}

#[test]
fn an_exact_metering_ledger_without_its_column_mirror_fails_the_read() {
    let store = store_with_one_cell();
    store
        .lock_writer()
        .execute("DELETE FROM usage_metering", [])
        .unwrap();
    let err = store.list_metering(20_000).unwrap_err().0;
    assert_eq!(
        err,
        "sqlite: exact metering cell of key 'damaged-key' model 'm' in bucket 20000 has no column mirror"
    );
}
