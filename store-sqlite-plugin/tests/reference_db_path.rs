// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `db_path` is reference-capable rather than a declared secret field; literal database paths remain accepted.

use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};

const DB_PATH: &str = "/var/lib/busbar/busbar.db";

fn linked() -> (Plugin<StoreV4>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("reference-db-path"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of_kind::<StoreV4>(
        busbar_store_sqlite::v4::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
    .expect("the row renders");
    (
        load_linked::<StoreV4>(&row, bind).expect("the door loads"),
        d,
    )
}

#[test]
fn the_db_path_is_not_declared_secret() {
    let (p, _d) = linked();
    assert!(
        !p.secret_refs().iter().any(|f| f == "db_path"),
        "{:?}",
        p.secret_refs()
    );
}

#[test]
fn a_reference_at_the_db_path_resolves_as_the_kernel_resolves_it() {
    let (p, _d) = linked();
    let mut tree = serde_json::json!({"db_path": {"env": "REFCAP_DB_PATH_FOR_TEST"}});
    busbar_contract::secret_fields::resolve_declared_fields(
        &mut tree,
        p.secret_refs(),
        p.reference_fields(),
        p.name(),
        |_, _| Ok(DB_PATH.to_string()),
    )
    .expect("a reference at the db_path resolves");
    assert_eq!(tree["db_path"], DB_PATH);
}

#[test]
fn a_literal_db_path_passes_as_written() {
    let (p, _d) = linked();
    let settings = format!(r#"{{"db_path":"{DB_PATH}"}}"#);
    let mut tree: serde_json::Value = serde_json::from_str(&settings).unwrap();
    busbar_contract::secret_fields::resolve_declared_fields(
        &mut tree,
        p.secret_refs(),
        p.reference_fields(),
        p.name(),
        |_, _| Err("a literal db_path resolves nothing".to_string()),
    )
    .expect("a literal db_path passes as written");
    assert_eq!(tree["db_path"], DB_PATH);
}
