// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `db_path` IS REFERENCE-CAPABLE, NOT SECRET (busbar lead ruling item 7a, as for the network
//! stores' `url`): a 1.5.5 config that writes `db_path` as `{env: VAR}` keeps booting (the reference
//! resolves in place, as the kernel resolves it), and a literal path passes as written (never
//! refused as a secret literal). The linked door is loaded the way the host binds it.

use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};
use busbar_test_kit::conformance::settings_as_the_kernel_resolves;

const DB_PATH: &str = "/var/lib/busbar/busbar.db";

fn linked() -> (Plugin<Store>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("reference-db-path"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of_macro(busbar_store_sqlite::door::MACRO_DOOR).expect("the row renders");
    (load_linked::<Store>(&row, bind).expect("the door loads"), d)
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
    let out = settings_as_the_kernel_resolves(
        &p,
        br#"{"db_path":{"env":"REFCAP_DB_PATH_FOR_TEST"}}"#,
        |_, _| Ok(DB_PATH.to_string()),
    )
    .expect("a reference at the db_path resolves");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["db_path"], DB_PATH);
}

#[test]
fn a_literal_db_path_passes_as_written() {
    let (p, _d) = linked();
    let settings = format!(r#"{{"db_path":"{DB_PATH}"}}"#);
    let out = settings_as_the_kernel_resolves(&p, settings.as_bytes(), |_, _| {
        Err("a literal db_path resolves nothing".to_string())
    })
    .expect("a literal db_path passes as written");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["db_path"], DB_PATH);
}
