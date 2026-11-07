// SPDX-License-Identifier: Apache-2.0
//! Linked and dropped native persistence doors use the same physical schema.
use busbar_contract::persistence::{
    Address, DatasetId, Failure, PersistenceBackend, Read, ReadResult,
};
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher,
    LinkedRow, NoSink, Plugin,
};
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};
use std::path::PathBuf;
use std::sync::Arc;

fn cdylib() -> PathBuf {
    let path = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join(busbar_plugin_loader::plugin_library_filename(
                    "busbar_store_sqlite_plugin",
                ))
        });
    assert!(
        path.is_absolute() && path.is_file(),
        "build the SQLite cdylib first: {}",
        path.display()
    );
    path
}
fn plugin(dropped: bool, dispatcher: &Arc<Dispatcher>) -> Plugin<StoreV4> {
    let bind = Bind {
        instance: Arc::from("sqlite-native-conformance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Probe,
    };
    if dropped {
        let path = cdylib();
        let stated = rendering_of_library(&path).unwrap().unwrap();
        load_dropped::<StoreV4>(&path, &stated, bind).unwrap()
    } else {
        let row = LinkedRow::of_kind::<StoreV4>(
            busbar_store_sqlite::v4::door as busbar_contract::abi::mechanism::door::DoorFn,
        )
        .unwrap();
        load_linked::<StoreV4>(&row, bind).unwrap()
    }
}
fn limits() -> Limits {
    Limits {
        descriptor_bytes: 1 << 20,
        output_items: 1024,
        output_bytes: 1 << 20,
        decode_bytes: 1 << 20,
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sqlite-native-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn exercise(dropped: bool) {
    let scratch = Scratch::new();
    let path = scratch.0.join("native.db");
    let settings = serde_json::to_vec(&serde_json::json!({ "db_path": path })).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut dataset = None;
        for _ in 0..2 {
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            let backend = LoadedPersistence::open(plugin(dropped, &dispatcher), dispatcher, &settings, limits()).await.unwrap();
            let info = backend.info();
            if let Some(previous) = dataset { assert_eq!(info.dataset, previous); }
            dataset = Some(info.dataset);
            assert_ne!(info.dataset, DatasetId([0; 16]));
            backend.clock(info.dataset).await.unwrap();
            let answer = backend.read(Arc::new(Read {
                dataset: info.dataset,
                addresses: vec![Address { namespace: [9; 16], key: b"absent".to_vec() }],
                time: None,
            })).await.unwrap();
            assert!(matches!(answer, ReadResult::Values { values, .. } if values.len() == 1 && values[0].is_none()));
            assert!(matches!(backend.clock(DatasetId([0;16])).await, Err(Failure::Refused)));
            drop(backend);
        }
    });
    // The only non-primitive relation is an empty native old-startup barrier.
    let conn =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let names = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(names, ["meta", "receipts", "records", "store_revision"]);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM store_revision", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(conn.query_row("SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND name GLOB '__busbar_freeze_*'",[],|r|r.get::<_,i64>(0)).unwrap(),3);
}
#[test]
fn linked_native_door_reopens_same_dataset() {
    exercise(false);
}
#[test]
fn dropped_native_door_reopens_same_dataset() {
    exercise(true);
}

#[test]
fn linked_and_dropped_bootstrap_freeze_legacy_without_ordinary_open() {
    use busbar_contract::persistence::lifecycle::{
        self, PreparedStore, Request, Response, SourceSelector,
    };
    use busbar_plugin_loader::store_v4::LoadedPrepared;
    for dropped in [false, true] {
        let scratch = Scratch::new();
        let path = scratch.0.join("source.db");
        std::fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../store-sqlite/tests/fixtures/1.5.5/governance.db"),
            &path,
        )
        .unwrap();
        let original = std::fs::read(&path).unwrap();
        let settings = serde_json::to_vec(&serde_json::json!({"db_path":path})).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let dispatcher=Arc::new(Dispatcher::new(DispatchConfig::default()));let prepared=LoadedPrepared::new(plugin(dropped,&dispatcher),dispatcher,&settings,limits()).unwrap();
            let limit=lifecycle::Bounds {items:128,bytes:1<<20};
            let inspected=prepared.bootstrap(Arc::new(Request::Inspect {bounds:limit})).await.unwrap();
            let Response::Inspected(inspected)=inspected.as_ref() else{panic!("inspection")};assert_eq!(inspected.state,lifecycle::InspectionState::Legacy);assert_eq!(std::fs::read(&path).unwrap(),original);
            let begun=prepared.bootstrap(Arc::new(Request::BeginOrResume {expected_source:inspected.source.clone().unwrap(),route_digest:[7;32],target_format:lifecycle::CORE_FORMAT,operation_id:[8;16]})).await.unwrap();
            let Response::Begun(upgrade)=begun.as_ref() else{panic!("upgrade")};
            let table=upgrade.catalogue.iter().position(|table|table.name=="keys").unwrap() as u32;
            let page=prepared.bootstrap(Arc::new(Request::SourcePage {upgrade:upgrade.reference.clone(),snapshot:upgrade.snapshot,family:lifecycle::SQLITE_SOURCE_OWNER,selector:SourceSelector::Scan {table},cursor:None,bounds:limit})).await.unwrap();
            let Response::SourcePage(page)=page.as_ref() else{panic!("source page")};assert!(!page.rows.is_empty());assert_eq!(page.snapshot,upgrade.snapshot);
            let target=prepared.target(upgrade.reference.clone()).await.unwrap();assert_eq!(target.info(),upgrade.target);target.clock(upgrade.target.dataset).await.unwrap();
            assert!(prepared.serving().is_err());assert_eq!(prepared.phase(),lifecycle::Phase::Upgrading);
            let old=rusqlite::Connection::open(&path).unwrap();assert!(old.execute("INSERT INTO store_revision(id,revision) VALUES(0,0) ON CONFLICT(id) DO NOTHING",[]).is_err());
        });
    }
}
