// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **SQLite store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store
//! carries (`kind: store`, alias `sqlite`). Build it, pack it, drop it into the engine's plugins
//! folder, and set `store: { module: sqlite, settings: {...} }`.
//!
//! All the store lives in the `busbar-store-sqlite` crate, including its one door
//! (`busbar_store_sqlite::door::door`, the store v3 table). This crate re-exports the logic crate,
//! so the library it builds carries exactly the code a busbar build links, and exports that door as
//! `busbar_plugin_door` (`export_door!`, unconditionally) — one source, both doors (DECISIONS #2
//! rule (1)). It also registers the store on the cold store lane the busbar kernel at the pin boots
//! a configured store through (`cold`, `export_store_plugin!`).
//!
//! This crate is `deny`, not `forbid`: the two export macros (`#[unsafe(no_mangle)]`, the cold
//! boundary's `unsafe extern` functions) are the reviewed exemptions (a `forbid` cannot be lifted
//! for them). No other `unsafe` exists here.

#![deny(unsafe_code)]

pub use busbar_store_sqlite::*;

/// The exported door: the macro's `#[no_mangle]` symbol is an exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_sqlite::door::door);
}

/// The store a busbar at the pin BOOTS. Its kernel opens a configured dropped-in store through the
/// cold store lane (`PluginRegistry::open_store` -> `load_store_image`: `busbar_abi`,
/// `busbar_plugin_kind`, `busbar_open`, ...), not through the door; an image that exports only
/// `busbar_plugin_door` answers `busbar_plugin_kind` with NULL there and the boot is refused
/// (BUSBAR-9007 "returned a null kind string"). This registration answers that lane over the same
/// [`SqliteStore`], opened by the door's own settings parser ([`door::open`]).
fn open_cold(cfg: &str) -> Result<busbar_contract::abi::sdk::StoreHandle, String> {
    door::open(cfg).map(|s| Box::new(s) as busbar_contract::abi::sdk::StoreHandle)
}

/// THE COLD LANE's registration (`export_store_plugin!`): the contract SDK's frozen symbols answer
/// through it. The macro's boundary functions are `unsafe extern "C-unwind"` by the cold ABI's own
/// definition, and it registers through a load-time initializer section — the other exemption.
#[allow(unsafe_code)]
mod cold {
    busbar_contract::abi::sdk::export_store_plugin!(super::open_cold);
}
