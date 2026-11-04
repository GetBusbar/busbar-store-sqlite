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
//! rule (1)). The image carries no other export: the memory-ABI door is the only way a busbar
//! reaches this store.
//!
//! This crate is `deny`, not `forbid`: the export macro (`#[unsafe(no_mangle)]`) is the reviewed
//! exemption (a `forbid` cannot be lifted for it). No other `unsafe` exists here.

#![deny(unsafe_code)]

pub use busbar_store_sqlite::*;

/// The exported door: the macro's `#[no_mangle]` symbol is an exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_sqlite::door::door);
}
