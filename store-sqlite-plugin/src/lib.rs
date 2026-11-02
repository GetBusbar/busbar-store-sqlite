// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **SQLite store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store

#![deny(unsafe_code)]

pub use busbar_store_sqlite::*;

/// The exported door: the macro's `#[no_mangle]` symbol is an exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_sqlite::door::door);
}
