// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **SQLite store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store
//! carries (`kind: store`, alias `sqlite`). Build it, pack it, drop it into the engine's plugins
//! folder, and set `store: { module: sqlite, settings: {...} }`.
//!
//! All the store lives in the `busbar-store-sqlite` crate, including its one door registration
//! (`export_store_plugin!(open)`): the frozen symbols the loader looks up are the contract SDK's,
//! defined once, and they answer through that door. This crate re-exports the logic crate so the
//! library it builds carries exactly the code a busbar build links — one source, both doors
//! (DECISIONS #2 rule (1)).

#![deny(unsafe_code)]

pub use busbar_store_sqlite::*;
