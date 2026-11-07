// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SQLite implementation of the primitive Store persistence contract.
//! Normal opens use the native schema and refuse historical databases.
//! Native preparation freezes supported historical sources before automatic import.

#![forbid(unsafe_code)]

mod legacy;
mod settings;

/// The native primitive Store door, shared by linked and dropped-in installations.
pub mod v4;
