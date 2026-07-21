//! Pure automotive protocol contracts for `oxfuzz`.
//!
//! The optional `automotive-scapy` feature exposes serializable domain types.
//! This crate never executes a process, reads an interface, or mutates files.
//!
//! # Module Overview
//!
//! | Module | Responsibility | Design Reference |
//! | --- | --- | --- |
//! | `contract` | Versioned requests, results, validation, and canonical hashes | `automotive-protocol-fuzzing-design.md` |
//! | `dbc` | DBC database parsing and deterministic signal decoding | `savvycan-inspired-automotive-tooling.md` |
//! | `capture` | Importers for common CAN capture/log formats | `savvycan-inspired-automotive-tooling.md` |
//! | `isotp` | ISO 15765-2 (ISO-TP) receiver reassembly | `savvycan-inspired-automotive-tooling.md` |
//! | `analysis` | Bus statistics, per-byte change maps, and capture diff | `savvycan-inspired-automotive-tooling.md` |

#![forbid(unsafe_code)]

#[cfg(feature = "automotive-scapy")]
mod contract;

#[cfg(feature = "automotive-scapy")]
pub use contract::*;

#[cfg(feature = "automotive-scapy")]
pub mod dbc;

#[cfg(feature = "automotive-scapy")]
pub mod capture;

#[cfg(feature = "automotive-scapy")]
pub mod isotp;

#[cfg(feature = "automotive-scapy")]
pub mod analysis;
