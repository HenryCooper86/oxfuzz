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

#![forbid(unsafe_code)]

#[cfg(feature = "automotive-scapy")]
mod contract;

#[cfg(feature = "automotive-scapy")]
pub use contract::*;
