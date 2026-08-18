//! hf-core: Core abstractions and traits for `oxfuzz`.
//!
//! This crate defines the contracts between all other `oxfuzz` crates.
//! Every cross-boundary interaction is mediated by a trait defined here.
//!
//! # Module Overview
//!
//! | Module | Key Traits | Design Reference |
//! |--------|-----------|-----------------|
//! | [`types`] | Shared IDs, `Message`, `TokenUsage` | - |
//! | [`error`] | `ClassifiedError`, `Redactable` | - |
//! | [`provider`] | `LlmProvider`, `ProviderPool` | (reuse y-agent) |
//! | [`runtime`] | `RuntimeAdapter` | runtime-design.md |
//! | [`tool`] | `Tool`, `ToolRegistry` | TOOL_CALL_PROTOCOL.md |
//! | [`session`] | `SessionStore`, `TranscriptStore` | - |
//! | [`memory`] | `MemoryClient`, `ExperienceStore` | - |
//! | [`checkpoint`] | `CheckpointStorage` | - |
//! | [`target`] | `TargetCandidate`, `TargetInventory` | TARGET_TAXONOMY.md |
//! | [`harness`] | `Harness`, `HarnessDraft` | HARNESS_STANDARD.md |
//! | [`engine`] | `EngineKind`, `FuzzRunConfig`, `FuzzProgress` | ENGINE_ADAPTER_STANDARD.md |
//! | [`retired_engine`] | Retired engine identifier recognition | retirement policy design |
//! | [`crash`] | `Crash`, `CrashReport` | crash-triage-design.md |
//! | [`corpus`] | `Corpus`, `CorpusEntry` | corpus-coverage-design.md |
//! | [`coverage`] | `CoverageReport` | corpus-coverage-design.md |

pub mod agent;
pub mod armed;
pub mod checkpoint;
pub mod corpus;
pub mod coverage;
pub mod crash;
pub mod embedding;
pub mod engine;
pub mod error;
pub mod exec;
pub mod harness;
pub mod memory;
pub mod permission_types;
pub mod provider;
pub mod retired_engine;
pub mod runtime;
pub mod session;
pub mod target;
pub mod tool;
pub mod trust;
pub mod types;
