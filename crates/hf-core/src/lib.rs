//! hf-core: Core abstractions and traits for `hobot_fuzz`.
//!
//! This crate defines the contracts between all other `hobot_fuzz` crates.
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
//! | [`hook`] | `Middleware`, `HookHandler`, `EventSubscriber` | - |
//! | [`skill`] | `SkillRegistry` | - |
//! | [`target`] | `TargetCandidate`, `TargetInventory` | TARGET_TAXONOMY.md |
//! | [`harness`] | `Harness`, `HarnessDraft` | HARNESS_STANDARD.md |
//! | [`engine`] | `EngineKind`, `FuzzRunConfig`, `FuzzProgress` | ENGINE_ADAPTER_STANDARD.md |
//! | [`crash`] | `Crash`, `CrashReport` | crash-triage-design.md |
//! | [`corpus`] | `Corpus`, `CorpusEntry` | corpus-coverage-design.md |
//! | [`coverage`] | `CoverageReport` | corpus-coverage-design.md |

pub mod agent;
pub mod checkpoint;
pub mod corpus;
pub mod coverage;
pub mod crash;
pub mod engine;
pub mod error;
pub mod harness;
pub mod hook;
pub mod memory;
pub mod provider;
pub mod runtime;
pub mod session;
pub mod skill;
pub mod target;
pub mod tool;
pub mod trust;
pub mod types;
