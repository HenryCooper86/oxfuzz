//! Target discovery and ranking.

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_core::target::{TargetInventory, TargetLanguage};
use hf_guardrails::Action;

use super::project_identity::{project_lookup_identity, stored_project_matches};
use super::{fuzzing_policy_error, LlmProviderBridge, SchedulableTarget, ServiceContainer};

/// A target inventory with the native static-analysis overlay computed from the
/// same parse.
///
/// The overlay is advisory and separate from the candidates: base fit scores
/// stay exactly as discovery produced them, and a consumer can always see what
/// a candidate scored before any signal touched it.
#[cfg(feature = "native-analysis")]
#[derive(Debug, Clone)]
pub struct AnalyzedInventory {
    /// Candidates, with base scores untouched.
    pub inventory: hf_core::target::TargetInventory,
    /// One score row per candidate.
    pub scores: Vec<hf_discovery::enrichment::TargetScore>,
    /// Signals the analyzer produced, for reporting how much evidence there was.
    pub signal_count: usize,
}

impl ServiceContainer {
    /// Discover fuzzing targets in a project.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the project root cannot be read.
    pub async fn discover(
        &self,
        project: &Path,
        lang: TargetLanguage,
    ) -> Result<TargetInventory, ClassifiedError> {
        self.authorize_recorded(Action::Discover, "discover", Some(project))
            .await?;
        let inv = hf_discovery::discover(project, lang).await?;
        if let Some(store) = &self.store {
            store.save_inventory(&inv, Utc::now()).await?;
        }
        Ok(inv)
    }

    /// Discover targets and the native static-analysis overlay together.
    ///
    /// The signals come from the trees the scan already built, so this costs a
    /// query-cursor pass rather than a second walk of the project.
    ///
    /// Independent of the Semgrep enrichment operation, which remains a separate,
    /// explicitly requested, deeper analysis. The two overlays are deliberately
    /// not merged: they are produced at different times from different evidence,
    /// and combining them would either double-count a defect both found or hide
    /// that both found it.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the project cannot be read, or the
    /// authorization for discovery is denied.
    #[cfg(feature = "native-analysis")]
    pub async fn discover_analyzed(
        &self,
        project: &Path,
        lang: TargetLanguage,
    ) -> Result<AnalyzedInventory, ClassifiedError> {
        self.authorize_recorded(Action::Discover, "discover", Some(project))
            .await?;
        let (inventory, signals) = hf_discovery::discover_with_signals(project, lang).await?;
        if let Some(store) = &self.store {
            store.save_inventory(&inventory, Utc::now()).await?;
        }
        let overlay = hf_discovery::enrichment::score_overlay(&inventory, &signals);
        Ok(AnalyzedInventory {
            inventory,
            scores: overlay.scores,
            signal_count: signals.len(),
        })
    }
    /// Re-rank a target inventory using the configured LLM provider pool.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Provider` if no provider is configured, or the
    /// underlying ranking error if the LLM call fails.
    pub async fn rank(
        &self,
        inventory: TargetInventory,
    ) -> Result<TargetInventory, ClassifiedError> {
        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider("no LLM provider configured for ranking".to_owned())
        })?;
        let bridge =
            LlmProviderBridge::new(pool).with_diagnostics(Arc::clone(&self.diagnostics), "rank");
        let ranked = hf_discovery::rank(inventory, Box::new(bridge)).await?;
        if let Some(store) = &self.store {
            store.save_inventory(&ranked, Utc::now()).await?;
        }
        Ok(ranked)
    }

    /// Targets in `project` that a scheduled campaign can legally run: those a
    /// human has smoke-qualified and promoted a harness for. `run_campaign`
    /// refuses everything else, so this is exactly the set the Automation view
    /// should offer -- and it carries the engine and language off the harness,
    /// so a schedule cannot be created for a combination that will fail at 3am.
    ///
    /// One entry per (target, engine) pair: a target promoted for two engines is
    /// schedulable under either.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] when persistence is not configured.
    pub async fn schedulable_targets(
        &self,
        project: &Path,
    ) -> Result<Vec<SchedulableTarget>, ClassifiedError> {
        // Resolve targets the same way `resolve_target_id` does -- with the
        // path-tolerant `stored_project_matches` over every stored target --
        // rather than an exact `list_targets(project_root)` string match. A
        // trailing-slash/symlinked/relative project path otherwise reports "no
        // schedulable targets" for a project that `run_campaign` would happily
        // run, because the two disagreed on path normalization. Uses the same
        // graceful identity (canonicalize-or-raw), so a project that does not
        // exist yields an empty list rather than an error.
        let identity = project_lookup_identity(project);
        let fuzzing = crate::config::effective_fuzzing_settings()
            .map_err(|error| fuzzing_policy_error(&error))?;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "scheduling campaigns requires the persistent service store".to_owned(),
            )
        })?;
        let targets = store
            .list_all_targets()
            .await
            .map_err(ClassifiedError::from)?;
        let project_targets = targets
            .into_iter()
            .filter(|candidate| stored_project_matches(&candidate.project_root, &identity))
            .collect::<Vec<_>>();
        #[cfg(feature = "semgrep-enrichment")]
        let mut effective_score_by_target = project_targets
            .iter()
            .map(|candidate| (candidate.id, candidate.fit_score))
            .collect::<std::collections::HashMap<_, _>>();
        #[cfg(feature = "semgrep-enrichment")]
        for language in [TargetLanguage::C, TargetLanguage::Cpp] {
            let candidates = project_targets
                .iter()
                .filter(|candidate| candidate.language == language)
                .cloned()
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                continue;
            }
            let effective = self
                .effective_inventory(
                    TargetInventory {
                        project_root: identity.clone(),
                        candidates,
                        call_graph: std::collections::HashMap::new(),
                    },
                    language,
                )
                .await?;
            for target in effective.candidates {
                effective_score_by_target.insert(target.candidate.id, target.effective_score);
            }
        }

        let mut schedulable = Vec::new();
        for candidate in project_targets {
            let harnesses = store
                .list_harnesses(candidate.id)
                .await
                .map_err(ClassifiedError::from)?;
            for harness in harnesses.iter().filter(|h| {
                h.status == HarnessStatus::Promoted && fuzzing.require_engine(h.engine).is_ok()
            }) {
                schedulable.push(SchedulableTarget {
                    target: candidate.symbol.clone(),
                    engine: harness.engine.as_str().to_owned(),
                    language: harness.language.as_str().to_owned(),
                    #[cfg(feature = "semgrep-enrichment")]
                    fit_score: effective_score_by_target
                        .get(&candidate.id)
                        .copied()
                        .unwrap_or(candidate.fit_score),
                    #[cfg(not(feature = "semgrep-enrichment"))]
                    fit_score: candidate.fit_score,
                });
            }
        }
        schedulable.sort_by(|a, b| (&a.target, &a.engine).cmp(&(&b.target, &b.engine)));
        schedulable.dedup_by(|a, b| a.target == b.target && a.engine == b.engine);
        Ok(schedulable)
    }
}

#[cfg(all(test, unix, feature = "semgrep-enrichment"))]
mod semgrep_ranking_consumer_tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use hf_core::engine::EngineKind;
    use hf_core::harness::{BuildCommand, Harness};
    use hf_core::target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };
    use hf_storage::Store;
    use uuid::Uuid;

    use super::*;

    fn candidate(
        project: &Path,
        symbol: &str,
        relative_file: &str,
        base_score: f64,
    ) -> TargetCandidate {
        TargetCandidate {
            id: Uuid::new_v4(),
            project_root: project.to_path_buf(),
            language: TargetLanguage::C,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: project.join(relative_file),
                line: 1,
                col: 1,
                end_line: Some(1),
                end_col: Some(40),
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score: base_score,
            sanitizers: Vec::new(),
            rationale: symbol.to_owned(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 1,
        }
    }

    fn inventory(project: &Path) -> TargetInventory {
        TargetInventory {
            project_root: project.to_path_buf(),
            candidates: vec![
                candidate(project, "high_base", "high.c", 0.55),
                candidate(project, "boosted", "boosted.c", 0.5),
            ],
            call_graph: HashMap::new(),
        }
    }

    fn promoted_harness(target: &TargetCandidate) -> Harness {
        Harness {
            id: Uuid::new_v4(),
            target_id: target.id,
            engine: EngineKind::LibFuzzer,
            source: format!("// {}", target.symbol),
            language: target.language,
            build_cmd: BuildCommand {
                compiler: "clang".to_owned(),
                args: Vec::new(),
                output: PathBuf::from("harness"),
                extra_flags: Vec::new(),
            },
            sanitizer: Sanitizer::Address,
            status: HarnessStatus::Promoted,
            smoke_run: None,
        }
    }

    async fn semgrep_run_count(store: &Store) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM semgrep_enrichment_runs")
            .fetch_one(store.pool())
            .await
            .unwrap()
    }

    fn assert_f64_eq(left: f64, right: f64) {
        assert_eq!(left.to_bits(), right.to_bits());
    }

    #[tokio::test]
    async fn schedulable_targets_use_effective_scores_without_starting_semgrep() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("high.c"),
            "int high_base(char *p) { return p[0]; }\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("boosted.c"),
            "int boosted(char *p) { return p[0]; }\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib.rs"),
            "pub fn rust_target(data: &[u8]) {}\n",
        )
        .unwrap();
        let project = std::fs::canonicalize(root.path()).unwrap();
        let inventory = inventory(&project);
        let high_base = inventory.candidates[0].clone();
        let boosted = inventory.candidates[1].clone();
        let rust_target = TargetCandidate {
            id: Uuid::new_v4(),
            language: TargetLanguage::Rust,
            symbol: "rust_target".to_owned(),
            location: SourceLocation {
                file: project.join("lib.rs"),
                line: 1,
                col: 1,
                end_line: Some(1),
                end_col: Some(36),
            },
            fit_score: 0.63,
            ..high_base.clone()
        };
        let store = Arc::new(
            Store::connect(root.path().join("scheduler.db"))
                .await
                .unwrap(),
        );
        store.save_inventory(&inventory, Utc::now()).await.unwrap();
        store
            .save_inventory(
                &TargetInventory {
                    project_root: project.clone(),
                    candidates: vec![rust_target.clone()],
                    call_graph: HashMap::new(),
                },
                Utc::now(),
            )
            .await
            .unwrap();
        store
            .upsert_harness(&promoted_harness(&high_base))
            .await
            .unwrap();
        store
            .upsert_harness(&promoted_harness(&boosted))
            .await
            .unwrap();
        store
            .upsert_harness(&promoted_harness(&rust_target))
            .await
            .unwrap();
        let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_store(Arc::clone(&store));
        service
            .semgrep_test_publish_inventory(&inventory, HashMap::from([(boosted.id, 0.2)]))
            .await
            .unwrap();
        let before = semgrep_run_count(&store).await;

        let targets = service.schedulable_targets(&project).await.unwrap();

        let scores = targets
            .into_iter()
            .map(|target| (target.target, target.fit_score))
            .collect::<HashMap<_, _>>();
        assert_f64_eq(*scores.get("high_base").unwrap(), 0.55);
        assert_f64_eq(*scores.get("boosted").unwrap(), 0.7);
        assert_f64_eq(*scores.get("rust_target").unwrap(), 0.63);
        assert_eq!(semgrep_run_count(&store).await, before);
    }
}
