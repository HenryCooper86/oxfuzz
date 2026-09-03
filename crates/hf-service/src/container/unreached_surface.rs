//! Gathering for the Unreached Surface ranking.
//!
//! The ranking itself is pure (`crate::unreached_surface`); this reads the
//! discovery candidates, the union of covered functions across every retained
//! coverage measurement for the project, and the harness attempt history.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use hf_core::harness::HarnessStatus;
use hf_core::target::TargetLanguage;

use crate::container::ServiceContainer;
use crate::unreached_surface::{
    coverage_attribution, unreached_surface, AttemptHistory, CoverageAttributionRequest,
    CoverageAttributionView, UnreachedSurfaceRequest, UnreachedSurfaceView,
};
use crate::ClassifiedError;

impl ServiceContainer {
    /// Rank the entry points no retained coverage measurement has ever
    /// covered, joined with what has already been attempted against each.
    ///
    /// Reads cached measurements only; never triggers one. A project with no
    /// completed measurement yields an unavailable result and no list, because
    /// absence judged against nothing measured would name every function.
    ///
    /// # Errors
    /// Returns a discovery error, or `ClassifiedError::Validation` when the
    /// persistent store is not configured.
    pub async fn unreached_surface(
        &self,
        project: &Path,
        lang: TargetLanguage,
    ) -> Result<UnreachedSurfaceView, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation(
                "unreached surface requires the persistent store".to_owned(),
            )
        })?;
        let inventory = self.discover(project, lang).await?;

        let mut covered_functions: HashSet<String> = HashSet::new();
        let mut attempts: HashMap<String, AttemptHistory> = HashMap::new();
        let mut measurements = 0usize;

        for candidate in &inventory.candidates {
            // The covered set is unioned across every target of the project,
            // not just the one being asked about: a function covered by a
            // harness retired two runs ago has still been reached.
            let covered = self.coverage_functions(project, &candidate.symbol).await;
            if !covered.is_empty() {
                measurements += 1;
                covered_functions.extend(covered);
            }

            let harnesses = store
                .list_harnesses(candidate.id)
                .await
                .map_err(|e| ClassifiedError::Validation(e.to_string()))?;
            if let Some(history) = attempt_history(&harnesses) {
                attempts.insert(candidate.symbol.clone(), history);
            }
        }

        let ranked_candidates = inventory
            .candidates
            .iter()
            .map(|candidate| (candidate.symbol.clone(), candidate.fit_score))
            .collect();

        Ok(unreached_surface(&UnreachedSurfaceRequest {
            ranked_candidates,
            covered_functions,
            attempts,
            measurements,
        }))
    }
}

/// The furthest any harness for a candidate reached.
///
/// `None` when no harness names it, which the ranking reads as
/// `NeverAttempted`; keeping that mapping in one place avoids two spellings of
/// the same absence.
fn attempt_history(harnesses: &[hf_core::harness::Harness]) -> Option<AttemptHistory> {
    if harnesses.is_empty() {
        return None;
    }
    let attempts = harnesses.len();
    let qualified = harnesses.iter().any(|h| {
        matches!(
            h.status,
            HarnessStatus::SmokePassed | HarnessStatus::Promoted
        )
    });
    if qualified {
        return Some(AttemptHistory::QualifiedYetUnreached { attempts });
    }
    let compiled = harnesses
        .iter()
        .any(|h| matches!(h.status, HarnessStatus::Compiled));
    if compiled {
        return Some(AttemptHistory::AttemptedSmokeFailed { attempts });
    }
    Some(AttemptHistory::AttemptedCompileFailed { attempts })
}

impl ServiceContainer {
    /// Attribute every discovered candidate against the union of retained
    /// coverage, ordered for the next harness: untouched ground first, the
    /// partial frontier next, saturated targets last.
    ///
    /// Reads cached measurements only; never triggers one. A project with no
    /// completed measurement yields an unavailable result and no list, for
    /// the same honesty reason as [`Self::unreached_surface`].
    ///
    /// # Errors
    /// Returns a discovery error, or `ClassifiedError::Validation` when the
    /// persistent store is not configured.
    pub async fn coverage_attribution(
        &self,
        project: &Path,
        lang: TargetLanguage,
    ) -> Result<CoverageAttributionView, ClassifiedError> {
        if self.store().is_none() {
            return Err(ClassifiedError::Validation(
                "coverage attribution requires the persistent store".to_owned(),
            ));
        }
        let inventory = self.discover(project, lang).await?;

        let mut covered_functions: HashSet<String> = HashSet::new();
        let mut measurements = 0usize;
        for candidate in &inventory.candidates {
            // The covered set is unioned across every target of the project,
            // matching `unreached_surface`: a function covered by a harness
            // retired two runs ago has still been reached.
            let covered = self.coverage_functions(project, &candidate.symbol).await;
            if !covered.is_empty() {
                measurements += 1;
                covered_functions.extend(covered);
            }
        }
        let ranked_candidates = inventory
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.symbol.clone(),
                    candidate.fit_score,
                    candidate.reachable_functions.clone(),
                )
            })
            .collect();

        Ok(coverage_attribution(&CoverageAttributionRequest {
            ranked_candidates,
            covered_functions,
            measurements,
        }))
    }
}
