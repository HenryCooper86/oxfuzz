//! Service-owned boundary for deterministic campaign advice.
//!
//! Advice remains side-effect free. Presentation callers receive a proposal
//! and its evidence, never authority to launch, mutate, or promote anything.

pub use hf_coverage::campaign_advisor::{
    CampaignAction, CampaignAdvice, CampaignAdviceRequest, CampaignBudget, CampaignObservation,
    EngineCostRate,
};

use hf_core::error::ClassifiedError;

use crate::container::ServiceContainer;

impl ServiceContainer {
    /// Evaluate a bounded coverage-per-cost request without changing state.
    ///
    /// # Errors
    /// Returns a validation error for malformed, ambiguous, or unbounded
    /// observations and pricing.
    pub fn campaign_advice(
        &self,
        request: &CampaignAdviceRequest,
    ) -> Result<CampaignAdvice, ClassifiedError> {
        hf_coverage::campaign_advisor::advise(request)
            .map_err(|error| ClassifiedError::Validation(error.to_string()))
    }
}
