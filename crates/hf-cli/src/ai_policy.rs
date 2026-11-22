use hf_service::ServiceContainer;

use crate::args::AiOption;

/// Apply an [`AiOption`] to a container for a whole multi-step flow.
///
/// `campaign` and `ci` are composite, and reach a model at several steps:
/// `campaign` at seed generation, the run dictionary, triage bug reports, and
/// the coverage-plateau harness refine; `ci` at the run dictionary and triage
/// bug reports. Threading a policy into each is how one gets forgotten -- the
/// dictionary augmentation is the easy one to miss, since it fires inside every
/// fuzz run rather than at a step anyone names. So `off` detaches the provider
/// instead: every one of those sites already checks for a provider and has a
/// no-model path, which makes "use no model" exact rather than aspirational.
///
/// `require` is a preflight, and only a preflight. A campaign can run for an
/// hour, so it is worth refusing to start one whose enrichment cannot work --
/// but the guarantee stops there. Each of those steps swallows a mid-flow
/// provider failure with a warning, by design (a model outage should not
/// discard a fuzzing campaign), so `require` cannot promise the model was
/// actually consulted. It promises the run did not begin with the model
/// already known to be unusable: none configured, or every one frozen by
/// earlier failures. `off` is the side of this flag that is exact.
///
/// # Errors
/// Returns an error under `require` when no provider is configured, or when
/// every configured provider is frozen.
pub(crate) async fn apply_ai_policy(
    container: ServiceContainer,
    ai: AiOption,
    what: &str,
) -> anyhow::Result<ServiceContainer> {
    container
        .scoped_to_ai_policy(ai.into(), what)
        .await
        .map_err(|error| match (ai, error) {
            // Name the flag the operator typed; the service names the cause.
            (AiOption::Require, hf_service::ClassifiedError::Validation(message)) => {
                anyhow::anyhow!("--ai require: {message}")
            }
            (_, error) => anyhow::Error::from(error),
        })
}

impl From<AiOption> for hf_service::AiPolicy {
    fn from(value: AiOption) -> Self {
        match value {
            AiOption::Auto => Self::Auto,
            AiOption::Require => Self::Require,
            AiOption::Off => Self::Off,
        }
    }
}
