//! Environment hygiene for processes oxfuzz spawns on the host.
//!
//! A sandboxed container's environment is already an allow-list: `docker.rs`
//! builds it from an empty map plus explicitly configured `--env` flags, and
//! Docker does not forward the host environment, so code running under the
//! sandbox never sees a provider credential.
//!
//! Host-side helpers are the gap this module closes. `std::process::Command`
//! inherits the full parent environment by default, so the `docker` CLI, `git`,
//! `pandoc`, and the Scapy sidecar all start with every secret the oxfuzz
//! process holds. They are trusted binaries, which is why this is a gap and not
//! an incident -- but the blast radius of a bug or a compromised tool in that
//! set is unbounded, and narrowing it costs one constructor call per spawn site.
//!
//! See `docs/standards/DEFENSIVE_PATTERNS.md` rule 6.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::process::Command;

/// Name fragments that mark a variable as carrying a credential.
///
/// Matched case-insensitively as substrings, so `HF_PROVIDER_API_KEY`,
/// `github_token`, and `AwsSecretAccessKey` are all dropped. The match is
/// deliberately broad: a false positive drops a variable a child did not need,
/// while a false negative leaks a credential. Only one of those is recoverable.
pub const SENSITIVE_NAME_FRAGMENTS: [&str; 4] = ["KEY", "SECRET", "TOKEN", "PASSWORD"];

/// Variables carrying oxfuzz's own configuration and identity.
///
/// Dropped for two reasons: a helper has no use for them, and a nested oxfuzz
/// invoked as a child must not silently adopt its parent's workspace root or
/// provider routing.
pub const HARNESS_NAME_PREFIX: &str = "HF_";

/// Whether a variable of this name must not reach a spawned process.
#[must_use]
pub fn is_sensitive_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with(HARNESS_NAME_PREFIX)
        || SENSITIVE_NAME_FRAGMENTS
            .iter()
            .any(|fragment| upper.contains(fragment))
}

/// The parent environment with credential-bearing variables removed.
///
/// `PATH`, `HOME`, locale, and proxy settings survive, because a helper that
/// cannot find its own binary or resolve a host is not safer, only broken.
///
/// Ordered so that two calls in one process produce the same environment: an
/// argument list that varies run to run is one more thing to rule out when a
/// sandboxed build reproduces on one machine and not another.
#[must_use]
pub fn scrubbed_parent_env() -> BTreeMap<String, String> {
    scrub(std::env::vars())
}

/// [`scrubbed_parent_env`] over an explicit iterator, so the rule is testable
/// without mutating the test process's own environment.
#[must_use]
pub fn scrub<I>(vars: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    vars.into_iter()
        .filter(|(name, _)| !is_sensitive_name(name))
        .collect()
}

/// A [`Command`] that starts from the scrubbed parent environment.
///
/// Use this instead of [`Command::new`] for every host-side spawn. A caller
/// that genuinely needs a credential forwards it explicitly with
/// [`Command::env`] afterwards, which makes the exception visible at the call
/// site and greppable across the workspace.
#[must_use]
pub fn scrubbed_command<S: AsRef<OsStr>>(program: S) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    command.envs(scrubbed_parent_env());
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn drops_the_provider_credential() {
        assert!(is_sensitive_name("HF_PROVIDER_API_KEY"));
    }

    #[test]
    fn matches_regardless_of_case() {
        for name in ["github_token", "AwsSecretAccessKey", "db_password", "api_key"] {
            assert!(is_sensitive_name(name), "{name} should be dropped");
        }
    }

    #[test]
    fn drops_every_harness_variable_even_without_a_sensitive_fragment() {
        // A nested oxfuzz must not adopt its parent's workspace root.
        assert!(is_sensitive_name("HF_WORKSPACE_DIR"));
        assert!(is_sensitive_name("HF_SANDBOX_IMAGE"));
    }

    #[test]
    fn keeps_what_a_helper_needs_to_function() {
        for name in [
            "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "SSH_AUTH_SOCK",
            "HTTPS_PROXY", "NO_PROXY", "DOCKER_HOST", "DOCKER_CONFIG",
        ] {
            assert!(!is_sensitive_name(name), "{name} should survive");
        }
    }

    #[test]
    fn a_false_positive_is_accepted_because_it_fails_safe() {
        // "MONKEY" contains "KEY". Dropping a variable a child did not need is
        // recoverable; leaking one is not. Documented so the behavior is a
        // decision rather than a surprise.
        assert!(is_sensitive_name("MONKEY"));
    }

    #[test]
    fn scrub_removes_only_the_sensitive_entries() {
        let scrubbed = scrub(vars(&[
            ("PATH", "/usr/bin"),
            ("HF_PROVIDER_API_KEY", "sk-live-should-not-survive"),
            ("HOME", "/home/oxfuzz"),
            ("GITHUB_TOKEN", "ghp_should_not_survive"),
        ]));
        assert_eq!(scrubbed.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(scrubbed.get("HOME").map(String::as_str), Some("/home/oxfuzz"));
        assert!(!scrubbed.contains_key("HF_PROVIDER_API_KEY"));
        assert!(!scrubbed.contains_key("GITHUB_TOKEN"));
        assert_eq!(scrubbed.len(), 2);
    }

    #[test]
    fn no_scrubbed_value_survives_anywhere_in_the_result() {
        // The property that matters is not "the key is absent" but "the secret
        // is absent": a variable renamed by a caller would still leak.
        let scrubbed = scrub(vars(&[
            ("HF_PROVIDER_API_KEY", "sk-live-secret"),
            ("PATH", "/usr/bin"),
        ]));
        assert!(
            !scrubbed.values().any(|value| value.contains("sk-live-secret")),
            "a scrubbed value reappeared under another name"
        );
    }

    #[test]
    fn the_result_is_ordered_so_two_calls_agree() {
        let first = scrub(vars(&[("B", "2"), ("A", "1"), ("C", "3")]));
        let second = scrub(vars(&[("C", "3"), ("A", "1"), ("B", "2")]));
        assert_eq!(
            first.keys().collect::<Vec<_>>(),
            second.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_empty_environment_scrubs_to_an_empty_environment() {
        assert!(scrub(Vec::new()).is_empty());
    }
}
