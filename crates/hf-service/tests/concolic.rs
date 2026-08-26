//! Concolic corpus enrichment domain contract.

#![cfg(feature = "concolic-enrichment")]

use hf_service::config::{parse_concolic_settings, ConcolicSettings};

#[test]
fn every_bound_defaults_to_something_that_actually_bounds() {
    let d = ConcolicSettings::default();
    assert!(d.max_inputs > 0);
    assert!(d.per_input_timeout_secs > 0);
    assert!(d.max_solved_inputs > 0);
    assert!(d.total_timeout_secs > 0);
}

#[test]
fn a_zero_bound_is_rejected_rather_than_read_as_unlimited() {
    // Path explosion is this subsystem's normal failure mode, so an unbounded
    // pass is never what an operator meant by zero.
    for field in [
        "max_inputs",
        "per_input_timeout_secs",
        "max_solved_inputs",
        "total_timeout_secs",
    ] {
        let toml = format!("[concolic]\n{field} = 0\n");
        assert!(
            parse_concolic_settings(&toml).is_err(),
            "{field} = 0 must be rejected"
        );
    }
}

#[test]
fn a_valid_override_is_accepted() {
    let parsed = parse_concolic_settings("[concolic]\nmax_inputs = 40\n")
        .expect("a positive bound is valid");
    assert_eq!(parsed.max_inputs, 40);
}
