//! cargo-fuzz backend: project scaffold + build command for Rust fuzz targets.
//!
//! Rust targets are fuzzed with cargo-fuzz (libfuzzer-sys under the hood), which
//! is structurally different from the single-file C/C++ compile path in
//! [`crate::generator::try_compile`]. cargo-fuzz needs a cargo-fuzz project laid
//! out beside the crate under test:
//!
//! ```text
//! <workspace>/            # the crate under test (staged Cargo.toml + src/)
//!   fuzz/
//!     Cargo.toml          # depends on libfuzzer-sys + the crate (path = "..")
//!     fuzz_targets/<name>.rs   # the generated `fuzz_target!` harness
//! ```
//!
//! `cargo fuzz build <name>` (run from the crate root) produces a standard
//! libFuzzer binary at `fuzz/target/<triple>/release/<name>`. Once that binary
//! is copied into the workspace under the `fuzz_<target>` name the run step
//! expects, the existing libFuzzer run path drives it unchanged -- no new engine
//! adapter is needed.
//!
//! The functions here are pure (they render strings and derive names); the file
//! I/O and sandbox invocation live in [`crate::generator`].

/// Render `fuzz/Cargo.toml` for a cargo-fuzz project.
///
/// `crate_name` is the package name of the crate under test (its `[package]
/// name`), depended on by path; `target_name` is the single fuzz binary.
#[must_use]
pub fn fuzz_cargo_toml(crate_name: &str, target_name: &str) -> String {
    format!(
        r#"[package]
name = "{crate_name}-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"

[dependencies.{crate_name}]
path = ".."

# Prevent this manifest from being absorbed into a parent workspace.
[workspace]
members = ["."]

[[bin]]
name = "{target_name}"
path = "fuzz_targets/{target_name}.rs"
test = false
doc = false
bench = false
"#
    )
}

/// Extract the `[package] name` from a crate's `Cargo.toml`.
///
/// A minimal line scanner sufficient for the common `name = "..."` form; it does
/// not evaluate full TOML (e.g. `name` set via inline tables or workspace
/// inheritance is not resolved). Returns `None` when no `[package] name` is found.
#[must_use]
pub fn crate_name_from_cargo_toml(cargo_toml: &str) -> Option<String> {
    let mut in_package = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            // A new table header: we are in `[package]` only for that section.
            in_package = rest.trim_end_matches(']').trim() == "package";
            continue;
        }
        if in_package {
            if let Some(rest) = trimmed.strip_prefix("name") {
                if let Some(val) = rest.trim_start().strip_prefix('=') {
                    let name = val.trim().trim_matches('"');
                    if !name.is_empty() {
                        return Some(name.to_owned());
                    }
                }
            }
        }
    }
    None
}

/// Normalize a name to a valid cargo target / Rust binary name: keep ASCII
/// alphanumerics and `_`, map every other byte to `_`, and guarantee a non-empty
/// result. Used for both the `[[bin]]` name and the `fuzz_targets/<name>.rs`
/// filename so they always agree and never need shell quoting.
#[must_use]
pub fn sanitize_target_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out.push_str("fuzz_target");
    }
    out
}

/// The bash script that builds a cargo-fuzz `target_name` and copies the produced
/// libFuzzer binary to `<container_ws>/<output_name>` (the path the run step
/// expects). Runs from `container_ws`, the crate root where `fuzz/` lives.
///
/// `target_name` must already be [`sanitize_target_name`]d and `container_ws` is
/// a value we control (`/work`), so no shell quoting is required. Sanitizer
/// selection is left to cargo-fuzz's defaults (`AddressSanitizer`).
#[must_use]
pub fn build_script(target_name: &str, output_name: &str, container_ws: &str) -> String {
    format!(
        "cd {container_ws} && cargo fuzz build {target_name} \
         && cp {container_ws}/fuzz/target/*/release/{target_name} {container_ws}/{output_name} \
         && chmod +x {container_ws}/{output_name}",
    )
}

#[cfg(test)]
mod tests {
    use super::{build_script, crate_name_from_cargo_toml, fuzz_cargo_toml, sanitize_target_name};

    #[test]
    fn fuzz_manifest_declares_crate_dep_and_binary() {
        let toml = fuzz_cargo_toml("mylib", "fuzz_parse");
        assert!(toml.contains("libfuzzer-sys"));
        assert!(toml.contains("[dependencies.mylib]"));
        assert!(toml.contains("path = \"..\""));
        assert!(toml.contains("name = \"fuzz_parse\""));
        assert!(toml.contains("path = \"fuzz_targets/fuzz_parse.rs\""));
    }

    #[test]
    fn extracts_package_name() {
        let cargo = "[package]\nname = \"my-crate\"\nversion = \"0.1.0\"\n";
        assert_eq!(
            crate_name_from_cargo_toml(cargo).as_deref(),
            Some("my-crate")
        );
    }

    #[test]
    fn ignores_name_outside_package_section() {
        // A `name` under `[dependencies]`/`[[bin]]` must not be mistaken for the
        // package name.
        let cargo = "[dependencies]\nname = \"nope\"\n\n[package]\nname = \"real\"\n";
        assert_eq!(crate_name_from_cargo_toml(cargo).as_deref(), Some("real"));
    }

    #[test]
    fn missing_package_name_is_none() {
        assert_eq!(
            crate_name_from_cargo_toml("[dependencies]\nfoo = \"1\"\n"),
            None
        );
    }

    #[test]
    fn sanitizes_names() {
        assert_eq!(sanitize_target_name("fuzz_parse"), "fuzz_parse");
        assert_eq!(sanitize_target_name("fuzz-my.sym"), "fuzz_my_sym");
        assert_eq!(sanitize_target_name(""), "fuzz_target");
    }

    #[test]
    fn build_script_builds_and_copies_to_expected_name() {
        let s = build_script("fuzz_parse", "fuzz_parse", "/work");
        assert!(s.contains("cargo fuzz build fuzz_parse"));
        assert!(s.contains("/work/fuzz/target/*/release/fuzz_parse"));
        assert!(s.contains("/work/fuzz_parse"));
    }
}
