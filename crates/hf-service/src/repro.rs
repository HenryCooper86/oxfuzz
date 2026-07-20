//! Self-contained reproduction bundles.
//!
//! A bundle lets a maintainer reproduce a `oxfuzz` finding *without* a
//! `oxfuzz` install: the exact harness source, the (minimized) crash input,
//! and a `REPRODUCE.md` manifest with the build command and run steps. This
//! serves the VISION reproducibility pillar and makes a finding actionable
//! outside the tool.

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The manifest metadata for a reproduction bundle. Rendered to `REPRODUCE.md`.
#[derive(Debug, Clone)]
pub struct ReproManifest {
    pub project: String,
    pub target: String,
    pub language: String,
    pub engine: String,
    pub sanitizer: String,
    /// The exact sandbox build command that produced the fuzz binary.
    pub build_command: String,
    /// The harness source filename inside the bundle (e.g. `harness.c`).
    pub harness_filename: String,
    /// The crash input filename inside the bundle.
    pub input_filename: String,
    /// The built binary name the run command invokes (e.g. `fuzz_bin`).
    pub binary_name: String,
    pub crash_kind: String,
    pub crash_summary: String,
    pub stack_signature: String,
    pub minimized: bool,
}

impl ReproManifest {
    /// The command that re-triggers the crash: a libFuzzer/AFL persistent binary
    /// replays a single input passed as its first argument.
    #[must_use]
    pub fn run_command(&self) -> String {
        format!("./{} {}", self.binary_name, self.input_filename)
    }
}

/// Render the `REPRODUCE.md` manifest for a bundle.
#[must_use]
pub fn render_repro_manifest(manifest: &ReproManifest) -> String {
    let input_state = if manifest.minimized {
        "minimized"
    } else {
        "raw"
    };
    let signature = if manifest.stack_signature.is_empty() {
        "(none -- frameless crash)".to_owned()
    } else {
        format!("`{}`", manifest.stack_signature)
    };
    format!(
        "# Reproduction bundle: {target}\n\
         \n\
         Self-contained reproducer for a crash found by oxfuzz. It needs only \
         the target's toolchain -- no oxfuzz install.\n\
         \n\
         ## Finding\n\
         - Project: `{project}`\n\
         - Target: `{target}` ({language})\n\
         - Engine: {engine}\n\
         - Sanitizer: {sanitizer}\n\
         - Crash kind: {kind}\n\
         - Stack signature: {signature}\n\
         - Summary: {summary}\n\
         - Input: `{input}` ({input_state})\n\
         \n\
         ## Build\n\
         ```sh\n{build}\n```\n\
         \n\
         ## Reproduce\n\
         ```sh\n{run}\n```\n\
         \n\
         The build compiles `{harness}` (included) into `{binary}`; running it on \
         `{input}` re-triggers the crash under the sanitizer above.\n",
        target = manifest.target,
        project = manifest.project,
        language = manifest.language,
        engine = manifest.engine,
        sanitizer = manifest.sanitizer,
        kind = manifest.crash_kind,
        signature = signature,
        summary = manifest.crash_summary,
        input = manifest.input_filename,
        input_state = input_state,
        build = manifest.build_command,
        run = manifest.run_command(),
        harness = manifest.harness_filename,
        binary = manifest.binary_name,
    )
}

/// Write a reproduction bundle to `dest`: the harness source, the crash input,
/// and the rendered `REPRODUCE.md`. `dest` is created if absent. Returns the
/// bundle directory.
///
/// # Errors
/// Returns an `io::Error` if the directory or any file cannot be written.
pub fn write_repro_bundle(
    dest: &Path,
    manifest: &ReproManifest,
    harness_source: &str,
    crash_input: &[u8],
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dest)?;
    std::fs::write(dest.join(&manifest.harness_filename), harness_source)?;
    std::fs::write(dest.join(&manifest.input_filename), crash_input)?;
    let mut manifest_file = std::fs::File::create(dest.join("REPRODUCE.md"))?;
    manifest_file.write_all(render_repro_manifest(manifest).as_bytes())?;
    Ok(dest.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ReproManifest {
        ReproManifest {
            project: "/src/libfoo".to_owned(),
            target: "parse_header".to_owned(),
            language: "C".to_owned(),
            engine: "libfuzzer".to_owned(),
            sanitizer: "address".to_owned(),
            build_command: "clang -g -O1 -fsanitize=address,fuzzer harness.c -o fuzz_bin"
                .to_owned(),
            harness_filename: "harness.c".to_owned(),
            input_filename: "crash_input".to_owned(),
            binary_name: "fuzz_bin".to_owned(),
            crash_kind: "Asan".to_owned(),
            crash_summary: "heap-buffer-overflow".to_owned(),
            stack_signature: "abc123".to_owned(),
            minimized: true,
        }
    }

    #[test]
    fn manifest_carries_build_and_run_steps() {
        let md = render_repro_manifest(&sample());
        assert!(md.contains("clang -g -O1 -fsanitize=address,fuzzer harness.c -o fuzz_bin"));
        assert!(
            md.contains("./fuzz_bin crash_input"),
            "run command must be present"
        );
        assert!(md.contains("`abc123`"), "signature is shown");
        assert!(md.contains("(minimized)"));
    }

    #[test]
    fn frameless_signature_is_labelled() {
        let mut m = sample();
        m.stack_signature = String::new();
        let md = render_repro_manifest(&m);
        assert!(md.contains("frameless crash"));
    }

    #[test]
    fn bundle_writes_all_three_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("bundle");
        write_repro_bundle(
            &dest,
            &sample(),
            "int LLVMFuzzerTestOneInput(){return 0;}",
            b"\x00\x01crash",
        )
        .unwrap();
        assert!(dest.join("harness.c").exists());
        assert!(dest.join("REPRODUCE.md").exists());
        assert_eq!(
            std::fs::read(dest.join("crash_input")).unwrap(),
            b"\x00\x01crash",
            "the exact crash bytes are preserved"
        );
    }
}
