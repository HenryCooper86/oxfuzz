//! Self-contained reproduction bundles.
//!
//! A bundle lets a maintainer reproduce a `oxfuzz` finding *without* a
//! `oxfuzz` install: the exact harness source, the (minimized) crash input,
//! and a `REPRODUCE.md` manifest with the build command and run steps. This
//! serves the VISION reproducibility pillar and makes a finding actionable
//! outside the tool.

use std::fmt::Write as _;
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
    /// Project translation units copied into the bundle, in the order the build
    /// command names them. Empty only for a language whose build is not a
    /// compiler command line (Rust builds a crate through `cargo fuzz`).
    pub bundled_sources: Vec<String>,
    /// Translation units the bundle could not carry, when the project exceeded
    /// the bundle cap. Named in `REPRODUCE.md` so the build line is never
    /// silently incomplete.
    pub omitted_sources: usize,
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

/// One project translation unit carried inside a bundle.
///
/// The harness declares the target `extern`, so without these the documented
/// build command fails to link with an undefined reference to the very function
/// the finding is about.
#[derive(Debug, Clone)]
pub struct BundledSource {
    /// Path relative to the bundle root, preserving the project's layout so a
    /// nested translation unit still compiles against its neighbours' headers.
    pub relative_path: PathBuf,
    /// File bytes, copied by value.
    pub contents: Vec<u8>,
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
         {sources_note}\n\
         The build compiles `{harness}` together with the project sources \
         included above into `{binary}`; running it on `{input}` re-triggers \
         the crash under the sanitizer above.\n",
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
        sources_note = sources_note(manifest),
    )
}

/// The `## Sources` section: what the bundle carries, and what it could not.
///
/// An omission is stated rather than hidden. The defect this whole section
/// exists to prevent is a build command that looks authoritative and does not
/// link, so a bundle that cannot be complete says which files are missing
/// instead of pretending.
fn sources_note(manifest: &ReproManifest) -> String {
    if manifest.bundled_sources.is_empty() && manifest.omitted_sources == 0 {
        return String::new();
    }
    let mut note = String::from("## Sources\n\n");
    for path in &manifest.bundled_sources {
        let _ = writeln!(note, "- `{path}`");
    }
    if manifest.omitted_sources > 0 {
        let _ = write!(
            note,
            "\n{} further translation unit(s) were omitted: this project is \
             larger than one reproduction bundle carries. Add them from the \
             project to complete the link.\n",
            manifest.omitted_sources
        );
    }
    note
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
    sources: &[BundledSource],
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dest)?;
    std::fs::write(dest.join(&manifest.harness_filename), harness_source)?;
    std::fs::write(dest.join(&manifest.input_filename), crash_input)?;
    for source in sources {
        let target = dest.join(&source.relative_path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(target, &source.contents)?;
    }
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
            bundled_sources: vec!["parse.c".to_owned(), "src/util.c".to_owned()],
            omitted_sources: 0,
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
            &[
                BundledSource {
                    relative_path: PathBuf::from("parse.c"),
                    contents: b"int parse_header(void){return 0;}".to_vec(),
                },
                BundledSource {
                    relative_path: PathBuf::from("src/util.c"),
                    contents: b"int util(void){return 0;}".to_vec(),
                },
            ],
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

    /// The bundle must carry the target's own translation units.
    ///
    /// The harness declares the target `extern`, so a bundle of harness plus
    /// input alone fails to link on exactly the function the finding is about --
    /// which is worse than shipping no bundle, because the build command reads
    /// as authoritative.
    #[test]
    fn bundle_carries_the_project_sources_its_build_command_names() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("bundle");
        write_repro_bundle(
            &dest,
            &sample(),
            "int LLVMFuzzerTestOneInput(){return 0;}",
            b"crash",
            &[
                BundledSource {
                    relative_path: PathBuf::from("parse.c"),
                    contents: b"int parse_header(void){return 0;}".to_vec(),
                },
                // A nested unit: its layout is preserved so it still compiles
                // against its neighbours' headers.
                BundledSource {
                    relative_path: PathBuf::from("src/util.c"),
                    contents: b"int util(void){return 0;}".to_vec(),
                },
            ],
        )
        .unwrap();

        assert_eq!(
            std::fs::read(dest.join("parse.c")).unwrap(),
            b"int parse_header(void){return 0;}"
        );
        assert!(
            dest.join("src/util.c").is_file(),
            "a nested translation unit keeps its relative path"
        );

        let md = std::fs::read_to_string(dest.join("REPRODUCE.md")).unwrap();
        assert!(md.contains("`parse.c`"), "sources are listed: {md}");
        assert!(md.contains("`src/util.c`"), "sources are listed: {md}");
    }

    /// An incomplete bundle says so instead of shipping a build line that
    /// cannot link.
    #[test]
    fn an_omitted_source_is_named_not_hidden() {
        let mut manifest = sample();
        manifest.omitted_sources = 3;
        let md = render_repro_manifest(&manifest);
        assert!(
            md.contains("3 further translation unit(s) were omitted"),
            "the shortfall must be stated: {md}"
        );
    }
}
