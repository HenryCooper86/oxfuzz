use super::{
    BehaviorCheck, BehaviorObservation, ClassifiedError, HarnessBehaviorReport, ServiceContainer,
};
use crate::container::staging::{verify_run_artifacts, RunArtifacts};
use hf_core::{
    engine::{EngineKind, FuzzRunConfig},
    harness::Harness,
    runtime::{CommandTermination, ResourceLimits, SandboxMount, SandboxOptions},
};
use hf_storage::RunRecord;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io::Read as _, path::Path};

type ProbeBatch<'a> = (&'static str, Vec<(&'static str, &'static str, &'a [u8])>);

const MAX_MAP_BYTES: u64 = 64 * 1024;
const MAX_INPUT_BYTES: u64 = 4096;

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| ClassifiedError::Validation(format!("read behavioral artifact: {e}")))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(ClassifiedError::Validation(
            "behavioral artifact must be a bounded regular file".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|e| ClassifiedError::Validation(format!("read behavioral artifact: {e}")))?;
    if bytes.len() as u64 > limit {
        return Err(ClassifiedError::Validation(
            "behavioral artifact grew beyond its limit".to_owned(),
        ));
    }
    Ok(bytes)
}

fn read_map(root: &Path, path: &Path) -> Result<Vec<u8>, ClassifiedError> {
    let resolved = std::fs::canonicalize(path)
        .map_err(|e| ClassifiedError::Validation(format!("resolve behavioral map: {e}")))?;
    let root = std::fs::canonicalize(root)
        .map_err(|e| ClassifiedError::Validation(format!("resolve behavioral output: {e}")))?;
    if !resolved.starts_with(root) {
        return Err(ClassifiedError::Validation(
            "behavioral map escaped its output directory".to_owned(),
        ));
    }
    read_regular(path, MAX_MAP_BYTES)
}

fn observation(
    label: &str,
    input: &[u8],
    bytes: &[u8],
) -> Result<BehaviorObservation, ClassifiedError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| ClassifiedError::Validation(format!("invalid AFL map encoding: {e}")))?;
    if bytes.len() as u64 > MAX_MAP_BYTES {
        return Err(ClassifiedError::Validation(
            "oversized behavioral AFL map".to_owned(),
        ));
    }
    let mut tuples = Vec::new();
    for line in text.lines() {
        let bytes = line.as_bytes();
        if bytes.len() < 4
            || !(b'1'..=b'8').contains(&bytes[0])
            || !bytes[1..].iter().all(u8::is_ascii_digit)
        {
            return Err(ClassifiedError::Validation(
                "invalid AFL cmin map".to_owned(),
            ));
        }
        let edge = line[1..]
            .parse::<u32>()
            .map_err(|e| ClassifiedError::Validation(format!("invalid AFL edge: {e}")))?;
        tuples.push((u64::from(edge), bytes[0] - b'0'));
    }
    tuples.sort_unstable();
    tuples.dedup();
    if tuples.is_empty() {
        return Err(ClassifiedError::Validation(
            "behavioral probe produced no coverage map".to_owned(),
        ));
    }
    Ok(BehaviorObservation {
        label: label.to_owned(),
        input_hex: hex::encode(input),
        input_sha256: format!("{:x}", Sha256::digest(input)),
        tuples,
    })
}

fn assess(report: &mut HarnessBehaviorReport, persistent: bool) {
    let get = |label: &str| report.observations.iter().find(|o| o.label == label);
    if let (Some(a), Some(repeat)) = (get("fresh_a"), get("repeat_a")) {
        report.repeated_input_stability = BehaviorCheck::measured(
            a.tuples == repeat.tuples,
            "Fresh A repeated with identical coverage",
            "Fresh A produced different coverage on repetition",
        );
    }
    let get = |label: &str| report.observations.iter().find(|o| o.label == label);
    if let (Some(a), Some(b)) = (get("fresh_a"), get("fresh_b")) {
        report.input_sensitivity = BehaviorCheck::measured(
            a.tuples != b.tuples,
            "A and B produced distinct coverage",
            "A and B produced identical coverage; input sensitivity was not demonstrated",
        );
    }
    let get = |label: &str| report.observations.iter().find(|o| o.label == label);
    if let (Some(empty), Some(a), Some(b)) = (get("empty"), get("fresh_a"), get("fresh_b")) {
        let grows = [a, b].iter().any(|o| {
            o.tuples
                .iter()
                .any(|t| empty.tuples.binary_search(t).is_err())
        });
        report.entry_rejection = BehaviorCheck::measured(
            grows,
            "A or B reached tuples beyond empty input (entry-rejection proxy)",
            "Neither A nor B reached tuples beyond empty input; possible early rejection",
        );
    }
    let get = |label: &str| report.observations.iter().find(|o| o.label == label);
    if persistent {
        if let (Some(a), Some(first), Some(last)) =
            (get("fresh_a"), get("sequence_a1"), get("sequence_a2"))
        {
            report.persistent_state = BehaviorCheck::measured(a.tuples == first.tuples && a.tuples == last.tuples, "No A-B-A coverage contamination observed under the AFL persistent protocol; exited children may restart and unobserved state changes remain possible", "A-B-A changed A coverage relative to fresh A; possible persistent state contamination");
        }
    }
}

impl ServiceContainer {
    pub(in crate::container) async fn collect_harness_behavior(
        &self,
        project: &Path,
        harness: &Harness,
        run: &RunRecord,
        artifacts: &RunArtifacts,
        config: &FuzzRunConfig,
        image: &str,
    ) -> Result<HarnessBehaviorReport, ClassifiedError> {
        let mut report =
            HarnessBehaviorReport::unavailable("Behavioral probes support AFL++ harnesses only");
        report.run_id = Some(run.id);
        report.source_sha256 = Some(artifacts.source_sha256.clone());
        report.binary_sha256 = Some(artifacts.binary_sha256.clone());
        report.sandbox_rev = run.sandbox_rev.clone();
        if harness.engine == EngineKind::AflPlusPlus {
            report = self
                .probe_harness_behavior(project, harness, artifacts, config, image, report)
                .await?;
        }
        let report_json =
            serde_json::to_string(&report).map_err(|e| ClassifiedError::Internal(e.to_string()))?;
        self.store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("behavior requires storage".to_owned()))?
            .record_harness_behavior(&hf_storage::HarnessBehaviorRecord {
                run_id: run.id,
                source_sha256: artifacts.source_sha256.clone(),
                binary_sha256: artifacts.binary_sha256.clone(),
                sandbox_rev: run.sandbox_rev.clone().ok_or_else(|| {
                    ClassifiedError::Validation("behavior requires exact image identity".to_owned())
                })?,
                report_sha256: format!("{:x}", Sha256::digest(report_json.as_bytes())),
                report_json,
            })
            .await?;
        Ok(report)
    }

    async fn probe_harness_behavior(
        &self,
        project: &Path,
        harness: &Harness,
        artifacts: &RunArtifacts,
        config: &FuzzRunConfig,
        image: &str,
        mut report: HarnessBehaviorReport,
    ) -> Result<HarnessBehaviorReport, ClassifiedError> {
        let settings =
            crate::config::effective_harness_settings().map_err(ClassifiedError::Validation)?;
        let timeout = settings.behavior_probe_timeout_secs.min(
            config
                .duration
                .ok_or_else(|| {
                    ClassifiedError::Internal(
                        "smoke behavior requires a resolved duration".to_owned(),
                    )
                })?
                .as_secs()
                / 5,
        );
        report.command_timeout_secs = timeout;
        let inputs = artifacts.output_host.join("behavior-inputs");
        let outputs = artifacts.output_host.join("behavior-maps");
        std::fs::create_dir(&inputs)
            .and_then(|()| std::fs::create_dir(&outputs))
            .map_err(|e| ClassifiedError::Internal(format!("stage behavior probe: {e}")))?;
        let mut a = b"A".to_vec();
        let corpus = hf_corpus::list(&artifacts.initial_corpus_host)?;
        let mut entries = corpus.entries;
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        for entry in entries {
            let metadata = std::fs::symlink_metadata(&entry.path)
                .map_err(|e| ClassifiedError::Validation(format!("inspect probe seed: {e}")))?;
            if metadata.len() > MAX_INPUT_BYTES {
                continue;
            }
            let bytes = read_regular(&entry.path, MAX_INPUT_BYTES)?;
            if !bytes.is_empty() {
                a = bytes;
                break;
            }
        }
        let mut b = a.clone();
        b[0] ^= 0xff;
        for (name, bytes) in [
            ("empty", &[][..]),
            ("a", a.as_slice()),
            ("b", b.as_slice()),
            ("a1", a.as_slice()),
            ("a2", a.as_slice()),
        ] {
            std::fs::write(inputs.join(name), bytes)
                .map_err(|e| ClassifiedError::Internal(format!("write behavioral input: {e}")))?;
        }
        let binary = read_regular(&artifacts.binary_host, 256 * 1024 * 1024)?;
        let persistent = binary
            .windows(b"##SIG_AFL_PERSISTENT##".len())
            .any(|w| w == b"##SIG_AFL_PERSISTENT##");
        report.persistent_state = BehaviorCheck::unavailable(if persistent {
            "Persistent sequence did not produce complete valid maps"
        } else {
            "Executable does not advertise AFL persistent support"
        });
        report.input_sensitivity =
            BehaviorCheck::unavailable("Fresh probes did not produce complete valid maps");
        report.entry_rejection = report.input_sensitivity.clone();
        report.repeated_input_stability = report.input_sensitivity.clone();
        let sandbox = SandboxOptions {
            image: Some(image.to_owned()),
            workspace_read_only: true,
            max_file_size_bytes: Some(MAX_MAP_BYTES),
            extra_mounts: vec![
                SandboxMount::read_only(inputs.clone(), "/behavior-inputs"),
                SandboxMount::writable(outputs.clone(), "/behavior-maps"),
            ],
            ..SandboxOptions::default()
        };
        let limits = ResourceLimits {
            max_mem_mb: config.max_mem_mb,
            max_cpus: config.max_cpus,
            max_duration_secs: timeout,
            env: HashMap::from([
                ("AFL_FUZZER_LOOPCOUNT".to_owned(), "100".to_owned()),
                (
                    "LLVM_PROFILE_FILE".to_owned(),
                    "/tmp/behavior-%p.profraw".to_owned(),
                ),
            ]),
            ptrace: false,
        };
        report.max_mem_mb = limits.max_mem_mb;
        report.max_cpus = limits.max_cpus;
        report.environment = limits.env.clone().into_iter().collect();
        let batches: Vec<ProbeBatch<'_>> = vec![
            ("empty", vec![("empty", "empty", &[])]),
            ("fresh_a", vec![("fresh_a", "a", &a)]),
            ("repeat_a", vec![("repeat_a", "a", &a)]),
            ("fresh_b", vec![("fresh_b", "b", &b)]),
            (
                "sequence",
                if persistent {
                    vec![
                        ("sequence_a1", "a1", &a),
                        ("sequence_b", "b", &b),
                        ("sequence_a2", "a2", &a),
                    ]
                } else {
                    Vec::new()
                },
            ),
        ];
        for (batch, samples) in batches {
            if samples.is_empty() {
                continue;
            }
            let map_dir = outputs.join(batch);
            std::fs::create_dir(&map_dir)
                .map_err(|e| ClassifiedError::Internal(format!("stage maps: {e}")))?;
            let mut args = vec![
                "afl-showmap".to_owned(),
                "-q".to_owned(),
                "-Z".to_owned(),
                "-t".to_owned(),
                (timeout * 1000).to_string(),
                "-o".to_owned(),
            ];
            if batch == "empty" {
                args.push("/behavior-maps/empty/empty".to_owned());
                args.push("--".to_owned());
                args.extend(hf_engine::afl::build_reproduction_args(
                    &artifacts.binary_container,
                    "/behavior-inputs/empty",
                ));
            } else {
                let mut list = String::new();
                for (_, file, _) in &samples {
                    list.push_str("/behavior-inputs/");
                    list.push_str(file);
                    list.push('\n');
                }
                std::fs::write(inputs.join(format!("{batch}.list")), list).map_err(|e| {
                    ClassifiedError::Internal(format!("write behavioral list: {e}"))
                })?;
                args.extend([
                    format!("/behavior-maps/{batch}"),
                    "-I".to_owned(),
                    format!("/behavior-inputs/{batch}.list"),
                    "--".to_owned(),
                    artifacts.binary_container.clone(),
                    "@@".to_owned(),
                ]);
            }
            verify_run_artifacts(artifacts)?;
            self.verify_harness_dispatch_image(project, harness, Some(image))
                .await?;
            report.commands.push(args.clone());
            let workspace = artifacts
                .input_host
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .ok_or_else(|| {
                    ClassifiedError::Internal("invalid retained run layout".to_owned())
                })?;
            let result = match self
                .runtime
                .run_command_opts(&args, workspace, &limits, &sandbox)
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    // Optional measurement failures retain unavailable evidence; the
                    // artifact and image admission checks above still fail closed.
                    let detail: String = error.to_string().chars().take(1024).collect();
                    report
                        .issues
                        .push(format!("{batch}: runtime probe unavailable: {detail}"));
                    continue;
                }
            };
            if result.termination != CommandTermination::Completed || result.exit_code != 0 {
                report.issues.push(format!(
                    "{batch}: {:?}, exit {}",
                    result.termination, result.exit_code
                ));
                continue;
            }
            let mut measured = Vec::new();
            for (label, file, bytes) in samples {
                let measurement = read_map(&outputs, &map_dir.join(file))
                    .and_then(|map| observation(label, bytes, &map));
                match measurement {
                    Ok(value) => measured.push(value),
                    Err(error) => {
                        tracing::warn!(%error, batch, "behavioral probe unavailable");
                        report.issues.push(format!("{batch}: {error}"));
                        measured.clear();
                        break;
                    }
                }
            }
            report.observations.extend(measured);
        }
        assess(&mut report, persistent);
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(label: &str, map: &str) -> BehaviorObservation {
        observation(label, b"A", map.as_bytes()).unwrap()
    }
    #[test]
    fn distinguishes_insensitive_unstable_and_contaminated_maps() {
        let mut report = HarnessBehaviorReport::unavailable("missing");
        report.observations = vec![
            sample("empty", "1001\n"),
            sample("fresh_a", "1001\n"),
            sample("repeat_a", "1002\n"),
            sample("fresh_b", "1001\n"),
            sample("sequence_a1", "1001\n"),
            sample("sequence_a2", "1003\n"),
        ];
        assess(&mut report, true);
        assert!(matches!(
            report.input_sensitivity,
            BehaviorCheck::Suspect { .. }
        ));
        assert!(matches!(
            report.entry_rejection,
            BehaviorCheck::Suspect { .. }
        ));
        assert!(matches!(
            report.repeated_input_stability,
            BehaviorCheck::Suspect { .. }
        ));
        assert!(matches!(
            report.persistent_state,
            BehaviorCheck::Suspect { .. }
        ));
    }
    #[test]
    fn cmin_count_classes_preserve_loop_variation() {
        let first = observation("a", b"A", b"1001\n2002\n").unwrap();
        let later = observation("a", b"A", b"1001\n8002\n").unwrap();
        assert_ne!(first.tuples, later.tuples);
    }

    #[test]
    fn oversized_artifacts_are_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("map");
        std::fs::write(&file, vec![b'1'; MAX_MAP_BYTES as usize + 1]).unwrap();
        assert!(read_map(directory.path(), &file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn output_parent_symlinks_cannot_escape_the_run() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("map"), b"1001\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), directory.path().join("sequence")).unwrap();
        assert!(read_map(directory.path(), &directory.path().join("sequence/map")).is_err());
    }

    #[test]
    fn missing_and_malformed_maps_never_count_as_stable() {
        assert!(observation("a", b"A", b"diagnostic\n1:1").is_err());
        assert!(observation("a", b"A", b"").is_err());
        let mut report = HarnessBehaviorReport::unavailable("missing");
        report.observations = vec![sample("fresh_a", "1001\n")];
        assess(&mut report, true);
        assert!(matches!(
            report.persistent_state,
            BehaviorCheck::Unavailable { .. }
        ));
    }
}
