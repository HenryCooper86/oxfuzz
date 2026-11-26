//! Draft and file an issue for one finding of a binary-only session.
//!
//! A binary-only session has no target, harness or run record, so its
//! findings are not rows of the crash table and `issue --crash` cannot name
//! them. They are named instead by the session report oxfuzz wrote and the
//! finding's input digest. The report is read from the project's own session
//! directories only, and filing goes through the same tracker client,
//! approval gate and exactly-once claim as a triaged crash.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_guardrails::Action;

use super::binary_only::{signal_name, BinaryFinding, BinaryFuzzOutcome, BinaryInput, REPORT_NAME};
use super::project_identity::project_slug;
use super::workspace::prepare_configured_workspace_root;
use super::ServiceContainer;

/// Largest session report read.
const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;
/// Shortest input digest prefix that may name a finding.
const MIN_FINDING_PREFIX: usize = 8;

fn invalid(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(message.into())
}

/// Read a session report that lies inside `sessions`, the project's own
/// directory of binary-only sessions.
pub(super) fn read_session_report(
    sessions: &Path,
    report: &Path,
) -> Result<BinaryFuzzOutcome, ClassifiedError> {
    if report.file_name().and_then(|name| name.to_str()) != Some(REPORT_NAME) {
        return Err(invalid(format!(
            "{} is not a session report; pass the {REPORT_NAME} a binary-only session wrote",
            report.display()
        )));
    }
    let resolve = |path: &Path, what: &str| {
        std::fs::canonicalize(path)
            .map_err(|error| invalid(format!("{what} {}: {error}", path.display())))
    };
    let sessions = resolve(
        sessions,
        "no binary-only session was recorded for this project under",
    )?;
    let resolved = resolve(report, "session report")?;
    if !resolved.starts_with(&sessions) {
        return Err(invalid(format!(
            "{} is not a session report of this project (its sessions are under {})",
            report.display(),
            sessions.display()
        )));
    }
    let metadata = std::fs::symlink_metadata(&resolved)
        .map_err(|error| invalid(format!("session report {}: {error}", report.display())))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_REPORT_BYTES {
        return Err(invalid(format!(
            "session report {} is not a regular file of at most {MAX_REPORT_BYTES} bytes",
            report.display()
        )));
    }
    let contents = std::fs::read(&resolved)
        .map_err(|error| invalid(format!("read session report {}: {error}", report.display())))?;
    serde_json::from_slice(&contents)
        .map_err(|error| invalid(format!("session report {}: {error}", report.display())))
}

/// The one finding of `outcome` whose input digest starts with `prefix`.
pub(super) fn finding_in_report<'a>(
    outcome: &'a BinaryFuzzOutcome,
    prefix: &str,
) -> Result<&'a BinaryFinding, ClassifiedError> {
    let prefix = prefix.trim().to_ascii_lowercase();
    if prefix.len() < MIN_FINDING_PREFIX || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "name the finding by at least {MIN_FINDING_PREFIX} hex digits of its input sha256"
        )));
    }
    let mut matching = outcome
        .findings
        .iter()
        .filter(|finding| finding.sha256.starts_with(&prefix));
    let found = matching
        .next()
        .ok_or_else(|| invalid(format!("the session has no finding {prefix}")))?;
    if matching.next().is_some() {
        return Err(invalid(format!(
            "more than one finding starts with {prefix}; give more digits"
        )));
    }
    Ok(found)
}

/// What identifies the bug behind a finding: its stack signature, or its
/// input when the replay printed no report.
fn filing_key(finding: &BinaryFinding) -> String {
    if finding.signature.is_empty() {
        format!("binary-input:{}", finding.sha256)
    } else {
        finding.signature.clone()
    }
}

fn signal_text(signal: Option<u32>) -> String {
    signal.map_or_else(
        || "unknown".to_owned(),
        |signal| format!("{} ({signal})", signal_name(signal)),
    )
}

fn issue_title(outcome: &BinaryFuzzOutcome, finding: &BinaryFinding) -> String {
    let binary = if outcome.binary_name.is_empty() {
        &outcome.binary_sha256[..outcome.binary_sha256.len().min(16)]
    } else {
        outcome.binary_name.as_str()
    };
    let what = if finding.summary.is_empty() {
        format!("crash with {}", signal_text(finding.fuzzer_signal))
    } else {
        finding.summary.clone()
    };
    format!("[oxfuzz] {binary}: {what}")
}

fn issue_description(outcome: &BinaryFuzzOutcome, finding: &BinaryFinding) -> String {
    let mut body = String::from("## Summary\n\n");
    if finding.summary.is_empty() {
        let _ = writeln!(
            body,
            "The binary died with {} on a fuzzer-generated input.",
            signal_text(finding.fuzzer_signal)
        );
    } else {
        let _ = writeln!(body, "{}", finding.summary);
    }
    body.push_str("\n## Fuzzing Context\n\n");
    if !outcome.binary_name.is_empty() {
        let _ = writeln!(body, "- Binary: `{}`", outcome.binary_name);
    }
    let _ = writeln!(body, "- Binary sha256: `{}`", outcome.binary_sha256);
    let _ = writeln!(body, "- Architecture: `{}`", outcome.machine.uname());
    let _ = writeln!(body, "- Engine: AFL++ QEMU mode (binary-only, no source)");
    let delivered = match outcome.input {
        BinaryInput::File => "a file named by the one argument",
        BinaryInput::Stdin => "standard input",
        BinaryInput::Socket => {
            "the byte stream of the first accepted connection, or one datagram on the bound \
             datagram socket"
        }
        BinaryInput::SocketMessages => {
            "a sequence of messages (separated by the bytes FF FE FD FC in the input), each \
             sent after the server read the one before"
        }
    };
    let _ = writeln!(body, "- Input delivered as: {delivered}");
    let _ = writeln!(body, "- Session: `{}`", outcome.session);
    let _ = writeln!(body, "- Signal: `{}`", signal_text(finding.fuzzer_signal));
    if let Some(kind) = finding.kind {
        let _ = writeln!(body, "- Crash kind: `{kind:?}`");
    }
    let replay = if !finding.replayed {
        "not replayed"
    } else if finding.confirmed {
        "reproduced with the same signal"
    } else {
        "did not reproduce the signal"
    };
    let _ = writeln!(body, "- Replay: {replay}");
    let _ = writeln!(
        body,
        "- Input: `{}` ({} bytes)",
        finding.sha256, finding.size
    );
    if let Some(minimized) = &finding.minimized {
        let _ = writeln!(
            body,
            "- Minimized input: `{}` ({} bytes), replayed as the same crash",
            minimized.sha256, minimized.size
        );
    }
    if !finding.signature.is_empty() {
        let _ = writeln!(body, "- Stack signature: `{}`", finding.signature);
    }
    if !finding.frames.is_empty() {
        body.push_str("\n## Stack\n\nModule offsets, innermost first.\n\n```text\n");
        body.push_str(&finding.frames.join("\n"));
        body.push_str("\n```\n");
    }
    // The same hidden marker a triaged crash carries, so a second filing of
    // this bug finds the first.
    let _ = writeln!(
        body,
        "\n<!-- {} -->",
        crate::issue_tracker::dedup_marker(&filing_key(finding))
    );
    body
}

impl ServiceContainer {
    fn binary_finding(
        project: &Path,
        report: &Path,
        finding: &str,
    ) -> Result<(BinaryFuzzOutcome, BinaryFinding), ClassifiedError> {
        let sessions = prepare_configured_workspace_root()?
            .join(PathBuf::from(project_slug(project)))
            .join(".binary");
        let outcome = read_session_report(&sessions, report)?;
        let found = finding_in_report(&outcome, finding)?.clone();
        Ok((outcome, found))
    }

    /// Draft an issue for one finding of a binary-only session, addressed to
    /// the configured tracker. Publishes nothing.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] when `report` is not a
    /// session report of `project` or names no single such finding.
    pub fn binary_issue_export(
        &self,
        project: &Path,
        report: &Path,
        finding: &str,
    ) -> Result<crate::workbench::IssueExport, ClassifiedError> {
        let (outcome, found) = Self::binary_finding(project, report, finding)?;
        Ok(crate::workbench::tracker_export(
            project,
            found.sha256.clone(),
            issue_title(&outcome, &found),
            issue_description(&outcome, &found),
        ))
    }

    /// File one finding of a binary-only session as an issue in the
    /// configured tracker. A finding whose stack signature was already filed
    /// returns that issue.
    ///
    /// # Errors
    /// Returns the approval gate's error when publishing is refused, the
    /// validation errors of [`Self::binary_issue_export`], and the tracker
    /// errors of [`Self::file_issue`].
    pub async fn binary_file_issue(
        &self,
        project: &Path,
        report: &Path,
        finding: &str,
    ) -> Result<crate::issue_tracker::CreatedIssue, ClassifiedError> {
        self.authorize_recorded(
            Action::PublishFindings {
                destination: "issue-tracker".to_owned(),
            },
            "binary_file_issue",
            Some(project),
        )
        .await?;
        let (outcome, found) = Self::binary_finding(project, report, finding)?;
        let store = self
            .store
            .as_deref()
            .ok_or_else(|| ClassifiedError::Storage("no database configured".to_owned()))?;
        let cfg = crate::issue_tracker::load_config()?;
        let token = crate::issue_tracker::resolve_token(&cfg)?;
        let client = crate::issue_tracker::IssueTrackerClient::from_config(&cfg, &token)?;
        let title = issue_title(&outcome, &found);
        let description = issue_description(&outcome, &found);
        let key = filing_key(&found);
        crate::workbench::file_issue_exactly_once(
            store,
            &format!("binary:{key}"),
            || async { client.find_existing_issue(&key).await },
            || async { client.create_issue(&title, &description, &cfg.labels).await },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ElfMachine, MinimizedInput};
    use hf_core::crash::CrashKind;
    use uuid::Uuid;

    fn finding(sha256: &str, signature: &str) -> BinaryFinding {
        BinaryFinding {
            input: PathBuf::from(format!("findings/crash-{sha256}")),
            sha256: sha256.to_owned(),
            size: 34,
            fuzzer_signal: Some(11),
            replay_signal: Some(11),
            replayed: true,
            confirmed: true,
            kind: Some(CrashKind::Segv),
            signature: signature.to_owned(),
            summary: "SEGV (signal 11) at (/work/target+0x89c)".to_owned(),
            frames: vec![
                "#0 0x550000089c (/work/target+0x89c)".to_owned(),
                "#1 0x5500000858 (/work/target+0x858)".to_owned(),
            ],
            duplicate_of: None,
            minimized: Some(MinimizedInput {
                input: PathBuf::from("minimized/crash"),
                sha256: "d4ecd6ef".to_owned(),
                size: 4,
            }),
        }
    }

    fn outcome(findings: Vec<BinaryFinding>) -> BinaryFuzzOutcome {
        BinaryFuzzOutcome {
            session: Uuid::nil(),
            workspace: PathBuf::from("/w"),
            binary_name: "decoder".to_owned(),
            binary_sha256: "ab".repeat(32),
            machine: ElfMachine::Aarch64,
            input: BinaryInput::Socket,
            duration_secs: 60,
            execs_done: None,
            execs_per_sec: None,
            edges_found: None,
            corpus_count: None,
            saved_hangs: None,
            distinct_findings: findings.len(),
            findings,
            findings_omitted: 0,
            started_at: None,
            finished_at: None,
            continued_from: None,
            dictionary_tokens: 0,
            compcov: false,
            stopped: false,
            persistent_entry: None,
            stability_pct: None,
        }
    }

    #[test]
    fn a_finding_is_named_by_a_unique_prefix_of_its_input_digest() {
        let report = outcome(vec![
            finding("e87a3081cfe02e7f", "one"),
            finding("e87a3081aaaaaaaa", "two"),
            finding("0528e25a6f55564a", "three"),
        ]);
        assert_eq!(
            finding_in_report(&report, " 0528E25A ").unwrap().signature,
            "three"
        );
        assert_eq!(
            finding_in_report(&report, "e87a3081c").unwrap().signature,
            "one"
        );
        for (prefix, expected) in [
            ("e87a3081", "more than one finding"),
            ("ffffffff", "no finding"),
            ("0528e2", "at least 8 hex digits"),
            ("../../etc", "at least 8 hex digits"),
        ] {
            let error = finding_in_report(&report, prefix).unwrap_err().to_string();
            assert!(error.contains(expected), "{prefix}: {error}");
        }
    }

    #[test]
    fn the_issue_states_the_fault_the_evidence_and_the_dedup_marker() {
        let report = outcome(vec![finding("e87a3081cfe02e7f", "feedc0de")]);
        let found = &report.findings[0];
        assert_eq!(
            issue_title(&report, found),
            "[oxfuzz] decoder: SEGV (signal 11) at (/work/target+0x89c)"
        );
        let body = issue_description(&report, found);
        for expected in [
            "- Binary: `decoder`",
            "- Architecture: `aarch64`",
            "- Engine: AFL++ QEMU mode",
            "first accepted connection",
            "- Signal: `SIGSEGV (11)`",
            "- Crash kind: `Segv`",
            "- Replay: reproduced with the same signal",
            "- Minimized input: `d4ecd6ef` (4 bytes)",
            "- Stack signature: `feedc0de`",
            "#1 0x5500000858 (/work/target+0x858)",
            "<!-- oxfuzz-signature:feedc0de -->",
        ] {
            assert!(body.contains(expected), "{expected}\n{body}");
        }
        // The operator's paths stay out of a body that leaves the host.
        assert!(!body.contains("/w\n") && !body.contains("findings/crash"));

        // No replay report: the signal is all there is, and the input names
        // the filing so two unsigned findings are never merged.
        let bare = BinaryFinding {
            kind: None,
            signature: String::new(),
            summary: String::new(),
            frames: Vec::new(),
            minimized: None,
            ..finding("0528e25a6f55564a", "")
        };
        assert_eq!(
            issue_title(&report, &bare),
            "[oxfuzz] decoder: crash with SIGSEGV (11)"
        );
        let body = issue_description(&report, &bare);
        assert!(body.contains("<!-- oxfuzz-signature:binary-input:0528e25a6f55564a -->"));
        assert!(!body.contains("## Stack"));
    }

    #[test]
    fn only_a_report_inside_the_projects_sessions_is_read() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join("project-1234/.binary");
        let session = sessions.join("abcd/0001");
        std::fs::create_dir_all(&session).unwrap();
        let report = outcome(vec![finding("e87a3081cfe02e7f", "one")]);
        std::fs::write(
            session.join("report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        let read = read_session_report(&sessions, &session.join("report.json")).unwrap();
        assert_eq!(read.findings[0].sha256, "e87a3081cfe02e7f");

        // The same bytes anywhere else are not a report of this project.
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::copy(session.join("report.json"), elsewhere.join("report.json")).unwrap();
        let error = read_session_report(&sessions, &elsewhere.join("report.json"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("not a session report of this project"),
            "{error}"
        );
        // Nor is a path that climbs out of the sessions directory.
        let climbing = session.join("../../../../elsewhere/report.json");
        assert!(read_session_report(&sessions, &climbing).is_err());

        let other = session.join("notes.json");
        std::fs::write(&other, b"{}").unwrap();
        let error = read_session_report(&sessions, &other)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is not a session report"), "{error}");

        std::fs::write(session.join("report.json"), b"not json").unwrap();
        assert!(read_session_report(&sessions, &session.join("report.json")).is_err());
        let missing = root.path().join("none/.binary");
        let error = read_session_report(&missing, &session.join("report.json"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no binary-only session was recorded"),
            "{error}"
        );
    }
}
