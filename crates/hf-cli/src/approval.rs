//! The CLI's human-in-the-loop approval gate.
//!
//! The environment policy (`EnvApprovalGate`) is binary and process-wide:
//! `HF_AUTO_APPROVE=1` approves every high-risk action, anything else denies
//! them all. On a terminal the CLI can do better: ask the operator per action.
//! [`CliApprovalGate`] keeps the environment contract (the variable still
//! approves without prompting, and piped/headless runs behave exactly like
//! the environment gate) and adds a fail-closed `[y]es/[n]o/[a]lways` prompt
//! when stdin and stderr are both terminals. An `a` answer is remembered per
//! action kind for the rest of the process and is never persisted.
//!
//! The gate only *decides*; enforcement and the persisted audit trail stay in
//! `hf-service` (`Guardrails::authorize` via `authorize_recorded`), exactly as
//! for the environment gate (Engineering Protocol 2.19).

use std::collections::HashSet;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use hf_service::{Action, ApprovalGate, EnvApprovalGate, Guardrails, ServiceContainer};

/// How a single interactive prompt was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptAnswer {
    /// Approve this one request.
    Yes,
    /// Deny this one request.
    No,
    /// Approve, and allow this action kind for the rest of the process.
    Always,
}

impl PromptAnswer {
    /// Parse one answer line. Anything that is not an explicit yes or always --
    /// including `n`, EOF (`None`), and empty or unrecognized input -- denies,
    /// so a confused or closed input stream fails closed.
    fn parse(line: Option<&str>) -> Self {
        match line.map(|raw| raw.trim().to_ascii_lowercase()).as_deref() {
            Some("y" | "yes") => Self::Yes,
            Some("a" | "always") => Self::Always,
            _ => Self::No,
        }
    }
}

/// Recover a poisoned lock: a prompt that panicked mid-write must not wedge
/// the gate for every later action.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One interactive prompt channel: the question writer and the answer reader.
/// Production wires stderr/stdin; tests drive scripted answers and capture the
/// transcript.
struct PromptChannel {
    writer: Mutex<Box<dyn Write + Send>>,
    reader: Mutex<Box<dyn BufRead + Send>>,
}

impl PromptChannel {
    /// Show `question`, read one answer line. A stream that cannot be written
    /// or read denies: a gate that cannot ask must not grant.
    fn ask(&self, question: &str) -> PromptAnswer {
        {
            let mut writer = lock(&self.writer);
            if write!(writer, "{question}")
                .and_then(|()| writer.flush())
                .is_err()
            {
                return PromptAnswer::No;
            }
        }
        let mut line = String::new();
        match lock(&self.reader).read_line(&mut line) {
            Ok(_) => PromptAnswer::parse(Some(&line)),
            Err(_) => PromptAnswer::parse(None),
        }
    }

    /// Echo the resolved decision so the terminal transcript shows it (the
    /// tracing subscriber filters to errors unless `RUST_LOG` asks for more,
    /// so the log line alone would not). A transcript echo that fails to write
    /// is lost, not fatal: the decision was already made and logged.
    fn echo(&self, line: &str) {
        let _ = writeln!(lock(&self.writer), "{line}");
    }
}

/// The one-line question: the policy/advisor reason, which names the action,
/// plus the action's human-readable label when the reason does not already
/// carry it (advisor reasons describe the requester, not the action).
fn prompt_question(action: &Action, reason: &str) -> String {
    let label = action.label();
    if reason.contains(&label) {
        format!("[approval] {reason} [y]es/[n]o/[a]lways: ")
    } else {
        format!("[approval] {label} -- {reason} [y]es/[n]o/[a]lways: ")
    }
}

/// The CLI's approval gate: an interactive terminal prompt when stdin and
/// stderr are both terminals, the environment policy everywhere else.
/// `HF_AUTO_APPROVE=1` approves without prompting in both modes.
pub(crate) struct CliApprovalGate {
    env: EnvApprovalGate,
    prompt: Option<Arc<PromptChannel>>,
    always_allowed: Arc<Mutex<HashSet<&'static str>>>,
}

impl CliApprovalGate {
    /// Detect the terminal: prompt only when both stdin (answers) and stderr
    /// (the question) are terminals. Anything piped or headless falls back to
    /// the environment policy, which never blocks on input.
    pub(crate) fn detect() -> Self {
        let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        Self::new(interactive.then(|| PromptChannel {
            writer: Mutex::new(Box::new(std::io::stderr())),
            reader: Mutex::new(Box::new(BufReader::new(std::io::stdin()))),
        }))
    }

    fn new(prompt: Option<PromptChannel>) -> Self {
        Self {
            env: EnvApprovalGate,
            prompt: prompt.map(Arc::new),
            always_allowed: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn echo(&self, line: &str) {
        if let Some(prompt) = &self.prompt {
            prompt.echo(line);
        }
    }
}

#[async_trait]
impl ApprovalGate for CliApprovalGate {
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        let kind = action.kind();
        // An operator who answered "always" for this kind is not asked again
        // in this process.
        if lock(&self.always_allowed).contains(kind) {
            tracing::warn!(action = %action.label(), reason, "guardrail approved via session 'always' choice");
            self.echo(&format!(
                "[approval] approved ('{kind}' was always-allowed this session): {}",
                action.label()
            ));
            return true;
        }
        // HF_AUTO_APPROVE keeps its unattended meaning: approve without ever
        // prompting, on a terminal or not.
        if EnvApprovalGate::auto_approve_enabled() {
            return self.env.request_approval(action, reason).await;
        }
        let Some(prompt) = &self.prompt else {
            // No terminal: exactly the environment policy's deny-with-guidance.
            return self.env.request_approval(action, reason).await;
        };
        let question = prompt_question(action, reason);
        let channel = Arc::clone(prompt);
        // The read blocks on a human; keep it off the async workers.
        let answer = match tokio::task::spawn_blocking(move || channel.ask(&question)).await {
            Ok(answer) => answer,
            Err(error) => {
                // A panicked prompt task denies: the question was never answered.
                tracing::warn!(%error, "approval prompt task failed; denying");
                PromptAnswer::No
            }
        };
        match answer {
            PromptAnswer::Yes => {
                tracing::warn!(action = %action.label(), reason, "guardrail approved via terminal prompt");
                self.echo(&format!("[approval] approved: {}", action.label()));
                true
            }
            PromptAnswer::Always => {
                lock(&self.always_allowed).insert(kind);
                tracing::warn!(action = %action.label(), kind, reason, "guardrail approved via terminal prompt; kind always-allowed for this session");
                self.echo(&format!(
                    "[approval] approved ('{kind}' always-allowed for this session): {}",
                    action.label()
                ));
                true
            }
            PromptAnswer::No => {
                tracing::warn!(action = %action.label(), reason, "guardrail denied via terminal prompt");
                self.echo(&format!("[approval] denied: {}", action.label()));
                false
            }
        }
    }
}

/// The CLI's default guardrails: the environment-driven selection
/// (`HF_GUARDRAILS=permissive` still opts into auto-approve-with-audit), with
/// the default policy's approval gate replaced by [`CliApprovalGate`].
pub(crate) fn cli_guardrails() -> Guardrails {
    Guardrails::from_env_with_gate(Arc::new(CliApprovalGate::detect()))
}

/// Bootstrap the canonical service container with the CLI's approval gate
/// installed. Every CLI command builds its container here so no command path
/// can forget the gate swap.
pub(crate) async fn bootstrap() -> ServiceContainer {
    ServiceContainer::bootstrap()
        .await
        .with_guardrails(cli_guardrails())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// Serializes the gate tests: they mutate the process-wide
    /// `HF_AUTO_APPROVE` variable, and Rust runs them on shared threads.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A writer that appends into a shared capture buffer.
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            lock(&self.0).write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A gate whose prompt channel reads `scripted_input` and captures every
    /// written byte; the returned handle inspects the transcript.
    fn scripted_gate(scripted_input: &'static [u8]) -> (CliApprovalGate, Arc<Mutex<Vec<u8>>>) {
        let output = Arc::new(Mutex::new(Vec::new()));
        let channel = PromptChannel {
            writer: Mutex::new(Box::new(SharedWriter(Arc::clone(&output)))),
            reader: Mutex::new(Box::new(Cursor::new(scripted_input))),
        };
        (CliApprovalGate::new(Some(channel)), output)
    }

    fn transcript(output: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(lock(output).clone()).expect("transcript is utf-8")
    }

    fn run_fuzzer() -> Action {
        Action::RunFuzzer {
            engine: "libfuzzer".to_owned(),
            duration_secs: 60,
        }
    }

    #[test]
    fn answers_parse_fail_closed() {
        assert_eq!(PromptAnswer::parse(Some("y")), PromptAnswer::Yes);
        assert_eq!(PromptAnswer::parse(Some("Y")), PromptAnswer::Yes);
        assert_eq!(PromptAnswer::parse(Some(" yes \n")), PromptAnswer::Yes);
        assert_eq!(PromptAnswer::parse(Some("a")), PromptAnswer::Always);
        assert_eq!(PromptAnswer::parse(Some("ALWAYS")), PromptAnswer::Always);
        for denied in [
            Some("n"),
            Some("no"),
            Some(""),
            Some("maybe"),
            Some("yes please"),
            None,
        ] {
            assert_eq!(
                PromptAnswer::parse(denied),
                PromptAnswer::No,
                "input {denied:?} must deny"
            );
        }
    }

    #[tokio::test]
    async fn yes_approves_once_and_the_next_request_asks_again() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("HF_AUTO_APPROVE");
        let (gate, output) = scripted_gate(b"y\ny\n");

        assert!(gate.request_approval(&run_fuzzer(), "test").await);
        assert!(gate.request_approval(&run_fuzzer(), "test").await);

        let transcript = transcript(&output);
        assert_eq!(
            transcript.matches("[y]es/[n]o/[a]lways").count(),
            2,
            "each 'y' covers exactly one request: {transcript}"
        );
        assert!(transcript.contains("[approval] approved: run libfuzzer for 60s"));
    }

    #[tokio::test]
    async fn no_denies_and_the_transcript_shows_it() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("HF_AUTO_APPROVE");
        let (gate, output) = scripted_gate(b"n\n");

        assert!(!gate.request_approval(&run_fuzzer(), "test").await);

        let transcript = transcript(&output);
        assert!(transcript.contains("[approval] denied: run libfuzzer for 60s"));
    }

    #[tokio::test]
    async fn always_approves_the_kind_for_the_rest_of_the_process() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("HF_AUTO_APPROVE");
        // One answer only: a second prompt would read EOF and deny.
        let (gate, output) = scripted_gate(b"a\n");

        assert!(gate.request_approval(&run_fuzzer(), "test").await);
        assert!(gate.request_approval(&run_fuzzer(), "test").await);

        let transcript = transcript(&output);
        assert_eq!(
            transcript.matches("[y]es/[n]o/[a]lways").count(),
            1,
            "the second request must not prompt again: {transcript}"
        );
        assert!(transcript.contains("'run_fuzzer' always-allowed for this session"));
        assert!(transcript.contains("'run_fuzzer' was always-allowed this session"));
    }

    #[tokio::test]
    async fn always_is_scoped_to_the_action_kind() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("HF_AUTO_APPROVE");
        let (gate, _output) = scripted_gate(b"a\nn\n");

        assert!(gate.request_approval(&Action::RunHarness, "test").await);
        // Always-allowing run_harness says nothing about promote_harness: the
        // second request prompts again and the scripted "n" denies it.
        assert!(!gate.request_approval(&Action::PromoteHarness, "test").await);
        // And the original kind is still remembered.
        assert!(gate.request_approval(&Action::RunHarness, "test").await);
    }

    #[tokio::test]
    async fn eof_empty_and_garbage_input_deny() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("HF_AUTO_APPROVE");
        for input in [&b""[..], &b"\n"[..], &b"maybe\n"[..]] {
            let (gate, _output) = scripted_gate(input);
            assert!(
                !gate.request_approval(&run_fuzzer(), "test").await,
                "input {input:?} must deny"
            );
        }
    }

    #[tokio::test]
    async fn hf_auto_approve_approves_without_prompting_on_a_terminal() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var("HF_AUTO_APPROVE", "1");
        // EOF if the gate did prompt, so an approval proves it did not.
        let (gate, output) = scripted_gate(b"");

        assert!(gate.request_approval(&run_fuzzer(), "test").await);
        assert!(
            transcript(&output).is_empty(),
            "HF_AUTO_APPROVE=1 must not prompt"
        );

        std::env::remove_var("HF_AUTO_APPROVE");
    }

    #[tokio::test]
    async fn without_a_terminal_the_env_policy_decides_and_nothing_is_written() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("HF_AUTO_APPROVE");
        let gate = CliApprovalGate::new(None);

        assert!(!gate.request_approval(&run_fuzzer(), "test").await);
    }

    #[test]
    fn cli_guardrails_uses_the_default_policy() {
        // The `HF_GUARDRAILS=permissive` composition is covered end-to-end by
        // the binary-level approval tests (a unit test would have to mutate the
        // process-wide variable, which the presentation-boundary checks forbid
        // in hf-cli sources).
        std::env::remove_var("HF_GUARDRAILS");
        let default = cli_guardrails();
        assert_eq!(
            default.policy().auto_allow_max,
            hf_service::RiskTier::Medium
        );
        assert_eq!(
            default.policy().deny_at,
            Some(hf_service::RiskTier::Critical)
        );
    }

    #[test]
    fn the_question_names_the_action_once() {
        // The policy reason embeds the label; printing both would name the
        // action twice on one line.
        let question = prompt_question(
            &run_fuzzer(),
            "High-risk action 'run libfuzzer for 60s' requires approval",
        );
        assert_eq!(
            question,
            "[approval] High-risk action 'run libfuzzer for 60s' requires approval [y]es/[n]o/[a]lways: "
        );

        // An advisor reason that does not name the action gets the label.
        let question = prompt_question(
            &Action::AgentTool {
                name: "fs_write".to_owned(),
            },
            "agent 'worker' runs with manual autonomy and requests tool 'fs_write'",
        );
        assert!(question.starts_with("[approval] agent tool: fs_write -- agent 'worker'"));
        assert!(question.ends_with("[y]es/[n]o/[a]lways: "));
    }
}
