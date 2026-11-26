//! Binary-only fuzzing: fuzz an operator-supplied, uninstrumented Linux ELF
//! with AFL++ QEMU mode.
//!
//! See `docs/design/binary-only-fuzzing-design.md`. There is no source, so
//! there is no harness to draft, review, or compile: the operator names the
//! binary and how it takes input (a file argument or stdin), and the whole
//! session -- the fuzz run and every replay -- happens in the sandbox. The
//! binary is untrusted like any harness binary; it is copied into a
//! session-owned workspace, mounted read-only, and never executed on the
//! host.
//!
//! The session stands beside the harness lifecycle rather than inside it:
//! its findings are written to the session directory and reported, not
//! stored as triaged crashes. Each replayed finding is signed from a crash
//! report a preload library prints, findings with one signature are grouped,
//! and each distinct finding is minimized with `afl-tmin` in QEMU mode.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use hf_core::crash::CrashKind;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandTermination, ResourceLimits, RuntimeAdapter, SandboxMount, SandboxOptions,
};
use hf_core::target::Sanitizer;
use hf_guardrails::Action;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::harness::sha256_hex;
use super::project_identity::project_slug;
use super::workspace::{ensure_workspace_directory, prepare_configured_workspace_root};
use super::ServiceContainer;

/// Largest target binary accepted.
pub const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
/// Longest fuzz session, in seconds.
pub const MAX_DURATION_SECS: u64 = 24 * 60 * 60;
/// Most seed files copied into a session.
const MAX_SEEDS: usize = 10_000;
/// Most shared objects staged beside the target.
const MAX_LIBRARIES: usize = 256;
/// Most crash files read from one session.
const MAX_FINDINGS: usize = 500;
/// Most findings replayed for confirmation.
const MAX_REPLAYS: usize = 50;
/// Bytes of one crash input kept.
const MAX_FINDING_BYTES: u64 = 16 * 1024 * 1024;
/// Per-file write ceiling in the session sandbox.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const SESSION_MEMORY_MB: u64 = 4096;
const REPLAY_SECS: u64 = 30;
/// Wall-clock slack past the fuzz budget for AFL++ start-up and shutdown.
const SHUTDOWN_GRACE_SECS: u64 = 90;

const TARGET_NAME: &str = "target";
const LIBRARY_DIR: &str = "libs";
const CORPUS_DIR: &str = "corpus";
const OUTPUT_DIR: &str = "out";
const FINDINGS_DIR: &str = "findings";
pub(super) const REPORT_NAME: &str = "report.json";
const DESOCK_DIR: &str = "desock";
const DESOCK_SOURCE_NAME: &str = "oxfuzz_desock.c";
const DESOCK_LIBRARY_NAME: &str = "oxfuzz_desock.so";
const MESSAGE_DICTIONARY_NAME: &str = "messages.dict";
/// The operator's dictionary, from `BinaryFuzzRequest::dictionary`.
const DICTIONARY_NAME: &str = "dictionary.dict";
/// Name prefix of corpus entries carried over from an earlier session.
const CARRIED_PREFIX: &str = "carried-";
/// What tells the socket shim to split the input into messages.
const DESOCK_MESSAGES_ENV: &str = "OXFUZZ_DESOCK_MESSAGES=1";
/// The preload shim a socket session compiles in the sandbox.
const DESOCK_SOURCE: &str = include_str!("binary_desock.c");
const SHIM_BUILD_SECS: u64 = 120;
const CRASHINFO_DIR: &str = "crashinfo";
const CRASHINFO_SOURCE_NAME: &str = "oxfuzz_crashinfo.c";
const CRASHINFO_LIBRARY_NAME: &str = "oxfuzz_crashinfo.so";
/// The replay crash reporter, compiled in the sandbox for each session.
const CRASHINFO_SOURCE: &str = include_str!("binary_crashinfo.c");
/// What the reporter writes at the start of its report and of its summary.
const CRASHINFO_ERROR_MARK: &str = "==ERROR: oxfuzz-crashinfo: ";
const CRASHINFO_SUMMARY_MARK: &str = "SUMMARY: oxfuzz-crashinfo: ";
/// Largest replay report read, and the most frames kept from it.
const MAX_REPORT_BYTES: usize = 64 * 1024;
const MAX_REPORT_FRAMES: usize = 16;
const MINIMIZED_DIR: &str = "minimized";
/// Distinct findings minimized per session, and the time each may take.
const MAX_MINIMIZED: usize = 10;
const MINIMIZE_SECS: u64 = 120;
/// Replays the message pass after `afl-tmin` may spend on one finding.
const MAX_MESSAGE_TRIALS: usize = 12;
/// The seed used when the operator supplies none: AFL++ needs one input.
const DEFAULT_SEED: &[u8] = b"0";

fn invalid(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(message.into())
}

/// How the target reads its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryInput {
    /// The input file path is the target's one argument (`target @@`).
    File,
    /// The input is the target's standard input.
    Stdin,
    /// The target is a server: the input is the byte stream of the first
    /// connection it accepts on a stream socket, or one datagram on the
    /// datagram socket it binds, delivered by a preload shim that the fuzzer
    /// feeds through standard input.
    Socket,
    /// A server target whose input is a sequence of messages separated by
    /// [`MESSAGE_SEPARATOR`]. The shim sends each message only after the
    /// server has read the one before: one message per read on a stream
    /// connection, one datagram per message on a datagram socket.
    SocketMessages,
}

impl BinaryInput {
    /// Whether the input reaches the target through the socket shim.
    #[must_use]
    pub const fn is_socket(self) -> bool {
        matches!(self, Self::Socket | Self::SocketMessages)
    }
}

/// The bytes that separate two messages of a [`BinaryInput::SocketMessages`]
/// input. The socket shim's source states the same bytes.
pub const MESSAGE_SEPARATOR: [u8; 4] = [0xff, 0xfe, 0xfd, 0xfc];

/// The AFL++ dictionary that teaches the fuzzer the message separator, so
/// mutation can add, move and remove whole messages.
fn message_dictionary() -> String {
    let mut token = String::new();
    for byte in MESSAGE_SEPARATOR {
        let _ = write!(token, "\\x{byte:02x}");
    }
    format!("separator=\"{token}\"\n")
}

/// The CPU an ELF image is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfMachine {
    Aarch64,
    X86_64,
}

impl ElfMachine {
    /// The name `uname -m` prints for this machine.
    #[must_use]
    pub const fn uname(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::X86_64 => "x86_64",
        }
    }

    fn from_uname(name: &str) -> Option<Self> {
        match name.trim() {
            "aarch64" | "arm64" => Some(Self::Aarch64),
            "x86_64" | "amd64" => Some(Self::X86_64),
            _ => None,
        }
    }
}

/// Read the machine of a 64-bit little-endian Linux executable from its ELF
/// header. Total over arbitrary bytes.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] naming the first reason the bytes
/// are not a binary this mode can run.
pub fn elf_machine(image: &[u8]) -> Result<ElfMachine, ClassifiedError> {
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const EM_X86_64: u16 = 62;
    const EM_AARCH64: u16 = 183;
    if !image.starts_with(b"\x7fELF") {
        return Err(invalid(
            "the file is not an ELF binary (binary-only fuzzing runs Linux executables)",
        ));
    }
    let header = image
        .get(..20)
        .ok_or_else(|| invalid("the file is too short to be an ELF binary"))?;
    if header[4] != 2 {
        return Err(invalid("only 64-bit ELF binaries are supported"));
    }
    if header[5] != 1 {
        return Err(invalid("only little-endian ELF binaries are supported"));
    }
    let kind = u16::from_le_bytes([header[16], header[17]]);
    if kind != ET_EXEC && kind != ET_DYN {
        return Err(invalid(
            "the ELF file is not an executable (relocatable objects and core files cannot run)",
        ));
    }
    match u16::from_le_bytes([header[18], header[19]]) {
        EM_X86_64 => Ok(ElfMachine::X86_64),
        EM_AARCH64 => Ok(ElfMachine::Aarch64),
        other => Err(invalid(format!(
            "ELF machine {other} is not supported (x86_64 and aarch64 only)"
        ))),
    }
}

/// What a Windows drive mounted into a WSL 2 container engine stores in
/// place of a colon, which a Windows file name cannot hold. The fuzzer writes
/// `id:000000,sig:11` in the container; the host then lists the file with
/// this character where each colon was.
const WINDOWS_MOUNT_COLON: char = '\u{f03a}';

/// An AFL++ output file name as the fuzzer wrote it, whichever host lists it.
fn fuzzer_file_name(name: &str) -> String {
    name.replace(WINDOWS_MOUNT_COLON, ":")
}

/// The signal AFL++ recorded in a crash file name (`id:000000,sig:11,...`).
#[must_use]
pub fn crash_file_signal(name: &str) -> Option<u32> {
    fuzzer_file_name(name)
        .split(',')
        .find_map(|field| field.strip_prefix("sig:"))
        .and_then(|value| value.parse().ok())
        .filter(|signal| (1..=64).contains(signal))
}

/// The signal a replay died from, read from its exit status: a process
/// killed by signal N exits the sandbox with 128 + N.
#[must_use]
pub fn exit_signal(exit_code: i32) -> Option<u32> {
    u32::try_from(exit_code)
        .ok()
        .filter(|code| (129..=192).contains(code))
        .map(|code| code - 128)
}

/// The conventional name of a Linux signal number, for the common fatal ones.
#[must_use]
pub const fn signal_name(signal: u32) -> &'static str {
    match signal {
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        31 => "SIGSYS",
        _ => "signal",
    }
}

/// The AFL++ QEMU-mode command for one session: the AFL++ adapter's own
/// single-instance argv with `-Q`, and without the `@@` placeholder when the
/// target reads standard input.
///
/// # Errors
/// Returns the adapter's validation errors.
pub fn fuzz_command(
    input: BinaryInput,
    duration_secs: u64,
    timeout_ms: u64,
    dictionary: bool,
) -> Result<Vec<String>, ClassifiedError> {
    let mut extra_args = vec!["-Q".to_owned()];
    if input == BinaryInput::SocketMessages {
        extra_args.extend([
            "-x".to_owned(),
            format!("/work/{DESOCK_DIR}/{MESSAGE_DICTIONARY_NAME}"),
        ]);
    }
    // AFL++ takes up to four `-x` dictionaries; the operator's is the second.
    if dictionary {
        extra_args.extend(["-x".to_owned(), format!("/work/{DICTIONARY_NAME}")]);
    }
    let config = FuzzRunConfig {
        harness_id: Uuid::nil(),
        engine: EngineKind::AflPlusPlus,
        duration: Some(Duration::from_secs(duration_secs)),
        max_mem_mb: SESSION_MEMORY_MB,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: Sanitizer::None,
        env: Vec::new(),
        extra_args,
        seed: None,
        replay_of: None,
        input_manifest_sha256: None,
        input_timeout: Some(Duration::from_millis(timeout_ms)),
        resume: false,
        cmplog: false,
    };
    let mut command = hf_engine::afl::build_run_args(
        &config,
        &format!("/work/{TARGET_NAME}"),
        &format!("/work/{CORPUS_DIR}"),
        &format!("/work/{OUTPUT_DIR}"),
    )?;
    if input != BinaryInput::File && command.last().is_some_and(|last| last == "@@") {
        command.pop();
    }
    Ok(command)
}

/// The replay runs the emulator as a child of a shell. The emulator reports
/// a guest signal by raising it on itself, and the first process of a
/// container ignores a signal it raises with the default action: run
/// directly, a crashing replay would wait forever instead of dying. The
/// trailing `exit` keeps the shell from replacing itself with the emulator.
const REPLAY_SCRIPT: &str = "afl-qemu-trace \"$@\"; exit $?";

/// A preload library oxfuzz ships as source and compiles in the sandbox, for
/// the image's own architecture.
struct Shim {
    what: &'static str,
    directory: &'static str,
    source_name: &'static str,
    library_name: &'static str,
    source: &'static str,
    threads: bool,
}

const DESOCK: Shim = Shim {
    what: "socket shim",
    directory: DESOCK_DIR,
    source_name: DESOCK_SOURCE_NAME,
    library_name: DESOCK_LIBRARY_NAME,
    source: DESOCK_SOURCE,
    threads: true,
};

const CRASHINFO: Shim = Shim {
    what: "crash reporter",
    directory: CRASHINFO_DIR,
    source_name: CRASHINFO_SOURCE_NAME,
    library_name: CRASHINFO_LIBRARY_NAME,
    source: CRASHINFO_SOURCE,
    threads: false,
};

impl Shim {
    fn library(&self) -> String {
        format!("/work/{}/{}", self.directory, self.library_name)
    }

    fn build_command(&self) -> Vec<String> {
        let mut command: Vec<String> = ["clang", "-O2", "-fPIC", "-shared"]
            .map(str::to_owned)
            .to_vec();
        if self.threads {
            command.push("-pthread".to_owned());
        }
        command.extend([
            "-o".to_owned(),
            self.library(),
            format!("/work/{}/{}", self.directory, self.source_name),
            "-ldl".to_owned(),
        ]);
        command
    }

    fn stage(&self, root: &Path) -> Result<(), ClassifiedError> {
        let directory = ensure_workspace_directory(root, Path::new(self.directory))?;
        write_new(
            &directory.join(self.source_name),
            self.source.as_bytes(),
            false,
        )
    }
}

/// The messages of a message-sequence input: the bytes between separators,
/// empty ones included. An input without a separator is one message.
fn split_messages(data: &[u8]) -> Vec<&[u8]> {
    let mut messages = Vec::new();
    let mut rest = data;
    while let Some(at) = rest
        .windows(MESSAGE_SEPARATOR.len())
        .position(|window| window == MESSAGE_SEPARATOR)
    {
        messages.push(&rest[..at]);
        rest = &rest[at + MESSAGE_SEPARATOR.len()..];
    }
    messages.push(rest);
    messages
}

/// The same messages without the empty ones, so without doubled, leading
/// or trailing separators.
fn without_empty_messages(data: &[u8]) -> Vec<u8> {
    let messages: Vec<&[u8]> = split_messages(data)
        .into_iter()
        .filter(|message| !message.is_empty())
        .collect();
    messages.join(MESSAGE_SEPARATOR.as_slice())
}

/// The same messages without the one at `index`.
fn without_message(data: &[u8], index: usize) -> Vec<u8> {
    let mut messages = split_messages(data);
    messages.remove(index);
    messages.join(MESSAGE_SEPARATOR.as_slice())
}

/// The command that shrinks one saved finding with `afl-tmin` under the
/// emulator the fuzzer used. The minimizer keeps an input only while it
/// still crashes; whether it is still the same crash is checked by a replay.
#[must_use]
pub fn minimize_command(input: BinaryInput, finding_name: &str, timeout_ms: u64) -> Vec<String> {
    let mut command = vec![
        "afl-tmin".to_owned(),
        "-Q".to_owned(),
        "-i".to_owned(),
        format!("/work/{FINDINGS_DIR}/{finding_name}"),
        "-o".to_owned(),
        format!("/work/{MINIMIZED_DIR}/{finding_name}"),
        "-m".to_owned(),
        "none".to_owned(),
        "-t".to_owned(),
        timeout_ms.to_string(),
        "--".to_owned(),
        format!("/work/{TARGET_NAME}"),
    ];
    if input == BinaryInput::File {
        command.push("@@".to_owned());
    }
    command
}

/// The command that replays one saved input under the same emulator the
/// fuzzer used. `saved` is the input's path inside the session directory
/// (`findings/<name>` or `minimized/<name>`). A stdin or socket target takes
/// the input through the sandbox's stdin.
/// A replay killed by signal N exits 128 + N.
#[must_use]
pub fn replay_command(input: BinaryInput, saved: &str) -> Vec<String> {
    let mut command = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        REPLAY_SCRIPT.to_owned(),
        "sh".to_owned(),
        format!("/work/{TARGET_NAME}"),
    ];
    if input == BinaryInput::File {
        command.push(format!("/work/{saved}"));
    }
    command
}

/// One request to fuzz a binary.
#[derive(Debug, Clone)]
pub struct BinaryFuzzRequest {
    /// The project directory the session belongs to (approval scope and
    /// workspace location).
    pub project: PathBuf,
    /// The ELF executable to fuzz.
    pub binary: PathBuf,
    pub input: BinaryInput,
    /// A flat directory of seed inputs; one default seed when absent.
    pub seeds: Option<PathBuf>,
    /// A flat directory of shared objects the target loads.
    pub libraries: Option<PathBuf>,
    pub duration_secs: u64,
    /// Per-input timeout in milliseconds.
    pub timeout_ms: u64,
    /// AFL++ dictionary tokens in escaped form (as `binary_inspect` returns
    /// them), staged as `dictionary.dict` and passed with `-x`. Empty: none.
    pub dictionary: Vec<String>,
    /// An earlier session of the same binary in this project whose queue
    /// seeds this session's corpus, so its coverage carries over.
    pub continue_from: Option<Uuid>,
    /// Split multi-byte comparisons in the emulator (`AFL_COMPCOV_LEVEL=2`)
    /// so AFL++ can solve magic values byte by byte. Fuzz run only.
    pub compcov: bool,
    /// Loop on one function instead of starting a process per input. File
    /// input only; fuzz run only.
    pub persistent: Option<BinaryPersistent>,
}

/// Persistent QEMU mode: the emulator loops on `entry` for `iterations`
/// inputs per process, restoring registers (and memory, when asked).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryPersistent {
    /// A defined function name, or a module offset such as `0x9d8`.
    pub entry: String,
    /// Inputs per process, at most [`MAX_PERSISTENT_ITERATIONS`].
    pub iterations: u32,
    /// Also restore writable memory each iteration: slower, no state leaks.
    pub restore_memory: bool,
}

/// Most persistent iterations per process.
pub const MAX_PERSISTENT_ITERATIONS: u32 = 100_000;
/// Where `afl-qemu-trace` loads a position-independent executable.
const QEMU_PIE_BASE_AARCH64: u64 = 0x55_0000_0000;
const QEMU_PIE_BASE_X86_64: u64 = 0x40_0000_0000;

/// A persistent entry resolved to the emulator's address.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPersistent {
    address: u64,
    /// The entry as the report states it, e.g. `main (target+0x9d8)`.
    label: String,
    iterations: u32,
    restore_memory: bool,
}

/// Refuse persistent settings the session cannot honor.
fn check_persistent(
    input: BinaryInput,
    persistent: &BinaryPersistent,
) -> Result<(), ClassifiedError> {
    if input != BinaryInput::File {
        return Err(invalid(
            "persistent mode needs file input: standard input cannot be rewound between \
             iterations, and the socket modes already loop through their shim",
        ));
    }
    if persistent.iterations == 0 || persistent.iterations > MAX_PERSISTENT_ITERATIONS {
        return Err(invalid(format!(
            "persistent iterations must be between 1 and {MAX_PERSISTENT_ITERATIONS}"
        )));
    }
    Ok(())
}

/// The link-time address of a persistent entry (a function name or a module
/// offset), with the label the report uses.
fn entry_address(
    functions: &[(String, u64)],
    load_base: u64,
    entry: &str,
) -> Result<(u64, String), ClassifiedError> {
    let entry = entry.trim();
    if let Some(hex) = entry.strip_prefix("0x") {
        let offset = u64::from_str_radix(hex, 16)
            .map_err(|_| invalid(format!("{entry} is not a hex module offset")))?;
        return Ok((
            load_base.saturating_add(offset),
            format!("target+0x{offset:x}"),
        ));
    }
    if let Some((_, address)) = functions.iter().find(|(name, _)| name == entry) {
        let offset = address.saturating_sub(load_base);
        return Ok((*address, format!("{entry} (target+0x{offset:x})")));
    }
    let known: Vec<&str> = functions
        .iter()
        .take(8)
        .map(|(name, _)| name.as_str())
        .collect();
    Err(invalid(format!(
        "the binary has no function {entry}; name a defined function ({}) or a module offset like 0x9d8",
        if known.is_empty() { "none are in its symbol tables".to_owned() } else { known.join(", ") }
    )))
}

/// The address the emulator runs a link-time address at.
fn persistent_address(pie: bool, machine: ElfMachine, load_base: u64, address: u64) -> u64 {
    if !pie {
        return address;
    }
    let base = match machine {
        ElfMachine::Aarch64 => QEMU_PIE_BASE_AARCH64,
        ElfMachine::X86_64 => QEMU_PIE_BASE_X86_64,
    };
    base.saturating_add(address.saturating_sub(load_base))
}

fn resolve_persistent(
    image: &[u8],
    machine: ElfMachine,
    input: BinaryInput,
    persistent: &BinaryPersistent,
) -> Result<ResolvedPersistent, ClassifiedError> {
    check_persistent(input, persistent)?;
    let functions = super::binary_profile::function_symbols(image)?;
    let load_base = super::binary_profile::load_base(image)?;
    let (address, label) = entry_address(&functions, load_base, &persistent.entry)?;
    let pie = super::binary_profile::is_position_independent(image)?;
    Ok(ResolvedPersistent {
        address: persistent_address(pie, machine, load_base, address),
        label,
        iterations: persistent.iterations,
        restore_memory: persistent.restore_memory,
    })
}

/// A finding's input after minimization, replayed and found to be the same
/// crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizedInput {
    /// The minimized input, under the session's `minimized` directory.
    pub input: PathBuf,
    pub sha256: String,
    pub size: u64,
}

/// One crashing input a session kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryFinding {
    /// The saved input, under the session's `findings` directory.
    pub input: PathBuf,
    pub sha256: String,
    pub size: u64,
    /// The signal AFL++ recorded when it saved the input.
    pub fuzzer_signal: Option<u32>,
    /// The signal the replay died from; `None` when the replay did not die
    /// from a signal or was not attempted.
    pub replay_signal: Option<u32>,
    /// Whether the replay was run at all (replays are capped per session).
    pub replayed: bool,
    /// Whether the replay died from the signal the fuzzer recorded.
    pub confirmed: bool,
    /// The crash class the replay report names; `None` when the replay
    /// printed no report (a statically linked target, a target with its own
    /// signal handlers, or a finding that was not replayed).
    #[serde(default)]
    pub kind: Option<CrashKind>,
    /// Stack signature of the replay report: the crash class and the top
    /// frames as module offsets. Empty when there is no report.
    #[serde(default)]
    pub signature: String,
    /// Where the fault was, as the replay report states it.
    #[serde(default)]
    pub summary: String,
    /// The report's stack frames, innermost first.
    #[serde(default)]
    pub frames: Vec<String>,
    /// The `sha256` of the earlier finding with the same signature.
    #[serde(default)]
    pub duplicate_of: Option<String>,
    /// The minimized input, when the finding was minimized and the result
    /// replayed as the same crash.
    #[serde(default)]
    pub minimized: Option<MinimizedInput>,
}

/// What a binary-only session did and found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryFuzzOutcome {
    pub session: Uuid,
    /// The session directory holding `findings/` and `report.json`.
    pub workspace: PathBuf,
    /// The file name the binary was given as; a label, never a path.
    #[serde(default)]
    pub binary_name: String,
    pub binary_sha256: String,
    pub machine: ElfMachine,
    pub input: BinaryInput,
    pub duration_secs: u64,
    pub execs_done: Option<u64>,
    pub execs_per_sec: Option<f64>,
    pub edges_found: Option<u64>,
    pub corpus_count: Option<u64>,
    pub saved_hangs: Option<u64>,
    pub findings: Vec<BinaryFinding>,
    /// Findings that are not a duplicate of an earlier one.
    #[serde(default)]
    pub distinct_findings: usize,
    /// Crash files AFL++ saved beyond the per-session cap, not read.
    pub findings_omitted: usize,
    /// When the session started and finished; absent in reports written
    /// before 2026-11-26.
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub finished_at: Option<DateTime<Utc>>,
    /// The earlier session whose queue seeded this one.
    #[serde(default)]
    pub continued_from: Option<Uuid>,
    /// Tokens in the operator's dictionary; zero when none was used.
    #[serde(default)]
    pub dictionary_tokens: usize,
    /// Whether the emulator split comparisons (`CompCov`) during the fuzz run.
    #[serde(default)]
    pub compcov: bool,
    /// Whether the operator stopped the fuzz run before its duration ended.
    #[serde(default)]
    pub stopped: bool,
    /// The persistent-mode entry, e.g. `main (target+0x9d8)`, when used.
    #[serde(default)]
    pub persistent_entry: Option<String>,
    /// AFL++'s bitmap stability, in percent; below about 90 a persistent
    /// entry leaks state between iterations.
    #[serde(default)]
    pub stability_pct: Option<f64>,
}

/// Where a running session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryStage {
    /// Staging inputs and building the preload shims.
    Preparing,
    /// AFL++ is fuzzing.
    Fuzzing,
    /// Saved crashes are replayed for confirmation and a report.
    Replaying,
    /// Confirmed, distinct findings are being minimized.
    Minimizing,
}

/// What a session stages beyond the request's own files.
#[derive(Debug, Default)]
struct StagedExtras {
    /// Rendered AFL++ dictionary text, when the request carries tokens.
    dictionary: Option<String>,
    /// Queue entries of the earlier session the request continues.
    carried: Vec<PathBuf>,
}

fn read_bounded(path: &Path, limit: u64, what: &str) -> Result<Vec<u8>, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("{what} {}: {error}", path.display())))?;
    if !metadata.file_type().is_file() {
        return Err(invalid(format!(
            "{what} {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > limit {
        return Err(invalid(format!(
            "{what} {} is {} bytes; the limit is {limit}",
            path.display(),
            metadata.len()
        )));
    }
    std::fs::read(path).map_err(|error| invalid(format!("read {what} {}: {error}", path.display())))
}

/// The regular files directly inside `directory`, sorted by name. Symlinks
/// and subdirectories are skipped; more than `limit` entries is an error.
fn flat_files(directory: &Path, limit: usize, what: &str) -> Result<Vec<PathBuf>, ClassifiedError> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| invalid(format!("read {what} {}: {error}", directory.display())))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| invalid(format!("read {what} {}: {error}", directory.display())))?;
        if entry.file_type().is_ok_and(|kind| kind.is_file()) {
            files.push(entry.path());
            if files.len() > limit {
                return Err(invalid(format!(
                    "{what} {} holds more than {limit} files",
                    directory.display()
                )));
            }
        }
    }
    files.sort();
    Ok(files)
}

fn write_new(path: &Path, data: &[u8], executable: bool) -> Result<(), ClassifiedError> {
    std::fs::write(path, data)
        .map_err(|error| ClassifiedError::Internal(format!("write {}: {error}", path.display())))?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(
            |error| {
                ClassifiedError::Internal(format!("mark {} executable: {error}", path.display()))
            },
        )?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    Ok(())
}

/// Copy the session inputs into `root`: the target, its libraries, and the
/// seed corpus. Returns whether a library directory was staged.
fn stage_session(
    root: &Path,
    image: &[u8],
    request: &BinaryFuzzRequest,
    extras: &StagedExtras,
) -> Result<bool, ClassifiedError> {
    write_new(&root.join(TARGET_NAME), image, true)?;
    if let Some(dictionary) = &extras.dictionary {
        write_new(&root.join(DICTIONARY_NAME), dictionary.as_bytes(), false)?;
    }
    for directory in [CORPUS_DIR, OUTPUT_DIR, FINDINGS_DIR, MINIMIZED_DIR] {
        ensure_workspace_directory(root, Path::new(directory))?;
    }
    CRASHINFO.stage(root)?;
    if request.input.is_socket() {
        DESOCK.stage(root)?;
    }
    if request.input == BinaryInput::SocketMessages {
        write_new(
            &root.join(DESOCK_DIR).join(MESSAGE_DICTIONARY_NAME),
            message_dictionary().as_bytes(),
            false,
        )?;
    }
    let corpus = root.join(CORPUS_DIR);
    let mut seeds = 0_usize;
    if let Some(directory) = &request.seeds {
        for (index, path) in flat_files(directory, MAX_SEEDS, "seed directory")?
            .iter()
            .enumerate()
        {
            let data = read_bounded(path, MAX_FINDING_BYTES, "seed")?;
            if data.is_empty() {
                continue;
            }
            write_new(&corpus.join(format!("seed-{index:05}")), &data, false)?;
            seeds += 1;
        }
    }
    for (index, path) in extras.carried.iter().enumerate() {
        let data = read_bounded(path, MAX_FINDING_BYTES, "carried queue entry")?;
        if data.is_empty() {
            continue;
        }
        write_new(
            &corpus.join(format!("{CARRIED_PREFIX}{index:05}")),
            &data,
            false,
        )?;
        seeds += 1;
    }
    if seeds == 0 {
        write_new(&corpus.join("seed-default"), DEFAULT_SEED, false)?;
    }
    let Some(directory) = &request.libraries else {
        return Ok(false);
    };
    let libraries = ensure_workspace_directory(root, Path::new(LIBRARY_DIR))?;
    for path in flat_files(directory, MAX_LIBRARIES, "library directory")? {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.contains(".so") {
            continue;
        }
        let data = read_bounded(&path, MAX_BINARY_BYTES, "library")?;
        write_new(&libraries.join(name), &data, true)?;
    }
    Ok(true)
}

/// The queue entries an earlier session's AFL++ kept, as host paths in name
/// order, bounded like operator seeds.
fn previous_queue(previous: &Path) -> Result<Vec<PathBuf>, ClassifiedError> {
    let queue = previous.join(OUTPUT_DIR).join("default").join("queue");
    let entries = std::fs::read_dir(&queue).map_err(|error| {
        invalid(format!(
            "the earlier session kept no queue to continue from ({}): {error}",
            queue.display()
        ))
    })?;
    let mut files: Vec<PathBuf> = entries
        // An entry that cannot be read is not carried; the rest still are.
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("id:"))
        })
        // A symbolic link or directory in the queue is not an input.
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .collect();
    files.sort();
    files.truncate(MAX_SEEDS);
    Ok(files)
}

/// The crash files AFL++ saved in a session's output tree, as
/// `(host path, recorded signal)`, sorted by name.
fn saved_crashes(output: &Path) -> Vec<(PathBuf, Option<u32>)> {
    let directory = output.join("default").join("crashes");
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut crashes: Vec<(PathBuf, Option<u32>)> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| {
            let name = fuzzer_file_name(&entry.file_name().to_string_lossy());
            name.starts_with("id:")
                .then(|| (entry.path(), crash_file_signal(&name)))
        })
        .collect();
    crashes.sort();
    crashes
}

fn session_sandbox(root: &Path, stdin: Option<Vec<u8>>) -> SandboxOptions {
    SandboxOptions {
        extra_mounts: vec![
            SandboxMount::writable(root.join(CORPUS_DIR), format!("/work/{CORPUS_DIR}")),
            SandboxMount::writable(root.join(OUTPUT_DIR), format!("/work/{OUTPUT_DIR}")),
        ],
        workspace_read_only: true,
        max_file_size_bytes: Some(MAX_FILE_BYTES),
        stdin,
        ..SandboxOptions::default()
    }
}

/// The level `afl-qemu-trace` splits comparisons at: 2 is every comparison
/// against an immediate or a register, not only read-only memory.
const COMPCOV_LEVEL: &str = "2";

/// The environment of the fuzz run. `CompCov` is read by the emulator itself,
/// so it is a plain variable and not part of `QEMU_SET_ENV`.
fn session_env(
    libraries: bool,
    input: BinaryInput,
    compcov: bool,
    persistent: Option<&ResolvedPersistent>,
) -> Result<HashMap<String, String>, ClassifiedError> {
    let mut env = emulated_env(libraries, input, false)?;
    if compcov {
        env.insert("AFL_COMPCOV_LEVEL".to_owned(), COMPCOV_LEVEL.to_owned());
    }
    if let Some(persistent) = persistent {
        env.insert(
            "AFL_QEMU_PERSISTENT_ADDR".to_owned(),
            format!("0x{:x}", persistent.address),
        );
        // Registers, and with them argc and argv, are restored each loop.
        env.insert("AFL_QEMU_PERSISTENT_GPR".to_owned(), "1".to_owned());
        env.insert(
            "AFL_QEMU_PERSISTENT_CNT".to_owned(),
            persistent.iterations.to_string(),
        );
        if persistent.restore_memory {
            env.insert("AFL_QEMU_PERSISTENT_MEM".to_owned(), "1".to_owned());
        }
    }
    Ok(env)
}

/// The environment of a replay: the fuzz run's, plus the crash reporter in
/// the emulated process.
fn replay_env(
    libraries: bool,
    input: BinaryInput,
) -> Result<HashMap<String, String>, ClassifiedError> {
    emulated_env(libraries, input, true)
}

/// The environment of a minimization: the fuzz run's, with the minimizer's
/// scratch file sent to the one directory it may write.
fn minimize_env(
    libraries: bool,
    input: BinaryInput,
) -> Result<HashMap<String, String>, ClassifiedError> {
    let mut env = emulated_env(libraries, input, false)?;
    env.insert("TMPDIR".to_owned(), format!("/work/{MINIMIZED_DIR}"));
    Ok(env)
}

fn emulated_env(
    libraries: bool,
    input: BinaryInput,
    crash_reporter: bool,
) -> Result<HashMap<String, String>, ClassifiedError> {
    let config = FuzzRunConfig {
        harness_id: Uuid::nil(),
        engine: EngineKind::AflPlusPlus,
        duration: None,
        max_mem_mb: SESSION_MEMORY_MB,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: Sanitizer::None,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed: None,
        replay_of: None,
        input_manifest_sha256: None,
        input_timeout: None,
        resume: false,
        cmplog: false,
    };
    let mut env = hf_engine::runner::run_env(EngineKind::AflPlusPlus, &config)?;
    // qemu-user passes these into the emulated process only, so the
    // emulator itself keeps the image's own libraries and is not preloaded.
    let mut emulated = Vec::new();
    if libraries {
        emulated.push(format!("LD_LIBRARY_PATH=/work/{LIBRARY_DIR}"));
    }
    // The socket shim goes first: it must be the one that answers `accept`.
    let mut preloads = Vec::new();
    if input.is_socket() {
        preloads.push(DESOCK.library());
    }
    if crash_reporter {
        preloads.push(CRASHINFO.library());
    }
    if !preloads.is_empty() {
        emulated.push(format!("LD_PRELOAD={}", preloads.join(":")));
    }
    if input == BinaryInput::SocketMessages {
        emulated.push(DESOCK_MESSAGES_ENV.to_owned());
    }
    if !emulated.is_empty() {
        env.insert("QEMU_SET_ENV".to_owned(), emulated.join(","));
    }
    Ok(env)
}

pub(super) fn limits(duration_secs: u64, env: HashMap<String, String>) -> ResourceLimits {
    ResourceLimits {
        max_mem_mb: SESSION_MEMORY_MB,
        max_cpus: 1,
        max_duration_secs: duration_secs,
        env,
        ptrace: false,
    }
}

async fn sandbox_machine(
    runtime: &dyn RuntimeAdapter,
    root: &Path,
) -> Result<ElfMachine, ClassifiedError> {
    let result = runtime
        .run_command_opts(
            &["uname".to_owned(), "-m".to_owned()],
            root,
            &limits(REPLAY_SECS, HashMap::new()),
            &SandboxOptions {
                workspace_read_only: true,
                ..SandboxOptions::default()
            },
        )
        .await?;
    ElfMachine::from_uname(&result.stdout).ok_or_else(|| {
        ClassifiedError::Sandbox(format!(
            "could not read the sandbox architecture (uname -m printed '{}')",
            result.stdout.trim()
        ))
    })
}

/// Compile a shim into its own directory of the session. Only that
/// directory is writable for the step; the fuzz run and the replays see it
/// read-only.
async fn build_shim(
    runtime: &dyn RuntimeAdapter,
    root: &Path,
    shim: &Shim,
) -> Result<(), ClassifiedError> {
    let result = runtime
        .run_command_opts(
            &shim.build_command(),
            root,
            &limits(SHIM_BUILD_SECS, HashMap::new()),
            &SandboxOptions {
                extra_mounts: vec![SandboxMount::writable(
                    root.join(shim.directory),
                    format!("/work/{}", shim.directory),
                )],
                workspace_read_only: true,
                max_file_size_bytes: Some(MAX_FILE_BYTES),
                ..SandboxOptions::default()
            },
        )
        .await?;
    if result.exit_code != 0 || !root.join(shim.directory).join(shim.library_name).is_file() {
        return Err(ClassifiedError::Sandbox(format!(
            "the {} did not compile in the sandbox (exit {}): {}",
            shim.what,
            result.exit_code,
            result.stderr.chars().take(1500).collect::<String>()
        )));
    }
    Ok(())
}

/// What a replay's crash report says.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayReport {
    kind: CrashKind,
    signature: String,
    summary: String,
    frames: Vec<String>,
}

/// Read the crash reporter's report out of a replay's standard error.
/// `None` when the replay printed none.
fn read_replay_report(stderr: &str) -> Option<ReplayReport> {
    let start = stderr.find(CRASHINFO_ERROR_MARK)?;
    // The report ends at its summary line; the emulator's own note about the
    // signal follows it and is not part of the evidence.
    let mut report = String::new();
    for line in stderr[start..].lines() {
        if report.len() + line.len() >= MAX_REPORT_BYTES {
            break;
        }
        report.push_str(line);
        report.push('\n');
        if line.starts_with(CRASHINFO_SUMMARY_MARK) {
            break;
        }
    }
    let (kind, signature, _) = hf_crash::classify(&report);
    let stated = |mark: &str| {
        report
            .lines()
            .find_map(|line| line.strip_prefix(mark))
            .map(|rest| rest.trim().to_owned())
    };
    let summary = stated(CRASHINFO_SUMMARY_MARK)
        .or_else(|| stated(CRASHINFO_ERROR_MARK))
        .unwrap_or_default();
    let frames = report
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('#'))
        .take(MAX_REPORT_FRAMES)
        .map(str::to_owned)
        .collect();
    Some(ReplayReport {
        kind,
        signature,
        summary,
        frames,
    })
}

/// Mark each finding whose signature an earlier finding already has, and
/// return how many findings are distinct. A finding without a signature is
/// always distinct: nothing says it is the same bug as another.
fn mark_duplicates(findings: &mut [BinaryFinding]) -> usize {
    let mut first_with: HashMap<String, String> = HashMap::new();
    let mut distinct = 0;
    for finding in findings.iter_mut() {
        if finding.signature.is_empty() {
            distinct += 1;
            continue;
        }
        if let Some(first) = first_with.get(&finding.signature) {
            finding.duplicate_of = Some(first.clone());
        } else {
            first_with.insert(finding.signature.clone(), finding.sha256.clone());
            distinct += 1;
        }
    }
    distinct
}

/// The inputs a session's replays and minimizations run with.
struct SessionRun<'a> {
    runtime: &'a dyn RuntimeAdapter,
    root: &'a Path,
    input: BinaryInput,
    libraries: bool,
    timeout_ms: u64,
}

/// How one replay ended: the signal it died from, and its crash report.
struct Replay {
    signal: Option<u32>,
    report: Option<ReplayReport>,
}

impl SessionRun<'_> {
    /// Replay the input saved at `saved` (a path inside the session
    /// directory). `None` when the replay did not run to an exit.
    async fn replay(&self, saved: &str, data: Vec<u8>) -> Result<Option<Replay>, ClassifiedError> {
        let stdin = (self.input != BinaryInput::File).then_some(data);
        let result = self
            .runtime
            .run_command_opts(
                &replay_command(self.input, saved),
                self.root,
                &limits(REPLAY_SECS, replay_env(self.libraries, self.input)?),
                &session_sandbox(self.root, stdin),
            )
            .await?;
        if result.termination != CommandTermination::Completed {
            return Ok(None);
        }
        Ok(Some(Replay {
            signal: exit_signal(result.exit_code),
            report: read_replay_report(&result.stderr),
        }))
    }

    /// Shrink one finding and keep the result only when it replays as the
    /// same crash: the same signal, and the same signature when the finding
    /// has one. A minimizer failure is not a session failure.
    async fn minimize(
        &self,
        finding: &BinaryFinding,
    ) -> Result<Option<MinimizedInput>, ClassifiedError> {
        let Some(name) = finding.input.file_name().and_then(|name| name.to_str()) else {
            return Ok(None);
        };
        let saved = self.root.join(MINIMIZED_DIR).join(name);
        let sandbox = SandboxOptions {
            extra_mounts: vec![SandboxMount::writable(
                self.root.join(MINIMIZED_DIR),
                format!("/work/{MINIMIZED_DIR}"),
            )],
            workspace_read_only: true,
            max_file_size_bytes: Some(MAX_FILE_BYTES),
            ..SandboxOptions::default()
        };
        self.runtime
            .run_command_opts(
                &minimize_command(self.input, name, self.timeout_ms),
                self.root,
                &limits(MINIMIZE_SECS, minimize_env(self.libraries, self.input)?),
                &sandbox,
            )
            .await?;
        let saved_name = format!("{MINIMIZED_DIR}/{name}");
        let minimized = match read_bounded(&saved, MAX_FINDING_BYTES, "minimized input") {
            Ok(data) if !data.is_empty() && (data.len() as u64) < finding.size => self
                .same_crash(finding, &saved_name, data.clone())
                .await?
                .then_some(data),
            _ => None,
        };
        let minimized = if self.input == BinaryInput::SocketMessages {
            let start = match &minimized {
                Some(data) => data.clone(),
                None => read_bounded(&finding.input, MAX_FINDING_BYTES, "finding input")?,
            };
            let reduced = self.reduce_messages(finding, &saved_name, start).await?;
            minimized.into_iter().chain(reduced).min_by_key(Vec::len)
        } else {
            minimized
        };
        let Some(data) = minimized.filter(|data| (data.len() as u64) < finding.size) else {
            // Only inputs known to reproduce the finding stay in `minimized`.
            let _ = std::fs::remove_file(&saved);
            return Ok(None);
        };
        std::fs::write(&saved, &data).map_err(|error| {
            ClassifiedError::Internal(format!("write {}: {error}", saved.display()))
        })?;
        Ok(Some(MinimizedInput {
            input: saved,
            sha256: sha256_hex(&data),
            size: data.len() as u64,
        }))
    }

    /// Whether replaying `data` ends as `finding` did: the same signal, and
    /// the same signature when the finding has one.
    async fn same_crash(
        &self,
        finding: &BinaryFinding,
        saved: &str,
        data: Vec<u8>,
    ) -> Result<bool, ClassifiedError> {
        Ok(self.replay(saved, data).await?.is_some_and(|replay| {
            replay.signal.is_some()
                && replay.signal == finding.replay_signal
                && (finding.signature.is_empty()
                    || replay
                        .report
                        .is_some_and(|report| report.signature == finding.signature))
        }))
    }

    /// `afl-tmin` deletes bytes on a fixed grid, so it cannot always take a
    /// four-byte separator out whole: a message sequence can keep empty
    /// messages, spare separators, or whole messages the fault does not need.
    /// Try those reductions message by message, keeping each one only when it
    /// still replays as the same crash, within [`MAX_MESSAGE_TRIALS`].
    /// Returns the smallest input that did, or `None` when none did.
    async fn reduce_messages(
        &self,
        finding: &BinaryFinding,
        saved: &str,
        start: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ClassifiedError> {
        let mut current = start;
        let mut reduced = None;
        let mut trials = 0;
        let compact = without_empty_messages(&current);
        if compact.len() < current.len() && !compact.is_empty() {
            trials += 1;
            if self.same_crash(finding, saved, compact.clone()).await? {
                current = compact;
                reduced = Some(current.clone());
            }
        }
        // Later messages are more often the faulting one; try the earlier
        // ones first and step back after each removal that held.
        let mut index = 0;
        while index < split_messages(&current).len() && trials < MAX_MESSAGE_TRIALS {
            if split_messages(&current).len() < 2 {
                break;
            }
            let candidate = without_message(&current, index);
            if candidate.is_empty() {
                index += 1;
                continue;
            }
            trials += 1;
            if self.same_crash(finding, saved, candidate.clone()).await? {
                current = candidate;
                reduced = Some(current.clone());
            } else {
                index += 1;
            }
        }
        Ok(reduced)
    }
}

/// Keep, replay, group and minimize the crash inputs of a finished session.
/// Returns the findings, how many are distinct, and how many crash files
/// were beyond the per-session cap.
async fn collect_findings(
    run: &SessionRun<'_>,
    stage: &StageReporter<'_>,
) -> Result<(Vec<BinaryFinding>, usize, usize), ClassifiedError> {
    stage(BinaryStage::Replaying);
    let crashes = saved_crashes(&run.root.join(OUTPUT_DIR));
    let omitted = crashes.len().saturating_sub(MAX_FINDINGS);
    let mut findings: Vec<BinaryFinding> = Vec::new();
    for (path, fuzzer_signal) in crashes.into_iter().take(MAX_FINDINGS) {
        let Ok(data) = read_bounded(&path, MAX_FINDING_BYTES, "crash input") else {
            continue;
        };
        let sha256 = sha256_hex(&data);
        if findings.iter().any(|finding| finding.sha256 == sha256) {
            continue;
        }
        let name = format!("crash-{}", &sha256[..16]);
        let saved = run.root.join(FINDINGS_DIR).join(&name);
        write_new(&saved, &data, false)?;
        let mut finding = BinaryFinding {
            input: saved,
            sha256,
            size: data.len() as u64,
            fuzzer_signal,
            replay_signal: None,
            replayed: false,
            confirmed: false,
            kind: None,
            signature: String::new(),
            summary: String::new(),
            frames: Vec::new(),
            duplicate_of: None,
            minimized: None,
        };
        if findings.len() < MAX_REPLAYS {
            finding.replayed = true;
            if let Some(replay) = run.replay(&format!("{FINDINGS_DIR}/{name}"), data).await? {
                finding.replay_signal = replay.signal;
                finding.confirmed = replay.signal.is_some() && replay.signal == fuzzer_signal;
                if let Some(report) = replay.report {
                    finding.kind = Some(report.kind);
                    finding.signature = report.signature;
                    finding.summary = report.summary;
                    finding.frames = report.frames;
                }
            }
        }
        findings.push(finding);
    }
    let distinct = mark_duplicates(&mut findings);
    stage(BinaryStage::Minimizing);
    let mut minimized = 0;
    for finding in &mut findings {
        if minimized >= MAX_MINIMIZED {
            break;
        }
        if !finding.confirmed || finding.duplicate_of.is_some() {
            continue;
        }
        minimized += 1;
        finding.minimized = run.minimize(finding).await?;
    }
    Ok((findings, distinct, omitted))
}

/// Told where a running session is, for progress reports.
pub(super) type StageReporter<'a> = dyn Fn(BinaryStage) + Send + Sync + 'a;

/// A request that passed validation, before anything is staged or run.
struct AdmittedBinary {
    image: Vec<u8>,
    machine: ElfMachine,
    sha256: String,
    command: Vec<String>,
    persistent: Option<ResolvedPersistent>,
}

fn admit(request: &BinaryFuzzRequest) -> Result<AdmittedBinary, ClassifiedError> {
    if request.duration_secs == 0 || request.duration_secs > MAX_DURATION_SECS {
        return Err(invalid(format!(
            "the duration must be between 1 second and {MAX_DURATION_SECS} seconds"
        )));
    }
    if request.timeout_ms == 0 || request.timeout_ms > 3_600_000 {
        return Err(invalid(
            "the per-input timeout must be between 1 and 3,600,000 milliseconds",
        ));
    }
    let image = read_bounded(&request.binary, MAX_BINARY_BYTES, "binary")?;
    let machine = elf_machine(&image)?;
    let persistent = request
        .persistent
        .as_ref()
        .map(|persistent| resolve_persistent(&image, machine, request.input, persistent))
        .transpose()?;
    let sha256 = sha256_hex(&image);
    let command = fuzz_command(
        request.input,
        request.duration_secs,
        request.timeout_ms,
        !request.dictionary.is_empty(),
    )?;
    Ok(AdmittedBinary {
        image,
        machine,
        sha256,
        command,
        persistent,
    })
}

/// Stage, fuzz, collect, replay, and report one session in `root`.
async fn run_session(
    runtime: &dyn RuntimeAdapter,
    root: &Path,
    session: Uuid,
    request: &BinaryFuzzRequest,
    admitted: AdmittedBinary,
    extras: &StagedExtras,
    stage: &StageReporter<'_>,
    cancel: &CancellationToken,
) -> Result<BinaryFuzzOutcome, ClassifiedError> {
    let started_at = Utc::now();
    stage(BinaryStage::Preparing);
    let libraries = stage_session(root, &admitted.image, request, extras)?;
    let sandbox = sandbox_machine(runtime, root).await?;
    if sandbox != admitted.machine {
        return Err(invalid(format!(
            "the binary is built for {}, but the sandbox runs {}; QEMU mode in this image \
             emulates the image's own architecture only",
            admitted.machine.uname(),
            sandbox.uname()
        )));
    }

    build_shim(runtime, root, &CRASHINFO).await?;
    if request.input.is_socket() {
        build_shim(runtime, root, &DESOCK).await?;
    }

    stage(BinaryStage::Fuzzing);
    // The streaming call is the runtime's cancellable one; the fuzzer's
    // output lines are not needed while it runs (progress reads its stats).
    let result = runtime
        .run_command_streaming_opts(
            &admitted.command,
            root,
            &limits(
                request.duration_secs + SHUTDOWN_GRACE_SECS,
                session_env(
                    libraries,
                    request.input,
                    request.compcov,
                    admitted.persistent.as_ref(),
                )?,
            ),
            &session_sandbox(root, None),
            cancel,
            &|_| {},
        )
        .await?;
    let stopped = result.termination == CommandTermination::Cancelled;
    let stats = std::fs::read(root.join(OUTPUT_DIR).join("default").join("fuzzer_stats"))
        .ok()
        .and_then(|contents| hf_engine::afl::parse_fuzzer_stats(&contents).ok());
    let Some(stats) = stats else {
        if stopped {
            return Err(invalid(
                "the session was stopped before AFL++ started fuzzing; nothing was found",
            ));
        }
        // AFL++ never reached its fuzzing loop: the target could not be
        // started under the emulator, or every seed failed the dry run.
        let output = format!("{}\n{}", result.stdout, result.stderr);
        let tail: String = output
            .chars()
            .rev()
            .take(1500)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        return Err(ClassifiedError::Engine(format!(
            "afl-fuzz -Q did not start fuzzing (exit {}); output: {tail}",
            result.exit_code
        )));
    };

    let (findings, distinct_findings, findings_omitted) = collect_findings(
        &SessionRun {
            runtime,
            root,
            input: request.input,
            libraries,
            timeout_ms: request.timeout_ms,
        },
        stage,
    )
    .await?;
    let outcome = BinaryFuzzOutcome {
        session,
        workspace: root.to_path_buf(),
        binary_name: request
            .binary
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        binary_sha256: admitted.sha256,
        machine: admitted.machine,
        input: request.input,
        duration_secs: request.duration_secs,
        execs_done: stats.execs_done,
        execs_per_sec: stats.execs_per_sec,
        edges_found: stats.edges_found,
        corpus_count: stats.corpus_count,
        saved_hangs: stats.saved_hangs,
        findings,
        distinct_findings,
        findings_omitted,
        started_at: Some(started_at),
        finished_at: Some(Utc::now()),
        continued_from: request.continue_from,
        dictionary_tokens: request.dictionary.len(),
        compcov: request.compcov,
        stopped,
        persistent_entry: admitted
            .persistent
            .as_ref()
            .map(|persistent| persistent.label.clone()),
        stability_pct: stats.stability_pct,
    };
    let report = serde_json::to_vec_pretty(&outcome)
        .map_err(|error| ClassifiedError::Internal(format!("encode report: {error}")))?;
    write_new(&root.join(REPORT_NAME), &report, false)?;
    Ok(outcome)
}

impl ServiceContainer {
    /// Fuzz an uninstrumented Linux binary with AFL++ QEMU mode in the
    /// sandbox, then keep and replay the crashing inputs it found.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] when the binary is not an ELF
    /// executable for the sandbox architecture or a limit is exceeded, the
    /// approval gate's error when execution is refused, and sandbox errors
    /// from the runtime -- including an AFL++ start-up failure, whose output
    /// is quoted.
    pub async fn binary_fuzz(
        &self,
        request: &BinaryFuzzRequest,
    ) -> Result<BinaryFuzzOutcome, ClassifiedError> {
        let admitted = admit(request)?;
        let dictionary = if request.dictionary.is_empty() {
            None
        } else {
            Some(super::binary_profile::render_dictionary(
                &request.dictionary,
            )?)
        };
        self.authorize_recorded(Action::RunHarness, "binary_fuzz", Some(&request.project))
            .await?;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        let workspace_root = prepare_configured_workspace_root()?;
        let binary_dir = PathBuf::from(project_slug(&request.project))
            .join(".binary")
            .join(&admitted.sha256[..16]);
        let carried = match request.continue_from {
            Some(previous) => {
                let previous_root = workspace_root.join(&binary_dir).join(previous.to_string());
                super::binary_sessions::verify_same_binary(&previous_root, &admitted.sha256)?;
                previous_queue(&previous_root)?
            }
            None => Vec::new(),
        };
        let session = Uuid::new_v4();
        let root =
            ensure_workspace_directory(&workspace_root, &binary_dir.join(session.to_string()))?;
        let binary_name = request
            .binary
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (_active, cancel) = self.track_binary_session(
            session,
            &request.project,
            binary_name,
            &root,
            request.duration_secs,
        );
        let registry = self.binary_session_registry();
        let stage = move |stage: BinaryStage| {
            super::binary_sessions::set_stage(&registry, session, stage);
        };
        run_session(
            self.runtime.as_ref(),
            &root,
            session,
            request,
            admitted,
            &StagedExtras {
                dictionary,
                carried,
            },
            &stage,
            &cancel,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf(class: u8, data: u8, kind: u16, machine: u16) -> Vec<u8> {
        let mut image = vec![0_u8; 64];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = class;
        image[5] = data;
        image[16..18].copy_from_slice(&kind.to_le_bytes());
        image[18..20].copy_from_slice(&machine.to_le_bytes());
        image
    }

    #[test]
    fn only_64_bit_little_endian_executables_for_a_known_machine_are_accepted() {
        assert_eq!(
            elf_machine(&elf(2, 1, 3, 183)).unwrap(),
            ElfMachine::Aarch64
        );
        assert_eq!(elf_machine(&elf(2, 1, 2, 62)).unwrap(), ElfMachine::X86_64);
        for (image, reason) in [
            (b"#!/bin/sh\nexit 0\n".to_vec(), "not an ELF binary"),
            (b"\x7fEL".to_vec(), "not an ELF binary"),
            (b"\x7fELF\x02\x01".to_vec(), "too short"),
            (elf(1, 1, 2, 3), "64-bit"),
            (elf(2, 2, 2, 62), "little-endian"),
            (elf(2, 1, 1, 62), "not an executable"),
            (elf(2, 1, 4, 62), "not an executable"),
            (elf(2, 1, 2, 243), "machine 243"),
        ] {
            let error = elf_machine(&image).unwrap_err().to_string();
            assert!(error.contains(reason), "{error}");
        }
        assert_eq!(
            ElfMachine::from_uname("aarch64\n"),
            Some(ElfMachine::Aarch64)
        );
        assert_eq!(ElfMachine::from_uname("x86_64"), Some(ElfMachine::X86_64));
        assert_eq!(ElfMachine::from_uname("riscv64"), None);
    }

    #[test]
    fn a_persistent_entry_resolves_to_the_emulators_address() {
        let functions = vec![("main".to_owned(), 0x9d8), ("parse".to_owned(), 0xb00)];
        // PIE on AArch64: the emulator's base plus the offset from the load base.
        assert_eq!(
            persistent_address(true, ElfMachine::Aarch64, 0, 0x9d8),
            0x55_0000_09d8
        );
        assert_eq!(
            persistent_address(true, ElfMachine::X86_64, 0, 0x1149),
            0x40_0000_1149
        );
        // A fixed-address executable runs at its link address.
        assert_eq!(
            persistent_address(false, ElfMachine::X86_64, 0x40_0000, 0x40_1149),
            0x40_1149
        );
        assert_eq!(
            entry_address(&functions, 0, "main").unwrap(),
            (0x9d8, "main (target+0x9d8)".to_owned())
        );
        assert_eq!(
            entry_address(&functions, 0x40_0000, "0x1149").unwrap(),
            (0x40_1149, "target+0x1149".to_owned())
        );
        let unknown = entry_address(&functions, 0, "decode")
            .unwrap_err()
            .to_string();
        assert!(
            unknown.contains("decode") && unknown.contains("main"),
            "{unknown}"
        );
        assert!(entry_address(&functions, 0, "0xzz").is_err());
    }

    #[test]
    fn persistent_mode_is_for_file_input_and_bounded_iterations() {
        let persistent = |iterations| BinaryPersistent {
            entry: "main".to_owned(),
            iterations,
            restore_memory: false,
        };
        assert!(check_persistent(BinaryInput::File, &persistent(1000)).is_ok());
        for input in [
            BinaryInput::Stdin,
            BinaryInput::Socket,
            BinaryInput::SocketMessages,
        ] {
            assert!(
                check_persistent(input, &persistent(1000)).is_err(),
                "{input:?}"
            );
        }
        assert!(check_persistent(BinaryInput::File, &persistent(0)).is_err());
        assert!(check_persistent(
            BinaryInput::File,
            &persistent(MAX_PERSISTENT_ITERATIONS + 1)
        )
        .is_err());
    }

    #[test]
    fn the_persistent_loop_is_set_for_the_fuzz_run_only() {
        let resolved = ResolvedPersistent {
            address: 0x55_0000_09d8,
            label: "main (target+0x9d8)".to_owned(),
            iterations: 1000,
            restore_memory: false,
        };
        let env = session_env(false, BinaryInput::File, false, Some(&resolved)).unwrap();
        assert_eq!(env["AFL_QEMU_PERSISTENT_ADDR"], "0x55000009d8");
        assert_eq!(env["AFL_QEMU_PERSISTENT_GPR"], "1");
        assert_eq!(env["AFL_QEMU_PERSISTENT_CNT"], "1000");
        assert!(!env.contains_key("AFL_QEMU_PERSISTENT_MEM"));
        assert!(!env.contains_key("AFL_QEMU_PERSISTENT_EXITS"));
        let restoring = ResolvedPersistent {
            restore_memory: true,
            ..resolved
        };
        let env = session_env(false, BinaryInput::File, false, Some(&restoring)).unwrap();
        assert_eq!(env["AFL_QEMU_PERSISTENT_MEM"], "1");
        assert!(!replay_env(false, BinaryInput::File)
            .unwrap()
            .contains_key("AFL_QEMU_PERSISTENT_ADDR"));
        assert!(!minimize_env(false, BinaryInput::File)
            .unwrap()
            .contains_key("AFL_QEMU_PERSISTENT_ADDR"));
    }

    #[test]
    fn compcov_is_set_for_the_fuzz_run_only() {
        let fuzz = session_env(false, BinaryInput::File, true, None).unwrap();
        assert_eq!(fuzz.get("AFL_COMPCOV_LEVEL").map(String::as_str), Some("2"));
        // The emulator reads it, not the emulated process.
        assert!(!fuzz
            .get("QEMU_SET_ENV")
            .is_some_and(|value| value.contains("COMPCOV")));
        assert!(!session_env(false, BinaryInput::File, false, None)
            .unwrap()
            .contains_key("AFL_COMPCOV_LEVEL"));
        assert!(!replay_env(false, BinaryInput::File)
            .unwrap()
            .contains_key("AFL_COMPCOV_LEVEL"));
        assert!(!minimize_env(false, BinaryInput::File)
            .unwrap()
            .contains_key("AFL_COMPCOV_LEVEL"));
    }

    #[test]
    fn an_operator_dictionary_is_a_second_dictionary_beside_the_separator() {
        let plain = fuzz_command(BinaryInput::File, 60, 1000, true).unwrap();
        let dictionaries: Vec<_> = plain
            .windows(2)
            .filter(|pair| pair[0] == "-x")
            .map(|pair| pair[1].clone())
            .collect();
        assert_eq!(dictionaries, ["/work/dictionary.dict"]);
        let messages = fuzz_command(BinaryInput::SocketMessages, 60, 1000, true).unwrap();
        let dictionaries: Vec<_> = messages
            .windows(2)
            .filter(|pair| pair[0] == "-x")
            .map(|pair| pair[1].clone())
            .collect();
        assert_eq!(
            dictionaries,
            ["/work/desock/messages.dict", "/work/dictionary.dict"]
        );
        assert!(!fuzz_command(BinaryInput::File, 60, 1000, false)
            .unwrap()
            .contains(&"-x".to_owned()));
    }

    #[test]
    fn a_continued_session_stages_the_dictionary_and_the_earlier_queue() {
        let source = tempfile::tempdir().unwrap();
        let earlier = tempfile::tempdir().unwrap();
        let queue = earlier.path().join("out/default/queue");
        std::fs::create_dir_all(queue.join(".state")).unwrap();
        std::fs::write(queue.join("id:000000,time:0,orig:seed"), b"AAAA").unwrap();
        std::fs::write(queue.join("id:000001,src:000000,op:havoc"), b"BBBB").unwrap();
        std::fs::write(queue.join("id:000002,empty"), b"").unwrap();
        std::fs::write(queue.join("README.txt"), b"not an input").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            queue.join("id:000000,time:0,orig:seed"),
            queue.join("id:000003,link"),
        )
        .unwrap();
        let carried = previous_queue(earlier.path()).unwrap();
        assert_eq!(carried.len(), 3, "{carried:?}");

        let root = tempfile::tempdir().unwrap();
        let request = BinaryFuzzRequest {
            project: source.path().to_path_buf(),
            binary: source.path().join("unused"),
            input: BinaryInput::File,
            seeds: None,
            libraries: None,
            duration_secs: 10,
            timeout_ms: 1000,
            dictionary: vec!["PIC1".to_owned()],
            continue_from: None,
            compcov: false,
            persistent: None,
        };
        let extras = StagedExtras {
            dictionary: Some("token_0001=\"PIC1\"\n".to_owned()),
            carried,
        };
        stage_session(root.path(), b"\x7fELF", &request, &extras).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("dictionary.dict")).unwrap(),
            "token_0001=\"PIC1\"\n"
        );
        let mut corpus: Vec<_> = std::fs::read_dir(root.path().join("corpus"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        corpus.sort();
        // The empty queue entry adds nothing; no default seed is needed.
        assert_eq!(corpus, ["carried-00000", "carried-00001"]);
        assert!(previous_queue(source.path()).is_err());
    }

    #[test]
    fn the_fuzz_command_is_the_afl_adapter_argv_in_qemu_mode() {
        let file = fuzz_command(BinaryInput::File, 60, 1000, false).unwrap();
        assert_eq!(
            file,
            [
                "afl-fuzz",
                "-i",
                "/work/corpus",
                "-o",
                "/work/out",
                "-V",
                "60",
                "-Q",
                "-t",
                "1000",
                "--",
                "/work/target",
                "@@"
            ]
        );
        // A stdin target gets no input-file placeholder.
        let stdin = fuzz_command(BinaryInput::Stdin, 60, 1000, false).unwrap();
        assert_eq!(stdin.last().map(String::as_str), Some("/work/target"));
        assert!(stdin.contains(&"-Q".to_owned()));

        assert_eq!(
            replay_command(BinaryInput::File, "findings/crash-0123456789abcdef"),
            [
                "sh",
                "-c",
                "afl-qemu-trace \"$@\"; exit $?",
                "sh",
                "/work/target",
                "/work/findings/crash-0123456789abcdef"
            ]
        );
        assert_eq!(
            replay_command(BinaryInput::Stdin, "findings/crash-0123456789abcdef"),
            [
                "sh",
                "-c",
                "afl-qemu-trace \"$@\"; exit $?",
                "sh",
                "/work/target"
            ]
        );
    }

    #[test]
    fn signals_are_read_from_crash_names_and_replay_exit_codes() {
        assert_eq!(
            crash_file_signal("id:000000,sig:11,src:000003,time:7224,execs:25435,op:havoc,rep:2"),
            Some(11)
        );
        assert_eq!(crash_file_signal("id:000001,sig:06,src:000000"), Some(6));
        assert_eq!(crash_file_signal("id:000001,src:000000"), None);
        assert_eq!(crash_file_signal("id:000001,sig:999"), None);
        assert_eq!(crash_file_signal("id:000001,sig:x"), None);
        assert_eq!(exit_signal(139), Some(11));
        assert_eq!(exit_signal(134), Some(6));
        for code in [0, 1, 127, 128, 255, -1] {
            assert_eq!(exit_signal(code), None, "{code}");
        }
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(6), "SIGABRT");
        assert_eq!(signal_name(40), "signal");
    }

    #[test]
    fn a_session_stages_the_target_seeds_and_only_shared_objects() {
        let source = tempfile::tempdir().unwrap();
        let seeds = source.path().join("seeds");
        let libs = source.path().join("libs");
        std::fs::create_dir_all(seeds.join("nested")).unwrap();
        std::fs::create_dir_all(&libs).unwrap();
        std::fs::write(seeds.join("b"), b"second").unwrap();
        std::fs::write(seeds.join("a"), b"first").unwrap();
        std::fs::write(seeds.join("empty"), b"").unwrap();
        std::fs::write(seeds.join("nested/skipped"), b"x").unwrap();
        std::fs::write(libs.join("libvendor.so.1"), b"\x7fELF").unwrap();
        std::fs::write(libs.join("README"), b"notes").unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut request = BinaryFuzzRequest {
            project: source.path().to_path_buf(),
            binary: source.path().join("unused"),
            input: BinaryInput::File,
            seeds: Some(seeds),
            libraries: Some(libs),
            duration_secs: 10,
            timeout_ms: 1000,
            dictionary: Vec::new(),
            continue_from: None,
            compcov: false,
            persistent: None,
        };
        assert!(stage_session(
            root.path(),
            b"\x7fELF image",
            &request,
            &StagedExtras::default()
        )
        .unwrap());
        assert_eq!(
            std::fs::read(root.path().join("target")).unwrap(),
            b"\x7fELF image"
        );
        let mut corpus: Vec<Vec<u8>> = std::fs::read_dir(root.path().join("corpus"))
            .unwrap()
            .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
            .collect();
        corpus.sort();
        assert_eq!(corpus, [b"first".to_vec(), b"second".to_vec()]);
        let staged: Vec<String> = std::fs::read_dir(root.path().join("libs"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(staged, ["libvendor.so.1"]);
        assert!(root.path().join("out").is_dir() && root.path().join("findings").is_dir());

        // No seeds: AFL++ still gets one input.
        let bare = tempfile::tempdir().unwrap();
        request.seeds = None;
        request.libraries = None;
        assert!(
            !stage_session(bare.path(), b"\x7fELF", &request, &StagedExtras::default()).unwrap()
        );
        assert_eq!(
            std::fs::read(bare.path().join("corpus/seed-default")).unwrap(),
            DEFAULT_SEED
        );
        assert_eq!(
            session_env(true, BinaryInput::File, false, None)
                .unwrap()
                .get("QEMU_SET_ENV")
                .map(String::as_str),
            Some("LD_LIBRARY_PATH=/work/libs")
        );
        assert!(!session_env(false, BinaryInput::Stdin, false, None)
            .unwrap()
            .contains_key("QEMU_SET_ENV"));
        assert!(!bare.path().join("desock").exists());
    }

    #[test]
    fn a_socket_session_takes_stdin_input_and_preloads_the_shim_into_the_target_only() {
        // The fuzzer delivers the input on standard input; the shim hands it
        // to the server as its first connection.
        let command = fuzz_command(BinaryInput::Socket, 60, 1000, false).unwrap();
        assert_eq!(command.last().map(String::as_str), Some("/work/target"));
        assert_eq!(
            replay_command(BinaryInput::Socket, "findings/crash-0123456789abcdef"),
            replay_command(BinaryInput::Stdin, "findings/crash-0123456789abcdef")
        );

        // The emulator passes the preload to the emulated process only.
        let env = session_env(false, BinaryInput::Socket, false, None).unwrap();
        assert_eq!(
            env.get("QEMU_SET_ENV").map(String::as_str),
            Some("LD_PRELOAD=/work/desock/oxfuzz_desock.so")
        );
        assert!(!env.contains_key("LD_PRELOAD") && !env.contains_key("AFL_PRELOAD"));
        assert_eq!(
            session_env(true, BinaryInput::Socket, false, None)
                .unwrap()
                .get("QEMU_SET_ENV")
                .map(String::as_str),
            Some("LD_LIBRARY_PATH=/work/libs,LD_PRELOAD=/work/desock/oxfuzz_desock.so")
        );

        let source = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let request = BinaryFuzzRequest {
            project: source.path().to_path_buf(),
            binary: source.path().join("unused"),
            input: BinaryInput::Socket,
            seeds: None,
            libraries: None,
            duration_secs: 10,
            timeout_ms: 1000,
            dictionary: Vec::new(),
            continue_from: None,
            compcov: false,
            persistent: None,
        };
        stage_session(root.path(), b"\x7fELF", &request, &StagedExtras::default()).unwrap();
        let shim = std::fs::read_to_string(root.path().join("desock/oxfuzz_desock.c")).unwrap();
        assert_eq!(shim, DESOCK_SOURCE);
        for symbol in ["accept4(", "listen(", "bind(", "MSG_NOSIGNAL"] {
            assert!(shim.contains(symbol), "{symbol}");
        }
        assert_eq!(
            DESOCK.build_command(),
            [
                "clang",
                "-O2",
                "-fPIC",
                "-shared",
                "-pthread",
                "-o",
                "/work/desock/oxfuzz_desock.so",
                "/work/desock/oxfuzz_desock.c",
                "-ldl"
            ]
        );
        assert_eq!(
            serde_json::to_string(&BinaryInput::Socket).unwrap(),
            "\"socket\""
        );
    }

    fn finding(sha256: &str, signature: &str) -> BinaryFinding {
        BinaryFinding {
            input: PathBuf::from(format!("findings/crash-{sha256}")),
            sha256: sha256.to_owned(),
            size: 8,
            fuzzer_signal: Some(11),
            replay_signal: Some(11),
            replayed: true,
            confirmed: true,
            kind: None,
            signature: signature.to_owned(),
            summary: String::new(),
            frames: Vec::new(),
            duplicate_of: None,
            minimized: None,
        }
    }

    const REPLAY_REPORT: &str = "==ERROR: oxfuzz-crashinfo: SEGV (signal 11) at \
        (/work/target+0x934), fault address 0x0\n    \
        #0 0x5500000934 (/work/target+0x934)\n    \
        #1 0x550000098c in decode_record (/work/target+0x98c)\n\
        SUMMARY: oxfuzz-crashinfo: SEGV (signal 11) at (/work/target+0x934)\n\
        qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n";

    #[test]
    fn a_replay_preloads_the_crash_reporter_and_the_fuzz_run_does_not() {
        // Fuzzing pays for no reporter; only replays load it.
        assert!(!session_env(false, BinaryInput::File, false, None)
            .unwrap()
            .contains_key("QEMU_SET_ENV"));
        assert_eq!(
            replay_env(false, BinaryInput::File)
                .unwrap()
                .get("QEMU_SET_ENV")
                .map(String::as_str),
            Some("LD_PRELOAD=/work/crashinfo/oxfuzz_crashinfo.so")
        );
        // A server replay keeps the socket shim first: it must own `accept`.
        assert_eq!(
            replay_env(true, BinaryInput::Socket)
                .unwrap()
                .get("QEMU_SET_ENV")
                .map(String::as_str),
            Some(
                "LD_LIBRARY_PATH=/work/libs,\
                 LD_PRELOAD=/work/desock/oxfuzz_desock.so:/work/crashinfo/oxfuzz_crashinfo.so"
            )
        );
        assert_eq!(
            CRASHINFO.build_command(),
            [
                "clang",
                "-O2",
                "-fPIC",
                "-shared",
                "-o",
                "/work/crashinfo/oxfuzz_crashinfo.so",
                "/work/crashinfo/oxfuzz_crashinfo.c",
                "-ldl"
            ]
        );

        // Every session stages the reporter source and a place for minimized
        // inputs, whatever the input mode.
        let source = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let request = BinaryFuzzRequest {
            project: source.path().to_path_buf(),
            binary: source.path().join("unused"),
            input: BinaryInput::File,
            seeds: None,
            libraries: None,
            duration_secs: 10,
            timeout_ms: 1000,
            dictionary: Vec::new(),
            continue_from: None,
            compcov: false,
            persistent: None,
        };
        stage_session(root.path(), b"\x7fELF", &request, &StagedExtras::default()).unwrap();
        let shim =
            std::fs::read_to_string(root.path().join("crashinfo/oxfuzz_crashinfo.c")).unwrap();
        assert_eq!(shim, CRASHINFO_SOURCE);
        for expected in [
            "oxfuzz-crashinfo: ",
            "SA_RESETHAND",
            "sigaltstack",
            "backtrace(",
        ] {
            assert!(shim.contains(expected), "{expected}");
        }
        assert!(root.path().join("minimized").is_dir());
    }

    #[test]
    fn a_replay_report_gives_the_finding_a_kind_a_signature_and_frames() {
        let report = read_replay_report(REPLAY_REPORT).unwrap();
        assert_eq!(report.kind, CrashKind::Segv);
        assert_eq!(report.signature.len(), 64);
        assert_eq!(report.summary, "SEGV (signal 11) at (/work/target+0x934)");
        assert_eq!(
            report.frames,
            [
                "#0 0x5500000934 (/work/target+0x934)",
                "#1 0x550000098c in decode_record (/work/target+0x98c)"
            ]
        );
        // The same fault at another load address is the same finding.
        let moved = REPLAY_REPORT.replace("0x55000", "0x7f000");
        assert_eq!(
            read_replay_report(&moved).unwrap().signature,
            report.signature
        );

        // A report cut before its summary line still names the fault.
        let cut = REPLAY_REPORT.split("SUMMARY").next().unwrap();
        let partial = read_replay_report(cut).unwrap();
        assert_eq!(partial.signature, report.signature);
        assert!(partial.summary.starts_with("SEGV (signal 11) at"));

        // A static target, or one with its own handlers, prints no report.
        assert!(read_replay_report(
            "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
        )
        .is_none());
    }

    #[test]
    fn findings_with_one_signature_are_one_distinct_finding() {
        let mut findings = vec![
            finding("aa", "sig-one"),
            finding("bb", ""),
            finding("cc", "sig-one"),
            finding("dd", "sig-two"),
            finding("ee", ""),
        ];
        // Unsigned findings are never merged: nothing says they are one bug.
        assert_eq!(mark_duplicates(&mut findings), 4);
        let duplicates: Vec<Option<&str>> = findings
            .iter()
            .map(|finding| finding.duplicate_of.as_deref())
            .collect();
        assert_eq!(duplicates, [None, None, Some("aa"), None, None]);
    }

    #[test]
    fn the_minimizer_runs_in_qemu_mode_with_the_session_input_mode() {
        assert_eq!(
            minimize_command(BinaryInput::File, "crash-0123456789abcdef", 250),
            [
                "afl-tmin",
                "-Q",
                "-i",
                "/work/findings/crash-0123456789abcdef",
                "-o",
                "/work/minimized/crash-0123456789abcdef",
                "-m",
                "none",
                "-t",
                "250",
                "--",
                "/work/target",
                "@@"
            ]
        );
        let stdin = minimize_command(BinaryInput::Stdin, "crash-0123456789abcdef", 250);
        assert_eq!(stdin.last().map(String::as_str), Some("/work/target"));
        assert_eq!(
            stdin,
            minimize_command(BinaryInput::Socket, "crash-0123456789abcdef", 250)
        );
        // The minimizer writes its scratch file where the session lets it.
        let env = minimize_env(false, BinaryInput::Socket).unwrap();
        assert_eq!(
            env.get("TMPDIR").map(String::as_str),
            Some("/work/minimized")
        );
        assert_eq!(
            env.get("QEMU_SET_ENV").map(String::as_str),
            Some("LD_PRELOAD=/work/desock/oxfuzz_desock.so")
        );
        // A minimized input replays from its own directory.
        assert_eq!(
            replay_command(BinaryInput::File, "minimized/crash-0123456789abcdef").last(),
            Some(&"/work/minimized/crash-0123456789abcdef".to_owned())
        );
    }

    #[test]
    fn a_session_report_round_trips_through_json() {
        let outcome = BinaryFuzzOutcome {
            session: Uuid::nil(),
            workspace: PathBuf::from("/tmp/session"),
            binary_name: "decoder".to_owned(),
            binary_sha256: "ab".repeat(32),
            machine: ElfMachine::Aarch64,
            input: BinaryInput::Socket,
            duration_secs: 60,
            execs_done: Some(10),
            execs_per_sec: Some(5.0),
            edges_found: Some(3),
            corpus_count: Some(2),
            saved_hangs: Some(0),
            findings: vec![BinaryFinding {
                kind: Some(CrashKind::Segv),
                minimized: Some(MinimizedInput {
                    input: PathBuf::from("minimized/crash-aa"),
                    sha256: "cc".to_owned(),
                    size: 4,
                }),
                ..finding("aa", "sig-one")
            }],
            distinct_findings: 1,
            findings_omitted: 0,
            started_at: None,
            finished_at: None,
            continued_from: None,
            dictionary_tokens: 0,
            compcov: false,
            stopped: false,
            persistent_entry: None,
            stability_pct: None,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let read: BinaryFuzzOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(read.findings[0].signature, "sig-one");
        assert_eq!(read.findings[0].kind, Some(CrashKind::Segv));
        assert_eq!(read.findings[0].minimized.as_ref().unwrap().size, 4);
        assert_eq!(read.distinct_findings, 1);
        // A report written before findings were signed still reads.
        let old = r#"{"session":"00000000-0000-0000-0000-000000000000","workspace":"/w",
            "binary_sha256":"ab","machine":"aarch64","input":"file","duration_secs":1,
            "execs_done":null,"execs_per_sec":null,"edges_found":null,"corpus_count":null,
            "saved_hangs":null,"findings":[{"input":"findings/crash-aa","sha256":"aa","size":1,
            "fuzzer_signal":11,"replay_signal":11,"replayed":true,"confirmed":true}],
            "findings_omitted":0}"#;
        let read: BinaryFuzzOutcome = serde_json::from_str(old).unwrap();
        assert!(read.findings[0].signature.is_empty());
        assert_eq!(read.distinct_findings, 0);
    }

    #[test]
    fn a_message_session_paces_the_input_and_teaches_the_fuzzer_the_separator() {
        // The shim and the dictionary state the same four bytes.
        assert_eq!(MESSAGE_SEPARATOR, [0xff, 0xfe, 0xfd, 0xfc]);
        assert!(DESOCK_SOURCE.contains(r#"#define SEPARATOR "\xff\xfe\xfd\xfc""#));
        assert_eq!(message_dictionary(), "separator=\"\\xff\\xfe\\xfd\\xfc\"\n");

        // The fuzzer is given the separator as a dictionary token, and the
        // input still arrives on standard input.
        let command = fuzz_command(BinaryInput::SocketMessages, 60, 1000, false).unwrap();
        let at = command.iter().position(|arg| arg == "-x").unwrap();
        assert_eq!(command[at + 1], "/work/desock/messages.dict");
        assert_eq!(command.last().map(String::as_str), Some("/work/target"));
        assert!(!fuzz_command(BinaryInput::Socket, 60, 1000, false)
            .unwrap()
            .contains(&"-x".to_owned()));

        // Only a message session asks the shim to split the input, in the
        // fuzz run, the replays and the minimizer alike.
        assert_eq!(
            session_env(false, BinaryInput::SocketMessages, false, None)
                .unwrap()
                .get("QEMU_SET_ENV")
                .map(String::as_str),
            Some("LD_PRELOAD=/work/desock/oxfuzz_desock.so,OXFUZZ_DESOCK_MESSAGES=1")
        );
        assert_eq!(
            replay_env(true, BinaryInput::SocketMessages)
                .unwrap()
                .get("QEMU_SET_ENV")
                .map(String::as_str),
            Some(
                "LD_LIBRARY_PATH=/work/libs,\
                 LD_PRELOAD=/work/desock/oxfuzz_desock.so:/work/crashinfo/oxfuzz_crashinfo.so,\
                 OXFUZZ_DESOCK_MESSAGES=1"
            )
        );
        assert!(minimize_env(false, BinaryInput::SocketMessages)
            .unwrap()
            .get("QEMU_SET_ENV")
            .is_some_and(|env| env.ends_with("OXFUZZ_DESOCK_MESSAGES=1")));
        assert!(!session_env(false, BinaryInput::Socket, false, None)
            .unwrap()
            .get("QEMU_SET_ENV")
            .is_some_and(|env| env.contains("MESSAGES")));
        assert_eq!(
            replay_command(
                BinaryInput::SocketMessages,
                "findings/crash-0123456789abcdef"
            ),
            replay_command(BinaryInput::Stdin, "findings/crash-0123456789abcdef")
        );
        assert_eq!(
            minimize_command(BinaryInput::SocketMessages, "crash-0123456789abcdef", 250),
            minimize_command(BinaryInput::Stdin, "crash-0123456789abcdef", 250)
        );

        let source = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut request = BinaryFuzzRequest {
            project: source.path().to_path_buf(),
            binary: source.path().join("unused"),
            input: BinaryInput::SocketMessages,
            seeds: None,
            libraries: None,
            duration_secs: 10,
            timeout_ms: 1000,
            dictionary: Vec::new(),
            continue_from: None,
            compcov: false,
            persistent: None,
        };
        stage_session(root.path(), b"\x7fELF", &request, &StagedExtras::default()).unwrap();
        assert!(root.path().join("desock/oxfuzz_desock.c").is_file());
        assert_eq!(
            std::fs::read_to_string(root.path().join("desock/messages.dict")).unwrap(),
            message_dictionary()
        );
        let plain = tempfile::tempdir().unwrap();
        request.input = BinaryInput::Socket;
        stage_session(plain.path(), b"\x7fELF", &request, &StagedExtras::default()).unwrap();
        assert!(!plain.path().join("desock/messages.dict").exists());

        assert_eq!(
            serde_json::to_string(&BinaryInput::SocketMessages).unwrap(),
            "\"socket_messages\""
        );
        assert!(BinaryInput::Socket.is_socket() && BinaryInput::SocketMessages.is_socket());
        assert!(!BinaryInput::Stdin.is_socket() && !BinaryInput::File.is_socket());
        // The shim stands in for datagram sockets as well as stream ones.
        for symbol in [
            "SOCK_DGRAM",
            "recvfrom(",
            "sendto(",
            "SIOCOUTQ",
            "__recv_chk(",
        ] {
            assert!(DESOCK_SOURCE.contains(symbol), "{symbol}");
        }
    }

    // AFL++ names its crash files with colons, which a Windows file system
    // does not accept in a host-written fixture.
    #[cfg(unix)]
    #[test]
    fn saved_crashes_are_afl_crash_files_only() {
        let root = tempfile::tempdir().unwrap();
        assert!(saved_crashes(root.path()).is_empty());
        let crashes = root.path().join("default/crashes");
        std::fs::create_dir_all(&crashes).unwrap();
        std::fs::write(crashes.join("README.txt"), b"how to").unwrap();
        std::fs::write(crashes.join("id:000001,sig:06,src:000000"), b"b").unwrap();
        std::fs::write(crashes.join("id:000000,sig:11,src:000003"), b"a").unwrap();
        let found = saved_crashes(root.path());
        assert_eq!(
            found.iter().map(|(_, signal)| *signal).collect::<Vec<_>>(),
            [Some(11), Some(6)]
        );
    }

    use hf_core::runtime::CommandResult;

    /// A runtime that answers every command with one prepared result and
    /// keeps what it was asked to run.
    struct ScriptedRuntime {
        exit_code: i32,
        stdout: &'static str,
        stderr: &'static str,
        calls: std::sync::Mutex<Vec<(Vec<String>, ResourceLimits, SandboxOptions)>>,
    }

    impl ScriptedRuntime {
        fn answering(exit_code: i32, stdout: &'static str, stderr: &'static str) -> Self {
            Self {
                exit_code,
                stdout,
                stderr,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(Vec<String>, ResourceLimits, SandboxOptions)> {
            self.calls.lock().unwrap().clone()
        }

        fn result(&self, cwd: &Path) -> CommandResult {
            CommandResult {
                exit_code: self.exit_code,
                stdout: self.stdout.to_owned(),
                stderr: self.stderr.to_owned(),
                workspace: cwd.to_path_buf(),
                termination: CommandTermination::Completed,
            }
        }
    }

    #[async_trait::async_trait]
    impl RuntimeAdapter for ScriptedRuntime {
        async fn run_command(
            &self,
            _cmd: &[String],
            cwd: &Path,
            _limits: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            Ok(self.result(cwd))
        }

        async fn run_command_opts(
            &self,
            cmd: &[String],
            cwd: &Path,
            limits: &ResourceLimits,
            opts: &SandboxOptions,
        ) -> Result<CommandResult, ClassifiedError> {
            self.calls
                .lock()
                .unwrap()
                .push((cmd.to_vec(), limits.clone(), opts.clone()));
            Ok(self.result(cwd))
        }

        async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
            Ok(())
        }

        async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
            Ok(String::new())
        }
    }

    /// A server that faults once a five-byte message with its top bit set
    /// follows the opening `LOGIN`; empty messages change nothing. Replays
    /// fault exactly then, and the minimizer's output is scripted.
    struct MessageServer {
        minimizer_output: Vec<u8>,
        replays: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl MessageServer {
        fn faults(data: &[u8]) -> bool {
            let messages: Vec<&[u8]> = split_messages(data)
                .into_iter()
                .filter(|message| !message.is_empty())
                .collect();
            messages.first() == Some(&b"LOGIN".as_slice())
                && messages[1..]
                    .iter()
                    .any(|message| message.len() == 5 && message[0] & 0x80 != 0)
        }
    }

    #[async_trait::async_trait]
    impl RuntimeAdapter for MessageServer {
        async fn run_command(
            &self,
            _cmd: &[String],
            cwd: &Path,
            _limits: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            unreachable!("{cwd:?}")
        }

        async fn run_command_opts(
            &self,
            cmd: &[String],
            cwd: &Path,
            _limits: &ResourceLimits,
            opts: &SandboxOptions,
        ) -> Result<CommandResult, ClassifiedError> {
            let result = |exit_code, stderr: &str| CommandResult {
                exit_code,
                stdout: String::new(),
                stderr: stderr.to_owned(),
                workspace: cwd.to_path_buf(),
                termination: CommandTermination::Completed,
            };
            if cmd[0] == "afl-tmin" {
                let output = cmd[cmd.iter().position(|arg| arg == "-o").unwrap() + 1]
                    .trim_start_matches("/work/");
                std::fs::write(cwd.join(output), &self.minimizer_output).unwrap();
                return Ok(result(0, ""));
            }
            let data = opts.stdin.clone().unwrap_or_default();
            let faults = Self::faults(&data);
            self.replays.lock().unwrap().push(data);
            Ok(if faults {
                result(139, REPLAY_REPORT)
            } else {
                result(0, "")
            })
        }

        async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
            Ok(())
        }

        async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
            Ok(String::new())
        }
    }

    fn joined_messages(messages: &[&[u8]]) -> Vec<u8> {
        messages.join(MESSAGE_SEPARATOR.as_slice())
    }

    async fn minimized_message_input(
        input: BinaryInput,
        minimizer_output: Vec<u8>,
    ) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
        let root = tempfile::tempdir().unwrap();
        for directory in [FINDINGS_DIR, MINIMIZED_DIR] {
            std::fs::create_dir_all(root.path().join(directory)).unwrap();
        }
        let original = joined_messages(&[b"LOGIN", b"", b"\x98rash", b"junk", b"", b""]);
        let input_path = root.path().join(FINDINGS_DIR).join("crash-a");
        std::fs::write(&input_path, &original).unwrap();
        let runtime = MessageServer {
            minimizer_output,
            replays: std::sync::Mutex::new(Vec::new()),
        };
        let run = SessionRun {
            runtime: &runtime,
            root: root.path(),
            input,
            libraries: false,
            timeout_ms: 1000,
        };
        let finding = BinaryFinding {
            input: input_path,
            size: original.len() as u64,
            replay_signal: Some(11),
            signature: read_replay_report(REPLAY_REPORT).unwrap().signature,
            ..finding(&sha256_hex(&original), "")
        };
        let kept = run
            .minimize(&finding)
            .await
            .unwrap()
            .map(|minimized| std::fs::read(minimized.input).unwrap());
        let replays = runtime.replays.lock().unwrap().clone();
        (kept, replays)
    }

    #[tokio::test]
    async fn a_minimized_message_sequence_loses_empty_messages_and_spare_separators() {
        // afl-tmin deletes bytes on a fixed grid, so it cannot always take a
        // four-byte separator out whole: it left an empty message and a
        // trailing separator around the faulting message.
        let from_minimizer = joined_messages(&[b"LOGIN", b"", b"\xfd0000", b""]);
        let (kept, replays) =
            minimized_message_input(BinaryInput::SocketMessages, from_minimizer).await;
        assert_eq!(kept.unwrap(), joined_messages(&[b"LOGIN", b"\xfd0000"]));
        assert!(replays.len() <= 1 + MAX_MESSAGE_TRIALS, "{}", replays.len());
    }

    #[tokio::test]
    async fn whole_messages_the_fault_does_not_need_are_removed() {
        let from_minimizer = joined_messages(&[b"LOGIN", b"0", b"\x98rash", b"0000"]);
        let (kept, _) = minimized_message_input(BinaryInput::SocketMessages, from_minimizer).await;
        assert_eq!(kept.unwrap(), joined_messages(&[b"LOGIN", b"\x98rash"]));
    }

    #[tokio::test]
    async fn the_message_pass_is_for_message_sequences_only() {
        let from_minimizer = joined_messages(&[b"LOGIN", b"", b"\xfd0000", b""]);
        let (kept, replays) =
            minimized_message_input(BinaryInput::Socket, from_minimizer.clone()).await;
        assert_eq!(kept.unwrap(), from_minimizer);
        assert_eq!(replays.len(), 1);
    }

    #[test]
    fn messages_split_and_join_on_the_separator() {
        let data = joined_messages(&[b"LOGIN", b"", b"x", b""]);
        assert_eq!(
            split_messages(&data),
            vec![b"LOGIN".as_slice(), b"", b"x", b""]
        );
        assert_eq!(
            without_empty_messages(&data),
            joined_messages(&[b"LOGIN", b"x"])
        );
        assert_eq!(split_messages(b"plain"), vec![b"plain".as_slice()]);
        assert_eq!(
            without_message(&joined_messages(&[b"a", b"b", b"c"]), 1),
            joined_messages(&[b"a", b"c"])
        );
    }

    fn writable_mounts(sandbox: &SandboxOptions) -> Vec<String> {
        sandbox
            .extra_mounts
            .iter()
            .filter(|mount| !mount.read_only)
            .map(|mount| mount.container_path.clone())
            .collect()
    }

    #[tokio::test]
    async fn the_sandbox_architecture_is_read_from_a_read_only_probe() {
        let root = tempfile::tempdir().unwrap();
        let runtime = ScriptedRuntime::answering(0, "x86_64\n", "");
        assert_eq!(
            sandbox_machine(&runtime, root.path()).await.unwrap(),
            ElfMachine::X86_64
        );
        let calls = runtime.calls();
        let (command, limits, sandbox) = &calls[0];
        assert_eq!(command, &["uname", "-m"]);
        assert_eq!(limits.max_duration_secs, REPLAY_SECS);
        assert!(sandbox.workspace_read_only);
        assert!(sandbox.extra_mounts.is_empty());

        let unknown = ScriptedRuntime::answering(0, "riscv64\n", "");
        let error = sandbox_machine(&unknown, root.path()).await.unwrap_err();
        assert!(
            error.to_string().contains("uname -m printed 'riscv64'"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_shim_is_built_with_only_its_own_directory_writable() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join(DESOCK.directory);
        std::fs::create_dir_all(&directory).unwrap();

        // The compiler failed: its diagnostics reach the operator.
        let failing = ScriptedRuntime::answering(1, "", "desock.c:3: error: nope");
        let error = build_shim(&failing, root.path(), &DESOCK)
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("socket shim did not compile"), "{message}");
        assert!(message.contains("(exit 1)"), "{message}");
        assert!(message.contains("desock.c:3: error: nope"), "{message}");

        // A clean exit that left no library is a failure too.
        let silent = ScriptedRuntime::answering(0, "", "");
        assert!(build_shim(&silent, root.path(), &DESOCK).await.is_err());

        std::fs::write(directory.join(DESOCK.library_name), b"\x7fELF").unwrap();
        build_shim(&silent, root.path(), &DESOCK).await.unwrap();
        let calls = silent.calls();
        let (command, limits, sandbox) = &calls[1];
        assert_eq!(command, &DESOCK.build_command());
        assert_eq!(limits.max_duration_secs, SHIM_BUILD_SECS);
        assert_eq!(limits.max_cpus, 1);
        assert!(!limits.ptrace);
        assert!(sandbox.workspace_read_only);
        assert_eq!(
            writable_mounts(sandbox),
            [format!("/work/{}", DESOCK.directory)]
        );
        assert_eq!(sandbox.max_file_size_bytes, Some(MAX_FILE_BYTES));
    }

    #[test]
    fn a_session_writes_only_to_its_corpus_and_output() {
        let sandbox = session_sandbox(Path::new("session"), Some(b"seed".to_vec()));
        assert!(sandbox.workspace_read_only);
        assert_eq!(
            writable_mounts(&sandbox),
            [format!("/work/{CORPUS_DIR}"), format!("/work/{OUTPUT_DIR}")]
        );
        assert_eq!(sandbox.extra_mounts.len(), 2);
        assert_eq!(sandbox.max_file_size_bytes, Some(MAX_FILE_BYTES));
        assert_eq!(sandbox.stdin.as_deref(), Some(b"seed".as_slice()));

        let env = HashMap::from([("AFL_NO_UI".to_owned(), "1".to_owned())]);
        let limits = limits(90, env.clone());
        assert_eq!(limits.max_mem_mb, SESSION_MEMORY_MB);
        assert_eq!(limits.max_cpus, 1);
        assert_eq!(limits.max_duration_secs, 90);
        assert_eq!(limits.env, env);
        assert!(!limits.ptrace);
    }

    // Seen on a Windows Server 2025 host with a WSL 2 engine on 2026-11-22:
    // a file the fuzzer names `id:000001,sig:11,...` appears on the Windows
    // side with U+F03A in place of each colon.
    #[test]
    fn crash_files_written_through_a_windows_drive_mount_are_recognized() {
        let root = tempfile::tempdir().unwrap();
        let crashes = root.path().join("default/crashes");
        std::fs::create_dir_all(&crashes).unwrap();
        std::fs::write(crashes.join("README.txt"), b"how to").unwrap();
        std::fs::write(
            crashes.join("id\u{f03a}000000,sig\u{f03a}11,src\u{f03a}000003"),
            b"a",
        )
        .unwrap();
        let found = saved_crashes(root.path());
        assert_eq!(
            found.iter().map(|(_, signal)| *signal).collect::<Vec<_>>(),
            [Some(11)]
        );
        assert_eq!(
            crash_file_signal("id\u{f03a}000001,sig\u{f03a}06,src\u{f03a}000000"),
            Some(6)
        );
    }
}

#[cfg(test)]
#[path = "binary_only_live_tests.rs"]
mod live_tests;
