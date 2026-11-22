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

use hf_core::crash::CrashKind;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandTermination, ResourceLimits, RuntimeAdapter, SandboxMount, SandboxOptions,
};
use hf_core::target::Sanitizer;
use hf_guardrails::Action;
use serde::{Deserialize, Serialize};
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

/// The signal AFL++ recorded in a crash file name (`id:000000,sig:11,...`).
#[must_use]
pub fn crash_file_signal(name: &str) -> Option<u32> {
    name.split(',')
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
) -> Result<Vec<String>, ClassifiedError> {
    let mut extra_args = vec!["-Q".to_owned()];
    if input == BinaryInput::SocketMessages {
        extra_args.extend([
            "-x".to_owned(),
            format!("/work/{DESOCK_DIR}/{MESSAGE_DICTIONARY_NAME}"),
        ]);
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
) -> Result<bool, ClassifiedError> {
    write_new(&root.join(TARGET_NAME), image, true)?;
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
            let name = entry.file_name().to_string_lossy().into_owned();
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

/// The environment of the fuzz run.
fn session_env(
    libraries: bool,
    input: BinaryInput,
) -> Result<HashMap<String, String>, ClassifiedError> {
    emulated_env(libraries, input, false)
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

fn limits(duration_secs: u64, env: HashMap<String, String>) -> ResourceLimits {
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
        let Ok(data) = read_bounded(&saved, MAX_FINDING_BYTES, "minimized input") else {
            return Ok(None);
        };
        let size = data.len() as u64;
        let sha256 = sha256_hex(&data);
        let same_crash = if data.is_empty() || size >= finding.size {
            false
        } else {
            self.replay(&format!("{MINIMIZED_DIR}/{name}"), data)
                .await?
                .is_some_and(|replay| {
                    replay.signal.is_some()
                        && replay.signal == finding.replay_signal
                        && (finding.signature.is_empty()
                            || replay
                                .report
                                .is_some_and(|report| report.signature == finding.signature))
                })
        };
        if !same_crash {
            // Only inputs known to reproduce the finding stay in `minimized`.
            let _ = std::fs::remove_file(&saved);
            return Ok(None);
        }
        Ok(Some(MinimizedInput {
            input: saved,
            sha256,
            size,
        }))
    }
}

/// Keep, replay, group and minimize the crash inputs of a finished session.
/// Returns the findings, how many are distinct, and how many crash files
/// were beyond the per-session cap.
async fn collect_findings(
    run: &SessionRun<'_>,
) -> Result<(Vec<BinaryFinding>, usize, usize), ClassifiedError> {
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

/// A request that passed validation, before anything is staged or run.
struct AdmittedBinary {
    image: Vec<u8>,
    machine: ElfMachine,
    sha256: String,
    command: Vec<String>,
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
    let sha256 = sha256_hex(&image);
    let command = fuzz_command(request.input, request.duration_secs, request.timeout_ms)?;
    Ok(AdmittedBinary {
        image,
        machine,
        sha256,
        command,
    })
}

/// Stage, fuzz, collect, replay, and report one session in `root`.
async fn run_session(
    runtime: &dyn RuntimeAdapter,
    root: &Path,
    session: Uuid,
    request: &BinaryFuzzRequest,
    admitted: AdmittedBinary,
) -> Result<BinaryFuzzOutcome, ClassifiedError> {
    let libraries = stage_session(root, &admitted.image, request)?;
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

    let result = runtime
        .run_command_opts(
            &admitted.command,
            root,
            &limits(
                request.duration_secs + SHUTDOWN_GRACE_SECS,
                session_env(libraries, request.input)?,
            ),
            &session_sandbox(root, None),
        )
        .await?;
    let stats = std::fs::read(root.join(OUTPUT_DIR).join("default").join("fuzzer_stats"))
        .ok()
        .and_then(|contents| hf_engine::afl::parse_fuzzer_stats(&contents).ok());
    let Some(stats) = stats else {
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

    let (findings, distinct_findings, findings_omitted) = collect_findings(&SessionRun {
        runtime,
        root,
        input: request.input,
        libraries,
        timeout_ms: request.timeout_ms,
    })
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
        self.authorize_recorded(Action::RunHarness, "binary_fuzz", Some(&request.project))
            .await?;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        let session = Uuid::new_v4();
        let root = ensure_workspace_directory(
            &prepare_configured_workspace_root()?,
            &PathBuf::from(project_slug(&request.project))
                .join(".binary")
                .join(&admitted.sha256[..16])
                .join(session.to_string()),
        )?;
        run_session(self.runtime.as_ref(), &root, session, request, admitted).await
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
    fn the_fuzz_command_is_the_afl_adapter_argv_in_qemu_mode() {
        let file = fuzz_command(BinaryInput::File, 60, 1000).unwrap();
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
        let stdin = fuzz_command(BinaryInput::Stdin, 60, 1000).unwrap();
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
        };
        assert!(stage_session(root.path(), b"\x7fELF image", &request).unwrap());
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
        assert!(!stage_session(bare.path(), b"\x7fELF", &request).unwrap());
        assert_eq!(
            std::fs::read(bare.path().join("corpus/seed-default")).unwrap(),
            DEFAULT_SEED
        );
        assert_eq!(
            session_env(true, BinaryInput::File)
                .unwrap()
                .get("QEMU_SET_ENV")
                .map(String::as_str),
            Some("LD_LIBRARY_PATH=/work/libs")
        );
        assert!(!session_env(false, BinaryInput::Stdin)
            .unwrap()
            .contains_key("QEMU_SET_ENV"));
        assert!(!bare.path().join("desock").exists());
    }

    #[test]
    fn a_socket_session_takes_stdin_input_and_preloads_the_shim_into_the_target_only() {
        // The fuzzer delivers the input on standard input; the shim hands it
        // to the server as its first connection.
        let command = fuzz_command(BinaryInput::Socket, 60, 1000).unwrap();
        assert_eq!(command.last().map(String::as_str), Some("/work/target"));
        assert_eq!(
            replay_command(BinaryInput::Socket, "findings/crash-0123456789abcdef"),
            replay_command(BinaryInput::Stdin, "findings/crash-0123456789abcdef")
        );

        // The emulator passes the preload to the emulated process only.
        let env = session_env(false, BinaryInput::Socket).unwrap();
        assert_eq!(
            env.get("QEMU_SET_ENV").map(String::as_str),
            Some("LD_PRELOAD=/work/desock/oxfuzz_desock.so")
        );
        assert!(!env.contains_key("LD_PRELOAD") && !env.contains_key("AFL_PRELOAD"));
        assert_eq!(
            session_env(true, BinaryInput::Socket)
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
        };
        stage_session(root.path(), b"\x7fELF", &request).unwrap();
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
        assert!(!session_env(false, BinaryInput::File)
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
        };
        stage_session(root.path(), b"\x7fELF", &request).unwrap();
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
        let command = fuzz_command(BinaryInput::SocketMessages, 60, 1000).unwrap();
        let at = command.iter().position(|arg| arg == "-x").unwrap();
        assert_eq!(command[at + 1], "/work/desock/messages.dict");
        assert_eq!(command.last().map(String::as_str), Some("/work/target"));
        assert!(!fuzz_command(BinaryInput::Socket, 60, 1000)
            .unwrap()
            .contains(&"-x".to_owned()));

        // Only a message session asks the shim to split the input, in the
        // fuzz run, the replays and the minimizer alike.
        assert_eq!(
            session_env(false, BinaryInput::SocketMessages)
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
        assert!(!session_env(false, BinaryInput::Socket)
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
        };
        stage_session(root.path(), b"\x7fELF", &request).unwrap();
        assert!(root.path().join("desock/oxfuzz_desock.c").is_file());
        assert_eq!(
            std::fs::read_to_string(root.path().join("desock/messages.dict")).unwrap(),
            message_dictionary()
        );
        let plain = tempfile::tempdir().unwrap();
        request.input = BinaryInput::Socket;
        stage_session(plain.path(), b"\x7fELF", &request).unwrap();
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

    /// Two faults behind one prefix: a null write for any `FUZZ...` input,
    /// and an abort for `FUZZA...`. Inputs differ, the faulting sites do not.
    const PLANTED_C: &str = "#include <stdio.h>\n#include <stdlib.h>\n\n__attribute__((noinline)) static void inner(unsigned char *b, size_t n) {\n  if (n > 4 && b[4] == 'A') abort();\n  volatile int *p = 0;\n  *p = b[0];\n}\n\nint main(int argc, char **argv) {\n  FILE *in = argc > 1 ? fopen(argv[1], \"rb\") : stdin;\n  if (!in) return 1;\n  unsigned char b[64];\n  size_t n = fread(b, 1, sizeof b, in);\n  if (n > 3 && b[0] == 'F' && b[1] == 'U' && b[2] == 'Z' && b[3] == 'Z') inner(b, n);\n  return 0;\n}\n";

    /// Build an uninstrumented crashing program in the sandbox, then run it
    /// through a whole session in each input mode: AFL++ QEMU mode finds the
    /// crash, and the replay under the emulator ends with the same signal.
    #[tokio::test]
    #[ignore = "requires a local Docker daemon and the pinned sandbox image"]
    async fn live_qemu_session_finds_and_confirms_a_planted_crash() {
        assert!(hf_runtime::docker_daemon_ready());
        let root = tempfile::tempdir().unwrap();
        let runtime = hf_runtime::docker::DockerRuntime::new(
            hf_runtime::RuntimeConfig::default(),
            root.path(),
        );
        let build = root.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("planted.c"), PLANTED_C).unwrap();
        let compiled = runtime
            .run_command_opts(
                &[
                    "clang".to_owned(),
                    "-O1".to_owned(),
                    "/work/planted.c".to_owned(),
                    "-o".to_owned(),
                    "/work/planted".to_owned(),
                ],
                &build,
                &limits(120, HashMap::new()),
                &SandboxOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(compiled.exit_code, 0, "{}", compiled.stderr);
        let seeds = root.path().join("seeds");
        std::fs::create_dir_all(&seeds).unwrap();
        std::fs::write(seeds.join("near"), b"FUZ!-a-longer-seed-to-shrink").unwrap();

        for input in [BinaryInput::File, BinaryInput::Stdin] {
            let request = BinaryFuzzRequest {
                project: root.path().join("project"),
                binary: build.join("planted"),
                input,
                seeds: Some(seeds.clone()),
                libraries: None,
                duration_secs: 40,
                timeout_ms: 1000,
            };
            let session = Uuid::new_v4();
            let session_root = root.path().join(format!("session-{session}"));
            std::fs::create_dir_all(&session_root).unwrap();
            let outcome = run_session(
                &runtime,
                &session_root,
                session,
                &request,
                admit(&request).unwrap(),
            )
            .await
            .unwrap();
            println!(
                "{input:?}: execs {:?} at {:?}/s, findings {:?}",
                outcome.execs_done, outcome.execs_per_sec, outcome.findings
            );
            assert!(outcome.execs_done.unwrap_or(0) > 0, "{input:?}");
            assert!(
                !outcome.findings.is_empty(),
                "{input:?}: the crash was found"
            );
            for finding in &outcome.findings {
                assert!(std::fs::read(&finding.input).unwrap().starts_with(b"FUZZ"));
                assert!(finding.confirmed, "{input:?}: {finding:?}");
                assert_eq!(finding.signature.len(), 64, "{input:?}: {finding:?}");
                assert!(finding.frames[0].contains("/work/target+0x"), "{finding:?}");
            }
            // Many inputs, at most two faulting sites: the signatures say so.
            let segv: Vec<&BinaryFinding> = outcome
                .findings
                .iter()
                .filter(|finding| finding.kind == Some(CrashKind::Segv))
                .collect();
            assert!(!segv.is_empty(), "{input:?}: the null write was found");
            assert!(segv.iter().all(|finding| finding.replay_signal == Some(11)));
            assert!(
                segv.iter()
                    .all(|finding| finding.signature == segv[0].signature),
                "{input:?}: one faulting site is one signature"
            );
            assert_eq!(
                segv.iter()
                    .filter(|finding| finding.duplicate_of.is_none())
                    .count(),
                1
            );
            assert!(
                segv[0].summary.starts_with("SEGV (signal 11) at"),
                "{:?}",
                segv[0]
            );
            let aborts = outcome
                .findings
                .iter()
                .filter(|finding| finding.kind == Some(CrashKind::Abort))
                .count();
            assert!(outcome.distinct_findings <= 2, "{input:?}");
            assert_eq!(
                outcome.distinct_findings,
                1 + usize::from(aborts > 0),
                "{input:?}"
            );
            // The first null-write input shrinks to the four bytes that
            // reach the fault, and the shrunk input is the same crash. An
            // input that is already those four bytes has nothing smaller.
            match &segv[0].minimized {
                Some(minimized) => {
                    assert_eq!(
                        std::fs::read(&minimized.input).unwrap(),
                        b"FUZZ",
                        "{input:?}"
                    );
                    assert!(minimized.size < segv[0].size, "{input:?}");
                }
                None => assert_eq!(segv[0].size, 4, "{input:?}: {:?}", segv[0]),
            }
            let report: BinaryFuzzOutcome =
                serde_json::from_slice(&std::fs::read(session_root.join(REPORT_NAME)).unwrap())
                    .unwrap();
            assert_eq!(report.distinct_findings, outcome.distinct_findings);
        }
    }

    const PLANTED_SERVER_C: &str = "#include <netinet/in.h>\n#include <poll.h>\n#include <string.h>\n#include <sys/socket.h>\n#include <unistd.h>\n\nint main(void) {\n  int one = 1;\n  int s = socket(AF_INET, SOCK_STREAM, 0);\n  struct sockaddr_in a;\n  memset(&a, 0, sizeof a);\n  a.sin_family = AF_INET;\n  a.sin_port = htons(80);\n  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);\n  if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) return 2;\n  if (listen(s, 8) != 0) return 3;\n  for (;;) {\n    struct pollfd p = {s, POLLIN, 0};\n    if (poll(&p, 1, -1) <= 0) return 4;\n    int c = accept(s, 0, 0);\n    if (c < 0) return 5;\n    setsockopt(c, IPPROTO_TCP, 1, &one, sizeof one);\n    unsigned char b[64];\n    ssize_t n = recv(c, b, sizeof b, 0);\n    if (n > 3 && b[0] == 'F' && b[1] == 'U' && b[2] == 'Z' && b[3] == 'Z') {\n      volatile int *q = 0;\n      *q = 1;\n    }\n    send(c, \"ok\\n\", 3, 0);\n    close(c);\n  }\n}\n";

    /// A server that binds a privileged port, waits in `poll`, and reads its
    /// request with `recv` is fuzzed through the socket shim: the planted
    /// crash is found, its replay confirmed, and a benign request ends the
    /// process cleanly at the second `accept`.
    #[tokio::test]
    #[ignore = "requires a local Docker daemon and the pinned sandbox image"]
    async fn live_socket_session_fuzzes_a_server_through_its_first_connection() {
        assert!(hf_runtime::docker_daemon_ready());
        let root = tempfile::tempdir().unwrap();
        let runtime = hf_runtime::docker::DockerRuntime::new(
            hf_runtime::RuntimeConfig::default(),
            root.path(),
        );
        let build = root.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("server.c"), PLANTED_SERVER_C).unwrap();
        let compiled = runtime
            .run_command_opts(
                &[
                    "clang".to_owned(),
                    "-O1".to_owned(),
                    "/work/server.c".to_owned(),
                    "-o".to_owned(),
                    "/work/server".to_owned(),
                ],
                &build,
                &limits(120, HashMap::new()),
                &SandboxOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(compiled.exit_code, 0, "{}", compiled.stderr);
        let seeds = root.path().join("seeds");
        std::fs::create_dir_all(&seeds).unwrap();
        std::fs::write(seeds.join("near"), b"FUZ!").unwrap();

        let request = BinaryFuzzRequest {
            project: root.path().join("project"),
            binary: build.join("server"),
            input: BinaryInput::Socket,
            seeds: Some(seeds),
            libraries: None,
            duration_secs: 40,
            timeout_ms: 1000,
        };
        let session = Uuid::new_v4();
        let session_root = root.path().join("session");
        std::fs::create_dir_all(&session_root).unwrap();
        let outcome = run_session(
            &runtime,
            &session_root,
            session,
            &request,
            admit(&request).unwrap(),
        )
        .await
        .unwrap();
        println!(
            "socket: execs {:?} at {:?}/s, hangs {:?}, findings {:?}",
            outcome.execs_done, outcome.execs_per_sec, outcome.saved_hangs, outcome.findings
        );
        assert!(outcome.execs_done.unwrap_or(0) > 100);
        assert_eq!(
            outcome.saved_hangs,
            Some(0),
            "a benign request must not hang"
        );
        assert!(!outcome.findings.is_empty(), "the crash was found");
        let finding = &outcome.findings[0];
        assert!(std::fs::read(&finding.input).unwrap().starts_with(b"FUZZ"));
        assert_eq!(finding.fuzzer_signal, Some(11));
        assert_eq!(finding.replay_signal, Some(11));
        assert!(finding.confirmed);
        // Both shims are loaded in a server replay: the socket shim delivers
        // the request and the reporter names the fault in the server.
        assert_eq!(finding.kind, Some(CrashKind::Segv), "{finding:?}");
        assert_eq!(finding.signature.len(), 64);
        assert!(finding.frames[0].contains("/work/target+0x"), "{finding:?}");
        assert_eq!(outcome.distinct_findings, 1);
        let minimized = finding.minimized.as_ref().expect("minimized");
        assert_eq!(std::fs::read(&minimized.input).unwrap(), b"FUZZ");

        // A benign request: the server answers, loops to `accept`, and the
        // shim ends the process with a clean exit.
        let benign = runtime
            .run_command_opts(
                &replay_command(BinaryInput::Socket, "unused"),
                &session_root,
                &limits(
                    REPLAY_SECS,
                    session_env(false, BinaryInput::Socket).unwrap(),
                ),
                &session_sandbox(&session_root, Some(b"hello".to_vec())),
            )
            .await
            .unwrap();
        assert_eq!(benign.termination, CommandTermination::Completed);
        assert_eq!(benign.exit_code, 0, "{}", benign.stderr);
    }

    /// A datagram server: blocks in `recvfrom`, checks the sender's address
    /// family, answers with `sendto`, and faults on a `FUZZ` datagram.
    const PLANTED_UDP_C: &str = "#include <netinet/in.h>\n#include <string.h>\n#include <sys/socket.h>\nint main(void) {\n  int s = socket(AF_INET, SOCK_DGRAM, 0);\n  struct sockaddr_in a; memset(&a, 0, sizeof a);\n  a.sin_family = AF_INET; a.sin_port = htons(53);\n  if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) return 2;\n  for (;;) {\n    unsigned char b[512]; struct sockaddr_in from; socklen_t fl = sizeof from;\n    ssize_t n = recvfrom(s, b, sizeof b, 0, (struct sockaddr *)&from, &fl);\n    if (n < 0) return 3;\n    if (from.sin_family != AF_INET) return 4;\n    if (n > 3 && b[0] == 'F' && b[1] == 'U' && b[2] == 'Z' && (b[3] & 0x80)) { volatile int *q = 0; *q = 1; }\n    sendto(s, \"ok\", 2, 0, (struct sockaddr *)&from, fl);\n  }\n}\n";

    /// A stateful datagram server on a non-blocking socket behind `poll`:
    /// it faults on a datagram whose first byte has the high bit set, but
    /// only after a separate `HELO` datagram.
    const PLANTED_UDP_STATE_C: &str = "#include <fcntl.h>\n#include <netinet/in.h>\n#include <poll.h>\n#include <string.h>\n#include <sys/socket.h>\nint main(void) {\n  int s = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0), greeted = 0;\n  struct sockaddr_in a; memset(&a, 0, sizeof a);\n  a.sin_family = AF_INET; a.sin_port = htons(5000);\n  if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) return 2;\n  for (;;) {\n    struct pollfd p = {s, POLLIN, 0};\n    if (poll(&p, 1, -1) <= 0) return 3;\n    for (;;) {\n      unsigned char b[512]; struct sockaddr_in from; socklen_t fl = sizeof from;\n      ssize_t n = recvfrom(s, b, sizeof b, 0, (struct sockaddr *)&from, &fl);\n      if (n < 0) break;\n      if (n == 4 && memcmp(b, \"HELO\", 4) == 0) greeted = 1;\n      else if (greeted && n >= 1 && (b[0] & 0x80)) { volatile int *q = 0; *q = 1; }\n      sendto(s, \"ok\", 2, 0, (struct sockaddr *)&from, fl);\n    }\n  }\n}\n";

    /// A stateful stream server that reads one request per `recv`: it faults
    /// on a five-byte request whose first byte has the high bit set, but only
    /// after a five-byte `LOGIN` request. One unprompted byte stream delivers
    /// both in a single `recv` and never reaches the fault.
    const PLANTED_TCP_STATE_C: &str = "#include <netinet/in.h>\n#include <string.h>\n#include <sys/socket.h>\n#include <unistd.h>\nint main(void) {\n  int s = socket(AF_INET, SOCK_STREAM, 0);\n  struct sockaddr_in a; memset(&a, 0, sizeof a);\n  a.sin_family = AF_INET; a.sin_port = htons(21);\n  if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) return 2;\n  if (listen(s, 4) != 0) return 3;\n  for (;;) {\n    int c = accept(s, 0, 0), authed = 0;\n    if (c < 0) return 4;\n    for (;;) {\n      unsigned char b[256];\n      ssize_t n = recv(c, b, sizeof b, 0);\n      if (n <= 0) break;\n      if (n == 5 && memcmp(b, \"LOGIN\", 5) == 0) { authed = 1; send(c, \"230\\n\", 4, 0); }\n      else if (authed && n == 5 && (b[0] & 0x80)) { volatile int *q = 0; *q = 1; }\n      else send(c, \"500\\n\", 4, 0);\n    }\n    close(c);\n  }\n}\n";

    fn joined(first: &[u8], second: &[u8]) -> Vec<u8> {
        [first, MESSAGE_SEPARATOR.as_slice(), second].concat()
    }

    /// One planted server and what its smallest crashing input looks like.
    struct ServerCase {
        name: &'static str,
        source: &'static str,
        input: BinaryInput,
        seed: Vec<u8>,
        /// The messages that must precede the faulting one.
        opening: &'static [u8],
        /// The length the faulting message must have.
        faulting_len: usize,
        /// An input that does not reach the fault.
        benign: Vec<u8>,
    }

    /// The socket shim beyond one unprompted stream: a datagram server, and
    /// stateful exchanges over a stream and over datagrams where the fault is
    /// reachable only when each message arrives as its own read.
    #[tokio::test]
    #[ignore = "requires a local Docker daemon and the pinned sandbox image"]
    async fn live_socket_sessions_reach_datagram_servers_and_stateful_exchanges() {
        assert!(hf_runtime::docker_daemon_ready());
        let root = tempfile::tempdir().unwrap();
        let runtime = hf_runtime::docker::DockerRuntime::new(
            hf_runtime::RuntimeConfig::default(),
            root.path(),
        );
        let cases = [
            ServerCase {
                name: "udp",
                source: PLANTED_UDP_C,
                input: BinaryInput::Socket,
                seed: b"FUZ!".to_vec(),
                opening: b"",
                faulting_len: 4,
                benign: b"hello".to_vec(),
            },
            ServerCase {
                name: "udp-state",
                source: PLANTED_UDP_STATE_C,
                input: BinaryInput::SocketMessages,
                seed: joined(b"HELO", b"boom"),
                opening: b"HELO",
                faulting_len: 1,
                benign: joined(b"\xffoom", b"HELO"),
            },
            ServerCase {
                name: "tcp-state",
                source: PLANTED_TCP_STATE_C,
                input: BinaryInput::SocketMessages,
                seed: joined(b"LOGIN", b"crash"),
                opening: b"LOGIN",
                faulting_len: 5,
                benign: b"LOGIN\xffrash".to_vec(),
            },
        ];
        for ServerCase {
            name,
            source,
            input,
            seed,
            opening,
            faulting_len,
            benign,
        } in cases
        {
            let build = root.path().join(format!("build-{name}"));
            std::fs::create_dir_all(&build).unwrap();
            std::fs::write(build.join("server.c"), source).unwrap();
            let compiled = runtime
                .run_command_opts(
                    &[
                        "clang".to_owned(),
                        "-O1".to_owned(),
                        "/work/server.c".to_owned(),
                        "-o".to_owned(),
                        "/work/server".to_owned(),
                    ],
                    &build,
                    &limits(120, HashMap::new()),
                    &SandboxOptions::default(),
                )
                .await
                .unwrap();
            assert_eq!(compiled.exit_code, 0, "{name}: {}", compiled.stderr);
            let seeds = root.path().join(format!("seeds-{name}"));
            std::fs::create_dir_all(&seeds).unwrap();
            std::fs::write(seeds.join("near"), &seed).unwrap();

            let request = BinaryFuzzRequest {
                project: root.path().join("project"),
                binary: build.join("server"),
                input,
                seeds: Some(seeds),
                libraries: None,
                duration_secs: 40,
                timeout_ms: 1000,
            };
            let session_root = root.path().join(format!("session-{name}"));
            std::fs::create_dir_all(&session_root).unwrap();
            let outcome = run_session(
                &runtime,
                &session_root,
                Uuid::new_v4(),
                &request,
                admit(&request).unwrap(),
            )
            .await
            .unwrap();
            println!(
                "{name}: execs {:?} at {:?}/s, hangs {:?}, findings {}, distinct {}",
                outcome.execs_done,
                outcome.execs_per_sec,
                outcome.saved_hangs,
                outcome.findings.len(),
                outcome.distinct_findings
            );
            assert!(outcome.execs_done.unwrap_or(0) > 100, "{name}");
            assert_eq!(outcome.saved_hangs, Some(0), "{name}: no input may hang");
            assert_eq!(
                outcome.distinct_findings, 1,
                "{name}: {:?}",
                outcome.findings
            );
            let finding = &outcome.findings[0];
            assert!(finding.confirmed, "{name}: {finding:?}");
            assert_eq!(finding.kind, Some(CrashKind::Segv), "{name}: {finding:?}");
            // The smallest input that reaches the fault: the opening
            // message when the server needs one, then the faulting message
            // on its own.
            let smallest = finding
                .minimized
                .as_ref()
                .map_or(&finding.input, |minimized| &minimized.input);
            let smallest = std::fs::read(smallest).unwrap();
            let faulting = if opening.is_empty() {
                smallest.as_slice()
            } else {
                let prefix = joined(opening, b"");
                assert!(smallest.starts_with(&prefix), "{name}: {smallest:?}");
                &smallest[prefix.len()..]
            };
            assert_eq!(faulting.len(), faulting_len, "{name}: {smallest:?}");
            assert!(faulting.iter().any(|byte| byte & 0x80 != 0), "{name}");

            // An input that does not reach the fault ends the process
            // cleanly once the server asks for more.
            let clean = runtime
                .run_command_opts(
                    &replay_command(input, "unused"),
                    &session_root,
                    &limits(REPLAY_SECS, replay_env(false, input).unwrap()),
                    &session_sandbox(&session_root, Some(benign)),
                )
                .await
                .unwrap();
            assert_eq!(clean.termination, CommandTermination::Completed, "{name}");
            assert_eq!(clean.exit_code, 0, "{name}: {}", clean.stderr);
        }
    }
}
