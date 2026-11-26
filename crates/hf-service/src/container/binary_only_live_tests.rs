//! Live binary-only sessions in the pinned sandbox image. Each test builds an
//! uninstrumented program with a planted crash and runs a whole session over
//! it, so they need a local Docker daemon and are ignored by default:
//! `cargo test -p hf-service --lib binary_only::live_tests -- --ignored`.

use super::*;
use std::collections::HashMap;
use std::time::Duration;

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
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
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
            dictionary: Vec::new(),
            continue_from: None,
            compcov: false,
            persistent: None,
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
            &StagedExtras::default(),
            &|_| {},
            &CancellationToken::new(),
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

const PLANTED_MAGIC_C: &str = "#include <stdio.h>\n#include <string.h>\n\nint main(int argc, char **argv) {\n  unsigned char b[64] = {0};\n  FILE *f = fopen(argv[1], \"rb\");\n  if (!f) return 1;\n  size_t n = fread(b, 1, sizeof b, f);\n  fclose(f);\n  if (n >= 14 && memcmp(b, \"MAGIC_TOKEN_42\", 14) == 0) {\n    volatile int *q = 0;\n    *q = 1;\n  }\n  return 0;\n}\n";

/// The operator's dictionary reaches AFL++: a crash behind a 14-byte
/// token that blind mutation does not find in seconds is found when the
/// token is in the dictionary. A continued session then starts from the
/// first session's queue.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_dictionary_reaches_afl_and_a_session_continues_from_its_queue() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
    let build = root.path().join("build");
    std::fs::create_dir_all(&build).unwrap();
    std::fs::write(build.join("magic.c"), PLANTED_MAGIC_C).unwrap();
    let compiled = runtime
        .run_command_opts(
            &["clang", "-O1", "/work/magic.c", "-o", "/work/magic"].map(str::to_owned),
            &build,
            &limits(120, HashMap::new()),
            &SandboxOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(compiled.exit_code, 0, "{}", compiled.stderr);
    let image = std::fs::read(build.join("magic")).unwrap();
    let profile = super::super::binary_profile::profile_binary(&image).unwrap();
    assert_eq!(profile.suggested_input, BinaryInput::File, "{profile:?}");
    assert!(
        profile
            .dictionary
            .iter()
            .any(|token| token == "MAGIC_TOKEN_42"),
        "{profile:?}"
    );

    let tokens = vec!["MAGIC_TOKEN_42".to_owned()];
    let request = BinaryFuzzRequest {
        project: root.path().join("project"),
        binary: build.join("magic"),
        input: BinaryInput::File,
        seeds: None,
        libraries: None,
        duration_secs: 30,
        timeout_ms: 1000,
        dictionary: tokens.clone(),
        continue_from: None,
        compcov: false,
        persistent: None,
    };
    let first_root = root.path().join("first");
    std::fs::create_dir_all(&first_root).unwrap();
    let first = run_session(
        &runtime,
        &first_root,
        Uuid::new_v4(),
        &request,
        admit(&request).unwrap(),
        &StagedExtras {
            dictionary: Some(super::super::binary_profile::render_dictionary(&tokens).unwrap()),
            carried: Vec::new(),
        },
        &|_| {},
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    println!(
        "first: execs {:?}, findings {}",
        first.execs_done,
        first.findings.len()
    );
    assert_eq!(first.dictionary_tokens, 1);
    assert!(first.started_at.is_some() && first.finished_at.is_some());
    assert!(
        first.findings.iter().any(|finding| finding.confirmed
            && std::fs::read(&finding.input)
                .unwrap()
                .starts_with(b"MAGIC_TOKEN_42")),
        "the dictionary token led AFL++ to the crash: {:?}",
        first.findings
    );

    let carried = previous_queue(&first_root).unwrap();
    assert!(!carried.is_empty());
    let continued = BinaryFuzzRequest {
        dictionary: Vec::new(),
        duration_secs: 10,
        continue_from: Some(first.session),
        ..request
    };
    let second_root = root.path().join("second");
    std::fs::create_dir_all(&second_root).unwrap();
    let second = run_session(
        &runtime,
        &second_root,
        Uuid::new_v4(),
        &continued,
        admit(&continued).unwrap(),
        &StagedExtras {
            dictionary: None,
            carried: carried.clone(),
        },
        &|_| {},
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    let staged = std::fs::read_dir(second_root.join(CORPUS_DIR))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(CARRIED_PREFIX)
        })
        .count();
    println!("second: carried {staged}, execs {:?}", second.execs_done);
    assert!(staged > 0 && staged <= carried.len());
    assert_eq!(second.continued_from, Some(first.session));
    assert!(second.execs_done.unwrap_or(0) > 0);
}

const PLANTED_INTEGER_MAGIC_C: &str = "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\nint main(int argc, char **argv) {\n  unsigned char b[64] = {0};\n  FILE *f = fopen(argv[1], \"rb\");\n  if (!f) return 1;\n  size_t n = fread(b, 1, sizeof b, f);\n  fclose(f);\n  uint32_t v;\n  memcpy(&v, b, 4);\n  if (n >= 4 && v == 0x4f58465aU) {\n    volatile int *q = 0;\n    *q = 1;\n  }\n  return 0;\n}\n";

/// `CompCov` reaches a crash behind a 32-bit magic value, and stopping a
/// five-minute session after thirty seconds ends the fuzz run early while
/// the session still replays and reports what it found.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_compcov_finds_a_magic_value_and_a_stopped_session_keeps_its_results() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
    let build = root.path().join("build");
    std::fs::create_dir_all(&build).unwrap();
    std::fs::write(build.join("magic.c"), PLANTED_INTEGER_MAGIC_C).unwrap();
    let compiled = runtime
        .run_command_opts(
            &["clang", "-O1", "/work/magic.c", "-o", "/work/magic"].map(str::to_owned),
            &build,
            &limits(120, HashMap::new()),
            &SandboxOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(compiled.exit_code, 0, "{}", compiled.stderr);
    let request = BinaryFuzzRequest {
        project: root.path().join("project"),
        binary: build.join("magic"),
        input: BinaryInput::File,
        seeds: None,
        libraries: None,
        duration_secs: 300,
        timeout_ms: 1000,
        dictionary: Vec::new(),
        continue_from: None,
        compcov: true,
        persistent: None,
    };
    let session_root = root.path().join("session");
    std::fs::create_dir_all(&session_root).unwrap();
    let cancel = CancellationToken::new();
    let stopper = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        stopper.cancel();
    });
    let started = std::time::Instant::now();
    let outcome = run_session(
        &runtime,
        &session_root,
        Uuid::new_v4(),
        &request,
        admit(&request).unwrap(),
        &StagedExtras::default(),
        &|_| {},
        &cancel,
    )
    .await
    .unwrap();
    println!(
        "stopped {} after {:?}: execs {:?}, findings {}",
        outcome.stopped,
        started.elapsed(),
        outcome.execs_done,
        outcome.findings.len()
    );
    assert!(outcome.stopped && outcome.compcov);
    assert!(
        started.elapsed() < Duration::from_secs(150),
        "the stop ended the run"
    );
    assert!(
        outcome.findings.iter().any(|finding| finding.confirmed),
        "CompCov reached the magic value: {:?}",
        outcome.findings
    );
    let report: BinaryFuzzOutcome =
        serde_json::from_slice(&std::fs::read(session_root.join(REPORT_NAME)).unwrap()).unwrap();
    assert!(report.stopped);
}

/// Persistent mode loops on `main` inside one emulated process: the same
/// file-reading target runs faster than with a process per input, stays
/// stable, and records the resolved entry. Crashes found in the loop are
/// still confirmed by a fresh-process replay.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_persistent_session_loops_on_main_faster_and_stays_stable() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
    let build = root.path().join("build");
    std::fs::create_dir_all(&build).unwrap();
    std::fs::write(build.join("magic.c"), PLANTED_INTEGER_MAGIC_C).unwrap();
    let compiled = runtime
        .run_command_opts(
            &["clang", "-O1", "/work/magic.c", "-o", "/work/magic"].map(str::to_owned),
            &build,
            &limits(120, HashMap::new()),
            &SandboxOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(compiled.exit_code, 0, "{}", compiled.stderr);
    let mut outcomes = Vec::new();
    for persistent in [
        None,
        Some(BinaryPersistent {
            entry: "main".to_owned(),
            iterations: 1000,
            restore_memory: false,
        }),
    ] {
        let request = BinaryFuzzRequest {
            project: root.path().join("project"),
            binary: build.join("magic"),
            input: BinaryInput::File,
            seeds: None,
            libraries: None,
            duration_secs: 25,
            timeout_ms: 1000,
            dictionary: Vec::new(),
            continue_from: None,
            compcov: true,
            persistent,
        };
        let session_root = root.path().join(format!("session-{}", outcomes.len()));
        std::fs::create_dir_all(&session_root).unwrap();
        let outcome = run_session(
            &runtime,
            &session_root,
            Uuid::new_v4(),
            &request,
            admit(&request).unwrap(),
            &StagedExtras::default(),
            &|_| {},
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        println!(
            "persistent {:?}: {:?} execs/s, stability {:?}, findings {}",
            outcome.persistent_entry,
            outcome.execs_per_sec,
            outcome.stability_pct,
            outcome.findings.len()
        );
        assert!(
            outcome.findings.iter().all(|finding| finding.confirmed),
            "every finding replays in a fresh process: {:?}",
            outcome.findings
        );
        outcomes.push(outcome);
    }
    let (plain, looped) = (&outcomes[0], &outcomes[1]);
    assert_eq!(plain.persistent_entry, None);
    let entry = looped.persistent_entry.as_deref().unwrap();
    assert!(entry.starts_with("main (target+0x"), "{entry}");
    assert!(
        looped.stability_pct.unwrap() >= 90.0,
        "{:?}",
        looped.stability_pct
    );
    assert!(
        looped.execs_per_sec.unwrap() > 1.5 * plain.execs_per_sec.unwrap(),
        "persistent {:?} vs plain {:?}",
        looped.execs_per_sec,
        plain.execs_per_sec
    );
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
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
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
        dictionary: Vec::new(),
        continue_from: None,
        compcov: false,
        persistent: None,
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
        &StagedExtras::default(),
        &|_| {},
        &CancellationToken::new(),
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
                session_env(false, BinaryInput::Socket, false, None).unwrap(),
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
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
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
            dictionary: Vec::new(),
            continue_from: None,
            compcov: false,
            persistent: None,
        };
        let session_root = root.path().join(format!("session-{name}"));
        std::fs::create_dir_all(&session_root).unwrap();
        let outcome = run_session(
            &runtime,
            &session_root,
            Uuid::new_v4(),
            &request,
            admit(&request).unwrap(),
            &StagedExtras::default(),
            &|_| {},
            &CancellationToken::new(),
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
