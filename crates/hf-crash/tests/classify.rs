//! Tests for crash classification and ingestion.

use hf_core::crash::CrashKind;
use hf_crash::{classify, ingest};
use std::fs;
use tempfile::TempDir;
use uuid::Uuid;

const ASAN_LOG: &str = r"==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000034
READ of size 1 at 0x602000000034 thread T0
    #0 0x4f2a80 in parse_string src/json.c:14:20
    #1 0x4f3c10 in parse_value_inner src/json.c:58:12
    #2 0x4f4a20 in parse_value src/json.c:150:5
    #3 0x4f5a30 in LLVMFuzzerTestOneInput fuzz_parse_value.c:8:5
    #4 0x7f8a2b3c4d5e in main
";

const SEGV_LOG: &str = r"==99999==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
PC: 0x4f2a80 bp: 0x7ffd sp: 0x7ffd
    #0 0x4f2a80 in parse_value src/json.c:150:5
    #1 0x4f5a30 in LLVMFuzzerTestOneInput fuzz_parse_value.c:8:5
";

const TIMEOUT_LOG: &str = r"ALARM: working on the last Unit for 1200 seconds
       timeout: 1200
";

#[test]
fn classify_asan_log() {
    let (kind, sig, summary) = classify(ASAN_LOG);
    assert_eq!(kind, CrashKind::Asan, "should classify as Asan");
    assert!(!sig.is_empty(), "stack signature should not be empty");
    assert!(
        summary.contains("heap-buffer-overflow"),
        "summary should contain the error type: {summary}"
    );
}

#[test]
fn classify_segv_log() {
    let (kind, _sig, _summary) = classify(SEGV_LOG);
    // SEGV could be classified as Segv or Asan depending on how ASan reports it.
    assert!(
        matches!(kind, CrashKind::Segv | CrashKind::Asan),
        "SEGV log should be Segv or Asan, got {kind:?}"
    );
}

#[test]
fn classify_timeout_log() {
    let (kind, _sig, _summary) = classify(TIMEOUT_LOG);
    assert_eq!(kind, CrashKind::Timeout, "should classify as Timeout");
}

#[test]
fn asan_report_mentioning_timeout_in_the_stack_stays_asan() {
    // A heap-buffer-overflow whose path/symbols contain "timeout" must not be
    // relabeled: the timeout token is stack content, not a fuzzer verdict.
    let log = r"==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000034
READ of size 1 at 0x602000000034 thread T0
    #0 0x4f2a80 in handle_timeout net/timeout.c:14:20
    #1 0x4f3c10 in parse_value src/json.c:58:12
SUMMARY: AddressSanitizer: heap-buffer-overflow net/timeout.c:14:20 in handle_timeout
";
    let (kind, _sig, _summary) = classify(log);
    assert_eq!(
        kind,
        CrashKind::Asan,
        "an incidental 'timeout' in the stack must not relabel an ASan report"
    );
}

#[test]
fn libfuzzer_timeout_headline_classifies_as_timeout() {
    // libFuzzer's own timeout verdict, on an ASan-instrumented binary (the
    // stack mentions __asan), is a Timeout, not an ASan finding.
    let log = r"==12345==ERROR: libFuzzer: timeout after 61 seconds
    #0 0x5a1b2c in __asan_report_load4 (/work/fuzz_bin+0x5a1b2c)
    #1 0x4f2a80 in parse_value src/json.c:150:5
SUMMARY: libFuzzer: timeout
";
    let (kind, _sig, _summary) = classify(log);
    assert_eq!(
        kind,
        CrashKind::Timeout,
        "libFuzzer's 'timeout after N seconds' verdict must classify as Timeout"
    );
}

#[test]
fn unresolved_frame_addresses_do_not_leak_into_the_signature() {
    // Two logs of the same crash from different processes: ASLR slides the
    // raw addresses of unresolved ("<unknown module>") frames, but the
    // signature must be identical or dedup sees two crashes.
    let log_a = r"==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x4f2a80 in parse_value src/json.c:150:5
    #1 0x00007f8a1b2c  (<unknown module>)
    #2 0x00007f8a9f10  (<unknown module>)
";
    let log_b = r"==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x5b3c91 in parse_value src/json.c:150:5
    #1 0x000055f0beef99  (<unknown module>)
    #2 0x000055f0c01234  (<unknown module>)
";
    let (_, sig_a, _) = classify(log_a);
    let (_, sig_b, _) = classify(log_b);
    assert!(
        !sig_a.is_empty(),
        "frames are present, so a signature exists"
    );
    assert_eq!(
        sig_a, sig_b,
        "ASLR-slid addresses must not change the stack signature"
    );
}

#[test]
fn classify_empty_log_is_other() {
    let (kind, _sig, _summary) = classify("nothing interesting\n");
    assert_eq!(kind, CrashKind::Other);
}

#[test]
fn stack_signature_is_deterministic() {
    let (kind1, sig1, _) = classify(ASAN_LOG);
    let (kind2, sig2, _) = classify(ASAN_LOG);
    assert_eq!(kind1, kind2);
    assert_eq!(sig1, sig2, "same log -> same signature");
}

#[test]
fn ingest_finds_crash_artifacts() {
    let dir = TempDir::new().unwrap();
    let run_id = Uuid::new_v4();
    // Simulate libFuzzer crash artifacts.
    fs::write(dir.path().join("crash-abc"), b"crash input 1").unwrap();
    fs::write(dir.path().join("crash-def"), b"crash input 2").unwrap();
    fs::write(dir.path().join("log-abc.txt"), ASAN_LOG).unwrap();
    fs::write(dir.path().join("normal_file"), b"not a crash").unwrap();

    let crashes = ingest(dir.path(), run_id, Uuid::new_v4()).unwrap();
    assert_eq!(
        crashes.len(),
        2,
        "should find 2 crash artifacts, got {}",
        crashes.len()
    );
    assert!(crashes
        .iter()
        .all(|c| c.kind != CrashKind::Other || c.summary.is_empty()));
}

#[test]
fn ingest_finds_afl_nested_instance_crashes() {
    // Single-instance AFL++ (no -M/-S) nests crashes under out/default/crashes,
    // not out/crashes -- the ingester must walk into the instance directory.
    let dir = TempDir::new().unwrap();
    let crashes_dir = dir.path().join("default").join("crashes");
    fs::create_dir_all(&crashes_dir).unwrap();
    // Real AFL names carry ':' (id:000000,sig:06); NTFS rejects it and the
    // ingester treats crash names as opaque apart from README.txt, so portable
    // stand-ins keep this fixture writable everywhere.
    fs::write(crashes_dir.join("id_000000,sig_06,src_000000"), b"boom").unwrap();
    fs::write(crashes_dir.join("id_000001,sig_11,src_000001"), b"bang").unwrap();
    // AFL drops a README.txt in the crashes dir; it must not count as a crash.
    fs::write(crashes_dir.join("README.txt"), b"these are crashes").unwrap();

    let crashes = ingest(dir.path(), Uuid::new_v4(), Uuid::new_v4()).unwrap();
    assert_eq!(
        crashes.len(),
        2,
        "expected 2 nested AFL crashes, got {}",
        crashes.len()
    );
}

#[test]
fn ingest_empty_dir_returns_empty() {
    let dir = TempDir::new().unwrap();
    let crashes = ingest(dir.path(), Uuid::new_v4(), Uuid::new_v4()).unwrap();
    assert!(crashes.is_empty());
}

#[test]
fn ingest_finds_honggfuzz_crash_artifacts() {
    let dir = TempDir::new().unwrap();
    // honggfuzz names crash files SIG<signal>.PC.<...>.<ext> and writes a
    // HONGGFUZZ.REPORT.TXT alongside them.
    fs::write(
        dir.path()
            .join("SIGSEGV.PC.7ffff7a9c0c0.STACK.18d50d2e.CODE.1.ADDR.0.INSTR.mov.fuzz"),
        b"crashing input",
    )
    .unwrap();
    fs::write(dir.path().join("HONGGFUZZ.REPORT.TXT"), ASAN_LOG).unwrap();
    fs::write(dir.path().join("input.fuzz"), b"not a crash").unwrap();

    let crashes = ingest(dir.path(), Uuid::new_v4(), Uuid::new_v4()).unwrap();
    assert_eq!(
        crashes.len(),
        1,
        "should find the honggfuzz SIG-prefixed crash, got {}",
        crashes.len()
    );
    // The uppercase .TXT report should be picked up for classification.
    assert_eq!(crashes[0].kind, CrashKind::Asan);
}
