//! Stack frame parsing and origin classification.
//!
//! oxfuzz's harnesses are written by a language model, so a fault inside the
//! harness is an expected failure mode rather than an unusual one. Without this
//! module every downstream artifact -- report, SARIF, issue tracker -- presents
//! a harness defect as a finding about the project under test.
//!
//! Classification keys on names oxfuzz itself writes. The harness source is
//! always `harness.<ext>` (`hf_core::target::TargetLanguage::harness_filename`),
//! and the engine entry points are fixed, so this is a lookup rather than a
//! heuristic.

use std::sync::OnceLock;

use hf_core::crash::CrashOrigin;
use regex::Regex;

/// Function names that are the harness entry point itself.
const HARNESS_FUNCTIONS: [&str; 2] = ["LLVMFuzzerTestOneInput", "rust_fuzzer_test_input"];

/// Base-name prefix of every harness source file oxfuzz writes.
const HARNESS_FILE_PREFIX: &str = "harness.";

/// Allocator and entry-point names that mean a frame belongs to the runtime.
///
/// Matched exactly rather than by substring: a target function named
/// `dns_free_message` contains `free` and is not the allocator.
const RUNTIME_EXACT_FUNCTIONS: [&str; 5] = ["malloc", "calloc", "realloc", "free", "_start"];

/// Prefixes that mean a frame belongs to the sanitizer runtime, the C++
/// allocator, or the libFuzzer driver.
const RUNTIME_FUNCTION_PREFIXES: [&str; 7] = [
    "operator new",
    "operator delete",
    "__libc_start",
    "__asan",
    "__sanitizer",
    "__interceptor",
    "fuzzer::",
];

/// Driver frames that appear without a recognizable prefix.
const RUNTIME_FUNCTION_FRAGMENTS: [&str; 3] = ["FuzzerDriver", "ExecuteCallback", "RunOneTest"];

/// Path prefixes holding toolchain and system code rather than project code.
const RUNTIME_PATH_PREFIXES: [&str; 3] = ["/usr/", "/lib/", "/build/"];

/// One parsed sanitizer stack frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    /// Frame index as the sanitizer printed it.
    pub index: u32,
    /// Symbolized function name.
    pub function: String,
    /// Source path as the sanitizer printed it.
    pub file: Option<String>,
    /// 1-indexed source line.
    pub line: Option<u32>,
}

/// Which layer a frame belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOrigin {
    /// The generated harness itself.
    Harness,
    /// Fuzzer driver, sanitizer runtime, or libc.
    Runtime,
    /// The project under test.
    Target,
}

/// The frame line a symbolized sanitizer report prints.
fn frame_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?m)^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)(?:\s+(/[^\s:]+)(?::(\d+))?(?::\d+)?)?\s*$",
        )
        .expect("frame pattern is a compile-time constant")
    })
}

/// Parse `#N 0xADDR in FUNC FILE:LINE:COL` frames, in printed order.
///
/// Frames without an `in <function>` clause are skipped. Those are
/// unsymbolized, and classifying the origin of a frame with no name would be a
/// guess; `classify::extract_top_frames` already handles them for dedup, which
/// needs a stable key rather than a layer.
#[must_use]
pub fn parse_frames(log: &str) -> Vec<StackFrame> {
    frame_pattern()
        .captures_iter(log)
        .map(|captures| StackFrame {
            index: captures[1].parse().unwrap_or(0),
            function: captures[2].trim().to_owned(),
            file: captures.get(3).map(|file| file.as_str().to_owned()),
            line: captures.get(4).and_then(|line| line.as_str().parse().ok()),
        })
        .collect()
}

/// Whether a function name is a harness entry point oxfuzz writes.
///
/// Exposed so coverage attribution asks the same question stack attribution
/// does, against one list (AGENTS.md 2.18).
#[must_use]
pub fn is_harness_function(name: &str) -> bool {
    HARNESS_FUNCTIONS.contains(&name)
}

/// Whether a frame's source file is the generated harness.
fn is_harness_file(frame: &StackFrame) -> bool {
    frame.file.as_deref().is_some_and(|file| {
        std::path::Path::new(file)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(HARNESS_FILE_PREFIX))
    })
}

/// Whether a frame belongs to the fuzzer driver, sanitizer, or system libraries.
fn is_runtime_frame(frame: &StackFrame) -> bool {
    let function = frame.function.as_str();
    if RUNTIME_EXACT_FUNCTIONS.contains(&function)
        || RUNTIME_FUNCTION_PREFIXES
            .iter()
            .any(|prefix| function.starts_with(prefix))
        || RUNTIME_FUNCTION_FRAGMENTS
            .iter()
            .any(|fragment| function.contains(fragment))
    {
        return true;
    }
    frame.file.as_deref().is_some_and(|file| {
        RUNTIME_PATH_PREFIXES
            .iter()
            .any(|prefix| file.starts_with(prefix))
    })
}

/// Which layer one frame belongs to.
///
/// The harness is checked first: it is the most specific signal, and a frame
/// naming the harness entry point is the harness whatever else it resembles.
#[must_use]
pub fn frame_origin(frame: &StackFrame) -> FrameOrigin {
    if HARNESS_FUNCTIONS.contains(&frame.function.as_str()) || is_harness_file(frame) {
        return FrameOrigin::Harness;
    }
    if is_runtime_frame(frame) {
        return FrameOrigin::Runtime;
    }
    FrameOrigin::Target
}

/// The first frame that is neither runtime nor harness: the frame naming the
/// target code responsible for the fault.
#[must_use]
pub fn root_target_frame(frames: &[StackFrame]) -> Option<&StackFrame> {
    frames
        .iter()
        .find(|frame| frame_origin(frame) == FrameOrigin::Target)
}

/// Which layer a whole sanitizer report blames.
///
/// Keys on the first frame that is not runtime. An `ASan` frame `#0` is the
/// faulting access, so a target bug reached through the harness still reports
/// `#0` inside the target; only a fault whose innermost non-runtime frame is
/// the harness is a harness defect.
#[must_use]
pub fn crash_origin(log: &str) -> CrashOrigin {
    parse_frames(log)
        .iter()
        .map(frame_origin)
        .find(|origin| *origin != FrameOrigin::Runtime)
        .map_or(CrashOrigin::Unknown, |origin| match origin {
            FrameOrigin::Harness => CrashOrigin::Harness,
            FrameOrigin::Target => CrashOrigin::Target,
            // Filtered out above; a runtime frame never decides the verdict.
            FrameOrigin::Runtime => CrashOrigin::Runtime,
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const HARNESS_FAULT: &str = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118
    #0 0x4f1a2b in __asan_memcpy /build/llvm/asan_interceptors_memintrinsics.cpp:22
    #1 0x51b3c4 in LLVMFuzzerTestOneInput /work/harness.c:14:5
    #2 0x41d0f9 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /build/FuzzerLoop.cpp:611
";

    pub(crate) const TARGET_FAULT: &str = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118
    #0 0x4f1a2b in dns_parse_name /work/src/parser/dns.c:88:11
    #1 0x4f2c30 in dns_parse_message /work/src/parser/dns.c:140:9
    #2 0x51b3c4 in LLVMFuzzerTestOneInput /work/harness.c:14:5
";

    #[test]
    fn parses_index_function_file_and_line() {
        let frames = parse_frames(TARGET_FAULT);
        assert_eq!(frames.len(), 3, "{frames:?}");
        assert_eq!(frames[0].index, 0);
        assert_eq!(frames[0].function, "dns_parse_name");
        assert_eq!(frames[0].file.as_deref(), Some("/work/src/parser/dns.c"));
        assert_eq!(frames[0].line, Some(88));
    }

    #[test]
    fn classifies_sanitizer_and_driver_frames_as_runtime() {
        let frames = parse_frames(HARNESS_FAULT);
        assert_eq!(frame_origin(&frames[0]), FrameOrigin::Runtime);
        assert_eq!(frame_origin(&frames[2]), FrameOrigin::Runtime);
    }

    #[test]
    fn classifies_the_harness_entry_point_as_harness() {
        let frames = parse_frames(HARNESS_FAULT);
        assert_eq!(frame_origin(&frames[1]), FrameOrigin::Harness);
    }

    #[test]
    fn classifies_a_harness_source_file_as_harness() {
        let frame = StackFrame {
            index: 0,
            function: "read_header".to_owned(),
            file: Some("/work/harness.cc".to_owned()),
            line: Some(9),
        };
        assert_eq!(frame_origin(&frame), FrameOrigin::Harness);
    }

    #[test]
    fn classifies_project_code_as_target() {
        let frames = parse_frames(TARGET_FAULT);
        assert_eq!(frame_origin(&frames[0]), FrameOrigin::Target);
        assert_eq!(frame_origin(&frames[1]), FrameOrigin::Target);
    }

    #[test]
    fn root_target_frame_skips_runtime_and_harness_frames() {
        let frames = parse_frames(TARGET_FAULT);
        assert_eq!(
            root_target_frame(&frames).unwrap().function,
            "dns_parse_name"
        );
    }

    #[test]
    fn a_harness_only_stack_has_no_root_target_frame() {
        let frames = parse_frames(HARNESS_FAULT);
        assert!(root_target_frame(&frames).is_none());
    }

    #[test]
    fn a_log_without_frames_parses_to_nothing() {
        assert!(parse_frames("==1==ERROR: libFuzzer: deadly signal").is_empty());
    }

    #[test]
    fn an_unsymbolized_frame_is_skipped() {
        // Origin classification on a frame with no name would be a guess;
        // dedup already handles unsymbolized frames through its own path.
        let frames = parse_frames("    #0 0x4f1a2b  (/work/fuzz_p+0x1a2b)\n");
        assert!(frames.is_empty(), "{frames:?}");
    }
}
