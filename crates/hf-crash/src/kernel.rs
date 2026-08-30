//! Kernel crash-report parsing for syzkaller campaigns.
//!
//! A kernel oops is not a sanitizer log. It names its bug class on a headline
//! (`BUG: KASAN: ...`, `WARNING: CPU: ...`, `general protection fault ...`),
//! and its stack is a `Call Trace:` of `symbol+0xoffset/0xsize file:line`
//! entries rather than libFuzzer's `#N 0xADDR in symbol`. Running kernel text
//! through [`crate::classify()`] yields no frames and an empty signature, which
//! makes dedup keep every duplicate, so this module parses it on its own terms.
//!
//! Design: `.claude/plans/syzkaller-kernel-crash-triage-20260828.md`.

use sha2::{Digest, Sha256};

/// How many call-trace frames identify a kernel bug.
///
/// Matches the userspace signature depth in [`crate::classify()`]: deep enough to
/// separate distinct bugs, shallow enough that an unrelated caller further down
/// the stack does not fork one bug into many.
const SIGNATURE_FRAMES: usize = 3;

/// Frames belonging to the reporting machinery rather than to the bug.
///
/// Every KASAN report walks out through the same dump/report path, so keeping
/// these would give every KASAN bug in the kernel an identical top-of-stack and
/// collapse distinct bugs onto one signature. Matched as a prefix, because the
/// compiler appends suffixes such as `.constprop.0` and `.isra.0`.
const REPORTING_FRAMES: &[&str] = &[
    "dump_stack",
    "__dump_stack",
    "dump_stack_lvl",
    "show_stack",
    "print_address_description",
    "print_report",
    "kasan_report",
    "__kasan_report",
    "kasan_check_range",
    "check_memory_region",
    "__asan_report",
    "kmsan_report",
    "__msan_warning",
    "kcsan_report",
    "report_bug",
    "handle_bug",
    "die",
    "do_error_trap",
    "exc_general_protection",
    "asm_exc_general_protection",
    "fail_dump",
    "should_fail",
];

/// The class of kernel bug a report announces.
///
/// Deliberately not mapped onto the userspace [`hf_core::crash::CrashKind`]
/// variants: a KASAN slab-out-of-bounds is not an `Asan` finding, and reusing
/// the userspace vocabulary is what this path exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelBugClass {
    /// `BUG: KASAN: ...` -- kernel address sanitizer, a memory-safety fault.
    Kasan,
    /// `BUG: KMSAN: ...` -- use of uninitialized memory.
    Kmsan,
    /// `BUG: KCSAN: ...` -- a data race.
    Kcsan,
    /// `kernel BUG at file:line!` -- a failed `BUG_ON`.
    KernelBug,
    /// `WARNING: CPU: ...` -- a failed `WARN_ON`.
    Warning,
    /// A general protection fault.
    GeneralProtectionFault,
    /// A NULL pointer dereference.
    NullDeref,
    /// `INFO: task ... blocked for more than N seconds` -- a hung task.
    HungTask,
    /// `Kernel panic - not syncing: ...`.
    Panic,
}

impl KernelBugClass {
    /// Stable identifier used in signatures and titles.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kasan => "KASAN",
            Self::Kmsan => "KMSAN",
            Self::Kcsan => "KCSAN",
            Self::KernelBug => "BUG",
            Self::Warning => "WARNING",
            Self::GeneralProtectionFault => "general protection fault",
            Self::NullDeref => "NULL pointer dereference",
            Self::HungTask => "hung task",
            Self::Panic => "kernel panic",
        }
    }
}

/// One parsed kernel crash report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelReport {
    /// The announced bug class.
    pub class: KernelBugClass,
    /// One-line human title, e.g. `KASAN: slab-out-of-bounds in ext4_xattr_set_entry`.
    pub title: String,
    /// Call-trace symbols, reporting machinery removed, faulting function first.
    pub frames: Vec<String>,
    /// SHA-256 over the class and the top three call-trace symbols. Empty only
    /// when no frame could be recovered.
    pub signature: String,
}

/// Parse a kernel crash report.
///
/// Returns `None` for text that does not announce a kernel bug, so a caller can
/// tell "not a kernel report" from "a kernel report I could not classify" and
/// leave userspace logs to [`crate::classify()`].
#[must_use]
pub fn parse_kernel_report(log: &str) -> Option<KernelReport> {
    let (class, headline) = detect_class(log)?;
    let frames = extract_frames(log);
    let title = title_for(class, headline, &frames);
    let signature = signature_for(class, &frames);
    Some(KernelReport {
        class,
        title,
        frames,
        signature,
    })
}

/// Find the headline that announces the bug, and what it announces.
///
/// Checked in report order rather than by a bare substring: a KASAN-enabled
/// kernel stamps `KASAN` into the oops line of a fault it did not report
/// (`... [#1] SMP KASAN`), so the specific headlines are matched before the
/// sanitizer name. Same reasoning as the userspace classifier, where an `ASan`
/// runtime frame must not claim a `UBSan` finding.
fn detect_class(log: &str) -> Option<(KernelBugClass, &str)> {
    for raw in log.lines() {
        let line = raw.trim();
        let lower = line.to_ascii_lowercase();
        let class = if lower.starts_with("bug: kasan:") {
            KernelBugClass::Kasan
        } else if lower.starts_with("bug: kmsan:") {
            KernelBugClass::Kmsan
        } else if lower.starts_with("bug: kcsan:") {
            KernelBugClass::Kcsan
        } else if lower.starts_with("bug: kernel null pointer dereference")
            || lower.starts_with("kasan: null-ptr-deref")
        {
            KernelBugClass::NullDeref
        } else if lower.starts_with("general protection fault") {
            KernelBugClass::GeneralProtectionFault
        } else if lower.starts_with("kernel bug at") {
            KernelBugClass::KernelBug
        } else if lower.starts_with("warning: cpu:") {
            KernelBugClass::Warning
        } else if lower.starts_with("kernel panic") {
            KernelBugClass::Panic
        } else if lower.starts_with("info: task") && lower.contains("blocked for more than") {
            KernelBugClass::HungTask
        } else {
            continue;
        };
        return Some((class, line));
    }
    None
}

/// Call-trace symbols, faulting function first, reporting machinery removed.
///
/// Handles the three shapes a kernel stack line takes:
/// `symbol+0x12/0x34 file.c:99`, `[<ffffffff81234567>] symbol+0x12/0x34`, and
/// the inlined `symbol file.c:99 [inline]`. Offsets, sizes, and raw addresses
/// are dropped: they move with every build, and a signature that moves with the
/// build cannot dedup one bug across two kernels.
fn extract_frames(log: &str) -> Vec<String> {
    let mut frames = Vec::new();
    for raw in log.lines() {
        let line = raw.trim();
        // `RIP:` names the faulting instruction on a fault report, where the
        // headline carries no symbol at all.
        let candidate = if let Some(rest) = line.strip_prefix("RIP:") {
            rest.split_once(':').map_or(rest, |(_, after)| after).trim()
        } else if let Some(rest) = line.strip_prefix("[<") {
            match rest.split_once(">]") {
                Some((_, after)) => after.trim(),
                None => continue,
            }
        } else if is_trace_frame(line) {
            line
        } else {
            continue;
        };

        let Some(symbol) = symbol_of(candidate) else {
            continue;
        };
        if is_reporting_frame(&symbol) || frames.contains(&symbol) {
            continue;
        }
        frames.push(symbol);
    }
    frames
}

/// Whether a bare line looks like a call-trace entry rather than prose.
///
/// A trace frame is `symbol+0xoffset/0xsize ...` or an inlined
/// `symbol file.c:line [inline]`. Requiring one of those two shapes keeps the
/// surrounding report text -- `CPU: 0 PID: ...`, `Read of size 4 at addr ...` --
/// out of the stack.
fn is_trace_frame(line: &str) -> bool {
    let head = line.split_whitespace().next().unwrap_or_default();
    if head.is_empty() || head.ends_with(':') {
        return false;
    }
    head.contains("+0x") || line.ends_with("[inline]")
}

/// The bare symbol from a frame: no offset, no size, no address, no suffix the
/// compiler appended.
fn symbol_of(frame: &str) -> Option<String> {
    let head = frame.split_whitespace().next()?;
    let symbol = head.split_once("+0x").map_or(head, |(name, _)| name);
    let symbol = symbol.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.');
    // `.constprop.0`, `.isra.0`, `.cold` are build-dependent compiler suffixes.
    let symbol = symbol.split_once('.').map_or(symbol, |(name, _)| name);
    (!symbol.is_empty() && symbol.chars().any(char::is_alphabetic)).then(|| symbol.to_owned())
}

fn is_reporting_frame(symbol: &str) -> bool {
    REPORTING_FRAMES
        .iter()
        .any(|noise| symbol == *noise || symbol.starts_with(noise))
}

/// A one-line title: the announced class and specifics, plus the faulting
/// function, matching how syzkaller titles the same bug.
fn title_for(class: KernelBugClass, headline: &str, frames: &[String]) -> String {
    let detail = headline
        .strip_prefix("BUG: ")
        .unwrap_or(headline)
        .split(" by task ")
        .next()
        .unwrap_or(headline)
        .trim()
        .to_owned();
    match frames.first() {
        // A headline that already names the faulting function needs no suffix.
        Some(symbol) if !detail.contains(symbol.as_str()) => {
            format!("{detail} in {symbol}")
        }
        _ => {
            if detail.is_empty() {
                class.as_str().to_owned()
            } else {
                detail
            }
        }
    }
}

fn signature_for(class: KernelBugClass, frames: &[String]) -> String {
    if frames.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(class.as_str().as_bytes());
    hasher.update(b"\n");
    for frame in frames.iter().take(SIGNATURE_FRAMES) {
        hasher.update(frame.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}
