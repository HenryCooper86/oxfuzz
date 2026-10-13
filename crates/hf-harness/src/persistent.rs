//! AFL++ persistent-mode harnesses: detection, validation, and the canonical
//! source template.
//!
//! A stock oxfuzz harness exposes `LLVMFuzzerTestOneInput` and links AFL++'s
//! libFuzzer-compatible driver, which already loops in the forkserver child
//! over shared-memory input. The persistent-mode flavor exists for stateful
//! or slow-to-initialize targets: the harness owns `main`, moves the fork
//! point past one-time setup with `__AFL_INIT()`, loops with `__AFL_LOOP(N)`,
//! and re-initializes all mutable state before every target call. See
//! `docs/standards/HARNESS_STANDARD.md` (persistent-mode section) for the
//! discipline and the run-contract evidence.
//!
//! A persistent harness builds with afl-clang-fast but WITHOUT
//! `-fsanitize=fuzzer`: `__AFL_FUZZ_INIT()` and the driver both define
//! `__afl_sharedmem_fuzzing` strongly, so the two cannot link together.
//! [`crate::build_command_for_source`] derives that build variant from the
//! source through [`is_persistent_source`]; both wrong pairings fail loudly
//! at link time rather than misbuilding (Engineering Protocol 2.16).

use std::fmt::Write as _;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetLanguage;

/// The loop-count override knob, honored by AFL++'s libFuzzer-compatible
/// driver (`aflpp_driver.c`) and by the persistent template below. The
/// function-coverage proof path sets it to 100 on profiled AFL++ campaigns so
/// forkserver children exit and flush their LLVM profile counters regularly.
pub const LOOPCOUNT_ENV: &str = "AFL_FUZZER_LOOPCOUNT";

/// Default iterations per forkserver child before AFL++ respawns it fresh.
/// AFL++'s persistent-mode documentation recommends 1000 as a starting point
/// (100-10000): high enough to amortize the fork, low enough to bound how
/// long leaked or drifting state can accumulate in one child.
pub const DEFAULT_LOOP_COUNT: u32 = 1000;

/// Upper clamp for the loop count, against a hand-set env value that would
/// defeat the leak-containment restart entirely.
pub const MAX_LOOP_COUNT: u32 = 100_000;

/// Whether the harness source owns its AFL++ forkserver loop: a code line
/// carries a `__AFL_LOOP(` or `__AFL_FUZZ_INIT(` call.
///
/// Either marker forces the driver-less build: `__AFL_FUZZ_INIT()` defines a
/// strong `__afl_sharedmem_fuzzing` that conflicts with the linked driver's
/// own definition (a link-time failure), and a custom `__AFL_LOOP` main
/// linked with the driver would still advertise shared-memory input through
/// the driver's definition while reading files, starving at calibration.
/// Comment-only lines never count, and a mere identifier mention
/// (`__AFL_LOOP_COUNT`) is not a call.
#[must_use]
pub fn is_persistent_source(source: &str) -> bool {
    source.lines().any(|line| {
        !crate::lint::is_comment_line(line, TargetLanguage::C)
            && (line_calls_macro(line, "__AFL_LOOP") || line_calls_macro(line, "__AFL_FUZZ_INIT"))
    })
}

/// Whether `line` calls `name` as a macro: the token preceded by a
/// non-identifier byte and followed by `(`.
pub(crate) fn line_calls_macro(line: &str, name: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = line[offset..].find(name) {
        let at = offset + found;
        let before_ok = at == 0 || {
            let byte = line.as_bytes()[at - 1];
            !byte.is_ascii_alphanumeric() && byte != b'_'
        };
        let after_ok = line[at + name.len()..].trim_start().starts_with('(');
        if before_ok && after_ok {
            return true;
        }
        offset = at + name.len();
    }
    false
}

/// Whether `line` contains `word` as a whole token (identifier-delimited).
pub(crate) fn line_has_word(line: &str, word: &str) -> bool {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|token| token == word)
}

/// Admit a persistent-mode draft request: the flavor is defined only for
/// AFL++ driving C/C++ targets. Called by the service before any drafting so
/// an unsupported combination fails before an LLM call is spent
/// (Engineering Protocol 2.16), and relied on by the compile path through
/// [`crate::build_command_for_source`].
///
/// # Errors
/// Returns `ClassifiedError::Validation` naming the supported combination.
pub fn require_persistent_support(
    engine: EngineKind,
    lang: TargetLanguage,
) -> Result<(), ClassifiedError> {
    if engine != EngineKind::AflPlusPlus {
        return Err(ClassifiedError::Validation(format!(
            "AFL++ persistent-mode harnesses apply only to the afl++ engine (requested '{}'): \
             the stock libFuzzer-driver build already loops every other userspace setup",
            engine.as_str()
        )));
    }
    if !matches!(lang, TargetLanguage::C | TargetLanguage::Cpp) {
        return Err(ClassifiedError::Validation(format!(
            "AFL++ persistent-mode harnesses apply to C/C++ targets, not {lang:?}: \
             the __AFL_LOOP/__AFL_INIT structure is a C-level forkserver contract"
        )));
    }
    Ok(())
}

/// The pieces of a persistent harness that depend on the target rather than
/// on the AFL++ structure. `includes`/`forward_decl` may be empty; `body` is
/// the per-iteration target call, indented for the entry-point body.
pub struct PersistentHarnessParts<'a> {
    /// Target symbol the harness drives.
    pub symbol: &'a str,
    /// `file:line` of the target, for the header comment.
    pub location: &'a str,
    /// The target's declared signature, for the entry-point comment.
    pub signature: Option<&'a str>,
    /// Extra `#include` lines (may be empty).
    pub includes: &'a str,
    /// The target's forward declaration (may be empty when a header covers it).
    pub forward_decl: &'a str,
    /// The per-iteration target call, indented for the entry-point body.
    pub body: &'a str,
}

/// Emit the canonical AFL++ persistent-mode harness source.
///
/// The structure (verified against the pinned AFL++ 4.09c sources):
///
/// - `__AFL_FUZZ_INIT()` at file scope: shared-memory testcase globals.
/// - `oxfuzz_target_setup()` runs before `__AFL_INIT()`: the deferred
///   forkserver clones only the post-setup state, so one-time initialization
///   is paid once per forkserver child, not once per input.
/// - `oxfuzz_target_reset()` runs before every target call: the per-iteration
///   reset the stateful-target contract requires.
/// - The loop bound defaults to [`DEFAULT_LOOP_COUNT`] and honors
///   [`LOOPCOUNT_ENV`] at run time, the same knob AFL++'s driver documents.
/// - Under a fuzzer the input arrives through shared memory; standalone
///   (`binary <file>`, the crash-replay form) replays each argv file once.
#[must_use]
pub fn render_harness_source(parts: &PersistentHarnessParts<'_>) -> String {
    let mut out = String::new();
    write!(
        out,
        "// AFL++ persistent-mode harness for {}\n\
         // Engine: AFL++ (persistent mode: deferred forkserver + in-process loop)\n\
         // Target: {}\n\
         //\n\
         // This harness owns main() and the forkserver loop, so it builds with\n\
         // afl-clang-fast WITHOUT -fsanitize=fuzzer: no AFL libFuzzer driver is\n\
         // linked (the driver and __AFL_FUZZ_INIT both define\n\
         // __afl_sharedmem_fuzzing and cannot link together). The state-reset\n\
         // discipline below is required reading: docs/standards/HARNESS_STANDARD.md,\n\
         // the persistent-mode section.\n",
        parts.symbol, parts.location
    )
    .expect("String formatting is infallible");
    out.push_str(
        "#include <stdint.h>\n\
         #include <stddef.h>\n\
         #include <stdio.h>\n\
         #include <stdlib.h>\n\
         #include <unistd.h>\n",
    );
    if !parts.includes.is_empty() {
        out.push_str(parts.includes);
        out.push('\n');
    }
    if !parts.forward_decl.is_empty() {
        out.push_str(parts.forward_decl);
        out.push('\n');
    }
    out.push_str(
        "\n__AFL_FUZZ_INIT();\n\
         \n\
         /* One-time setup: runs ONCE per forkserver child, before __AFL_INIT() moves\n\
         \x20* the fork point past it, so heavy initialization is paid once per child\n\
         \x20* instead of once per input. Never read the fuzzed input here and never\n\
         \x20* start threads: the forkserver cannot clone them. */\n\
         static void oxfuzz_target_setup(void) {\n\
         \x20   /* e.g. target_init(); fill in when the target needs one-time setup */\n\
         }\n\
         \n\
         /* Per-iteration reset: runs before EVERY target call. Return all mutable\n\
         \x20* state the target keeps between calls (globals, statics, cached buffers,\n\
         \x20* open handles) to its initial value; state leaking between inputs causes\n\
         \x20* phantom crashes and findings that never reproduce. */\n\
         static void oxfuzz_target_reset(void) {\n\
         \x20   /* e.g. target_reset(); fill in when the target keeps state */\n\
         }\n\
         \n",
    );
    write!(
        out,
        "/* Per-iteration entry: called once per fuzzed input from the persistent loop\n\
         \x20* below (and once per file in standalone replay). */\n\
         int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n\
         \x20   // Target signature: {}\n\
         \x20   oxfuzz_target_reset();\n",
        parts.signature.unwrap_or("(unknown)")
    )
    .expect("String formatting is infallible");
    out.push_str(parts.body);
    out.push_str("\n    return 0;\n}\n\n");
    write!(
        out,
        "/* Iterations per forkserver child before AFL++ respawns it fresh: the bound\n\
         \x20* limits how long leaked or drifting state can accumulate. {DEFAULT_LOOP_COUNT} is AFL++'s\n\
         \x20* recommended starting point (100-10000). {LOOPCOUNT_ENV} overrides the default at run\n\
         \x20* time; oxfuzz's function-coverage proof sets it to 100 on profiled\n\
         \x20* campaigns so children exit and flush LLVM profile counters. */\n\
         #define OXFUZZ_PERSISTENT_LOOP_DEFAULT {DEFAULT_LOOP_COUNT}\n\
         #define OXFUZZ_PERSISTENT_LOOP_MAX {MAX_LOOP_COUNT}\n\
         \n\
         static unsigned int oxfuzz_loop_count(void) {{\n\
         \x20   const char *env = getenv(\"{LOOPCOUNT_ENV}\");\n\
         \x20   if (env) {{\n\
         \x20       long n = strtol(env, NULL, 10);\n\
         \x20       if (n >= 1 && n <= OXFUZZ_PERSISTENT_LOOP_MAX) {{\n\
         \x20           return (unsigned int)n;\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   return OXFUZZ_PERSISTENT_LOOP_DEFAULT;\n\
         }}\n\
         \n"
    )
    .expect("String formatting is infallible");
    out.push_str(
        "int main(int argc, char **argv) {\n\
         \x20   oxfuzz_target_setup();\n\
         #ifdef __AFL_HAVE_MANUAL_CONTROL\n\
         \x20   __AFL_INIT();\n\
         #endif\n\
         \n\
         \x20   if (__afl_fuzz_ptr) {\n\
         \x20       /* A fuzzer attached the shared-memory testcase buffer (afl-fuzz, and\n\
         \x20        * afl-showmap/afl-cmin through their forkserver): inputs arrive\n\
         \x20        * through it. The `@@` on the afl-fuzz command line is inert in this\n\
         \x20        * mode -- afl-fuzz detects the shared-memory capability and switches\n\
         \x20        * to it. */\n\
         \x20       unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;\n\
         \x20       while (__AFL_LOOP(oxfuzz_loop_count())) {\n\
         \x20           size_t len = __AFL_FUZZ_TESTCASE_LEN;\n\
         \x20           LLVMFuzzerTestOneInput(buf, len);\n\
         \x20       }\n\
         \x20       return 0;\n\
         \x20   }\n\
         \n\
         \x20   /* Standalone: no fuzzer attached, so replay each file argument once and\n\
         \x20    * stop. This is the path direct crash replay drives (`binary <input>`).\n\
         \x20    * Inputs are read through the same 1 MiB cap AFL++ applies to shared-\n\
         \x20    * memory testcases. */\n\
         \x20   for (int i = 1; i < argc; i++) {\n\
         \x20       uint8_t input[1048576];\n\
         \x20       FILE *f = fopen(argv[i], \"rb\");\n\
         \x20       if (!f) {\n\
         \x20           continue;\n\
         \x20       }\n\
         \x20       size_t len = fread(input, 1, sizeof(input), f);\n\
         \x20       fclose(f);\n\
         \x20       LLVMFuzzerTestOneInput(input, len);\n\
         \x20   }\n\
         \x20   return 0;\n\
         }\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::super::persistent::{
        is_persistent_source, render_harness_source, require_persistent_support,
        PersistentHarnessParts, DEFAULT_LOOP_COUNT, LOOPCOUNT_ENV, MAX_LOOP_COUNT,
    };
    use crate::{build_command, build_command_for_source, cmplog_build_command_for_source};
    use hf_core::engine::EngineKind;
    use hf_core::target::{Sanitizer, TargetLanguage};

    fn parts() -> PersistentHarnessParts<'static> {
        PersistentHarnessParts {
            symbol: "parse_entry",
            location: "src/parse.c:42",
            signature: Some("int parse_entry(const uint8_t *data, size_t len)"),
            includes: "#include \"parse.h\"",
            forward_decl: "int parse_entry(const uint8_t *data, size_t len);",
            body: "    parse_entry((const uint8_t *)data, size);",
        }
    }

    // -- detection ----------------------------------------------------------

    #[test]
    fn a_driver_style_source_is_not_persistent() {
        let source = "#include <stdint.h>\n\
                      int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }\n";
        assert!(!is_persistent_source(source));
    }

    #[test]
    fn a_loop_or_shm_init_call_makes_the_source_persistent() {
        assert!(is_persistent_source(
            "int main(void) { while (__AFL_LOOP(1000)) { run(); } }"
        ));
        assert!(is_persistent_source(
            "__AFL_FUZZ_INIT();\nint main(void) { return 0; }"
        ));
    }

    #[test]
    fn markers_in_comment_only_lines_do_not_count() {
        let source = "// do not use __AFL_LOOP(1000) here\n\
                      /* __AFL_FUZZ_INIT(); belongs elsewhere */\n\
                      int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }\n";
        assert!(!is_persistent_source(source));
    }

    #[test]
    fn a_mere_identifier_mention_is_not_a_call() {
        // `__AFL_LOOP_COUNT` is an identifier, not the loop macro; a trailing
        // comment after a call still counts.
        assert!(!is_persistent_source("#define __AFL_LOOP_COUNT 5\n"));
        assert!(is_persistent_source(
            "while (__AFL_LOOP(N)) { } // per input"
        ));
    }

    // -- request validation ---------------------------------------------------

    #[test]
    fn persistent_support_requires_afl_and_a_c_language() {
        assert!(require_persistent_support(EngineKind::AflPlusPlus, TargetLanguage::C).is_ok());
        assert!(require_persistent_support(EngineKind::AflPlusPlus, TargetLanguage::Cpp).is_ok());
        for engine in [EngineKind::LibFuzzer, EngineKind::Honggfuzz] {
            let error = require_persistent_support(engine, TargetLanguage::C).unwrap_err();
            assert!(error.to_string().contains("afl++"), "{error}");
        }
        let error =
            require_persistent_support(EngineKind::AflPlusPlus, TargetLanguage::Rust).unwrap_err();
        assert!(error.to_string().contains("C/C++"), "{error}");
    }

    // -- the emitted template -------------------------------------------------

    #[test]
    fn the_template_carries_the_persistent_structure() {
        let source = render_harness_source(&parts());
        for marker in [
            "__AFL_FUZZ_INIT();",
            "__AFL_INIT();",
            "while (__AFL_LOOP(",
            "__AFL_FUZZ_TESTCASE_BUF",
            "__AFL_FUZZ_TESTCASE_LEN",
            "LLVMFuzzerTestOneInput",
            "int main(int argc, char **argv)",
            "fopen(argv[i]",
        ] {
            assert!(source.contains(marker), "missing {marker}:\n{source}");
        }
        assert!(source.contains("parse_entry((const uint8_t *)data, size);"));
        assert!(source.contains("#include \"parse.h\""));
        assert!(source.contains("int parse_entry(const uint8_t *data, size_t len);"));
    }

    #[test]
    fn the_template_orders_setup_reset_and_the_fork_point() {
        let source = render_harness_source(&parts());
        // One-time setup runs before the deferred forkserver starts.
        let main_at = source.find("int main(").unwrap();
        let setup_call = source[main_at..].find("oxfuzz_target_setup();").unwrap();
        let fork_point = source[main_at..].find("__AFL_INIT();").unwrap();
        assert!(setup_call < fork_point, "{source}");
        // The per-iteration reset precedes the target call inside the entry.
        let entry_at = source.find("int LLVMFuzzerTestOneInput").unwrap();
        let reset = source[entry_at..].find("oxfuzz_target_reset();").unwrap();
        let call = source[entry_at..]
            .find("parse_entry((const uint8_t *)data, size);")
            .unwrap();
        assert!(reset < call, "{source}");
        // The loop drives the entry through the shared-memory buffer.
        let loop_at = source.find("while (__AFL_LOOP(").unwrap();
        assert!(
            source[loop_at..].contains("LLVMFuzzerTestOneInput(buf, len);"),
            "{source}"
        );
        // The shared-memory branch comes before the standalone file branch.
        assert!(source.find("__afl_fuzz_ptr").unwrap() < source.find("fopen(argv[i]").unwrap());
    }

    #[test]
    fn the_template_names_the_loop_count_and_its_env_override() {
        let source = render_harness_source(&parts());
        assert!(
            source.contains("#define OXFUZZ_PERSISTENT_LOOP_DEFAULT 1000"),
            "{source}"
        );
        assert!(
            source.contains("#define OXFUZZ_PERSISTENT_LOOP_MAX 100000"),
            "{source}"
        );
        assert!(
            source.contains("getenv(\"AFL_FUZZER_LOOPCOUNT\")"),
            "{source}"
        );
        assert_eq!(LOOPCOUNT_ENV, "AFL_FUZZER_LOOPCOUNT");
        assert_eq!(DEFAULT_LOOP_COUNT, 1000);
        assert_eq!(MAX_LOOP_COUNT, 100_000);
    }

    #[test]
    fn the_template_is_detected_persistent_and_lint_clean() {
        let source = render_harness_source(&parts());
        assert!(is_persistent_source(&source));
        let findings = crate::lint_harness_source(&source, TargetLanguage::C);
        assert!(findings.is_empty(), "{findings:?}\n{source}");
        let findings_cpp = crate::lint_harness_source(&source, TargetLanguage::Cpp);
        assert!(findings_cpp.is_empty(), "{findings_cpp:?}\n{source}");
    }

    // -- the source-derived build variant -------------------------------------

    #[test]
    fn a_persistent_afl_source_builds_without_the_fuzzer_driver() {
        let source = render_harness_source(&parts());
        let cmd = build_command_for_source(
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            "fuzz_parse_entry",
            Sanitizer::Address,
            &source,
        )
        .unwrap();
        assert_eq!(cmd.compiler, "afl-clang-fast");
        assert!(
            !cmd.args.iter().any(|arg| arg == "-fsanitize=fuzzer"),
            "a persistent harness owns main; the driver must not link: {:?}",
            cmd.args
        );
        assert!(cmd.args.iter().any(|arg| arg == "-fsanitize=address"));
    }

    #[test]
    fn a_driver_style_afl_source_keeps_the_fuzzer_driver() {
        let cmd = build_command_for_source(
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            "fuzz_parse_entry",
            Sanitizer::Address,
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }",
        )
        .unwrap();
        assert!(cmd.args.iter().any(|arg| arg == "-fsanitize=fuzzer"));
    }

    #[test]
    fn build_command_without_a_source_is_the_existing_behavior() {
        for engine in [
            EngineKind::LibFuzzer,
            EngineKind::AflPlusPlus,
            EngineKind::Honggfuzz,
        ] {
            assert_eq!(
                build_command(engine, TargetLanguage::C, "fuzz_t", Sanitizer::Address)
                    .unwrap()
                    .args,
                build_command_for_source(
                    engine,
                    TargetLanguage::C,
                    "fuzz_t",
                    Sanitizer::Address,
                    ""
                )
                .unwrap()
                .args,
            );
        }
    }

    #[test]
    fn the_persistent_build_variant_keeps_sanitizer_and_cpp_choices() {
        let source = render_harness_source(&parts());
        let ubsan = build_command_for_source(
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            "fuzz_t",
            Sanitizer::Undefined,
            &source,
        )
        .unwrap();
        assert!(ubsan.args.iter().any(|arg| arg == "-fsanitize=undefined"));
        assert!(ubsan
            .args
            .iter()
            .any(|arg| arg == "-fno-sanitize-recover=undefined"));
        assert!(!ubsan.args.iter().any(|arg| arg == "-fsanitize=fuzzer"));

        let cpp = build_command_for_source(
            EngineKind::AflPlusPlus,
            TargetLanguage::Cpp,
            "fuzz_t",
            Sanitizer::Address,
            &source,
        )
        .unwrap();
        assert_eq!(cpp.compiler, "afl-clang-fast++");
        assert!(!cpp.args.iter().any(|arg| arg == "-fsanitize=fuzzer"));
    }

    #[test]
    fn a_persistent_source_does_not_change_other_engines_builds() {
        // The persistent flavor is AFL++-only; other engines reject the source
        // at compile time, and the constructor never rewrites their flags.
        let source = render_harness_source(&parts());
        let cmd = build_command_for_source(
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            "fuzz_t",
            Sanitizer::Address,
            &source,
        )
        .unwrap();
        assert!(cmd.args.iter().any(|arg| arg == "-fsanitize=fuzzer"));
    }

    #[test]
    fn the_cmplog_companion_follows_the_main_builds_driver_choice() {
        let source = render_harness_source(&parts());
        let persistent = cmplog_build_command_for_source(
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            "fuzz_t.cmplog",
            Sanitizer::Address,
            &source,
        )
        .unwrap();
        assert!(
            !persistent.args.iter().any(|arg| arg == "-fsanitize=fuzzer"),
            "the companion compiles the same persistent source: {:?}",
            persistent.args
        );
        let driver = cmplog_build_command_for_source(
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            "fuzz_t.cmplog",
            Sanitizer::Address,
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }",
        )
        .unwrap();
        assert!(driver.args.iter().any(|arg| arg == "-fsanitize=fuzzer"));
    }
}
