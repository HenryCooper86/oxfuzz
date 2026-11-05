//! Staged project translation units and how each one enters a harness link.
//!
//! A harness build links every staged C/C++ unit so multi-file targets
//! resolve. Two kinds of unit cannot be linked as they are:
//!
//! - an entry program defines `main`, which collides with the engine driver's
//!   `main`. It is compiled alone with `main` renamed and its object is linked,
//!   so every other symbol it defines stays available.
//! - a fuzz entry is a harness the project already ships (it defines
//!   `LLVMFuzzerTestOneInput` or uses the honggfuzz/AFL++ persistent loop). It
//!   is left out of the link: its entry points collide with the generated
//!   harness and it calls engine-specific functions the build does not link.

use std::fmt::Write as _;
use std::path::Path;

/// Workspace directories that never hold project source.
///
/// `corpus` and `out` hold attacker-controlled bytes, which may carry a source
/// file's name; compiling one would build the fuzzer's own input. `fuzz` is the
/// generated cargo-fuzz scaffold. `runs` holds retained per-run evidence
/// including `input/source-context` copies of the project sources; compiling
/// those alongside the staged sources duplicates every target symbol after the
/// first campaign.
const NON_SOURCE_DIRS: [&str; 4] = ["corpus", "out", "fuzz", "runs"];

/// Cap on translation units handed to one compile. A project past this is not
/// something a single-command harness build links.
const MAX_EXTRA_SOURCES: usize = 5_000;

/// Units larger than this are linked as library code without being read.
const MAX_CLASSIFIED_BYTES: u64 = 16 * 1024 * 1024;

/// Identifiers whose use marks a honggfuzz or AFL++ persistent-mode harness.
const PERSISTENT_LOOP_MARKERS: [&str; 3] = ["HF_ITER", "__AFL_LOOP", "__AFL_FUZZ_INIT"];

/// How one staged translation unit enters a harness link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitRole {
    /// Ordinary project code, linked as is.
    Library,
    /// Defines `main`; compiled alone with `main` renamed.
    EntryProgram,
    /// A fuzz harness the project ships; left out of the link.
    FuzzEntry,
}

/// Classify one C/C++ translation unit from its source text. Comments and
/// string or character literals are ignored.
#[must_use]
pub fn classify_unit(source: &str) -> UnitRole {
    let code = strip_comments_and_literals(source);
    if defines_function(&code, "LLVMFuzzerTestOneInput")
        || PERSISTENT_LOOP_MARKERS
            .iter()
            .any(|marker| identifier_positions(&code, marker).next().is_some())
    {
        return UnitRole::FuzzEntry;
    }
    if defines_function(&code, "main") {
        return UnitRole::EntryProgram;
    }
    UnitRole::Library
}

/// The staged project units one harness build links, by role. Paths are
/// workspace-relative with `/` separators, sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectLinkInputs {
    library: Vec<String>,
    entry_programs: Vec<String>,
    fuzz_entries: Vec<String>,
}

impl ProjectLinkInputs {
    /// Walk `workspace` for C/C++ translation units, leaving out
    /// `excluded_names` (bare file names such as the harness source).
    ///
    /// Recursive because project staging preserves the directory layout;
    /// symlinks are not followed, and the walk is bounded and sorted so one
    /// project always produces one command.
    #[must_use]
    pub fn collect(workspace: &Path, excluded_names: &[&str]) -> Self {
        let mut relative = Vec::new();
        collect_source_files(workspace, workspace, excluded_names, &mut relative);
        relative.sort();
        relative.truncate(MAX_EXTRA_SOURCES);
        let mut inputs = Self::default();
        for path in relative {
            match classify_file(&workspace.join(&path)) {
                UnitRole::Library => inputs.library.push(path),
                UnitRole::EntryProgram => inputs.entry_programs.push(path),
                UnitRole::FuzzEntry => inputs.fuzz_entries.push(path),
            }
        }
        inputs
    }

    /// Units that are fuzz harnesses shipped by the project, left out of the
    /// link.
    #[must_use]
    pub fn fuzz_entries(&self) -> &[String] {
        &self.fuzz_entries
    }

    /// Shell steps that compile each entry program alone, with `main` renamed,
    /// into `/tmp`. `compile_prefix` is the compiler with its arguments and
    /// flags, already quoted. Each step ends with `&& ` so the result is
    /// prepended to the link command; empty when there is no entry program.
    #[must_use]
    pub fn precompile_script(&self, compile_prefix: &str, container_ws: &str) -> String {
        let mut script = String::new();
        for (index, path) in self.entry_programs.iter().enumerate() {
            // Writing to a String cannot fail.
            let _ = write!(
                script,
                "{compile_prefix} -Dmain={symbol} -c {container_ws}/{source} -o {object} && ",
                symbol = renamed_main(index),
                source = sh_quote(path),
                object = entry_object(index),
            );
        }
        script
    }

    /// Link arguments: the library units as container paths, then the objects
    /// [`precompile_script`](Self::precompile_script) produces. Every path from
    /// the project is shell-quoted.
    #[must_use]
    pub fn link_args(&self, container_ws: &str) -> String {
        self.library
            .iter()
            .map(|path| format!("{container_ws}/{}", sh_quote(path)))
            .chain((0..self.entry_programs.len()).map(entry_object))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The symbol an entry program's `main` is renamed to.
fn renamed_main(index: usize) -> String {
    format!("oxfuzz_project_main_{index}")
}

/// Container path of an entry program's renamed object.
fn entry_object(index: usize) -> String {
    format!("/tmp/{}.o", renamed_main(index))
}

/// Read and classify one staged unit. An unreadable or oversized file is
/// linked as library code, as it was before classification existed.
fn classify_file(path: &Path) -> UnitRole {
    let readable = std::fs::metadata(path).is_ok_and(|meta| meta.len() <= MAX_CLASSIFIED_BYTES);
    if !readable {
        return UnitRole::Library;
    }
    // Swallowed: a read error leaves the unit as library code, which is the
    // pre-classification behavior; the compiler reports the file itself.
    std::fs::read(path).map_or(UnitRole::Library, |bytes| {
        classify_unit(&String::from_utf8_lossy(&bytes))
    })
}

/// Collect workspace-relative source paths beneath `directory`.
fn collect_source_files(
    root: &Path,
    directory: &Path,
    excluded_names: &[&str],
    found: &mut Vec<String>,
) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if found.len() >= MAX_EXTRA_SOURCES {
            return;
        }
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let name = entry.file_name();
            if NON_SOURCE_DIRS
                .iter()
                .any(|skipped| std::ffi::OsStr::new(skipped) == name)
            {
                continue;
            }
            collect_source_files(root, &path, excluded_names, found);
            continue;
        }
        if !kind.is_file()
            || excluded_names
                .iter()
                .any(|&excluded| entry.file_name() == excluded)
        {
            continue;
        }
        let is_source = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "c" | "cc" | "cpp" | "cxx"));
        if !is_source {
            continue;
        }
        if let Ok(rel) = path.strip_prefix(root) {
            found.push(hf_core::runtime::posix_relative(rel));
        }
    }
}

/// Single-quote a string for safe interpolation into a POSIX shell command.
pub(crate) fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Replace comment bodies and string/character literal contents with spaces,
/// keeping newlines, so identifier searches see only code.
fn strip_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        let next = bytes.get(i + 1).copied();
        if byte == b'/' && next == Some(b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if byte == b'/' && next == Some(b'*') {
            out.extend_from_slice(b"  ");
            i += 2;
            while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            let closing = (bytes.len() - i).min(2);
            out.extend(std::iter::repeat_n(b' ', closing));
            i += closing;
        } else if byte == b'"' || byte == b'\'' {
            out.push(byte);
            i += 1;
            while i < bytes.len() && bytes[i] != byte && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(b' ');
                    i += 1;
                }
                out.push(b' ');
                i += 1;
            }
            if i < bytes.len() {
                out.push(bytes[i]);
                i += 1;
            }
        } else {
            out.push(byte);
            i += 1;
        }
    }
    // Only ASCII bytes were replaced with ASCII spaces, and multi-byte
    // sequences outside comments and literals are copied whole.
    String::from_utf8_lossy(&out).into_owned()
}

/// Byte offsets where `name` occurs as a whole identifier.
fn identifier_positions<'a>(code: &'a str, name: &'a str) -> impl Iterator<Item = usize> + 'a {
    let bytes = code.as_bytes();
    code.match_indices(name).filter_map(move |(at, _)| {
        let before = at.checked_sub(1).map(|index| bytes[index]);
        let after = bytes.get(at + name.len()).copied();
        let is_ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
        (!before.is_some_and(is_ident) && !after.is_some_and(is_ident)).then_some(at)
    })
}

/// Whether `code` defines a function named `name`: the identifier, a balanced
/// parameter list, then a body. A prototype or a call has no body after the
/// list; a member access (`.name(`, `->name(`) is not a definition.
fn defines_function(code: &str, name: &str) -> bool {
    let bytes = code.as_bytes();
    identifier_positions(code, name).any(|at| {
        let preceding = code[..at].trim_end().as_bytes().last().copied();
        if matches!(preceding, Some(b'.' | b'>')) {
            return false;
        }
        let mut i = skip_whitespace(bytes, at + name.len());
        if bytes.get(i) != Some(&b'(') {
            return false;
        }
        let mut depth = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        bytes.get(skip_whitespace(bytes, i + 1)) == Some(&b'{')
    })
}

fn skip_whitespace(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::{classify_unit, ProjectLinkInputs, UnitRole};

    #[test]
    fn a_main_definition_marks_an_entry_program() {
        for source in [
            "int main(int argc, char **argv) { return 0; }",
            "int\nmain (int argc, char *argv[])\n{\n  return 0;\n}",
            "int main(void){return 0;}",
        ] {
            assert_eq!(classify_unit(source), UnitRole::EntryProgram, "{source}");
        }
    }

    #[test]
    fn a_main_prototype_call_or_mention_is_library_code() {
        for source in [
            "int main(int argc, char **argv);\nint parse(const char *s) { return s[0]; }",
            "int run(int c, char **v) { return main(c, v); }",
            "/* int main(void) { } */ int parse(const char *s) { return 1; }",
            "// int main(void) { }\nint parse(const char *s) { return 1; }",
            "const char *usage = \"int main(void) { }\"; int parse(const char *s) { return 1; }",
            "int parse(struct app *a) { return a->main(1) + a.main(2); }",
            "int domain(int x) { return x; } int remain(int y) { return y; }",
        ] {
            assert_eq!(classify_unit(source), UnitRole::Library, "{source}");
        }
    }

    #[test]
    fn a_shipped_fuzz_harness_is_a_fuzz_entry() {
        for source in [
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }",
            "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n return 0;\n}",
            // The honggfuzz glibc example: persistent loop plus its own main.
            "int main(int argc, char *argv[]) { for (;;) { HF_ITER(&buf, &len); } }",
            "int main(void) { while (__AFL_LOOP(1000)) { run(); } }",
            "__AFL_FUZZ_INIT();\nint main(void) { return 0; }",
        ] {
            assert_eq!(classify_unit(source), UnitRole::FuzzEntry, "{source}");
        }
        // A declaration alone is not a harness.
        assert_eq!(
            classify_unit("int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);"),
            UnitRole::Library
        );
    }

    fn write(dir: &std::path::Path, path: &str, content: &str) {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn entry_programs_are_precompiled_with_main_renamed() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "lib/parse.c",
            "int parse(const char *s){return s[0];}",
        );
        write(
            dir.path(),
            "tools/cli.c",
            "int main(int c, char **v){return parse(v[1]);}",
        );
        write(dir.path(), "tools/dump.c", "int main(void){return 0;}");

        let inputs = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);

        assert_eq!(
            inputs.precompile_script("clang -fsanitize=fuzzer -I/work", "/work"),
            "clang -fsanitize=fuzzer -I/work -Dmain=oxfuzz_project_main_0 -c /work/'tools/cli.c' \
             -o /tmp/oxfuzz_project_main_0.o && \
             clang -fsanitize=fuzzer -I/work -Dmain=oxfuzz_project_main_1 -c /work/'tools/dump.c' \
             -o /tmp/oxfuzz_project_main_1.o && "
        );
        assert_eq!(
            inputs.link_args("/work"),
            "/work/'lib/parse.c' /tmp/oxfuzz_project_main_0.o /tmp/oxfuzz_project_main_1.o"
        );
    }

    #[test]
    fn shipped_fuzz_harnesses_are_left_out_of_the_link() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "parse.c",
            "int parse(const char *s){return s[0];}",
        );
        write(
            dir.path(),
            "tests/fuzz_parse.c",
            "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){return parse((const char*)d);}",
        );

        let inputs = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);

        assert_eq!(inputs.link_args("/work"), "/work/'parse.c'");
        assert_eq!(inputs.precompile_script("clang", "/work"), "");
        assert_eq!(inputs.fuzz_entries(), ["tests/fuzz_parse.c".to_owned()]);
    }

    #[test]
    fn nested_sources_are_linked_at_their_relative_paths() {
        // Project staging keeps the project's layout, so the compiler must be
        // handed nested translation units too; listing only the workspace
        // root leaves every one of them out of the link.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/parser/dns.c", "int p(void){return 0;}");
        write(dir.path(), "top.c", "int t(void){return 0;}");

        let listed = ProjectLinkInputs::collect(dir.path(), &["harness.c"]).link_args("/work");

        assert_eq!(listed, "/work/'src/parser/dns.c' /work/'top.c'");
    }

    #[test]
    fn corpus_run_output_and_retained_run_context_are_never_compiled() {
        // A corpus input is attacker-controlled bytes that may be named like a
        // source file; retained run context duplicates every project symbol.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "corpus/seed.c", "int evil(void){return 0;}");
        write(dir.path(), "out/crash.c", "int evil2(void){return 0;}");
        write(
            dir.path(),
            "runs/00000000-0000-0000-0000-000000000000/input/source-context/real.c",
            "int r(void){return 0;}",
        );
        write(dir.path(), "real.c", "int r(void){return 0;}");

        let listed = ProjectLinkInputs::collect(dir.path(), &["harness.c"]).link_args("/work");

        assert_eq!(listed, "/work/'real.c'");
    }

    #[test]
    fn every_given_excluded_name_is_left_out() {
        // The concolic build excludes two staged non-project files (the
        // harness and a driver).
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "harness.c", "int main(void){return 0;}");
        write(dir.path(), "symcc_driver.c", "int main(void){return 0;}");
        write(dir.path(), "real.c", "int r(void){return 0;}");

        let inputs = ProjectLinkInputs::collect(dir.path(), &["harness.c", "symcc_driver.c"]);

        assert_eq!(inputs.link_args("/work"), "/work/'real.c'");
        assert_eq!(inputs.precompile_script("clang", "/work"), "");
    }

    #[test]
    fn linked_sources_are_deterministically_ordered() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b/two.c", "int two(void){return 0;}");
        write(dir.path(), "a.c", "int a(void){return 0;}");

        let first = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);

        assert_eq!(
            first,
            ProjectLinkInputs::collect(dir.path(), &["harness.c"])
        );
        assert_eq!(first.link_args("/work"), "/work/'a.c' /work/'b/two.c'");
    }

    #[test]
    fn project_paths_are_shell_quoted() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "evil; touch pwned.c", "int x;");
        write(dir.path(), "it's main.c", "int main(void){return 0;}");

        let inputs = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);

        assert!(
            inputs
                .link_args("/work")
                .contains("/work/'evil; touch pwned.c'"),
            "{inputs:?}"
        );
        assert!(
            inputs
                .precompile_script("clang", "/work")
                .contains("/work/'it'\\''s main.c'"),
            "{inputs:?}"
        );
    }
}
