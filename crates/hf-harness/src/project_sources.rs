//! Staged project translation units and how each one enters a harness link.
//!
//! A harness build links every staged C/C++ unit so multi-file targets
//! resolve. Each unit's [`UnitRole`] (from `hf_core::c_unit`, shared with
//! discovery) decides how: an entry program is compiled alone with `main`
//! renamed and its object goes into one static archive, so every other symbol
//! it defines stays available while a program the harness does not need is
//! never linked; a fuzz entry (a harness the project already ships) is left
//! out.
//!
//! The archive matters for a project that ships several programs. bzip2 has
//! `bzip2.c`, `bzip2recover.c` and `unzcrash.c`, each with its own `progName`:
//! linked as plain objects they collide, and no harness repair can fix that.
//! The linker takes an archive member only to resolve a symbol something
//! already needs.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub use hf_core::c_unit::{classify_unit, UnitRole};

/// Workspace directories that never hold project source.
///
/// `corpus` and `out` hold attacker-controlled bytes, which may carry a source
/// file's name; compiling one would build the fuzzer's own input. `fuzz` is the
/// generated cargo-fuzz scaffold. `runs` holds retained per-run evidence
/// including `input/source-context` copies of the project sources; compiling
/// those alongside the staged sources duplicates every target symbol after the
/// first campaign.
const NON_SOURCE_DIRS: [&str; 4] = ["corpus", "out", "fuzz", "runs"];

/// Workspace file listing the translation units the project's own build
/// compiles, one workspace-relative path per line. When present, only those
/// units are linked.
///
/// A source tree holds more than its build does: libxml2 ships `os400/`,
/// `win32/`, examples and test programs that its build never compiles on this
/// platform and that do not compile here. The compile database is the
/// project's statement of which units make up the library.
pub const LINK_UNITS_FILE: &str = "harness.units";

/// Record, or with `None` clear, the units [`ProjectLinkInputs::collect`]
/// links for `workspace`.
///
/// # Errors
/// Returns the I/O error of the write or removal.
pub fn write_link_units(workspace: &Path, units: Option<&[String]>) -> std::io::Result<()> {
    let path = workspace.join(LINK_UNITS_FILE);
    match units {
        Some(units) => std::fs::write(path, units.join("\n")),
        None => match std::fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        },
    }
}

/// The recorded unit list of `workspace`, when one is present and names at
/// least one unit that exists there. A list naming nothing present describes
/// some other tree and is ignored.
fn recorded_link_units(
    workspace: &Path,
    found: &[String],
) -> Option<std::collections::HashSet<String>> {
    let text = std::fs::read_to_string(workspace.join(LINK_UNITS_FILE)).ok()?;
    let units: std::collections::HashSet<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    found
        .iter()
        .any(|path| units.contains(path))
        .then_some(units)
}

/// Cap on translation units handed to one compile. A project past this is not
/// something a single-command harness build links.
const MAX_EXTRA_SOURCES: usize = 5_000;

/// Units larger than this are linked as library code without being read.
const MAX_CLASSIFIED_BYTES: u64 = 16 * 1024 * 1024;

/// The staged project units one harness build links, by role. Paths are
/// workspace-relative with `/` separators, sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectLinkInputs {
    library: Vec<String>,
    entry_programs: Vec<String>,
    fuzz_entries: Vec<String>,
    /// System libraries the linked code's includes call for, in
    /// [`SYSTEM_LIBRARIES`] order.
    system_libraries: Vec<&'static str>,
}

/// System headers whose library the project's own build links, mapped to the
/// libraries the pinned sandbox image ships for them. `configure` and `CMake`
/// enable optional codecs when they find these (`LibTIFF` compiles its ZIP and
/// LZMA codecs against zlib and liblzma), but a compile database records no
/// link line, so without them the harness link fails on undefined symbols.
/// A header whose library the image lacks (libjpeg, libpng) is absent on
/// purpose: naming it would fail the link with "cannot find -l...".
const SYSTEM_LIBRARIES: [(&str, &[&str]); 13] = [
    ("zlib.h", &["z"]),
    ("lzma.h", &["lzma"]),
    ("zstd.h", &["zstd"]),
    ("openssl/", &["ssl", "crypto"]),
    ("libxml/", &["xml2"]),
    ("expat.h", &["expat"]),
    ("pcre2.h", &["pcre2-8"]),
    ("ffi.h", &["ffi"]),
    ("glib.h", &["glib-2.0"]),
    ("pixman.h", &["pixman-1"]),
    ("math.h", &["m"]),
    ("pthread.h", &["pthread"]),
    ("dlfcn.h", &["dl"]),
];

/// Cap on header files read for system includes.
const MAX_SCANNED_HEADERS: usize = 5_000;

/// The headers a source text includes with `#include <...>` or `"..."`.
fn included_headers(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter_map(|line| {
        let rest = line.trim_start().strip_prefix('#')?.trim_start();
        let rest = rest.strip_prefix("include")?.trim_start();
        let (open, close) = match rest.chars().next()? {
            '<' => ('<', '>'),
            '"' => ('"', '"'),
            _ => return None,
        };
        let inner = rest.strip_prefix(open)?;
        inner.split(close).next()
    })
}

/// The system libraries called for by the includes of `files`.
fn system_libraries_for(files: &[PathBuf]) -> Vec<&'static str> {
    let mut wanted = [false; SYSTEM_LIBRARIES.len()];
    for file in files {
        let readable = std::fs::metadata(file).is_ok_and(|meta| meta.len() <= MAX_CLASSIFIED_BYTES);
        if !readable {
            continue;
        }
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for header in included_headers(&text) {
            for (index, (prefix, _)) in SYSTEM_LIBRARIES.iter().enumerate() {
                let matches = if prefix.ends_with('/') {
                    header.starts_with(prefix)
                } else {
                    header == *prefix
                };
                wanted[index] |= matches;
            }
        }
    }
    let mut libraries = Vec::new();
    for (index, (_, names)) in SYSTEM_LIBRARIES.iter().enumerate() {
        if wanted[index] {
            for name in *names {
                if !libraries.contains(name) {
                    libraries.push(*name);
                }
            }
        }
    }
    libraries
}

/// Every header file under `directory`, bounded and without following links.
/// Every project header under `workspace`, workspace-relative and sorted, as
/// the harness build's include directories see them.
#[must_use]
pub fn project_headers(workspace: &Path) -> Vec<String> {
    let mut found = Vec::new();
    collect_headers(workspace, &mut found);
    let mut relative: Vec<String> = found
        .iter()
        .filter_map(|path| path.strip_prefix(workspace).ok())
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect();
    relative.sort();
    relative
}

fn collect_headers(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if found.len() >= MAX_SCANNED_HEADERS {
            return;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_dir() {
            let name = entry.file_name();
            if !NON_SOURCE_DIRS
                .iter()
                .any(|skipped| std::ffi::OsStr::new(skipped) == name)
            {
                collect_headers(&path, found);
            }
        } else if kind.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| matches!(extension, "h" | "hh" | "hpp" | "hxx"))
        {
            found.push(path);
        }
    }
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
        if let Some(units) = recorded_link_units(workspace, &relative) {
            relative.retain(|path| units.contains(path));
        }
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
        if !inputs.library.is_empty() || !inputs.entry_programs.is_empty() {
            let mut scanned: Vec<PathBuf> = inputs
                .library
                .iter()
                .chain(&inputs.entry_programs)
                .map(|path| workspace.join(path))
                .collect();
            collect_headers(workspace, &mut scanned);
            inputs.system_libraries = system_libraries_for(&scanned);
            // A C++ unit linked by the C driver (a C harness) needs the C++
            // standard library named; the C++ driver adds it on its own, and
            // `--as-needed` drops the duplicate.
            let has_cpp_unit = inputs
                .library
                .iter()
                .chain(&inputs.entry_programs)
                .any(|path| {
                    Path::new(path)
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| matches!(extension, "cc" | "cpp" | "cxx"))
                });
            if has_cpp_unit {
                inputs.system_libraries.push("stdc++");
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

    /// The workspace-relative translation units the harness build compiles:
    /// the library units and the programs whose `main` it renames.
    pub fn linked_units(&self) -> impl Iterator<Item = &str> {
        self.library
            .iter()
            .chain(&self.entry_programs)
            .map(String::as_str)
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
        if !self.entry_programs.is_empty() {
            let objects = (0..self.entry_programs.len())
                .map(entry_object)
                .collect::<Vec<_>>()
                .join(" ");
            // Writing to a String cannot fail.
            let _ = write!(
                script,
                "rm -f {ENTRY_PROGRAM_ARCHIVE} && ar rcs {ENTRY_PROGRAM_ARCHIVE} {objects} && "
            );
        }
        script
    }

    /// Link arguments: the library units as container paths, then the archive
    /// of entry-program objects [`precompile_script`](Self::precompile_script)
    /// produces, last so it resolves what the units before it left undefined.
    /// Every path from the project is shell-quoted.
    #[must_use]
    pub fn link_args(&self, container_ws: &str) -> String {
        // System libraries come last, after every object that may need them,
        // and `--as-needed` drops any the link does not use (an include under
        // a disabled `#ifdef` still names one).
        let libraries = (!self.system_libraries.is_empty()).then(|| {
            std::iter::once("-Wl,--as-needed".to_owned())
                .chain(self.system_libraries.iter().map(|name| format!("-l{name}")))
                .collect::<Vec<_>>()
                .join(" ")
        });
        self.library
            .iter()
            .map(|path| format!("{container_ws}/{}", sh_quote(path)))
            .chain((!self.entry_programs.is_empty()).then(|| ENTRY_PROGRAM_ARCHIVE.to_owned()))
            .chain(libraries)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The static archive holding every entry program's object.
const ENTRY_PROGRAM_ARCHIVE: &str = "/tmp/oxfuzz_project_programs.a";

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

/// Shell-quote each flag and join them with spaces, for interpolation into a
/// POSIX shell command (project flags come from an untrusted compile
/// database).
#[must_use]
pub fn shell_quoted(flags: &[String]) -> String {
    flags
        .iter()
        .map(|flag| sh_quote(flag))
        .collect::<Vec<_>>()
        .join(" ")
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

#[cfg(test)]
mod tests {
    use super::write_link_units;
    use super::ProjectLinkInputs;

    #[test]
    fn libraries_the_project_includes_are_linked_last_and_as_needed() {
        // LibTIFF 4.0.4: configure found zlib and liblzma, so tif_zip.c and
        // tif_lzma.c call them; the harness link failed on inflateInit_ and
        // lzma_code until the libraries were named.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "libtiff/tif_zip.c",
            "#include \"tiffiop.h\"\n#include \"zlib.h\"\nint z;",
        );
        write(
            dir.path(),
            "libtiff/tif_lzma.c",
            "#include \"lzma.h\"\nint l;",
        );
        write(
            dir.path(),
            "libtiff/tiffiop.h",
            "#  include <math.h>\n#include <jpeglib.h>\n",
        );
        write(dir.path(), "tools/tiffinfo.c", "int main(void){return 0;}");

        let inputs = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);
        let args = inputs.link_args("/work");

        assert!(
            args.ends_with("/tmp/oxfuzz_project_programs.a -Wl,--as-needed -lz -llzma -lm"),
            "{args}"
        );
        assert!(
            !args.contains("-ljpeg"),
            "the image ships no libjpeg: {args}"
        );
    }

    #[test]
    fn a_cpp_unit_in_a_c_link_brings_the_cpp_standard_library() {
        // LibTIFF 4.0.4 builds tif_stream.cxx (std::ostream) next to its C
        // units; a C harness linked by `clang` left std::ostream undefined.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "libtiff/tif_open.c", "int o;");
        write(
            dir.path(),
            "libtiff/tif_stream.cxx",
            "#include <ostream>\nint s;",
        );
        let args = ProjectLinkInputs::collect(dir.path(), &["harness.c"]).link_args("/work");
        assert!(args.ends_with("-Wl,--as-needed -lstdc++"), "{args}");

        let plain = tempfile::tempdir().unwrap();
        write(plain.path(), "a.c", "int a;");
        let args = ProjectLinkInputs::collect(plain.path(), &["harness.c"]).link_args("/work");
        assert!(!args.contains("stdc++"), "{args}");
    }

    #[test]
    fn a_link_with_no_project_units_names_no_system_library() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "harness.c", "#include <zlib.h>\nint h;");
        let inputs = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);
        assert_eq!(inputs.link_args("/work"), "");
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
             -o /tmp/oxfuzz_project_main_1.o && \
             rm -f /tmp/oxfuzz_project_programs.a && \
             ar rcs /tmp/oxfuzz_project_programs.a /tmp/oxfuzz_project_main_0.o \
             /tmp/oxfuzz_project_main_1.o && "
        );
        // The programs are linked as one archive, after the library units, so
        // two programs defining the same global do not collide: only a member
        // the harness needs is pulled in.
        assert_eq!(
            inputs.link_args("/work"),
            "/work/'lib/parse.c' /tmp/oxfuzz_project_programs.a"
        );
    }

    #[test]
    fn a_recorded_unit_list_limits_the_link_to_the_projects_own_build() {
        // libxml2: `os400/xmlcatlgcl.c` includes a header that exists only on
        // that platform. The project's build does not compile it; the harness
        // build did, and failed.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "parser.c",
            "int parse(const char *s){return s[0];}",
        );
        write(dir.path(), "tree.c", "int tree(int x){return x;}");
        write(
            dir.path(),
            "os400/xmlcatlgcl.c",
            "#include <qshell.h>\nint q(void){return 0;}",
        );
        write(dir.path(), "example/demo.c", "int main(void){return 0;}");

        let all = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);
        assert!(all.link_args("/work").contains("os400"), "{all:?}");

        write_link_units(
            dir.path(),
            Some(&["parser.c".to_owned(), "tree.c".to_owned()]),
        )
        .unwrap();
        let limited = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);
        assert_eq!(
            limited.link_args("/work"),
            "/work/'parser.c' /work/'tree.c'"
        );
        assert_eq!(limited.precompile_script("clang", "/work"), "");

        // A list that names nothing in this tree is not this tree's list.
        write_link_units(dir.path(), Some(&["elsewhere/a.c".to_owned()])).unwrap();
        assert_eq!(ProjectLinkInputs::collect(dir.path(), &["harness.c"]), all);

        write_link_units(dir.path(), None).unwrap();
        assert_eq!(ProjectLinkInputs::collect(dir.path(), &["harness.c"]), all);
        write_link_units(dir.path(), None).unwrap();
    }

    #[test]
    fn a_project_without_entry_programs_builds_no_archive() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "parse.c",
            "int parse(const char *s){return s[0];}",
        );
        let inputs = ProjectLinkInputs::collect(dir.path(), &["harness.c"]);
        assert_eq!(inputs.precompile_script("clang", "/work"), "");
        assert_eq!(inputs.link_args("/work"), "/work/'parse.c'");
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
