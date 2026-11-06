//! How one C/C++ translation unit enters a harness link.
//!
//! The harness build (`hf-harness`) uses the role to decide what it links, and
//! discovery (`hf-discovery`) uses it to decide what it offers as a target: a
//! function whose only definition is never linked cannot be harnessed. Both
//! read the role from here so the two never disagree.
//!
//! - an entry program defines `main`, which collides with the engine driver's
//!   `main`. The harness build compiles it alone with `main` renamed.
//! - a fuzz entry is a harness the project already ships (it defines
//!   `LLVMFuzzerTestOneInput` or uses the honggfuzz/AFL++ persistent loop). It
//!   is left out of the link: its entry points collide with the generated
//!   harness and it calls engine-specific functions the build does not link.

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
    use super::{classify_unit, UnitRole};

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
}
