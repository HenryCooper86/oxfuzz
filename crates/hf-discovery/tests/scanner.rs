//! Integration tests for the C/C++ target scanner.

use hf_core::target::{TargetKind, TargetLanguage};
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("sample_c")
}

#[tokio::test]
async fn discover_returns_non_empty_inventory() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    assert!(!inv.candidates.is_empty(), "inventory must not be empty");
}

#[tokio::test]
async fn candidates_carry_their_project_root() {
    let root = fixture_root();
    let canonical = std::fs::canonicalize(&root).expect("fixture root should resolve");
    let inv = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed");
    // Every candidate must know which project it belongs to, so persistence can
    // dedup by (project, symbol, file) and reports can attribute targets.
    assert!(
        inv.project_root == canonical
            && inv
                .candidates
                .iter()
                .all(|candidate| candidate.project_root == canonical),
        "the inventory and candidates should carry the canonical project root"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn project_aliases_share_one_inventory_and_target_identity() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parser.c"),
        "int parse_alias(const unsigned char *data, unsigned long size) { return size && data[0]; }\n",
    )
    .unwrap();
    let links = tempfile::tempdir().unwrap();
    let alias = links.path().join("project-link");
    std::os::unix::fs::symlink(project.path(), &alias).unwrap();

    let direct = hf_discovery::discover(project.path(), TargetLanguage::C)
        .await
        .expect("direct discovery");
    let linked = hf_discovery::discover(&alias, TargetLanguage::C)
        .await
        .expect("linked discovery");

    assert_eq!(direct.project_root, linked.project_root);
    assert_eq!(direct.candidates.len(), linked.candidates.len());
    assert_eq!(direct.candidates[0].id, linked.candidates[0].id);
    assert_eq!(
        direct.candidates[0].project_root,
        linked.candidates[0].project_root
    );
}

#[tokio::test]
async fn rust_discovery_rejects_a_missing_project_root() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("missing-project");
    let error = hf_discovery::discover(&missing, TargetLanguage::Rust)
        .await
        .expect_err("a missing project root must not look like an empty project");
    assert!(
        error.to_string().contains("project root"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn discover_finds_parse_value() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let symbols: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
    assert!(
        symbols.contains(&"parse_value"),
        "parse_value must be a candidate; got {symbols:?}"
    );
}

#[tokio::test]
async fn discover_assigns_parser_kind_to_parse_value() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let pv = inv
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_value")
        .expect("parse_value must be present");
    assert!(
        matches!(pv.kind, TargetKind::Parser | TargetKind::Function),
        "parse_value should be Parser or Function"
    );
}

#[tokio::test]
async fn candidate_ids_are_stable_across_discovery_passes() {
    // Persistence (harnesses, corpus, crashes, run linkage) is keyed on the
    // target id. If a symbol got a fresh random id on every discovery pass, all
    // of that stored state would be orphaned the next time discovery ran. The id
    // must therefore be deterministic per (project_root, file, symbol).
    let root = fixture_root();
    let first = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let second = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed");

    for c in &first.candidates {
        let again = second
            .candidates
            .iter()
            .find(|o| o.symbol == c.symbol)
            .unwrap_or_else(|| panic!("{} should be found on the second pass", c.symbol));
        assert_eq!(
            c.id, again.id,
            "candidate id for {} must be stable across passes",
            c.symbol
        );
    }

    // Distinct symbols must still get distinct ids.
    let ids: std::collections::HashSet<_> = first.candidates.iter().map(|c| c.id).collect();
    assert_eq!(
        ids.len(),
        first.candidates.len(),
        "each distinct symbol must get its own id"
    );
}

#[tokio::test]
async fn discover_skips_no_arg_functions() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let names: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
    // `json_free` has one arg (ok), `json_dump` has 3 args (ok).
    // A function with zero params would be filtered. Our fixture has none,
    // so this asserts the filter does not remove valid candidates.
    assert!(names.contains(&"json_free"));
    assert!(names.contains(&"json_dump"));
}

#[tokio::test]
async fn discover_complexity_json_dump_greater_than_parse_value() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let by_name = |n: &str| {
        inv.candidates
            .iter()
            .find(|c| c.symbol == n)
            .unwrap_or_else(|| panic!("{n} must be present"))
    };
    let dump = by_name("json_dump");
    let pv = by_name("parse_value");
    assert!(
        dump.complexity > pv.complexity,
        "json_dump complexity ({}) should exceed parse_value complexity ({})",
        dump.complexity,
        pv.complexity
    );
}

#[tokio::test]
async fn discover_skips_static_functions() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let names: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
    // These are `static` in json.c -- they have internal linkage and cannot
    // be called from a separately-compiled harness, so the scanner must skip
    // them.
    assert!(
        !names.contains(&"parse_value_inner"),
        "static function parse_value_inner must not be a candidate; got {names:?}"
    );
    assert!(
        !names.contains(&"skip_ws"),
        "static function skip_ws must not be a candidate; got {names:?}"
    );
    assert!(
        !names.contains(&"parse_array"),
        "static function parse_array must not be a candidate; got {names:?}"
    );
}

#[tokio::test]
async fn discover_rust_finds_public_parameterized_functions() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("lib.rs"),
        "pub fn parse_packet(data: &[u8]) -> bool {\n\
         \x20   if data.is_empty() { return false; }\n\
         \x20   data[0] == 0x7f\n\
         }\n\
         fn private_helper(x: u32) -> u32 { x + 1 }\n\
         pub fn getter() -> u32 { 42 }\n",
    )
    .unwrap();

    let inv = hf_discovery::discover(dir.path(), TargetLanguage::Rust)
        .await
        .expect("rust discovery should succeed");

    // The public, byte-taking parser is found and classified as a Parser.
    let parse = inv
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_packet")
        .expect("parse_packet should be discovered");
    assert_eq!(parse.language, TargetLanguage::Rust);
    assert_eq!(parse.kind, TargetKind::Parser);

    // Private functions and zero-arg getters are excluded.
    assert!(inv.candidates.iter().all(|c| c.symbol != "private_helper"));
    assert!(inv.candidates.iter().all(|c| c.symbol != "getter"));
}

#[tokio::test]
async fn discover_skips_void_prototype_functions() {
    // tree-sitter-c parses `int f(void)` as a parameter_list holding one
    // parameter_declaration (a `void` primitive_type). Counting that as one
    // parameter would make a genuinely argument-less function a fuzz candidate.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("mod.c"),
        "int startup(void) { return 42; }\n\
         int parse_thing(const unsigned char *data, unsigned long n) { return n && data[0]; }\n",
    )
    .unwrap();

    let inv = hf_discovery::discover(dir.path(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let names: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();

    assert!(
        !names.contains(&"startup"),
        "a `(void)` function has no argument to fuzz and must not be a candidate; got {names:?}"
    );
    // A real argument-bearing function is still discovered (control).
    assert!(
        names.contains(&"parse_thing"),
        "the argument-bearing parser must remain a candidate; got {names:?}"
    );
}

#[tokio::test]
async fn discover_rust_parses_args_past_a_generic_bound() {
    use hf_core::target::InputSurface;

    // `<F: Fn(u8) -> bool>` contains its own parentheses and a `->` arrow. The
    // argument list is the `(...)` *after* the generic section, not the bound's
    // `(u8)`. Reading the bound would mis-count the parameters and infer the
    // wrong input surface (or drop the candidate entirely).
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("lib.rs"),
        "pub fn scan_bytes<F: Fn(u8) -> bool>(pred: F, data: &[u8]) -> usize {\n\
         \x20   data.iter().filter(|b| pred(**b)).count()\n\
         }\n",
    )
    .unwrap();

    let inv = hf_discovery::discover(dir.path(), TargetLanguage::Rust)
        .await
        .expect("rust discovery should succeed");
    let scan = inv
        .candidates
        .iter()
        .find(|c| c.symbol == "scan_bytes")
        .expect("scan_bytes should be discovered past its generic bound");
    // The real argument list carries a byte slice, so the surface is Bytes;
    // mis-parsing the `Fn(u8)` bound would yield Structured instead.
    assert_eq!(
        scan.input_surface,
        InputSurface::Bytes,
        "the `&[u8]` argument must be parsed past the generic bound"
    );
}

#[tokio::test]
async fn discover_rust_scans_crlf_identically_to_lf() {
    // CRLF sources must scan identically to LF ones. A byte offset that only
    // accounts for '\n' drifts one byte per preceding line on CRLF files, so the
    // offset-derived parameter list and complexity get read from the wrong span.
    // The preceding line ends in a stray '(' so a drifted offset latches onto
    // the wrong parenthesis group -- the exact failure mode of the bug.
    let body = "// region helpers\n\
                let region = open_scope(\n\
                pub fn decode_frame(buf: &[u8], len: usize) -> bool {\n\
                \x20   !buf.is_empty() && len > 0\n\
                }\n";
    let lf_dir = tempfile::tempdir().unwrap();
    std::fs::write(lf_dir.path().join("lib.rs"), body).unwrap();
    let crlf_dir = tempfile::tempdir().unwrap();
    std::fs::write(crlf_dir.path().join("lib.rs"), body.replace('\n', "\r\n")).unwrap();

    let lf = hf_discovery::discover(lf_dir.path(), TargetLanguage::Rust)
        .await
        .expect("lf discovery");
    let crlf = hf_discovery::discover(crlf_dir.path(), TargetLanguage::Rust)
        .await
        .expect("crlf discovery");

    let pick = |inv: &hf_core::target::TargetInventory| {
        inv.candidates
            .iter()
            .find(|c| c.symbol == "decode_frame")
            .map(|c| (c.input_surface, c.complexity))
    };
    let lf_frame = pick(&lf).expect("decode_frame found on LF");
    let crlf_frame = pick(&crlf).expect("decode_frame found on CRLF");
    // The offset-derived input surface and complexity must match LF exactly.
    assert_eq!(
        lf_frame, crlf_frame,
        "CRLF scan diverged from LF (offset drift): LF={lf_frame:?} CRLF={crlf_frame:?}"
    );
}

#[tokio::test]
async fn discover_go_finds_exported_functions_and_methods() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("parser.go"),
        "package parser\n\
         \n\
         func ParsePacket(data []byte, offset int) bool {\n\
         \tif len(data) == 0 {\n\
         \t\treturn false\n\
         \t}\n\
         \treturn data[0] == 0x7f && offset >= 0\n\
         }\n\
         \n\
         func (d *Decoder) DecodeFrame(buf []byte) error {\n\
         \tif d.strict && len(buf) > 0 {\n\
         \t\treturn nil\n\
         \t}\n\
         \treturn nil\n\
         }\n\
         \n\
         func helper(x int) int { return x + 1 }\n\
         func main() {}\n\
         func init() {}\n\
         func NoParams() int { return 42 }\n",
    )
    .unwrap();
    // Test files are not fuzz-target sources: the scanner skips them.
    std::fs::write(
        dir.path().join("parser_test.go"),
        "package parser\n\
         \n\
         import \"testing\"\n\
         \n\
         func TestParsePacket(t *testing.T) {}\n",
    )
    .unwrap();

    let inv = hf_discovery::discover(dir.path(), TargetLanguage::Go)
        .await
        .expect("go discovery should succeed");

    // Every candidate is stamped with the Go language.
    assert!(
        !inv.candidates.is_empty()
            && inv
                .candidates
                .iter()
                .all(|c| c.language == TargetLanguage::Go),
        "all candidates must carry TargetLanguage::Go"
    );

    let ranked: Vec<&str> = inv.ranked().iter().map(|c| c.symbol.as_str()).collect();
    assert!(
        ranked.contains(&"ParsePacket"),
        "exported parser must be ranked; got {ranked:?}"
    );
    assert!(
        ranked.contains(&"Decoder.DecodeFrame"),
        "exported method must be ranked under its receiver type; got {ranked:?}"
    );
    for skipped in ["helper", "main", "init", "NoParams", "TestParsePacket"] {
        assert!(
            !ranked.contains(&skipped),
            "{skipped} must not be a candidate; got {ranked:?}"
        );
    }

    let parse = inv
        .candidates
        .iter()
        .find(|c| c.symbol == "ParsePacket")
        .expect("ParsePacket should be discovered");
    assert_eq!(parse.kind, TargetKind::Parser);
}

#[tokio::test]
async fn discover_python_finds_defs_and_methods() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("codec.py"),
        "import struct\n\
         \n\
         \n\
         def parse_packet(data, offset=0):\n\
         \x20   if not data:\n\
         \x20       return None\n\
         \x20   while offset < len(data):\n\
         \x20       if data[offset] == 0x7f:\n\
         \x20           return data[offset:]\n\
         \x20       offset += 1\n\
         \x20   return None\n\
         \n\
         \n\
         async def fetch_payload(url, timeout=10):\n\
         \x20   return url\n\
         \n\
         \n\
         class Decoder:\n\
         \x20   @staticmethod\n\
         \x20   def load(raw, strict=False):\n\
         \x20       return raw\n\
         \n\
         \x20   def decode_frame(self, buf):\n\
         \x20       if self.strict and buf:\n\
         \x20           return buf\n\
         \x20       return None\n\
         \n\
         \x20   def _validate(self):\n\
         \x20       return True\n\
         \n\
         \n\
         def test_parse_packet():\n\
         \x20   assert parse_packet(b\"\\x7f\")\n",
    )
    .unwrap();

    let inv = hf_discovery::discover(dir.path(), TargetLanguage::Python)
        .await
        .expect("python discovery should succeed");

    assert!(
        !inv.candidates.is_empty()
            && inv
                .candidates
                .iter()
                .all(|c| c.language == TargetLanguage::Python),
        "all candidates must carry TargetLanguage::Python"
    );

    let ranked: Vec<&str> = inv.ranked().iter().map(|c| c.symbol.as_str()).collect();
    for expected in [
        "parse_packet",
        "fetch_payload",
        "Decoder.load",
        "Decoder.decode_frame",
    ] {
        assert!(
            ranked.contains(&expected),
            "{expected} must be ranked; got {ranked:?}"
        );
    }
    for skipped in ["Decoder._validate", "test_parse_packet"] {
        assert!(
            !ranked.contains(&skipped),
            "{skipped} must not be a candidate; got {ranked:?}"
        );
    }

    let parse = inv
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_packet")
        .expect("parse_packet should be discovered");
    assert_eq!(parse.kind, TargetKind::Parser);
}

/// A directory whose name carries a source-file extension (legal on disk, e.g.
/// `pkg.go/`) must not abort discovery: the extension filter alone would let it
/// through to `read_to_string`, which fails with "is a directory". The scan
/// must skip it and still return the real candidate.
#[tokio::test]
async fn directory_named_like_source_file_does_not_abort_scan() {
    let project = tempfile::tempdir().unwrap();
    // A directory that looks like a Go source file.
    std::fs::create_dir(project.path().join("pkg.go")).unwrap();
    // A real Go source file with an exported, parameter-bearing function.
    std::fs::write(
        project.path().join("decode.go"),
        "package main\n\nfunc DecodeFrame(data []byte) int { return len(data) }\n",
    )
    .unwrap();

    let inv = hf_discovery::discover(project.path(), TargetLanguage::Go)
        .await
        .expect("discovery must not abort on a directory named like a source file");
    assert!(
        inv.candidates.iter().any(|c| c.symbol == "DecodeFrame"),
        "the real candidate must survive; got {:?}",
        inv.candidates.iter().map(|c| &c.symbol).collect::<Vec<_>>()
    );
}
