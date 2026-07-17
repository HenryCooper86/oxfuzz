//! End-to-end: discovery populates interprocedural reachability from real source.

use hf_core::target::TargetLanguage;
use hf_discovery::discover;

#[tokio::test]
async fn discover_populates_reachability() {
    let dir = tempfile::tempdir().unwrap();
    // entry parses input and calls validate -> decode; sink is a leaf.
    std::fs::write(
        dir.path().join("lib.c"),
        r"
#include <stddef.h>
int decode(const unsigned char *p, size_t n) { if (n > 0 && p[0] > 10) return 1; return 0; }
int validate(const unsigned char *p, size_t n) { if (n < 4) return -1; return decode(p, n); }
int parse_entry(const unsigned char *data, size_t len) {
    if (len == 0) return 0;
    int r = validate(data, len);
    if (r < 0) return r;
    return decode(data, len);
}
",
    )
    .unwrap();

    let inv = discover(dir.path(), TargetLanguage::C)
        .await
        .expect("discover");
    let entry = inv
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_entry")
        .expect("parse_entry discovered");

    // parse_entry reaches validate + decode (transitively); accumulated > own.
    assert!(entry.reachable_functions.contains(&"validate".to_owned()));
    assert!(entry.reachable_functions.contains(&"decode".to_owned()));
    assert!(
        entry.accumulated_complexity > entry.complexity,
        "accumulated ({}) should exceed own ({})",
        entry.accumulated_complexity,
        entry.complexity
    );

    // The call graph exposes project-only direct edges for the tree view.
    let entry_callees = inv
        .call_graph
        .get("parse_entry")
        .expect("parse_entry edges");
    assert!(entry_callees.contains(&"validate".to_owned()));
    assert!(entry_callees.contains(&"decode".to_owned()));
    assert_eq!(
        inv.call_graph.get("validate"),
        Some(&vec!["decode".to_owned()])
    );
    // Leaf functions with only library calls have no edges.
    assert!(!inv.call_graph.contains_key("decode"));
}

#[tokio::test]
async fn duplicate_symbol_definitions_merge_call_edges() {
    let dir = tempfile::tempdir().unwrap();
    // Two translation units each define `parse_opts` (name-keyed identity is
    // deliberate). The merged call graph must carry BOTH definitions' edges;
    // the second definition must not overwrite the first.
    std::fs::write(
        dir.path().join("a.c"),
        r"
int helper_a(const char *p) { return p[0]; }
int parse_opts(const char *p) { return helper_a(p); }
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.c"),
        r"
int helper_b(const char *p) { return p[1]; }
int parse_opts(const char *p) { return helper_b(p); }
",
    )
    .unwrap();

    let inv = discover(dir.path(), TargetLanguage::C)
        .await
        .expect("discover");
    let edges = inv.call_graph.get("parse_opts").expect("parse_opts edges");
    assert!(
        edges.contains(&"helper_a".to_owned()),
        "first definition's callee must survive: {edges:?}"
    );
    assert!(
        edges.contains(&"helper_b".to_owned()),
        "second definition's callee must be merged in: {edges:?}"
    );
}
