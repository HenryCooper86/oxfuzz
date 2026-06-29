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
