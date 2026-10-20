#![cfg(feature = "clang-analysis")]

use hf_core::clang_analysis::ClangLimits;
use hf_discovery::clang_analysis::{normalize_index, reachable_functions};
use serde_json::{json, Value};

fn limits() -> ClangLimits {
    ClangLimits {
        max_targets: 16,
        max_translation_units: 1024,
        max_snapshot_bytes: 268_435_456,
        max_output_bytes: 16_777_216,
        max_functions: 100_000,
        max_calls: 500_000,
        timeout_secs: 600,
        memory_mb: 2048,
        cpus: 1,
        max_context_bytes: 16_384,
    }
}

fn function(id: &str, file: &str, name: &str) -> Value {
    json!({"id": id, "unit": "a", "usr": id, "name": name,
        "location": {"file": file, "line": 1, "column": 1},
        "result_type": "int", "parameters": [], "variadic": false,
        "linkage": "internal", "access": "none", "method": false,
        "static_method": false, "definition": true})
}

fn index() -> Value {
    json!({"schema_version": 1, "clang_version": "18.1.8", "helper_sha256": "a".repeat(64),
        "units": [{"id":"a", "file":"a.c", "scope": "a"}],
        "functions": [function("entry", "a.c", "entry"),
            function("setup:a", "a.c", "setup"), function("setup:b", "b.c", "setup"),
            function("leaf", "a.c", "leaf")],
        "calls": [
            {"caller":"entry","callee":"setup:a","dispatch":"direct","location":{"file":"a.c","line":2,"column":1}},
            {"caller":"setup:a","callee":"leaf","dispatch":"direct","location":{"file":"a.c","line":3,"column":1}},
            {"caller":"leaf","callee":"entry","dispatch":"direct","location":{"file":"a.c","line":4,"column":1}},
            {"caller":"entry","callee":"setup:b","dispatch":"virtual","location":{"file":"a.c","line":5,"column":1}},
            {"caller":"entry","callee":null,"dispatch":"indirect","location":{"file":"a.c","line":6,"column":1}}]})
}

#[test]
fn zero_argument_helpers_and_cycles_preserve_exact_identities() {
    let graph = normalize_index(&serde_json::to_vec(&index()).unwrap(), &limits()).unwrap();
    assert_eq!(
        reachable_functions(&graph, "entry"),
        vec!["leaf", "setup:a"]
    );
    assert!(graph.functions.iter().all(|f| f.parameters.is_empty()));
}

#[test]
fn invalid_foreign_graphs_are_rejected() {
    let mut cases = Vec::new();
    let mut bad = index();
    bad["schema_version"] = json!(2);
    cases.push(bad);
    let mut bad = index();
    bad["calls"][0]["callee"] = json!("absent");
    cases.push(bad);
    let mut bad = index();
    bad["functions"][0]["location"]["file"] = json!("../escape.c");
    cases.push(bad);
    let mut bad = index();
    bad["functions"][0]["location"]["line"] = json!(0);
    cases.push(bad);
    let mut bad = index();
    bad["extra"] = json!(true);
    cases.push(bad);
    let mut bad = index();
    bad["functions"][1]["id"] = json!("entry");
    cases.push(bad);
    for bad in cases {
        assert!(normalize_index(&serde_json::to_vec(&bad).unwrap(), &limits()).is_err());
    }
    let mut small = limits();
    small.max_functions = 1;
    assert!(normalize_index(&serde_json::to_vec(&index()).unwrap(), &small).is_err());
}

#[test]
fn external_definitions_join_only_in_an_explicit_shared_scope() {
    let mut data = index();
    data["units"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"b","file":"b.c","scope":"b"}));
    let mut declaration = function("declaration", "a.c", "other");
    declaration["usr"] = json!("external:other");
    declaration["definition"] = json!(false);
    declaration["linkage"] = json!("external");
    let mut definition = function("definition", "b.c", "other");
    definition["unit"] = json!("b");
    definition["usr"] = json!("external:other");
    definition["linkage"] = json!("external");
    data["functions"]
        .as_array_mut()
        .unwrap()
        .extend([declaration, definition]);
    data["calls"].as_array_mut().unwrap().push(json!({"caller":"entry","callee":"declaration","dispatch":"direct","location":{"file":"a.c","line":7,"column":1}}));
    let graph = normalize_index(&serde_json::to_vec(&data).unwrap(), &limits()).unwrap();
    assert!(!reachable_functions(&graph, "entry").contains(&"definition".to_owned()));
    data["units"][0]["scope"] = json!("linked");
    data["units"][1]["scope"] = json!("linked");
    let graph = normalize_index(&serde_json::to_vec(&data).unwrap(), &limits()).unwrap();
    assert_eq!(
        reachable_functions(&graph, "entry"),
        vec!["definition", "leaf", "setup:a"]
    );
}
