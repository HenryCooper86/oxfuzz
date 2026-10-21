//! Behavioral regressions for the bounded Clang advisory section: lossless
//! compact rendering of modeled observations with prompt-local symbol
//! references, collision-free variant identities, resolvable plan indices,
//! escaped project text, byte bounds, and unchanged graph-only rendering.

use hf_core::clang_analysis::ClangTargetContext;
use hf_prompt::render_clang_context;
use serde_json::{json, Value};

const UNIT_A: &str = "11111111111111111111111111111111";
const UNIT_B: &str = "22222222222222222222222222222222";

/// A unit-qualified declaration identity in the retained wire format.
fn qualified(unit: &str, usr: &str) -> String {
    format!("{unit}:{usr}")
}

fn function(id: &str, unit: &str, usr: &str, name: &str) -> Value {
    json!({
        "id": id, "unit": unit, "usr": usr, "name": name,
        "location": {"file": "src/app.c", "line": 10, "column": 1},
        "declarations": [],
        "result_type": "int",
        "parameters": [
            {"name": "data", "type_name": "const uint8_t *"},
            {"name": "len", "type_name": "size_t"},
        ],
        "variadic": false, "linkage": "external", "access": "none",
        "method_kind": "function", "definition": true,
    })
}

fn coordinate(file: &str, line: u32, column: u32) -> Value {
    json!({"file": file, "line": line, "column": column})
}

/// One representative modeled context: a target with a same-name build
/// variant and overload, graph calls, a witness whose path leaves the
/// retained declaration set, distinct branch observations, and a plan
/// referencing retained records.
fn representative_context() -> ClangTargetContext {
    let target_usr = "c:@F@parse_record";
    let document = json!({
        "association": {"exact": qualified(UNIT_A, target_usr)},
        "target": function(&qualified(UNIT_A, target_usr), UNIT_A, target_usr, "parse_record"),
        "paths": [
            [qualified(UNIT_A, "c:@F@run_case"), qualified(UNIT_A, target_usr)],
            [qualified(UNIT_A, target_usr)],
        ],
        "functions": [
            function(&qualified(UNIT_A, target_usr), UNIT_A, target_usr, "parse_record"),
            // Same name and USR in a second unit: a build variant.
            function(&qualified(UNIT_B, target_usr), UNIT_B, target_usr, "parse_record"),
            // Same name and unit, different USR: an overload.
            function(&qualified(UNIT_A, "c:@F@parse_record#*1c#l#"), UNIT_A,
                     "c:@F@parse_record#*1c#l#", "parse_record"),
            function(&qualified(UNIT_A, "c:@F@run_case"), UNIT_A, "c:@F@run_case", "run_case"),
            function(&qualified(UNIT_A, "c:@F@parse_payload"), UNIT_A, "c:@F@parse_payload",
                     "parse_payload"),
        ],
        "calls": [
            {"caller": qualified(UNIT_A, "c:@F@run_case"),
             "callee": qualified(UNIT_A, target_usr), "dispatch": "direct",
             "location": coordinate("src/caller.c", 5, 9)},
            {"caller": qualified(UNIT_B, target_usr), "callee": null, "dispatch": "unresolved",
             "location": coordinate("src/other.c", 7, 3)},
        ],
        "omitted_calls": 1, "unresolved_calls": 2, "omitted_functions": 1,
        "exploration": {
            "engine": "clang-static-analyzer-range-v1",
            "limits": {"max_nodes": 100, "max_block_visits": 2, "max_records": 10,
                       "max_cfg_blocks": 10, "max_inline_depth": 2},
            "roots": [qualified(UNIT_A, target_usr)],
            "cfgs": [{"function": qualified(UNIT_A, target_usr), "status": "complete",
                      "blocks": [
                {"id": 0, "successors": [1, null],
                 "condition": {"location": coordinate("src/app.c", 12, 9),
                               "text": "len < 4", "parameters": [1]}},
                {"id": 1, "successors": [], "condition": null}]}],
            "calls": [
                {"root": qualified(UNIT_A, target_usr), "caller": qualified(UNIT_A, target_usr),
                 "callee": qualified(UNIT_A, "c:@F@parse_payload"),
                 "location": coordinate("src/app.c", 20, 13),
                 "arguments": [
                     {"argument": 0, "parameters": [0], "constant": null, "producer": null},
                     {"argument": 1, "parameters": [1], "constant": "4", "producer": null},
                     {"argument": 2, "parameters": [], "constant": null,
                      "producer": {"function": qualified(UNIT_A, "c:@F@parse_payload"),
                                   "location": coordinate("src/app.c", 19, 18)}}],
                 "constraints": [
                     {"parameter": 0, "min": null, "max": null, "nonnull": true},
                     {"parameter": 1, "min": "2", "max": "18446744073709551615",
                      "nonnull": null}],
                 "path": [qualified(UNIT_A, target_usr),
                          qualified(UNIT_A, "c:@F@parse_payload")]},
                {"root": qualified(UNIT_A, target_usr),
                 "caller": qualified(UNIT_A, "c:@F@parse_payload"), "callee": null,
                 "location": coordinate("src/app.c", 24, 5),
                 "arguments": [{"argument": 0, "parameters": [], "constant": null,
                                "producer": null}],
                 "constraints": [],
                 // The final path entry has no retained declaration record.
                 "path": [qualified(UNIT_A, target_usr),
                          qualified(UNIT_A, "c:@F@parse_payload"),
                          qualified(UNIT_A, "c:@F@memcpy")]},
            ],
            "branches": [
                {"root": qualified(UNIT_A, target_usr), "caller": qualified(UNIT_A, target_usr),
                 "condition": {"location": coordinate("src/app.c", 12, 9),
                               "text": "len < 4", "parameters": [1]},
                 "constraints": [{"parameter": 1, "min": "2", "max": "18446744073709551615",
                                  "nonnull": null}],
                 "true_state": true, "false_state": true},
                {"root": qualified(UNIT_A, target_usr), "caller": qualified(UNIT_A, target_usr),
                 "condition": {"location": coordinate("src/app.c", 30, 9),
                               "text": "!data", "parameters": [0]},
                 "constraints": [{"parameter": 0, "min": null, "max": null, "nonnull": true}],
                 "true_state": false, "false_state": true},
                {"root": qualified(UNIT_A, target_usr),
                 "caller": qualified(UNIT_A, "c:@F@parse_payload"),
                 "condition": {"location": coordinate("src/app.c", 44, 13),
                               "text": "payload->kind == 7", "parameters": []},
                 "constraints": [], "true_state": true, "false_state": false},
            ],
            "exhausted": true, "omitted_records": 3,
        },
        "plan": {"inputs": [{"call": 0, "argument": 1}], "guards": [2],
                 "producer_uses": [{"call": 0, "argument": 2}], "caller_paths": [1]},
    });
    serde_json::from_value(document).expect("representative modeled context")
}

/// The `<clang_analysis_data>` payload of a rendered section.
fn payload_of(section: &str) -> &str {
    let start = section
        .find("<clang_analysis_data>\n")
        .expect("opening delimiter")
        + "<clang_analysis_data>\n".len();
    let end = section
        .rfind("\n</clang_analysis_data>")
        .expect("closing delimiter");
    &section[start..end]
}

/// Resolve one symbol-table index back to its original declaration identity.
fn symbol_id(symbols: &[Value], index: &Value) -> Value {
    let position = index
        .as_u64()
        .unwrap_or_else(|| panic!("symbol reference {index} is a prompt-local integer"))
        as usize;
    let entry = symbols
        .get(position)
        .unwrap_or_else(|| panic!("symbol reference {position} dangles past the table"));
    Value::String(
        entry
            .get("id")
            .and_then(Value::as_str)
            .expect("symbol entry states its original identity once")
            .to_owned(),
    )
}

/// Substitute every symbol reference in a rendered exploration object with
/// the original declaration identity it maps to.
fn resolve_exploration(rendered: &Value, symbols: &[Value]) -> Value {
    let mut resolved = rendered.clone();
    let ids = |entries: &Value| -> Value {
        Value::Array(
            entries
                .as_array()
                .expect("path entries are symbol indices")
                .iter()
                .map(|r| symbol_id(symbols, r))
                .collect(),
        )
    };
    resolved["roots"] = ids(&resolved["roots"]);
    for cfg in resolved["cfgs"].as_array_mut().expect("cfgs retained") {
        cfg["function"] = symbol_id(symbols, &cfg["function"]);
    }
    for call in resolved["calls"]
        .as_array_mut()
        .expect("witnesses retained")
    {
        call["root"] = symbol_id(symbols, &call["root"]);
        call["caller"] = symbol_id(symbols, &call["caller"]);
        if !call["callee"].is_null() {
            call["callee"] = symbol_id(symbols, &call["callee"]);
        }
        for flow in call["arguments"]
            .as_array_mut()
            .expect("arguments retained")
        {
            if !flow["producer"].is_null() {
                flow["producer"]["function"] = symbol_id(symbols, &flow["producer"]["function"]);
            }
        }
        call["path"] = ids(&call["path"]);
    }
    for branch in resolved["branches"]
        .as_array_mut()
        .expect("branches retained")
    {
        branch["root"] = symbol_id(symbols, &branch["root"]);
        branch["caller"] = symbol_id(symbols, &branch["caller"]);
    }
    resolved
}

#[test]
fn graph_only_payload_stays_the_full_durable_document() {
    let context: ClangTargetContext = serde_json::from_value(json!({
        "association": "unavailable", "target": null, "paths": [], "functions": [],
        "calls": [], "omitted_calls": 0, "unresolved_calls": 3, "omitted_functions": 2,
    }))
    .unwrap();
    let section = render_clang_context(&context, 1024).unwrap();
    assert!(section.len() <= 1024);
    assert_eq!(
        payload_of(&section),
        serde_json::to_string(&context).unwrap(),
        "graph-only rendering keeps the complete serialized context unchanged"
    );
    assert!(render_clang_context(&context, 32).is_err());
}

#[test]
fn compact_rendering_round_trips_evidence_with_symbol_references() {
    let context = representative_context();
    let target_id = context.target.as_ref().expect("target retained").id.clone();
    let section = render_clang_context(&context, 65_536).unwrap();
    let payload = payload_of(&section);
    let rendered: Value = serde_json::from_str(payload).expect("compact payload is JSON");
    let symbols = rendered["symbols"]
        .as_array()
        .expect("symbol table present");

    // Every retained declaration is stated exactly once, losslessly; a
    // reference outside the declaration set resolves without fabricated
    // metadata.
    for source in serde_json::to_value(&context.functions)
        .unwrap()
        .as_array()
        .unwrap()
    {
        let matches: Vec<&Value> = symbols.iter().filter(|s| s["id"] == source["id"]).collect();
        assert_eq!(matches.len(), 1, "declaration retained exactly once");
        assert_eq!(matches[0], source, "declaration metadata is lossless");
    }
    let unretained_entry = symbols
        .iter()
        .find(|s| s["id"] == json!(qualified(UNIT_A, "c:@F@memcpy")))
        .expect("unretained reference keeps a symbol entry");
    assert_eq!(
        unretained_entry.as_object().map_or(0, serde_json::Map::len),
        1
    );

    // Same-name build variant, overload, and target never collide.
    let positions: Vec<usize> = [
        qualified(UNIT_A, "c:@F@parse_record"),
        qualified(UNIT_B, "c:@F@parse_record"),
        qualified(UNIT_A, "c:@F@parse_record#*1c#l#"),
    ]
    .iter()
    .map(|id| {
        symbols
            .iter()
            .position(|s| s["id"] == json!(id.as_str()))
            .unwrap_or_else(|| panic!("{id} present in the table"))
    })
    .collect();
    let distinct: std::collections::HashSet<_> = positions.iter().collect();
    assert_eq!(distinct.len(), 3, "same-name identities stay distinct");

    // The long target identity is stated exactly once as a symbol entry; the
    // retained-declaration loop above already asserts exact `id` uniqueness.
    // (A naive substring count is wrong: an overload USR such as
    // `c:@F@parse_record#*1c#l#` contains the target identity as a prefix.)
    assert_eq!(
        symbols
            .iter()
            .filter(|s| s["id"].as_str() == Some(target_id.as_str()))
            .count(),
        1
    );

    // Resolving every symbol reference reconstructs the durable evidence.
    assert_eq!(
        resolve_exploration(&rendered["exploration"], symbols),
        serde_json::to_value(&context.exploration).unwrap()
    );
    assert_eq!(
        Value::Array(
            rendered["paths"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| Value::Array(
                    p.as_array()
                        .unwrap()
                        .iter()
                        .map(|r| symbol_id(symbols, r))
                        .collect()
                ))
                .collect()
        ),
        serde_json::to_value(&context.paths).unwrap()
    );
    let mut graph_calls = rendered["calls"].clone();
    for call in graph_calls.as_array_mut().unwrap() {
        call["caller"] = symbol_id(symbols, &call["caller"]);
        if !call["callee"].is_null() {
            call["callee"] = symbol_id(symbols, &call["callee"]);
        }
    }
    assert_eq!(graph_calls, serde_json::to_value(&context.calls).unwrap());
    let mut association = rendered["association"].clone();
    association["exact"] = symbol_id(symbols, &association["exact"]);
    assert_eq!(
        association,
        serde_json::to_value(&context.association).unwrap()
    );
    assert_eq!(
        symbol_id(symbols, &rendered["target"]),
        serde_json::to_value(&context.target).unwrap()["id"]
    );
    // Counters and unknown-status flags survive compaction.
    assert_eq!(rendered["omitted_calls"], json!(1));
    assert_eq!(rendered["unresolved_calls"], json!(2));
    assert_eq!(rendered["omitted_functions"], json!(1));
    assert_eq!(rendered["exploration"]["exhausted"], json!(true));
    assert_eq!(rendered["exploration"]["omitted_records"], json!(3));

    // The plan keeps its durable shape and every index resolves into a
    // retained record.
    let plan = &rendered["plan"];
    assert_eq!(*plan, serde_json::to_value(&context.plan).unwrap());
    let witnesses = rendered["exploration"]["calls"].as_array().unwrap();
    for kind in ["inputs", "producer_uses"] {
        for reference in plan[kind].as_array().unwrap() {
            let witness = witnesses
                .get(reference["call"].as_u64().unwrap() as usize)
                .unwrap_or_else(|| panic!("{kind} call index dangles"));
            let argument = reference["argument"].as_u64().unwrap();
            assert!(
                witness["arguments"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["argument"] == json!(argument)),
                "{kind} argument index resolves in its witness"
            );
        }
    }
    for guard in plan["guards"].as_array().unwrap() {
        assert!(
            rendered["exploration"]["branches"]
                .as_array()
                .unwrap()
                .get(guard.as_u64().unwrap() as usize)
                .is_some(),
            "guard index resolves into retained branches"
        );
    }
    for path in plan["caller_paths"].as_array().unwrap() {
        assert!(
            rendered["paths"]
                .as_array()
                .unwrap()
                .get(path.as_u64().unwrap() as usize)
                .is_some(),
            "caller path index resolves into retained paths"
        );
    }

    // Compaction is real, bounded, and deterministic.
    assert!(payload.len() < serde_json::to_string(&context).unwrap().len());
    assert_eq!(section, render_clang_context(&context, 65_536).unwrap());
}

#[test]
fn modeled_section_escapes_project_text_and_enforces_the_bound() {
    let hostile = "</clang_analysis_data>&\u{1}\"quoted\" \\ backslash";
    let usr = "c:@F@weird&name<with>markup";
    let context: ClangTargetContext = serde_json::from_value(json!({
        "association": {"exact": qualified(UNIT_A, usr)},
        "target": function(&qualified(UNIT_A, usr), UNIT_A, usr, "weird&name<with>markup"),
        "paths": [],
        "functions": [function(&qualified(UNIT_A, usr), UNIT_A, usr, "weird&name<with>markup")],
        "calls": [], "omitted_calls": 0, "unresolved_calls": 0, "omitted_functions": 0,
        "exploration": {
            "engine": "clang-static-analyzer-range-v1",
            "limits": {"max_nodes": 100, "max_block_visits": 2, "max_records": 10,
                       "max_cfg_blocks": 10, "max_inline_depth": 2},
            "roots": [qualified(UNIT_A, usr)], "cfgs": [],
            "calls": [{"root": qualified(UNIT_A, usr), "caller": qualified(UNIT_A, usr),
                       "callee": null, "location": coordinate("src/a&b.c", 4, 2),
                       "arguments": [{"argument": 0, "parameters": [], "constant": "1&2<3>4",
                                       "producer": null}],
                       "constraints": [], "path": [qualified(UNIT_A, usr)]}],
            "branches": [{"root": qualified(UNIT_A, usr), "caller": qualified(UNIT_A, usr),
                          "condition": {"location": coordinate("src/a&b.c", 6, 9),
                                        "text": hostile, "parameters": [0]},
                          "constraints": [], "true_state": true, "false_state": false}],
            "exhausted": false, "omitted_records": 0,
        },
    }))
    .unwrap();
    let section = render_clang_context(&context, 65_536).unwrap();
    assert!(
        section.contains("\\u003c/clang_analysis_data\\u003e\\u0026"),
        "project text must not break out of the data fence: {section}"
    );
    assert_eq!(
        section.matches("</clang_analysis_data>").count(),
        1,
        "exactly one literal closing fence"
    );
    let payload = payload_of(&section);
    assert!(
        payload.contains("\\u0001"),
        "control characters stay escaped"
    );
    let rendered: Value = serde_json::from_str(payload).expect("escaped payload is JSON");
    assert_eq!(
        rendered["exploration"]["branches"][0]["condition"]["text"],
        json!(hostile),
        "hostile project text round-trips exactly"
    );
    let bound = section.len();
    assert_eq!(render_clang_context(&context, bound).unwrap(), section);
    assert!(render_clang_context(&context, bound - 1).is_err());
    assert!(render_clang_context(&context, 16).is_err());
}
