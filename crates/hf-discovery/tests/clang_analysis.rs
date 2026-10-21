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
        "declarations": [], "result_type": "int", "parameters": [], "variadic": false,
        "linkage": "internal", "access": "none", "method_kind": "function", "definition": true})
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

fn explored() -> Value {
    let mut data = index();
    data["schema_version"] = json!(2);
    for i in [0, 1] {
        data["functions"][i]["parameters"] = json!([{"name":"n","type_name":"int"}]);
    }
    let condition =
        json!({"location":{"file":"a.c","line":2,"column":1},"text":"n > 4","parameters":[0]});
    data["exploration"] = json!({
        "engine":"clang-static-analyzer-range-v1",
        "limits":{"max_nodes":10000,"max_block_visits":4,"max_records":256,"max_cfg_blocks":2048,"max_inline_depth":4},
        "roots":["entry"],
        "cfgs":[{"function":"entry","status":"complete","blocks":[
            {"id":0,"successors":[1,null],"condition":condition},
            {"id":1,"successors":[],"condition":null}]}],
        "calls":[{"root":"entry","caller":"entry","callee":"setup:a",
            "location":{"file":"a.c","line":2,"column":1},
            "arguments":[{"argument":0,"parameters":[0],"constant":null,
                "producer":{"function":"setup:b","location":{"file":"a.c","line":5,"column":1}}}],
            "constraints":[{"parameter":0,"min":"5","max":"2147483647","nonnull":null}],
            "path":["entry","setup:a"]}],
        "branches":[{"root":"entry","caller":"entry","condition":condition,
            "constraints":[{"parameter":0,"min":"5","max":"2147483647","nonnull":null}],
            "true_state":false,"false_state":true}],
        "exhausted":false,"omitted_records":0});
    data
}

#[test]
fn advanced_evidence_is_retained_and_foreign_references_are_checked() {
    let good = explored();
    let normalized = normalize_index(&serde_json::to_vec(&good).unwrap(), &limits()).unwrap();
    assert_eq!(
        serde_json::to_value(normalized).unwrap()["exploration"],
        good["exploration"]
    );
    let mut cases = vec![];
    for (pointer, value) in [
        ("/schema_version", json!(3)),
        ("/schema_version", json!(1)),
        ("/exploration/engine", json!("invented")),
        ("/exploration/roots/0", json!("absent")),
        ("/exploration/cfgs/0/blocks/0/successors/0", json!(9)),
        (
            "/exploration/cfgs/0/blocks/0/condition/parameters/0",
            json!(7),
        ),
        ("/exploration/calls/0/root", json!("leaf")),
        ("/exploration/calls/0/callee", json!("absent")),
        ("/exploration/calls/0/arguments/0/parameters/0", json!(9)),
        (
            "/exploration/calls/0/arguments/0/producer/function",
            json!("absent"),
        ),
        (
            "/exploration/calls/0/arguments/0/producer/location/line",
            json!(99),
        ),
        ("/exploration/calls/0/constraints/0/min", json!("nan")),
        ("/exploration/calls/0/constraints/0/max", json!("3")),
        ("/exploration/calls/0/path/0", json!("leaf")),
        (
            "/exploration/calls/0/path",
            json!(["entry", "leaf", "setup:a"]),
        ),
        ("/exploration/limits/max_records", json!(1)),
        ("/exploration/limits/max_nodes", json!(0)),
        ("/exploration/limits/max_cfg_blocks", json!(1)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        cases.push(bad);
    }
    let mut missing = good;
    missing.as_object_mut().unwrap().remove("exploration");
    cases.push(missing);
    for bad in cases {
        assert!(
            normalize_index(&serde_json::to_vec(&bad).unwrap(), &limits()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn modeled_function_pointer_resolution_preserves_the_static_unknown_site() {
    let mut data = explored();
    data["calls"][0]["callee"] = Value::Null;
    data["calls"][0]["dispatch"] = json!("indirect");
    let graph = normalize_index(&serde_json::to_vec(&data).unwrap(), &limits()).unwrap();
    assert!(graph.calls.iter().any(|c| c.callee.is_none()));
    assert!(graph.exploration.unwrap().calls[0].callee.is_some());
    data["exploration"]["calls"][0]["location"]["line"] = json!(99);
    assert!(normalize_index(&serde_json::to_vec(&data).unwrap(), &limits()).is_err());
}

#[tokio::test]
async fn advanced_context_and_plan_refer_to_retained_evidence_only() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.c"), "int entry(int n){return n;}").unwrap();
    let inventory = hf_discovery::discover(root.path(), hf_core::target::TargetLanguage::C)
        .await
        .unwrap();
    let target = inventory
        .candidates
        .iter()
        .find(|c| c.symbol == "entry")
        .unwrap();
    let data = explored();
    let graph = normalize_index(&serde_json::to_vec(&data).unwrap(), &limits()).unwrap();
    let context = hf_discovery::clang_analysis::target_context(&graph, target, &limits()).unwrap();
    let encoded = serde_json::to_value(&context).unwrap();
    assert_eq!(encoded["exploration"]["roots"], json!(["entry"]));
    assert_eq!(encoded["plan"]["inputs"], json!([{"call":0,"argument":0}]));
    assert_eq!(encoded["plan"]["guards"], json!([0]));
    assert_eq!(
        encoded["plan"]["producer_uses"],
        json!([{"call":0,"argument":0}])
    );
    let mut small = limits();
    small.max_context_bytes = 4096;
    let context = hf_discovery::clang_analysis::target_context(&graph, target, &small).unwrap();
    assert!(hf_prompt_size(&context) <= small.max_context_bytes);
    let mut unrelated = target.clone();
    unrelated.symbol = "leaf".into();
    let context =
        hf_discovery::clang_analysis::target_context(&graph, &unrelated, &limits()).unwrap();
    assert!(serde_json::to_value(context).unwrap()["exploration"].is_null());
}

#[tokio::test]
async fn planner_accepted_context_always_renders_within_budget() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.c"), "int entry(int n){return n;}").unwrap();
    let inventory = hf_discovery::discover(root.path(), hf_core::target::TargetLanguage::C)
        .await
        .unwrap();
    let target = inventory
        .candidates
        .iter()
        .find(|c| c.symbol == "entry")
        .unwrap();
    let graph = normalize_index(&serde_json::to_vec(&explored()).unwrap(), &limits()).unwrap();
    for budget in [1024usize, 2048, 4096, 8192, 16_384, 32_768] {
        let mut small = limits();
        small.max_context_bytes = budget;
        let Ok(context) = hf_discovery::clang_analysis::target_context(&graph, target, &small)
        else {
            continue;
        };
        assert!(
            hf_prompt::render_clang_context(&context, budget).is_ok(),
            "planner accepted a context the renderer rejects at {budget} bytes"
        );
    }
}

fn hf_prompt_size(context: &hf_core::clang_analysis::ClangTargetContext) -> usize {
    serde_json::to_string(context)
        .unwrap()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .len()
        + hf_prompt::clang_context_wrapper_bytes(context)
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

#[tokio::test]
async fn context_keeps_transitive_reverse_paths_and_reports_unknown_dispatch() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.c"), "int entry(char*x){return *x;}").unwrap();
    let inventory = hf_discovery::discover(root.path(), hf_core::target::TargetLanguage::C)
        .await
        .unwrap();
    let target = inventory
        .candidates
        .iter()
        .find(|c| c.symbol == "entry")
        .unwrap();
    let mut data = index();
    data["functions"].as_array_mut().unwrap().extend([
        function("outer", "a.c", "outer"),
        function("caller", "a.c", "caller"),
    ]);
    for (caller, callee) in [("outer", "caller"), ("caller", "entry")] {
        data["calls"].as_array_mut().unwrap().push(json!({"caller":caller,"callee":callee,"dispatch":"direct","location":{"file":"a.c","line":8,"column":1}}));
    }
    let graph = normalize_index(&serde_json::to_vec(&data).unwrap(), &limits()).unwrap();
    let context = hf_discovery::clang_analysis::target_context(&graph, target, &limits()).unwrap();
    assert!(context
        .paths
        .contains(&vec!["outer".into(), "caller".into(), "entry".into()]));
    assert_eq!(context.unresolved_calls, 2);
}

#[tokio::test]
async fn same_line_overloads_associate_by_definition_coordinates() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("a.cpp"),
        "int parse(int x){return x;} int parse(char*x){return *x;}",
    )
    .unwrap();
    let inventory = hf_discovery::discover(root.path(), hf_core::target::TargetLanguage::Cpp)
        .await
        .unwrap();
    let mut data = index();
    data["units"][0]["file"] = json!("a.cpp");
    let first = function("first", "a.cpp", "parse");
    let mut second = function("second", "a.cpp", "parse");
    second["location"]["column"] = json!(28);
    data["functions"] = json!([first, second]);
    data["calls"] = json!([]);
    let graph = normalize_index(&serde_json::to_vec(&data).unwrap(), &limits()).unwrap();
    let first_candidate = inventory
        .candidates
        .iter()
        .find(|c| c.location.col == 1)
        .unwrap();
    assert_eq!(
        hf_discovery::clang_analysis::associate_target(&graph, first_candidate),
        hf_core::clang_analysis::ClangTargetAssociation::Exact("first".into())
    );
}

async fn entry_target(source: &str) -> (tempfile::TempDir, hf_core::target::TargetCandidate) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.c"), source).unwrap();
    let inventory = hf_discovery::discover(root.path(), hf_core::target::TargetLanguage::C)
        .await
        .unwrap();
    (
        root,
        inventory
            .candidates
            .iter()
            .find(|c| c.symbol == "entry")
            .unwrap()
            .clone(),
    )
}

fn duplicated_observations() -> Value {
    let mut data = explored();
    let call = data["exploration"]["calls"][0].clone();
    data["exploration"]["calls"]
        .as_array_mut()
        .unwrap()
        .push(call);
    let branch = data["exploration"]["branches"][0].clone();
    data["exploration"]["branches"]
        .as_array_mut()
        .unwrap()
        .push(branch);
    data
}

#[tokio::test]
async fn repeated_exact_observations_collapse_without_omission_or_duplicate_plan_entries() {
    let (_root, target) = entry_target("int entry(int n){return n;}").await;
    let graph = normalize_index(
        &serde_json::to_vec(&duplicated_observations()).unwrap(),
        &limits(),
    )
    .unwrap();
    let context = hf_discovery::clang_analysis::target_context(&graph, &target, &limits()).unwrap();
    let exploration = context.exploration.as_ref().unwrap();
    assert_eq!(exploration.calls.len(), 1);
    assert_eq!(exploration.branches.len(), 1);
    assert_eq!(exploration.omitted_records, 0);
    let encoded = serde_json::to_value(&context).unwrap();
    assert_eq!(encoded["plan"]["inputs"], json!([{"call":0,"argument":0}]));
    assert_eq!(encoded["plan"]["guards"], json!([0]));
    assert_eq!(
        encoded["plan"]["producer_uses"],
        json!([{"call":0,"argument":0}])
    );
}

fn alternative_observations() -> Value {
    let mut data = explored();
    let branch = data["exploration"]["branches"][0].clone();
    let mut range_alt = branch.clone();
    range_alt["constraints"][0]["min"] = json!("8");
    let mut outcome_alt = branch.clone();
    outcome_alt["true_state"] = json!(true);
    outcome_alt["false_state"] = json!(false);
    let mut caller_alt = branch.clone();
    caller_alt["caller"] = json!("setup:b");
    caller_alt["condition"] =
        json!({"location":{"file":"a.c","line":7,"column":1},"text":"flag","parameters":[]});
    data["exploration"]["branches"] =
        json!([branch.clone(), branch, range_alt, outcome_alt, caller_alt]);
    let call = data["exploration"]["calls"][0].clone();
    let mut site_range_alt = call.clone();
    site_range_alt["constraints"][0]["min"] = json!("8");
    let mut site_alt = call.clone();
    site_alt["caller"] = json!("setup:a");
    site_alt["callee"] = json!("leaf");
    site_alt["location"] = json!({"file":"a.c","line":3,"column":1});
    site_alt["path"] = json!(["entry", "setup:a", "leaf"]);
    site_alt["arguments"] =
        json!([{"argument":0,"parameters":[0],"constant":null,"producer":null}]);
    data["exploration"]["calls"] = json!([call.clone(), call, site_range_alt, site_alt]);
    data
}

#[tokio::test]
async fn distinct_alternative_observations_stay_separate_records() {
    let (_root, target) = entry_target("int entry(int n){return n;}").await;
    let graph = normalize_index(
        &serde_json::to_vec(&alternative_observations()).unwrap(),
        &limits(),
    )
    .unwrap();
    let context = hf_discovery::clang_analysis::target_context(&graph, &target, &limits()).unwrap();
    let exploration = context.exploration.as_ref().unwrap();
    assert_eq!(exploration.calls.len(), 3);
    assert_eq!(exploration.branches.len(), 4);
    assert_eq!(exploration.omitted_records, 0);
    let calls = &exploration.calls;
    assert_ne!(calls[0].constraints, calls[1].constraints);
    let branches = &exploration.branches;
    assert_ne!(branches[0].constraints, branches[1].constraints);
    assert_ne!(branches[0].true_state, branches[2].true_state);
    assert_ne!(branches[0].caller, branches[3].caller);
    let encoded = serde_json::to_value(&context).unwrap();
    assert_eq!(encoded["plan"]["guards"], json!([0, 1, 2, 3]));
    assert_eq!(
        encoded["plan"]["inputs"],
        json!([{"call":0,"argument":0},{"call":1,"argument":0},{"call":2,"argument":0}])
    );
    assert_eq!(
        encoded["plan"]["producer_uses"],
        json!([{"call":0,"argument":0},{"call":1,"argument":0}])
    );
}

fn guarded_root() -> Value {
    let mut data = index();
    data["schema_version"] = json!(2);
    data["functions"] = json!([function("entry", "a.c", "entry")]);
    data["functions"][0]["parameters"] = json!([{"name": "n", "type_name": "int"}]);
    data["calls"] = json!([{"caller":"entry","callee":null,"dispatch":"indirect",
        "location":{"file":"a.c","line":9,"column":1}}]);
    let blocks: Vec<Value> = (0..60)
        .map(|i| {
            let successors = if i + 1 < 60 {
                json!([i + 1])
            } else {
                json!([])
            };
            json!({"id": i, "successors": successors,
                "condition": {"location": {"file":"a.c","line": i + 2,"column":1},
                    "text":"n != 0","parameters":[0]}})
        })
        .collect();
    let call = json!({"root":"entry","caller":"entry","callee":null,
        "location":{"file":"a.c","line":9,"column":1},
        "arguments":[{"argument":0,"parameters":[0],"constant":"5","producer":null}],
        "constraints":[{"parameter":0,"min":"5","max":"2147483647","nonnull":null}],
        "path":["entry"]});
    let branches: Vec<Value> = ["5", "7", "9"]
        .into_iter()
        .map(|min| json!({"root":"entry","caller":"entry",
            "condition":{"location":{"file":"a.c","line":2,"column":1},"text":"n != 0","parameters":[0]},
            "constraints":[{"parameter":0,"min":min,"max":"2147483647","nonnull":null}],
            "true_state":false,"false_state":true}))
        .collect();
    data["exploration"] = json!({
        "engine":"clang-static-analyzer-range-v1",
        "limits":{"max_nodes":10000,"max_block_visits":4,"max_records":256,"max_cfg_blocks":2048,"max_inline_depth":4},
        "roots":["entry"],
        "cfgs":[{"function":"entry","status":"complete","blocks":blocks}],
        "calls":[call.clone(), call.clone(), call.clone(), call.clone(), call],
        "branches":branches,
        "exhausted":true,"omitted_records":73});
    data
}

#[tokio::test]
async fn tight_budgets_keep_distinct_guards_behind_redundant_raw_evidence() {
    let (_root, target) = entry_target("int entry(int n){return n;}").await;
    let graph = normalize_index(&serde_json::to_vec(&guarded_root()).unwrap(), &limits()).unwrap();
    let mut roomy = limits();
    roomy.max_context_bytes = 1 << 20;
    let reference = hf_discovery::clang_analysis::target_context(&graph, &target, &roomy).unwrap();
    let value = serde_json::to_value(&reference).unwrap();
    assert_eq!(
        value["exploration"]["cfgs"].as_array().map(Vec::len),
        Some(1)
    );
    let cfg_len = serde_json::to_vec(&value["exploration"]["cfgs"][0])
        .unwrap()
        .len();
    let mut tight = limits();
    tight.max_context_bytes = hf_prompt_size(&reference) - cfg_len + 512;
    let context = hf_discovery::clang_analysis::target_context(&graph, &target, &tight).unwrap();
    assert!(hf_prompt_size(&context) <= tight.max_context_bytes);
    let exploration = context.exploration.as_ref().unwrap();
    assert_eq!(exploration.branches.len(), 3);
    assert_eq!(exploration.calls.len(), 1);
    assert_eq!(
        exploration.calls.len() + exploration.branches.len() + exploration.cfgs.len(),
        4
    );
    assert_eq!(exploration.omitted_records, 73 + 1);
    assert!(exploration.exhausted);
    let plan = context.plan.as_ref().unwrap();
    assert_eq!(plan.guards, &[0, 1, 2]);
    for guard in &plan.guards {
        assert!(*guard < exploration.branches.len());
    }
    for input in &plan.inputs {
        let call = exploration.calls.get(input.call).expect("plan call ref");
        assert!(!call.arguments[input.argument].parameters.is_empty());
    }
}

fn pressured_root() -> Value {
    let mut data = index();
    data["schema_version"] = json!(2);
    data["functions"] = json!([
        function("entry", "a.c", "entry"),
        function("setup:b", "b.c", "setup")
    ]);
    data["functions"][0]["parameters"] = json!([{"name": "n", "type_name": "int"}]);
    data["calls"] = json!([
        {"caller":"entry","callee":null,"dispatch":"indirect",
            "location":{"file":"a.c","line":9,"column":1}},
        {"caller":"entry","callee":"setup:b","dispatch":"direct",
            "location":{"file":"a.c","line":5,"column":1}}]);
    let calls: Vec<Value> = (0..12)
        .map(|i| json!({"root":"entry","caller":"entry","callee":null,
            "location":{"file":"a.c","line":9,"column":1},
            "arguments":[{"argument":0,"parameters":[0],"constant":null,
                "producer":{"function":"setup:b","location":{"file":"a.c","line":5,"column":1}}}],
            "constraints":[{"parameter":0,"min":(i * 7).to_string(),"max":"2147483647","nonnull":null}],
            "path":["entry"]}))
        .collect();
    data["exploration"] = json!({
        "engine":"clang-static-analyzer-range-v1",
        "limits":{"max_nodes":10000,"max_block_visits":4,"max_records":256,"max_cfg_blocks":2048,"max_inline_depth":4},
        "roots":["entry"],
        "cfgs":[{"function":"entry","status":"complete",
            "blocks":[{"id":0,"successors":[],"condition":null}]}],
        "calls":calls,
        "branches":[
            {"root":"entry","caller":"entry",
                "condition":{"location":{"file":"a.c","line":2,"column":1},"text":"n != 0","parameters":[0]},
                "constraints":[{"parameter":0,"min":"5","max":"2147483647","nonnull":null}],
                "true_state":false,"false_state":true},
            {"root":"entry","caller":"entry",
                "condition":{"location":{"file":"a.c","line":2,"column":1},"text":"n != 0","parameters":[0]},
                "constraints":[{"parameter":0,"min":"5","max":"2147483647","nonnull":null}],
                "true_state":true,"false_state":false}],
        "exhausted":false,"omitted_records":0});
    data
}

#[tokio::test]
async fn plan_references_survive_budget_selection_pressure() {
    let (_root, target) = entry_target("int entry(int n){return n;}").await;
    let graph =
        normalize_index(&serde_json::to_vec(&pressured_root()).unwrap(), &limits()).unwrap();
    let mut roomy = limits();
    roomy.max_context_bytes = 1 << 20;
    let reference = hf_discovery::clang_analysis::target_context(&graph, &target, &roomy).unwrap();
    let value = serde_json::to_value(&reference).unwrap();
    let call_len = serde_json::to_vec(&value["exploration"]["calls"][0])
        .unwrap()
        .len();
    let mut tight = limits();
    tight.max_context_bytes = hf_prompt_size(&reference) - 7 * call_len;
    let context = hf_discovery::clang_analysis::target_context(&graph, &target, &tight).unwrap();
    assert!(hf_prompt_size(&context) <= tight.max_context_bytes);
    let exploration = context.exploration.as_ref().unwrap();
    assert!((1..12).contains(&exploration.calls.len()));
    assert_eq!(exploration.branches.len(), 2);
    let retained = exploration.calls.len() + exploration.branches.len() + exploration.cfgs.len();
    assert!(retained < 15);
    assert_eq!(exploration.omitted_records, 15 - retained);
    let plan = context.plan.as_ref().unwrap();
    for guard in &plan.guards {
        assert!(*guard < exploration.branches.len());
    }
    for path in &plan.caller_paths {
        assert!(*path < context.paths.len());
    }
    for plan_ref in plan.inputs.iter().chain(&plan.producer_uses) {
        let call = exploration
            .calls
            .get(plan_ref.call)
            .expect("plan call reference retained");
        let argument = call
            .arguments
            .get(plan_ref.argument)
            .expect("plan argument reference retained");
        if plan.inputs.contains(plan_ref) {
            assert!(!argument.parameters.is_empty());
        }
        if plan.producer_uses.contains(plan_ref) {
            assert!(argument.producer.is_some());
        }
    }
    assert!(!plan.inputs.is_empty());
    assert!(!plan.producer_uses.is_empty());
}
