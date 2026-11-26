//! The requests the frontend sends for the command-line parity commands
//! reach their Rust handlers: every one is registered, and its arguments
//! deserialize under the names the webview uses.
//!
//! Each request names a target, run or file that does not exist, so the
//! service refuses it before doing any work. A refusal from the service is
//! the expected outcome; a refusal from the IPC layer is the defect.

use std::sync::Arc;

use hf_service::test_support::desktop_approval::{
    in_isolated_test_process, DesktopApprovalFixture,
};
use serde_json::{json, Value};

const MISSING_RUN: &str = "00000000-0000-4000-8000-000000000001";

fn requests(project: &str) -> Vec<(&'static str, Value)> {
    let scope = json!({ "project": project, "target": "no_such_target" });
    let with = |extra: Value| {
        let mut body = scope.clone();
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    let mut requests = vec![
        (
            "harness_draft",
            with(json!({
                "engine": "afl++", "lang": "c", "ai": "off",
                "build": { "sanitizer": "memory", "cmplog": true, "persistent": true },
            })),
        ),
        (
            "harness_smoke_with_options",
            with(json!({
                "engine": "libfuzzer", "lang": "c", "repairs": 2,
                "skipModelReview": true, "ai": "off",
            })),
        ),
        (
            "harness_refine",
            with(json!({ "engine": "libfuzzer", "lang": "c", "repairs": 1, "ai": "off" })),
        ),
        (
            "harness_adopt_revision",
            with(json!({ "engine": "libfuzzer", "lang": "c", "harnessId": MISSING_RUN })),
        ),
        (
            "run_campaign",
            json!({ "options": {
                "project": project, "target": "no_such_target", "engine": "libfuzzer",
                "lang": "c", "durationSecs": 5, "iterations": 1, "timeoutMs": 500,
                "resume": false, "sanitizer": "address", "cmplog": false,
                "seed": "7", "ai": "off",
            }}),
        ),
        (
            "run_ci_gate",
            with(json!({ "engine": "libfuzzer", "durationSecs": 5, "ai": "off" })),
        ),
        ("user_dictionary", scope.clone()),
        (
            "set_user_dictionary",
            with(json!({ "text": "not a dictionary" })),
        ),
        ("clear_user_dictionary", scope.clone()),
        (
            "fuzzing_preflight",
            json!({ "engine": "libfuzzer", "durationSecs": 60, "requireProvider": true }),
        ),
        (
            "fuzz_prepare",
            json!({
                "project": project, "engine": "libfuzzer", "target": "no_such_target",
                "lang": "c", "build": { "sanitizer": "address" }, "fresh": true,
                "skipModelReview": true,
            }),
        ),
        ("verify_regressions", scope.clone()),
        ("corpus_afl_cmin", scope.clone()),
        ("corpus_regenerate_dead_seeds", with(json!({ "lang": "c" }))),
        ("corpus_absorb_crashes", scope.clone()),
        ("coverage_summary", scope.clone()),
        (
            "export_coverage_line_report",
            with(json!({ "format": "pdf" })),
        ),
        ("triage", with(json!({ "ai": "off" }))),
        ("thaw_provider", json!({ "providerId": "no-such-provider" })),
        ("create_session", json!({ "title": "Parity check" })),
        ("run_detail", json!({ "runId": MISSING_RUN })),
        (
            "remote_schedule_arm",
            json!({ "url": "not-a-url", "action": "status", "token": null }),
        ),
    ];
    requests.push((
        "run_fuzzer",
        with(json!({
            "engine": "libfuzzer", "duration": 5, "seed": "7",
            "options": {
                "cpus": 1, "timeoutMs": 1000, "resume": false,
                "sanitizer": "address", "cmplog": false, "ai": "off",
            },
        })),
    ));
    #[cfg(feature = "clang-analysis")]
    requests.extend([
        (
            "clang_analysis_start",
            json!({ "project": "/no/such/project", "lang": "c" }),
        ),
        (
            "clang_analysis_status",
            json!({ "operationId": MISSING_RUN }),
        ),
        (
            "clang_analysis_result",
            json!({ "operationId": MISSING_RUN }),
        ),
        (
            "clang_analysis_cancel",
            json!({ "operationId": MISSING_RUN }),
        ),
    ]);
    #[cfg(feature = "rest-server")]
    requests.extend([
        ("rest_server_status", json!({})),
        (
            "rest_server_start",
            json!({ "port": 0, "projectRoots": ["/no/such/project"] }),
        ),
        ("rest_server_stop", json!({})),
    ]);
    // Pushed rather than listed above so the list is mutated in a build with
    // every optional feature off.
    requests.push(("clang_available", json!({})));
    #[cfg(feature = "managed-mutators")]
    requests.extend([
        (
            "grammar_mutator_source",
            json!({ "grammar": "", "engine": "afl++" }),
        ),
        (
            "attach_grammar_mutator",
            with(json!({ "engine": "afl++", "expectedHarnessId": MISSING_RUN, "grammar": "" })),
        ),
    ]);
    #[cfg(feature = "binary-only-fuzzing")]
    requests.extend([
        (
            "binary_fuzz",
            json!({ "options": {
                "project": project, "binary": format!("{project}/no_such_binary"),
                "input": "socket_messages", "seeds": null, "libraries": null,
                "durationSecs": 5, "timeoutMs": 1000,
            }}),
        ),
        (
            "binary_issue_export",
            json!({ "project": project, "report": format!("{project}/report.json"), "finding": "abcdef12" }),
        ),
        (
            "binary_file_issue",
            json!({ "project": project, "report": format!("{project}/report.json"), "finding": "abcdef12" }),
        ),
        ("binary_inspect", json!({ "binary": format!("{project}/no_such_binary") })),
        (
            "binary_seed_drafts",
            json!({ "project": project, "binary": format!("{project}/no_such_binary"),
                    "input": "file", "description": null, "count": 4 }),
        ),
        (
            "binary_dictionary_refine",
            json!({ "project": project, "binary": format!("{project}/no_such_binary"),
                    "input": "stdin", "tokens": ["PIC1"] }),
        ),
        ("binary_progress", json!({ "project": project })),
        (
            "binary_stop",
            json!({ "project": project, "session": "00000000-0000-0000-0000-000000000000" }),
        ),
        ("binary_sessions", json!({ "project": project })),
        (
            "binary_session",
            json!({ "project": project, "session": "00000000-0000-0000-0000-000000000000" }),
        ),
        (
            "binary_finding_explanation",
            json!({ "project": project, "session": "00000000-0000-0000-0000-000000000000",
                    "finding": "abcdef12" }),
        ),
        (
            "binary_finding_explain",
            json!({ "project": project, "session": "00000000-0000-0000-0000-000000000000",
                    "finding": "abcdef12" }),
        ),
    ]);
    #[cfg(feature = "crash-bisection")]
    requests.push((
        "bisect_crash",
        with(json!({ "crashId": "no-such-crash", "good": "v1", "bad": "HEAD" })),
    ));
    #[cfg(feature = "concolic-enrichment")]
    requests.extend([
        ("concolic_availability", json!({})),
        ("corpus_concolic", scope.clone()),
    ]);
    #[cfg(feature = "unreached-surface")]
    requests.extend([
        (
            "unreached_surface",
            json!({ "project": project, "lang": "c" }),
        ),
        (
            "coverage_attribution",
            json!({ "project": project, "lang": "c" }),
        ),
    ]);
    #[cfg(feature = "campaign-trust")]
    requests.push(("campaign_trust_report", json!({ "runId": MISSING_RUN })));
    #[cfg(feature = "run-closeout")]
    requests.extend([
        (
            "run_edge_diff",
            json!({ "baselineId": MISSING_RUN, "resultId": MISSING_RUN }),
        ),
        ("capture_run_edges", json!({ "runId": MISSING_RUN })),
    ]);
    #[cfg(feature = "crash-alerts")]
    requests.extend([
        ("notifications_test", json!({})),
        ("notify_latest_run", scope.clone()),
    ]);
    #[cfg(feature = "ai-target-ranking")]
    requests.push((
        "ranked_discovery_start",
        json!({ "project": project, "lang": "c", "ai": "require" }),
    ));
    requests
}

/// The parity commands, registered for the mock runtime.
fn parity_handler() -> impl Fn(tauri::ipc::Invoke<tauri::test::MockRuntime>) -> bool + Send + Sync {
    tauri::generate_handler![
        crate::commands::harness_draft,
        crate::commands::fuzz_prepare,
        crate::commands::triage,
        crate::commands::create_session,
        crate::parity_harness::harness_smoke_with_options,
        crate::parity_harness::harness_refine,
        crate::parity_harness::harness_adopt_revision,
        #[cfg(feature = "managed-mutators")]
        crate::parity_harness::grammar_mutator_source,
        #[cfg(feature = "managed-mutators")]
        crate::parity_harness::attach_grammar_mutator,
        crate::parity_run::run_campaign,
        crate::parity_run::run_ci_gate,
        crate::parity_run::user_dictionary,
        crate::parity_run::set_user_dictionary,
        crate::parity_run::clear_user_dictionary,
        crate::parity_run::fuzzing_preflight,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_fuzz,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_issue_export,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_file_issue,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_inspect,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_seed_drafts,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_dictionary_refine,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_progress,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_stop,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_sessions,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_session,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_finding_explanation,
        #[cfg(feature = "binary-only-fuzzing")]
        crate::parity_binary::binary_finding_explain,
        #[cfg(feature = "crash-bisection")]
        crate::parity_analysis::bisect_crash,
        crate::parity_analysis::verify_regressions,
        crate::parity_analysis::corpus_afl_cmin,
        crate::parity_analysis::corpus_regenerate_dead_seeds,
        crate::parity_analysis::corpus_absorb_crashes,
        #[cfg(feature = "concolic-enrichment")]
        crate::parity_analysis::concolic_availability,
        #[cfg(feature = "concolic-enrichment")]
        crate::parity_analysis::corpus_concolic,
        crate::parity_analysis::coverage_summary,
        crate::parity_analysis::export_coverage_line_report,
        #[cfg(feature = "unreached-surface")]
        crate::parity_analysis::unreached_surface,
        #[cfg(feature = "unreached-surface")]
        crate::parity_analysis::coverage_attribution,
        #[cfg(feature = "campaign-trust")]
        crate::parity_analysis::campaign_trust_report,
        #[cfg(feature = "run-closeout")]
        crate::parity_analysis::run_edge_diff,
        #[cfg(feature = "run-closeout")]
        crate::parity_analysis::capture_run_edges,
        #[cfg(feature = "crash-alerts")]
        crate::parity_settings::notifications_test,
        #[cfg(feature = "crash-alerts")]
        crate::parity_settings::notify_latest_run,
        crate::parity_settings::thaw_provider,
        crate::commands::run_fuzzer,
        #[cfg(feature = "clang-analysis")]
        crate::parity_discovery::clang_analysis_start,
        #[cfg(feature = "clang-analysis")]
        crate::parity_discovery::clang_analysis_status,
        #[cfg(feature = "clang-analysis")]
        crate::parity_discovery::clang_analysis_result,
        #[cfg(feature = "clang-analysis")]
        crate::parity_discovery::clang_analysis_cancel,
        #[cfg(feature = "rest-server")]
        crate::rest_server::rest_server_start,
        #[cfg(feature = "rest-server")]
        crate::rest_server::rest_server_stop,
        #[cfg(feature = "rest-server")]
        crate::rest_server::rest_server_status,
        crate::parity_discovery::clang_available,
        crate::parity_discovery::run_detail,
        crate::parity_discovery::remote_schedule_arm,
        #[cfg(feature = "ai-target-ranking")]
        crate::ranked_discovery_commands::ranked_discovery_start,
    ]
}

/// Whether an error came from the IPC layer rather than from the service.
fn is_ipc_defect(error: &Value) -> bool {
    let text = error.to_string();
    text.contains("invalid args") || (text.contains("Command ") && text.contains("not found"))
}

#[tokio::test(flavor = "multi_thread")]
async fn every_parity_request_of_the_frontend_reaches_its_handler() {
    if in_isolated_test_process(
        "parity_ipc_tests::every_parity_request_of_the_frontend_reaches_its_handler",
    ) {
        return;
    }
    let fixture = DesktopApprovalFixture::new(false).await;
    let scheduler = Arc::new(
        hf_service::scheduler::CampaignScheduler::try_start(
            fixture.service.clone(),
            fixture.directory.path().join("schedules.json"),
            None,
        )
        .await
        .unwrap(),
    );
    let app = crate::with_rest_server(tauri::test::mock_builder().manage(
        crate::state::AppState::new(fixture.service.clone(), Arc::clone(&scheduler)),
    ))
    .invoke_handler(parity_handler())
    .build(tauri::test::mock_context(tauri::test::noop_assets()))
    .unwrap();
    let window = tauri::WebviewWindowBuilder::new(&app, "main", tauri::WebviewUrl::default())
        .build()
        .unwrap();
    let project = fixture.project.to_string_lossy().into_owned();

    let mut defects = Vec::new();
    for (command, body) in requests(&project) {
        let response = tauri::test::get_ipc_response(
            &window,
            tauri::webview::InvokeRequest {
                cmd: command.to_owned(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: window.url().unwrap(),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: tauri::http::HeaderMap::new(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        );
        if let Err(error) = response {
            if is_ipc_defect(&error) {
                defects.push(format!("{command}: {error}"));
            }
        }
    }
    // These commands need neither a sandbox run nor an approval, so they run
    // to completion here and their replies are checked.
    let call = |command: &str, body: Value| {
        tauri::test::get_ipc_response(
            &window,
            tauri::webview::InvokeRequest {
                cmd: command.to_owned(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: window.url().unwrap(),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: tauri::http::HeaderMap::new(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .map(|reply| reply.deserialize::<Value>().unwrap())
    };
    assert_eq!(
        call("clang_available", json!({})).unwrap(),
        json!(cfg!(feature = "clang-analysis"))
    );
    let preflight = call(
        "fuzzing_preflight",
        json!({ "engine": "libfuzzer", "durationSecs": 60, "requireProvider": false }),
    )
    .unwrap();
    assert_eq!(preflight["engine"], "libfuzzer", "{preflight}");
    assert!(preflight["status"].is_object(), "{preflight}");
    assert!(call("create_session", json!({ "title": "Parity check" })).is_ok());
    let refused = call(
        "remote_schedule_arm",
        json!({ "url": "not-a-url", "action": "status", "token": null }),
    )
    .unwrap_err();
    assert!(refused.to_string().contains("must start with http://"));
    scheduler.stop().await;
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

#[test]
fn every_parity_request_names_a_command_the_application_registers() {
    let registered = include_str!("lib.rs");
    let missing: Vec<&str> = requests("/p")
        .into_iter()
        .map(|(command, _)| command)
        .filter(|command| !registered.contains(&format!("{command},")))
        .collect();
    assert!(missing.is_empty(), "not registered: {missing:?}");
}

#[test]
fn an_argument_name_the_handler_does_not_know_is_recognized_as_an_ipc_defect() {
    assert!(is_ipc_defect(&json!(
        "invalid args `runId` for command `run_detail`: command run_detail missing required key runId"
    )));
    assert!(!is_ipc_defect(&json!("validation: unknown provider id: x")));
}
