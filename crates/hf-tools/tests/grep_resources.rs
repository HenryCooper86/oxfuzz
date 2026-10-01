use hf_core::tool::{Tool, ToolInput, ToolOutput};
use hf_core::types::{SessionId, ToolName};
use hf_tools::builtin::grep::GrepTool;
use hf_tools::{ToolExecutor, ToolRegistryConfig, ToolRegistryImpl};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;

async fn search_result(
    tool: GrepTool,
    project: &Path,
    arguments: Value,
) -> Result<ToolOutput, hf_tools::ToolRegistryError> {
    let registry = ToolRegistryImpl::new(ToolRegistryConfig::default());
    let definition = tool.definition().clone();
    registry
        .register_tool(Arc::new(tool), definition)
        .await
        .unwrap();
    ToolExecutor::new()
        .execute(
            &registry,
            &ToolName::from_string("Grep"),
            ToolInput {
                call_id: "grep-resources".into(),
                name: ToolName::from_string("Grep"),
                arguments,
                session_id: SessionId::new(),
                working_dir: Some(project.display().to_string()),
                additional_read_dirs: Vec::new(),
                command_runner: None,
            },
        )
        .await
}

async fn search(tool: GrepTool, project: &Path, arguments: Value) -> ToolOutput {
    search_result(tool, project, arguments).await.unwrap()
}

#[tokio::test]
async fn oversized_matching_line_obeys_retained_bytes_and_advances_cursor() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("source.txt"),
        format!("needle {}\n", "x".repeat(11000)),
    )
    .unwrap();
    let out = search(
        GrepTool::new(),
        project.path(),
        json!({"pattern":"needle", "output_mode":"content", "head_limit":0}),
    )
    .await;
    assert!(out.content["content"].as_str().unwrap().len() <= 10000);
    assert_eq!(out.content["truncated"], true);
    assert_eq!(out.content["totalsComplete"], false);
    assert_eq!(out.content["nextOffset"], 1);
    assert_eq!(out.content["numReturned"], 1);
}

#[tokio::test]
async fn page_stops_after_one_extra_witness_and_reports_observed_totals() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("source.txt"),
        "needle 0\nneedle 1\nneedle 2\nneedle 3\nneedle 4\n",
    )
    .unwrap();
    let out = search(
        GrepTool::new(),
        project.path(),
        json!({"pattern":"needle", "output_mode":"content", "offset":1, "head_limit":2}),
    )
    .await;
    assert_eq!(out.content["numLines"], 4);
    assert_eq!(out.content["numReturned"], 2);
    assert_eq!(out.content["nextOffset"], 3);
    assert_eq!(out.content["hasMore"], true);
    assert_eq!(out.content["totalsComplete"], false);
    assert!(!out.content["content"]
        .as_str()
        .unwrap()
        .contains("needle 3"));
}

#[tokio::test]
async fn complete_results_declare_full_scan_in_every_mode() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("source.txt"), "needle needle\n").unwrap();
    for mode in ["content", "count", "files_with_matches"] {
        let out = search(
            GrepTool::new(),
            project.path(),
            json!({"pattern":"needle", "output_mode":mode}),
        )
        .await;
        assert_eq!(out.content["totalsComplete"], true, "{mode}");
        assert_eq!(out.content["truncated"], false, "{mode}");
        assert_eq!(out.content["numReturned"], 1, "{mode}");
        if mode == "count" {
            assert_eq!(out.content["numMatches"], 2);
        }
    }
}

fn limited(output_bytes: usize, heap_bytes: usize) -> GrepTool {
    GrepTool::new().with_limits(
        hf_core::grep_limits::GrepLimitsConfig {
            output_bytes,
            heap_bytes,
            timeout_secs: 2,
        }
        .resolve()
        .unwrap(),
    )
}

#[tokio::test]
async fn configured_bytes_are_applied_before_utf8_content_is_retained() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("text"), "needle αβγδεζηθ\n").unwrap();
    let path = project.path().join("text").display().to_string();
    let allowance = path.len() + 3 + "needle ".len() + 3;
    let out = search(
        limited(allowance, 4096),
        project.path(),
        json!({"pattern":"needle","output_mode":"content"}),
    )
    .await;
    let content = out.content["content"].as_str().unwrap();
    assert_eq!(content, format!("{path}:1:needle α"));
    assert_eq!(out.content["limitingReason"], "output_bytes");
    assert_eq!(out.content["nextOffset"], 1);
}

#[tokio::test]
async fn numeric_parameters_are_rejected_by_the_actual_tool() {
    let project = tempfile::tempdir().unwrap();
    for key in ["head_limit", "offset", "-B", "-A", "context", "-C"] {
        for value in [json!(-1), json!(1.5), json!("1"), json!(null)] {
            let mut input = json!({"pattern":"needle"});
            input[key] = value;
            let result = GrepTool::new()
                .execute(ToolInput {
                    call_id: "invalid".into(),
                    name: ToolName::from_string("Grep"),
                    arguments: input,
                    session_id: SessionId::new(),
                    working_dir: Some(project.path().display().to_string()),
                    additional_read_dirs: Vec::new(),
                    command_runner: None,
                })
                .await;
            assert!(result.is_err(), "{key}");
        }
    }
}

#[tokio::test]
async fn reader_allowance_rejects_large_line_and_multiline_file() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("text"),
        format!("needle {}\n", "x".repeat(4096)),
    )
    .unwrap();
    for multiline in [false, true] {
        let result = search_result(
            limited(10000, 1024),
            project.path(),
            json!({"pattern":"needle","output_mode":"content","multiline":multiline}),
        )
        .await;
        assert!(result.is_err(), "multiline={multiline}");
    }
}

#[tokio::test]
async fn atomic_entries_fail_when_they_cannot_fit_alone() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("text"), "needle\n").unwrap();
    for mode in ["count", "files_with_matches"] {
        let result = search_result(
            limited(1, 4096),
            project.path(),
            json!({"pattern":"needle","output_mode":mode}),
        )
        .await;
        assert!(result.is_err(), "{mode}");
    }
}

#[tokio::test]
async fn whole_entries_use_exact_budget_and_continue_without_skipping() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("a"), "needle\n").unwrap();
    std::fs::write(project.path().join("b"), "needle needle\n").unwrap();
    for mode in ["files_with_matches", "count"] {
        let bytes =
            project.path().join("a").display().to_string().len() + usize::from(mode == "count") * 2;
        let first = search(
            limited(bytes, 4096),
            project.path(),
            json!({"pattern":"needle","output_mode":mode,"head_limit":0}),
        )
        .await;
        assert_eq!(first.content["numReturned"], 1);
        assert_eq!(first.content["nextOffset"], 1);
        assert_eq!(first.content["numFiles"], 2);
        assert_eq!(first.content["totalsComplete"], false);
        let second = search(
            limited(bytes, 4096),
            project.path(),
            json!({"pattern":"needle","output_mode":mode,"offset":1}),
        )
        .await;
        assert_eq!(second.content["numReturned"], 1);
        assert_eq!(second.content["totalsComplete"], true);
        if mode == "count" {
            assert_eq!(second.content["numMatches"], 3);
        }
    }
}

#[tokio::test]
async fn explicit_file_line_numbers_context_and_multiline_remain_matching_records() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("text"),
        "before\nneedle\nsecond\nafter\n",
    )
    .unwrap();
    let out = search(
        limited(10000, 4096),
        project.path(),
        json!({"pattern":"needle","path":"text","output_mode":"content","-n":false,"context":2}),
    )
    .await;
    assert_eq!(out.content["numLines"], 1);
    assert!(out.content["content"]
        .as_str()
        .unwrap()
        .ends_with(":needle"));
    let out = search(
        limited(10000, 4096),
        project.path(),
        json!({"pattern":"needle\\nsecond","path":"text","output_mode":"content","multiline":true}),
    )
    .await;
    assert_eq!(out.content["numLines"], 1);
    assert!(out.content["content"]
        .as_str()
        .unwrap()
        .ends_with(":2:needle\nsecond"));
}

#[tokio::test]
async fn exact_content_allowance_reports_complete_scan_but_one_less_consumes_record() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("text"), "needle\n").unwrap();
    let expected = format!("{}:1:needle", project.path().join("text").display());
    for bytes in [expected.len(), expected.len() - 1] {
        let out = search(
            limited(bytes, 4096),
            project.path(),
            json!({"pattern":"needle","output_mode":"content"}),
        )
        .await;
        assert_eq!(out.content["content"].as_str().unwrap().len(), bytes);
        assert_eq!(out.content["nextOffset"], 1);
        assert_eq!(out.content["totalsComplete"], bytes == expected.len());
    }
}

#[tokio::test]
async fn following_cursors_preserves_records_before_late_nul_and_in_other_files() {
    let project = tempfile::tempdir().unwrap();
    let mut binary = format!("needle 0\nneedle 1\nneedle 2\n{}", "x\n".repeat(3000)).into_bytes();
    binary.push(0);
    binary.extend_from_slice(b"\n");
    std::fs::write(project.path().join("a"), binary).unwrap();
    std::fs::write(project.path().join("b"), "needle ordinary\n").unwrap();
    let mut offset = 0;
    let mut records = Vec::new();
    for _ in 0..6 {
        let out = search(
            limited(10000, 4096),
            project.path(),
            json!({"pattern":"needle","output_mode":"content","head_limit":1,"offset":offset}),
        )
        .await;
        if out.content["numReturned"] == 1 {
            records.push(out.content["content"].as_str().unwrap().to_owned());
        }
        if out.content["totalsComplete"] == true {
            break;
        }
        offset = out.content["nextOffset"].as_u64().unwrap();
    }
    assert_eq!(records.len(), 4);
    assert!(records
        .iter()
        .any(|record| record.ends_with("needle ordinary")));
    let count = search(
        limited(10000, 4096),
        project.path(),
        json!({"pattern":"needle","output_mode":"count"}),
    )
    .await;
    assert_eq!(count.content["numMatches"], 4);
}
