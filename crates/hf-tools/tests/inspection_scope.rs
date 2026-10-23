#![cfg(unix)]

use std::path::Path;
use std::sync::Arc;

use hf_core::tool::{Tool, ToolInput, ToolOutput};
use hf_core::types::{SessionId, ToolName};
use hf_tools::builtin::{file_read::FileReadTool, glob::GlobTool, grep::GrepTool};
use hf_tools::error::ToolRegistryError;
use hf_tools::{ToolExecutor, ToolRegistryConfig, ToolRegistryImpl};
use serde_json::{json, Value};

async fn inspect(
    tool: Arc<dyn Tool>,
    project: &Path,
    arguments: Value,
) -> Result<ToolOutput, ToolRegistryError> {
    let definition = tool.definition().clone();
    let name = definition.name.clone();
    let registry = ToolRegistryImpl::new(ToolRegistryConfig::default());
    registry.register_tool(tool, definition).await.unwrap();
    ToolExecutor::new()
        .execute(
            &registry,
            &name,
            ToolInput {
                call_id: "inspection-scope".into(),
                name: ToolName::from_string(name.as_str()),
                arguments,
                session_id: SessionId::new(),
                working_dir: Some(project.display().to_string()),
                additional_read_dirs: Vec::new(),
                command_runner: None,
            },
        )
        .await
}

fn linked_project() -> (tempfile::TempDir, tempfile::TempDir) {
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let source = project.path().join("source.txt");
    let private = outside.path().join("private.txt");
    std::fs::write(&source, "scope_needle ordinary project source\n").unwrap();
    std::fs::write(&private, "scope_needle private outside data\n").unwrap();
    for (target, name) in [
        (private.as_path(), "escape.txt"),
        (source.as_path(), "alias.txt"),
        (outside.path(), "linked-directory"),
    ] {
        std::os::unix::fs::symlink(target, project.path().join(name)).unwrap();
    }
    (project, outside)
}

#[tokio::test]
async fn directory_grep_searches_regular_files_without_following_child_links() {
    let (project, _outside) = linked_project();
    for mode in ["content", "count", "files_with_matches"] {
        let output = inspect(
            Arc::new(GrepTool::new()),
            project.path(),
            json!({"pattern": "scope_needle", "output_mode": mode}),
        )
        .await
        .unwrap();
        assert_eq!(output.content["numFiles"], 1, "mode: {mode}");
        let result = output.content.to_string();
        assert!(result.contains("source.txt"), "mode: {mode}");
        assert!(!result.contains("escape.txt"), "mode: {mode}");
        assert!(!result.contains("alias.txt"), "mode: {mode}");
        assert!(!result.contains("private outside data"), "mode: {mode}");
    }
}

#[tokio::test]
async fn directory_glob_lists_regular_files_without_child_links() {
    let (project, _outside) = linked_project();
    let output = inspect(
        Arc::new(GlobTool::new()),
        project.path(),
        json!({"pattern": "**/*"}),
    )
    .await
    .unwrap();
    assert_eq!(output.content["count"], 1);
    assert_eq!(
        output.content["matches"],
        json!([project.path().join("source.txt").display().to_string()])
    );
}

#[tokio::test]
async fn explicit_grep_link_keeps_canonical_project_authorization() {
    let (project, _outside) = linked_project();
    let output = inspect(
        Arc::new(GrepTool::new()),
        project.path(),
        json!({"pattern": "scope_needle", "path": "alias.txt", "output_mode": "content"}),
    )
    .await
    .unwrap();
    assert!(output.content["content"]
        .as_str()
        .unwrap()
        .contains("ordinary project source"));
    let denied = inspect(
        Arc::new(GrepTool::new()),
        project.path(),
        json!({"pattern": "scope_needle", "path": "escape.txt", "output_mode": "content"}),
    )
    .await;
    assert!(denied.is_err());
}

#[tokio::test]
async fn file_read_rejects_special_files_inside_its_allowed_root() {
    let result = inspect(
        Arc::new(FileReadTool::new()),
        Path::new("/dev"),
        json!({"path": "null"}),
    )
    .await;
    assert!(result.is_err(), "device files must not be read as source");
}

#[tokio::test]
async fn file_read_resolves_parent_components_after_symlinks() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("nested/deep")).unwrap();
    std::fs::write(project.path().join("source.txt"), "wrong lexical source").unwrap();
    std::fs::write(project.path().join("nested/source.txt"), "resolved source").unwrap();
    std::os::unix::fs::symlink(
        project.path().join("nested/deep"),
        project.path().join("alias"),
    )
    .unwrap();
    let result = inspect(
        Arc::new(FileReadTool::new()),
        project.path(),
        json!({"path":"alias/../source.txt"}),
    )
    .await
    .unwrap();
    assert_eq!(result.content["content"], "resolved source");
}

#[tokio::test]
async fn file_read_rejects_fifo_without_waiting_for_a_writer() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().join("pipe");
    assert!(std::process::Command::new("mkfifo")
        .env_clear()
        .arg(&path)
        .status()
        .unwrap()
        .success());
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        inspect(
            Arc::new(FileReadTool::new()),
            project.path(),
            json!({"path":"pipe"}),
        ),
    )
    .await;
    if result.is_err() {
        // Release a regressed blocking open so runtime shutdown can finish the failed test.
        let _writer = rustix::fs::open(
            &path,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        panic!("FIFO admission must not block");
    }
    let result = result.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn file_read_retains_in_project_symlink_support() {
    let (project, _outside) = linked_project();
    let result = inspect(
        Arc::new(FileReadTool::new()),
        project.path(),
        json!({"path":"alias.txt"}),
    )
    .await
    .unwrap();
    assert_eq!(
        result.content["content"],
        "scope_needle ordinary project source"
    );
}
