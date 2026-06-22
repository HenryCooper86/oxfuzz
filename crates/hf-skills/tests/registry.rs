//! Tests for the skill registry.

use hf_core::skill::SkillRegistry;
use hf_skills::FileSkillRegistry;
use std::fs;
use tempfile::TempDir;

fn make_skill(dir: &std::path::Path, name: &str) {
    let skill_dir = dir.join(name);
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(
        skill_dir.join("skill.toml"),
        format!(
            r#"[skill]
name = "{name}"
version = "0.1.0"
description = "test skill"
author = "test"
source_format = "markdown"

[skill.root]
path = "root.md"
token_count = 100
"#,
        ),
    )
    .unwrap();
    fs::write(skill_dir.join("root.md"), "# test skill\n").unwrap();
}

#[tokio::test]
async fn list_returns_all_skills() {
    let dir = TempDir::new().unwrap();
    make_skill(dir.path(), "target-triage");
    make_skill(dir.path(), "harness-author");
    make_skill(dir.path(), "crash-triage");

    let registry = FileSkillRegistry::new(dir.path());
    let names = registry.list().await.unwrap();
    assert_eq!(names.len(), 3, "should find 3 skills: {names:?}");
    assert!(names.contains(&"target-triage".to_owned()));
    assert!(names.contains(&"harness-author".to_owned()));
    assert!(names.contains(&"crash-triage".to_owned()));
}

#[tokio::test]
async fn load_returns_skill_with_root_doc() {
    let dir = TempDir::new().unwrap();
    make_skill(dir.path(), "target-triage");

    let registry = FileSkillRegistry::new(dir.path());
    let skill = registry.load("target-triage").await.unwrap();
    assert_eq!(skill.name, "target-triage");
    assert_eq!(skill.version, "0.1.0");
    assert!(skill.root_doc.exists());
}

#[tokio::test]
async fn load_missing_skill_returns_error() {
    let dir = TempDir::new().unwrap();
    let registry = FileSkillRegistry::new(dir.path());
    let result = registry.load("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn list_empty_dir_returns_empty() {
    let dir = TempDir::new().unwrap();
    let registry = FileSkillRegistry::new(dir.path());
    let names = registry.list().await.unwrap();
    assert!(names.is_empty());
}
