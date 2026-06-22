//! File-backed skill registry that scans a directory for `skill.toml`.

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::skill::{Skill, SkillRegistry};
use std::path::{Path, PathBuf};

/// A skill registry that loads skills from a filesystem directory.
pub struct FileSkillRegistry {
    root: PathBuf,
}

impl FileSkillRegistry {
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }
}

#[async_trait]
impl SkillRegistry for FileSkillRegistry {
    async fn load(&self, name: &str) -> Result<Skill, ClassifiedError> {
        let skill_dir = self.root.join(name);
        let toml_path = skill_dir.join("skill.toml");
        if !toml_path.is_file() {
            return Err(ClassifiedError::Internal(format!(
                "skill '{name}' not found at {}",
                toml_path.display()
            )));
        }
        let content = std::fs::read_to_string(&toml_path)
            .map_err(|e| ClassifiedError::Internal(format!("read skill.toml: {e}")))?;
        let parsed: SkillToml = toml::from_str(&content)
            .map_err(|e| ClassifiedError::Internal(format!("parse skill.toml: {e}")))?;
        let root_doc = skill_dir.join(&parsed.skill.root.path);
        Ok(Skill {
            name: parsed.skill.name,
            version: parsed.skill.version,
            root_doc,
        })
    }

    async fn list(&self) -> Result<Vec<String>, ClassifiedError> {
        if !self.root.is_dir() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        let dir = self
            .root
            .read_dir()
            .map_err(|e| ClassifiedError::Internal(format!("read skills dir: {e}")))?;
        for entry in dir {
            let entry = entry.map_err(|e| ClassifiedError::Internal(e.to_string()))?;
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                let toml_path = entry.path().join("skill.toml");
                if toml_path.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        names.push(name.to_owned());
                    }
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

#[derive(serde::Deserialize)]
struct SkillToml {
    skill: SkillTomlInner,
}

#[derive(serde::Deserialize)]
struct SkillTomlInner {
    name: String,
    version: String,
    root: SkillRoot,
}

#[derive(serde::Deserialize)]
struct SkillRoot {
    path: String,
}
