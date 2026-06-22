//! Skill registry trait.

use async_trait::async_trait;
use std::path::PathBuf;

use crate::error::ClassifiedError;

/// A skill is a versioned, self-improving capability document.
#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub version: String,
    pub root_doc: PathBuf,
}

#[async_trait]
pub trait SkillRegistry: Send + Sync {
    async fn load(&self, name: &str) -> Result<Skill, ClassifiedError>;
    async fn list(&self) -> Result<Vec<String>, ClassifiedError>;
}
