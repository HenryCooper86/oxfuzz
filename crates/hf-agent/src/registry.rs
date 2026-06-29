//! The agent registry: shipped built-in fuzzing agents plus user-authored
//! agents and overrides loaded from `config/agents/*.toml`.
//!
//! Built-ins are embedded in the binary (so they always exist), and a user file
//! with the same `id` overrides the built-in. Deleting a user file restores the
//! built-in (a reset); deleting a purely user-defined agent removes it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use thiserror::Error;

use crate::definition::{AgentDefinition, AgentRole, Autonomy, TrustTier};

/// Embedded built-in agent definitions: `(id, toml source)`.
const BUILTINS: &[(&str, &str)] = &[
    ("orchestrator", include_str!("builtins/orchestrator.toml")),
    ("target-scout", include_str!("builtins/target-scout.toml")),
    (
        "harness-author",
        include_str!("builtins/harness-author.toml"),
    ),
    ("run-operator", include_str!("builtins/run-operator.toml")),
    ("crash-triager", include_str!("builtins/crash-triager.toml")),
    (
        "coverage-analyst",
        include_str!("builtins/coverage-analyst.toml"),
    ),
    (
        "corpus-curator",
        include_str!("builtins/corpus-curator.toml"),
    ),
];

/// The agent that drives a chat when the user has not chosen one.
pub const DEFAULT_AGENT_ID: &str = "orchestrator";

/// Errors from registry mutations.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// No user directory is configured (built-in-only registry).
    #[error("no agents directory configured")]
    NoUserDir,
    /// The id contains characters not allowed in a file name.
    #[error("invalid agent id '{0}' (use letters, digits, '-' or '_')")]
    InvalidId(String),
    /// The agent id was not found.
    #[error("unknown agent '{0}'")]
    NotFound(String),
    /// A filesystem error.
    #[error("agent file io: {0}")]
    Io(#[from] std::io::Error),
    /// A TOML serialization error.
    #[error("agent serialize: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// An indexed set of agent definitions.
pub struct AgentRegistry {
    agents: BTreeMap<String, AgentDefinition>,
    agents_dir: Option<PathBuf>,
}

fn parse_builtins() -> BTreeMap<String, AgentDefinition> {
    let mut map = BTreeMap::new();
    for (id, src) in BUILTINS {
        match AgentDefinition::from_toml(src) {
            Ok(mut def) => {
                def.trust_tier = TrustTier::BuiltIn;
                map.insert((*id).to_owned(), def);
            }
            // Built-ins are validated by `builtins_all_parse`; a failure here
            // means a bad edit shipped, so skip it loudly rather than panic.
            Err(e) => tracing::error!("built-in agent '{id}' failed to parse: {e}"),
        }
    }
    map
}

/// A minimal, hand-built orchestrator used only if every embedded built-in
/// failed to parse (which `builtins_all_parse` guards against). Avoids any
/// panic on the default-agent path.
fn fallback_orchestrator() -> AgentDefinition {
    AgentDefinition {
        id: DEFAULT_AGENT_ID.to_owned(),
        name: "Orchestrator".to_owned(),
        description: "Drives a fuzzing campaign across every stage.".to_owned(),
        role: AgentRole::Orchestrator,
        icon: None,
        system_prompt: "You are the hobot_fuzz Orchestrator, an autonomous AI fuzzing agent. \
Discover targets, write harnesses, run fuzzers, and triage crashes by calling tools."
            .to_owned(),
        allowed_tools: ["discover", "harness", "run", "triage", "corpus"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        skills: Vec::new(),
        model_tags: Vec::new(),
        temperature: None,
        max_iterations: 16,
        autonomy: Autonomy::Assist,
        capabilities: Vec::new(),
        user_callable: true,
        trust_tier: TrustTier::BuiltIn,
    }
}

fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl AgentRegistry {
    /// A registry of just the embedded built-in agents (no user directory).
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            agents: parse_builtins(),
            agents_dir: None,
        }
    }

    /// A registry of built-ins plus user agents loaded from `dir`. User files
    /// override built-ins with the same id; unreadable/invalid files are
    /// skipped with a warning.
    #[must_use]
    pub fn with_user_dir(dir: impl Into<PathBuf>) -> Self {
        let mut reg = Self {
            agents: parse_builtins(),
            agents_dir: Some(dir.into()),
        };
        reg.load_user_agents();
        reg
    }

    fn load_user_agents(&mut self) {
        let Some(dir) = &self.agents_dir else { return };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_toml = path.extension().is_some_and(|e| e == "toml");
            // Skip the old-style example files outright.
            let is_example = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".example.toml"));
            if !is_toml || is_example {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(src) => match AgentDefinition::from_toml(&src) {
                    Ok(mut def) => {
                        def.trust_tier = TrustTier::UserDefined;
                        self.agents.insert(def.id.clone(), def);
                    }
                    Err(e) => tracing::warn!("skipping invalid agent {}: {e}", path.display()),
                },
                Err(e) => tracing::warn!("cannot read agent {}: {e}", path.display()),
            }
        }
    }

    /// All agents, built-ins first then user agents, each group alphabetical.
    #[must_use]
    pub fn list(&self) -> Vec<AgentDefinition> {
        let mut out: Vec<AgentDefinition> = self.agents.values().cloned().collect();
        out.sort_by(|a, b| {
            let tier = |t: TrustTier| u8::from(t == TrustTier::UserDefined);
            tier(a.trust_tier)
                .cmp(&tier(b.trust_tier))
                .then_with(|| a.name.cmp(&b.name))
        });
        out
    }

    /// Fetch an agent by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&AgentDefinition> {
        self.agents.get(id)
    }

    /// The default agent (the orchestrator), or any agent if it is missing.
    #[must_use]
    pub fn default_agent(&self) -> AgentDefinition {
        self.get(DEFAULT_AGENT_ID)
            .or_else(|| self.agents.values().next())
            .cloned()
            // Built-ins are embedded, so the registry is never empty; this
            // fallback only guards a hypothetical all-builtins-failed-to-parse
            // case (caught by `builtins_all_parse`) without panicking.
            .unwrap_or_else(fallback_orchestrator)
    }

    /// Persist a user agent to `config/agents/<id>.toml` and register it.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if no user dir is set, the id is unsafe, or the
    /// file cannot be written.
    pub fn save(&mut self, mut def: AgentDefinition) -> Result<(), RegistryError> {
        let dir = self.agents_dir.as_ref().ok_or(RegistryError::NoUserDir)?;
        if !is_safe_id(&def.id) {
            return Err(RegistryError::InvalidId(def.id));
        }
        def.trust_tier = TrustTier::UserDefined;
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{}.toml", def.id));
        std::fs::write(&path, def.to_toml()?)?;
        self.agents.insert(def.id.clone(), def);
        Ok(())
    }

    /// Delete a user agent (or reset a built-in override): removes the user file
    /// and restores the built-in if one exists with that id.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if no user dir is set, the id is unsafe/unknown,
    /// or the file cannot be removed.
    pub fn delete(&mut self, id: &str) -> Result<(), RegistryError> {
        let dir = self.agents_dir.as_ref().ok_or(RegistryError::NoUserDir)?;
        if !is_safe_id(id) {
            return Err(RegistryError::InvalidId(id.to_owned()));
        }
        let path = dir.join(format!("{id}.toml"));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        // Restore the built-in if this id shadows one; otherwise drop it.
        if let Some((_, src)) = BUILTINS.iter().find(|(bid, _)| *bid == id) {
            if let Ok(mut def) = AgentDefinition::from_toml(src) {
                def.trust_tier = TrustTier::BuiltIn;
                self.agents.insert(id.to_owned(), def);
                return Ok(());
            }
        }
        if self.agents.remove(id).is_none() {
            return Err(RegistryError::NotFound(id.to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_all_parse() {
        let reg = AgentRegistry::builtin();
        assert_eq!(reg.list().len(), BUILTINS.len());
        for (id, _) in BUILTINS {
            let def = reg.get(id).expect("builtin present");
            assert_eq!(def.trust_tier, TrustTier::BuiltIn);
            assert!(!def.system_prompt.trim().is_empty());
            assert!(!def.allowed_tools.is_empty());
        }
    }

    #[test]
    fn default_is_orchestrator() {
        let reg = AgentRegistry::builtin();
        assert_eq!(reg.default_agent().id, "orchestrator");
    }

    #[test]
    fn save_and_delete_roundtrip() {
        let dir = std::env::temp_dir().join(format!("hf-agents-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut reg = AgentRegistry::with_user_dir(&dir);
        let base = reg.get("crash-triager").expect("builtin").clone();
        let custom = AgentDefinition {
            id: "my-triager".to_owned(),
            name: "My Triager".to_owned(),
            ..base
        };
        reg.save(custom).expect("save");
        assert!(reg.get("my-triager").is_some());

        // Reload from disk to confirm persistence.
        let reg2 = AgentRegistry::with_user_dir(&dir);
        let loaded = reg2.get("my-triager").expect("persisted");
        assert_eq!(loaded.trust_tier, TrustTier::UserDefined);

        reg.delete("my-triager").expect("delete");
        assert!(reg.get("my-triager").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overriding_builtin_then_deleting_restores_it() {
        let dir = std::env::temp_dir().join(format!("hf-agents-ovr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut reg = AgentRegistry::with_user_dir(&dir);
        let mut over = reg.get("orchestrator").expect("builtin").clone();
        over.name = "Custom Orchestrator".to_owned();
        reg.save(over).expect("save override");
        assert_eq!(reg.get("orchestrator").unwrap().name, "Custom Orchestrator");
        assert_eq!(
            reg.get("orchestrator").unwrap().trust_tier,
            TrustTier::UserDefined
        );

        reg.delete("orchestrator").expect("reset");
        assert_eq!(reg.get("orchestrator").unwrap().name, "Orchestrator");
        assert_eq!(
            reg.get("orchestrator").unwrap().trust_tier,
            TrustTier::BuiltIn
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
