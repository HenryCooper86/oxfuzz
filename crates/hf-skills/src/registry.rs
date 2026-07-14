//! The skill registry: shipped built-in fuzzing skills plus user-authored
//! skills and overrides loaded from `skills/<name>/{skill.toml,root.md}`.
//!
//! Mirrors the agent registry: built-ins are embedded in the binary (so they
//! always exist), a user skill with the same name overrides the built-in, and
//! deleting a user skill restores the built-in (a reset).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Per-skill injection cap (~2000 tokens at 4 chars/token), so an oversized
/// playbook can't blow the prompt budget when injected into an agent.
const INJECT_CHAR_CAP: usize = 8000;

/// Embedded built-in skills: `(name, skill.toml, root.md)`.
const BUILTINS: &[(&str, &str, &str)] = &[
    (
        "target-triage",
        include_str!("builtins/target-triage/skill.toml"),
        include_str!("builtins/target-triage/root.md"),
    ),
    (
        "harness-author",
        include_str!("builtins/harness-author/skill.toml"),
        include_str!("builtins/harness-author/root.md"),
    ),
    (
        "crash-triage",
        include_str!("builtins/crash-triage/skill.toml"),
        include_str!("builtins/crash-triage/root.md"),
    ),
    (
        "corpus-curation",
        include_str!("builtins/corpus-curation/skill.toml"),
        include_str!("builtins/corpus-curation/root.md"),
    ),
    (
        "coverage-analysis",
        include_str!("builtins/coverage-analysis/skill.toml"),
        include_str!("builtins/coverage-analysis/root.md"),
    ),
];

/// Provenance of a skill: a shipped built-in or a user-authored one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Ships with `hobot_fuzz`; embedded in the binary, resettable.
    BuiltIn,
    /// Authored or overridden by the user under `skills/`.
    #[default]
    UserDefined,
}

/// A fuzzing skill: a versioned instruction playbook (the `root.md` body) plus
/// the metadata needed to surface and inject it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDefinition {
    /// Skill id / directory name (kebab-case).
    pub name: String,
    /// Semantic version of the playbook.
    pub version: String,
    /// One-line summary.
    pub description: String,
    /// Domain/classification tags.
    pub domain: Vec<String>,
    /// The LLM-facing instruction body (the `root.md` content).
    pub body: String,
    /// Maximum input tokens the skill expects to consume.
    pub max_input_tokens: u32,
    /// Provenance, set by the registry on load.
    pub trust_tier: TrustTier,
}

/// The nested `[skill]` manifest read from `skill.toml`.
#[derive(Debug, Deserialize)]
struct SkillToml {
    skill: SkillTomlInner,
}

#[derive(Debug, Deserialize)]
struct SkillTomlInner {
    name: String,
    #[serde(default = "default_version")]
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    classification: Classification,
    #[serde(default)]
    constraints: Constraints,
}

#[derive(Debug, Default, Deserialize)]
struct Classification {
    #[serde(default)]
    domain: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Constraints {
    #[serde(default)]
    max_input_tokens: u32,
}

fn default_version() -> String {
    "0.1.0".to_owned()
}

impl SkillDefinition {
    /// Build a definition from a `skill.toml` manifest and its `root.md` body.
    ///
    /// # Errors
    /// Returns the `toml` error if the manifest is malformed.
    pub fn from_files(manifest: &str, body: &str) -> Result<Self, toml::de::Error> {
        let parsed: SkillToml = toml::from_str(manifest)?;
        Ok(Self {
            name: parsed.skill.name,
            version: parsed.skill.version,
            description: parsed.skill.description,
            domain: parsed.skill.classification.domain,
            body: body.to_owned(),
            max_input_tokens: parsed.skill.constraints.max_input_tokens,
            trust_tier: TrustTier::UserDefined,
        })
    }

    /// Render the `skill.toml` manifest for persistence (the body is written
    /// separately as `root.md`).
    fn manifest_toml(&self) -> String {
        let domain = self
            .domain
            .iter()
            .map(|d| format!("\"{}\"", toml_escape(d)))
            .collect::<Vec<_>>()
            .join(", ");
        let token_count = self.body.chars().count() / 4;
        let max_in = if self.max_input_tokens == 0 {
            12000
        } else {
            self.max_input_tokens
        };
        format!(
            "[skill]\nname = \"{name}\"\nversion = \"{version}\"\ndescription = \"{desc}\"\n\
author = \"hobot_fuzz\"\nsource_format = \"markdown\"\n\n\
[skill.classification]\ntype = \"llm_reasoning\"\ndomain = [{domain}]\natomic = true\n\n\
[skill.constraints]\nmax_input_tokens = {max_in}\nmax_output_tokens = 4000\n\n\
[skill.root]\npath = \"root.md\"\ntoken_count = {token_count}\n",
            name = toml_escape(&self.name),
            version = toml_escape(&self.version),
            desc = toml_escape(&self.description),
        )
    }
}

/// Escape a string for a TOML basic (double-quoted) string. A user-authored
/// skill saved via the GUI can carry a backslash (a `\d+` regex, a Windows
/// path) or a newline in its description/version; interpolating those raw
/// produced invalid TOML, so `load_user_skills` failed to parse the manifest and
/// the saved skill silently vanished on the next reload.
fn toml_escape(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Errors from registry mutations.
#[derive(Debug, Error)]
pub enum SkillError {
    /// No user directory is configured (built-in-only registry).
    #[error("no skills directory configured")]
    NoUserDir,
    /// The name contains characters not allowed in a directory name.
    #[error("invalid skill name '{0}' (use letters, digits, '-' or '_')")]
    InvalidName(String),
    /// The skill was not found.
    #[error("unknown skill '{0}'")]
    NotFound(String),
    /// A filesystem error.
    #[error("skill file io: {0}")]
    Io(#[from] std::io::Error),
}

/// An indexed set of skill definitions.
pub struct SkillRegistry {
    skills: BTreeMap<String, SkillDefinition>,
    skills_dir: Option<PathBuf>,
}

fn parse_builtins() -> BTreeMap<String, SkillDefinition> {
    let mut map = BTreeMap::new();
    for (name, manifest, body) in BUILTINS {
        match SkillDefinition::from_files(manifest, body) {
            Ok(mut def) => {
                def.trust_tier = TrustTier::BuiltIn;
                map.insert((*name).to_owned(), def);
            }
            Err(e) => tracing::error!("built-in skill '{name}' failed to parse: {e}"),
        }
    }
    map
}

fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl SkillRegistry {
    /// A registry of just the embedded built-in skills (no user directory).
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            skills: parse_builtins(),
            skills_dir: None,
        }
    }

    /// A registry of built-ins plus user skills loaded from `dir`. User skills
    /// override built-ins with the same name; unreadable/invalid skills are
    /// skipped with a warning.
    #[must_use]
    pub fn with_user_dir(dir: impl Into<PathBuf>) -> Self {
        let mut reg = Self {
            skills: parse_builtins(),
            skills_dir: Some(dir.into()),
        };
        reg.load_user_skills();
        reg
    }

    fn load_user_skills(&mut self) {
        let Some(dir) = &self.skills_dir else { return };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let skill_dir = entry.path();
            if !skill_dir.is_dir() {
                continue;
            }
            let manifest_path = skill_dir.join("skill.toml");
            if !manifest_path.is_file() {
                continue;
            }
            let body_path = skill_dir.join("root.md");
            let manifest = std::fs::read_to_string(&manifest_path);
            let body = std::fs::read_to_string(&body_path).unwrap_or_default();
            match manifest.map(|m| SkillDefinition::from_files(&m, &body)) {
                Ok(Ok(mut def)) => {
                    def.trust_tier = TrustTier::UserDefined;
                    self.skills.insert(def.name.clone(), def);
                }
                Ok(Err(e)) => {
                    tracing::warn!("skipping invalid skill {}: {e}", manifest_path.display());
                }
                Err(e) => tracing::warn!("cannot read skill {}: {e}", manifest_path.display()),
            }
        }
    }

    /// All skills, built-ins first then user skills, each group alphabetical.
    #[must_use]
    pub fn list(&self) -> Vec<SkillDefinition> {
        let mut out: Vec<SkillDefinition> = self.skills.values().cloned().collect();
        out.sort_by(|a, b| {
            let tier = |t: TrustTier| u8::from(t == TrustTier::UserDefined);
            tier(a.trust_tier)
                .cmp(&tier(b.trust_tier))
                .then_with(|| a.name.cmp(&b.name))
        });
        out
    }

    /// Fetch a skill by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SkillDefinition> {
        self.skills.get(name)
    }

    /// Render the given skills into a prompt section for injection into an
    /// agent's context, or `None` if none resolve. Each body is capped so an
    /// oversized playbook cannot dominate the prompt.
    #[must_use]
    pub fn render(&self, names: &[String]) -> Option<String> {
        let mut sections = Vec::new();
        for name in names {
            let Some(skill) = self.get(name) else {
                continue;
            };
            let body: String = if skill.body.chars().count() > INJECT_CHAR_CAP {
                let mut t: String = skill.body.chars().take(INJECT_CHAR_CAP).collect();
                t.push_str("\n...[truncated]");
                t
            } else {
                skill.body.clone()
            };
            sections.push(format!(
                "### Skill: {}\n{}\n\n{}",
                skill.name,
                skill.description,
                body.trim()
            ));
        }
        if sections.is_empty() {
            return None;
        }
        Some(format!(
            "## Reference skills\nApply these playbooks where relevant:\n\n{}",
            sections.join("\n\n---\n\n")
        ))
    }

    /// Persist a user skill to `skills/<name>/{skill.toml,root.md}` and register
    /// it.
    ///
    /// # Errors
    /// Returns [`SkillError`] if no user dir is set, the name is unsafe, or the
    /// files cannot be written.
    pub fn save(&mut self, mut def: SkillDefinition) -> Result<(), SkillError> {
        let dir = self.skills_dir.as_ref().ok_or(SkillError::NoUserDir)?;
        if !is_safe_name(&def.name) {
            return Err(SkillError::InvalidName(def.name));
        }
        def.trust_tier = TrustTier::UserDefined;
        let skill_dir = dir.join(&def.name);
        std::fs::create_dir_all(&skill_dir)?;
        std::fs::write(skill_dir.join("skill.toml"), def.manifest_toml())?;
        std::fs::write(skill_dir.join("root.md"), &def.body)?;
        self.skills.insert(def.name.clone(), def);
        Ok(())
    }

    /// Delete a user skill (or reset a built-in override): removes the skill
    /// directory and restores the built-in if one exists with that name.
    ///
    /// # Errors
    /// Returns [`SkillError`] if no user dir is set, the name is unsafe/unknown,
    /// or the directory cannot be removed.
    pub fn delete(&mut self, name: &str) -> Result<(), SkillError> {
        let dir = self.skills_dir.as_ref().ok_or(SkillError::NoUserDir)?;
        if !is_safe_name(name) {
            return Err(SkillError::InvalidName(name.to_owned()));
        }
        let skill_dir = dir.join(name);
        if skill_dir.exists() {
            std::fs::remove_dir_all(&skill_dir)?;
        }
        if let Some((_, manifest, body)) = BUILTINS.iter().find(|(n, _, _)| *n == name) {
            if let Ok(mut def) = SkillDefinition::from_files(manifest, body) {
                def.trust_tier = TrustTier::BuiltIn;
                self.skills.insert(name.to_owned(), def);
                return Ok(());
            }
        }
        if self.skills.remove(name).is_none() {
            return Err(SkillError::NotFound(name.to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_all_parse() {
        let reg = SkillRegistry::builtin();
        assert_eq!(reg.list().len(), BUILTINS.len());
        for (name, _, _) in BUILTINS {
            let s = reg.get(name).expect("builtin present");
            assert_eq!(s.trust_tier, TrustTier::BuiltIn);
            assert!(!s.body.trim().is_empty());
            assert!(!s.description.is_empty());
        }
    }

    #[test]
    fn render_injects_named_skills() {
        let reg = SkillRegistry::builtin();
        let out = reg
            .render(&["crash-triage".to_owned(), "missing".to_owned()])
            .expect("some");
        assert!(out.contains("### Skill: crash-triage"));
        assert!(out.contains("Reference skills"));
        assert!(!out.contains("Skill: missing"));
    }

    #[test]
    fn render_empty_when_none_resolve() {
        let reg = SkillRegistry::builtin();
        assert!(reg.render(&["nope".to_owned()]).is_none());
    }

    #[test]
    fn manifest_round_trips_special_characters() {
        // A user-authored skill whose description carries a backslash, a quote,
        // and a newline must produce valid TOML that parses back losslessly --
        // previously it emitted broken TOML and the skill vanished on reload.
        let skill = SkillDefinition {
            name: "my-skill".to_owned(),
            version: "1.0.0-rc.1".to_owned(),
            description: "matches \\d+ and \"quoted\"\nsecond line".to_owned(),
            domain: vec!["path\\with\\slash".to_owned(), "plain".to_owned()],
            body: "root body".to_owned(),
            max_input_tokens: 0,
            trust_tier: TrustTier::UserDefined,
        };
        let manifest = skill.manifest_toml();
        let reparsed =
            SkillDefinition::from_files(&manifest, &skill.body).expect("manifest must parse");
        assert_eq!(reparsed.name, skill.name);
        assert_eq!(reparsed.version, skill.version);
        assert_eq!(reparsed.description, skill.description);
        assert_eq!(reparsed.domain, skill.domain);
    }

    #[test]
    fn save_and_reset_override() {
        let dir = std::env::temp_dir().join(format!("hf-skills-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut reg = SkillRegistry::with_user_dir(&dir);

        let mut over = reg.get("target-triage").expect("builtin").clone();
        over.description = "Custom triage".to_owned();
        reg.save(over).expect("save");
        assert_eq!(
            reg.get("target-triage").unwrap().description,
            "Custom triage"
        );
        assert_eq!(
            reg.get("target-triage").unwrap().trust_tier,
            TrustTier::UserDefined
        );

        let reg2 = SkillRegistry::with_user_dir(&dir);
        assert_eq!(
            reg2.get("target-triage").unwrap().description,
            "Custom triage"
        );

        reg.delete("target-triage").expect("reset");
        assert_eq!(
            reg.get("target-triage").unwrap().trust_tier,
            TrustTier::BuiltIn
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
