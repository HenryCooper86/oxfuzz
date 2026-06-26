//! Shared types and identifiers.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a fuzz run, target, harness, or crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id(pub Uuid);

impl Id {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}

/// Strongly-typed provider identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderId(pub String);

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl ProviderId {
    /// Create a new random identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from an existing string.
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the inner string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ProviderId {
    fn default() -> Self {
        Self::new()
    }
}

/// A UTC timestamp.
pub type Timestamp = DateTime<Utc>;

/// The current UTC timestamp.
#[must_use]
pub fn now() -> Timestamp {
    Utc::now()
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Role in a conversation message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// Generate a new unique message ID.
#[must_use]
pub fn generate_message_id() -> String {
    Uuid::new_v4().to_string()
}

/// A single message in a conversation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Unique message identifier for checkpoint addressing.
    #[serde(default = "generate_message_id")]
    pub message_id: String,
    pub role: Role,
    pub content: String,
    /// Tool call ID (when role = Tool, this links to the originating call).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Tool calls requested by the assistant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCallRequest>,
    #[serde(default = "Utc::now")]
    pub timestamp: Timestamp,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl Message {
    /// A message with an explicit role.
    pub fn new(role: Role, content: impl Into<String>) -> Self {
        Self {
            message_id: generate_message_id(),
            role,
            content: content.into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
            timestamp: Utc::now(),
            metadata: serde_json::Value::Null,
        }
    }

    /// A system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::new(Role::System, content)
    }

    /// A user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::new(Role::User, content)
    }

    /// An assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(Role::Assistant, content)
    }

    /// A tool-result message linked to the originating call.
    pub fn tool(content: impl Into<String>, tool_call_id: impl Into<String>) -> Self {
        let mut m = Self::new(Role::Tool, content);
        m.tool_call_id = Some(tool_call_id.into());
        m
    }
}

/// A tool call requested by the LLM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallRequest {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Token usage
// ---------------------------------------------------------------------------

/// Source of token usage data.
///
/// Providers report token counts through different mechanisms. This enum
/// tracks the origin so downstream consumers can assess accuracy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenUsageSource {
    /// Usage reported by the provider's API response (authoritative).
    #[default]
    ProviderReported,
    /// Usage estimated via heuristic (e.g., chars/4 approximation).
    Estimated,
}

/// Token usage reported by an LLM provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_tokens: Option<u32>,
    /// How the token counts were obtained.
    #[serde(default)]
    pub source: TokenUsageSource,
}

impl TokenUsage {
    /// Total tokens (input + output), saturating.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}
