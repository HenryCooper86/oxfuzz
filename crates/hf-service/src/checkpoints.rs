//! View structs for the chat checkpoint / branch UI.
//!
//! The persistent [`ChatCheckpointStore`](hf_core::session::ChatCheckpointStore)
//! implementation lives in `hf-storage`
//! ([`SqliteChatCheckpointStore`](hf_storage::SqliteChatCheckpointStore)); these
//! types shape what the presentation layers render.

use serde::Serialize;

/// A session in the conversation tree, surfaced to the GUI branch switcher.
#[derive(Debug, Clone, Serialize)]
pub struct BranchView {
    pub id: String,
    /// Display title (the manual/auto title, or "Main"/"Branch").
    pub title: String,
    /// Tree depth (0 = the main/root session).
    pub depth: u32,
    /// Whether this is the main (root) session.
    pub is_main: bool,
    /// Whether this is the session currently open in the chat.
    pub active: bool,
}

/// A checkpoint surfaced to the GUI turn picker.
#[derive(Debug, Clone, Serialize)]
pub struct CheckpointView {
    pub checkpoint_id: String,
    /// 1-indexed turn this checkpoint precedes.
    pub turn_number: u32,
    /// Transcript length before this turn -- rolling back truncates to here.
    pub message_count_before: u32,
    /// Preview of the user message that started this turn.
    pub preview: String,
}
