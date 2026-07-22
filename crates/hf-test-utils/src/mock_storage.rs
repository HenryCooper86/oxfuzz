//! Mock storage implementations for `CheckpointStorage`, `SessionStore`, and
//! `TranscriptStore`.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

use hf_core::checkpoint::{CheckpointError, CheckpointStorage, WorkflowCheckpoint};
use hf_core::session::{
    CreateSessionOptions, SessionError, SessionFilter, SessionNode, SessionState, SessionStore,
    TranscriptStore,
};
use hf_core::types::{Message, SessionId, WorkflowId};

// ---------------------------------------------------------------------------
// MockCheckpointStorage
// ---------------------------------------------------------------------------

/// In-memory checkpoint storage for tests.
#[derive(Debug, Default)]
pub struct MockCheckpointStorage {
    data: RwLock<HashMap<String, WorkflowCheckpoint>>,
}

impl MockCheckpointStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CheckpointStorage for MockCheckpointStorage {
    async fn write_pending(
        &self,
        workflow_id: &WorkflowId,
        session_id: &SessionId,
        step_number: u64,
        state: &serde_json::Value,
    ) -> Result<(), CheckpointError> {
        let mut map = self.data.write().unwrap();
        let key = workflow_id.to_string();
        let cp = map.entry(key).or_insert_with(|| WorkflowCheckpoint {
            workflow_id: workflow_id.clone(),
            session_id: session_id.clone(),
            step_number: 0,
            status: hf_core::checkpoint::CheckpointStatus::Running,
            committed_state: serde_json::Value::Null,
            pending_state: None,
            interrupt_data: None,
            versions_seen: serde_json::Value::Object(serde_json::Map::new()),
            created_at: hf_core::types::now(),
            updated_at: hf_core::types::now(),
        });
        cp.step_number = step_number;
        cp.pending_state = Some(state.clone());
        cp.updated_at = hf_core::types::now();
        Ok(())
    }

    async fn commit(
        &self,
        workflow_id: &WorkflowId,
        _step_number: u64,
    ) -> Result<(), CheckpointError> {
        let mut map = self.data.write().unwrap();
        let key = workflow_id.to_string();
        let cp = map.get_mut(&key).ok_or(CheckpointError::NotFound {
            workflow_id: key.clone(),
        })?;
        if let Some(pending) = cp.pending_state.take() {
            cp.committed_state = pending;
        }
        cp.updated_at = hf_core::types::now();
        Ok(())
    }

    async fn read_committed(
        &self,
        workflow_id: &WorkflowId,
    ) -> Result<Option<WorkflowCheckpoint>, CheckpointError> {
        let map = self.data.read().unwrap();
        Ok(map.get(&workflow_id.to_string()).cloned())
    }

    async fn set_interrupted(
        &self,
        workflow_id: &WorkflowId,
        interrupt_data: serde_json::Value,
    ) -> Result<(), CheckpointError> {
        let mut map = self.data.write().unwrap();
        let key = workflow_id.to_string();
        let cp = map.get_mut(&key).ok_or(CheckpointError::NotFound {
            workflow_id: key.clone(),
        })?;
        cp.status = hf_core::checkpoint::CheckpointStatus::Interrupted;
        cp.interrupt_data = Some(interrupt_data);
        Ok(())
    }

    async fn set_completed(&self, workflow_id: &WorkflowId) -> Result<(), CheckpointError> {
        let mut map = self.data.write().unwrap();
        let key = workflow_id.to_string();
        let cp = map.get_mut(&key).ok_or(CheckpointError::NotFound {
            workflow_id: key.clone(),
        })?;
        cp.status = hf_core::checkpoint::CheckpointStatus::Completed;
        Ok(())
    }

    async fn set_failed(
        &self,
        workflow_id: &WorkflowId,
        _error: &str,
    ) -> Result<(), CheckpointError> {
        let mut map = self.data.write().unwrap();
        let key = workflow_id.to_string();
        let cp = map.get_mut(&key).ok_or(CheckpointError::NotFound {
            workflow_id: key.clone(),
        })?;
        cp.status = hf_core::checkpoint::CheckpointStatus::Failed;
        Ok(())
    }

    async fn prune(
        &self,
        _workflow_id: &WorkflowId,
        _keep_after_step: u64,
    ) -> Result<u64, CheckpointError> {
        Ok(0) // no-op for mock
    }
}

// ---------------------------------------------------------------------------
// MockSessionStore
// ---------------------------------------------------------------------------

/// In-memory session store for tests.
#[derive(Debug, Default)]
pub struct MockSessionStore {
    sessions: RwLock<HashMap<String, SessionNode>>,
    context_reset_indexes: RwLock<HashMap<String, u32>>,
    custom_system_prompts: RwLock<HashMap<String, String>>,
}

impl MockSessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for MockSessionStore {
    async fn create(&self, options: CreateSessionOptions) -> Result<SessionNode, SessionError> {
        let id = SessionId::new();
        let (root_id, depth, path) = match options.parent_id.as_ref() {
            Some(parent_id) => {
                let map = self.sessions.read().unwrap();
                let parent =
                    map.get(&parent_id.to_string())
                        .ok_or_else(|| SessionError::NotFound {
                            id: parent_id.to_string(),
                        })?;
                let mut path = parent.path.clone();
                path.push(parent.id.clone());
                (parent.root_id.clone(), parent.depth + 1, path)
            }
            None => (id.clone(), 0, Vec::new()),
        };

        let node = SessionNode {
            id: id.clone(),
            parent_id: options.parent_id,
            root_id,
            depth,
            path,
            session_type: options.session_type,
            state: SessionState::Active,
            agent_id: options.agent_id,
            title: options.title,
            manual_title: None,
            channel: None,
            label: None,
            token_count: 0,
            message_count: 0,
            last_compaction: None,
            compaction_count: 0,
            created_at: hf_core::types::now(),
            updated_at: hf_core::types::now(),
        };

        self.sessions
            .write()
            .unwrap()
            .insert(id.to_string(), node.clone());
        Ok(node)
    }

    async fn get(&self, id: &SessionId) -> Result<SessionNode, SessionError> {
        let map = self.sessions.read().unwrap();
        map.get(&id.to_string())
            .cloned()
            .ok_or(SessionError::NotFound { id: id.to_string() })
    }

    async fn list(&self, filter: &SessionFilter) -> Result<Vec<SessionNode>, SessionError> {
        let map = self.sessions.read().unwrap();
        let results: Vec<SessionNode> = map
            .values()
            .filter(|s| filter.state.as_ref().is_none_or(|st| s.state == *st))
            .filter(|s| {
                filter
                    .session_type
                    .as_ref()
                    .is_none_or(|t| s.session_type == *t)
            })
            .filter(|s| {
                filter
                    .agent_id
                    .as_ref()
                    .is_none_or(|agent_id| s.agent_id.as_ref() == Some(agent_id))
            })
            .filter(|s| {
                filter
                    .root_id
                    .as_ref()
                    .is_none_or(|root_id| &s.root_id == root_id)
            })
            .cloned()
            .collect();
        Ok(results)
    }

    async fn set_state(&self, id: &SessionId, state: SessionState) -> Result<(), SessionError> {
        let mut map = self.sessions.write().unwrap();
        let node = map
            .get_mut(&id.to_string())
            .ok_or(SessionError::NotFound { id: id.to_string() })?;
        node.state = state;
        Ok(())
    }

    async fn update_metadata(
        &self,
        id: &SessionId,
        title: Option<String>,
        token_count: u32,
        message_count: u32,
    ) -> Result<(), SessionError> {
        let mut map = self.sessions.write().unwrap();
        let node = map
            .get_mut(&id.to_string())
            .ok_or(SessionError::NotFound { id: id.to_string() })?;
        if let Some(t) = title {
            node.title = Some(t);
        }
        node.token_count = token_count;
        node.message_count = message_count;
        Ok(())
    }

    async fn children(&self, id: &SessionId) -> Result<Vec<SessionNode>, SessionError> {
        let map = self.sessions.read().unwrap();
        let id_str = id.to_string();
        Ok(map
            .values()
            .filter(|s| s.parent_id.as_ref().map(ToString::to_string) == Some(id_str.clone()))
            .cloned()
            .collect())
    }

    async fn ancestors(&self, id: &SessionId) -> Result<Vec<SessionNode>, SessionError> {
        let map = self.sessions.read().unwrap();
        let node = map
            .get(&id.to_string())
            .ok_or_else(|| SessionError::NotFound { id: id.to_string() })?;
        Ok(node
            .path
            .iter()
            .filter_map(|ancestor_id| map.get(&ancestor_id.to_string()).cloned())
            .collect())
    }

    async fn set_title(&self, id: &SessionId, title: String) -> Result<(), SessionError> {
        let mut map = self.sessions.write().unwrap();
        let node = map
            .get_mut(&id.to_string())
            .ok_or(SessionError::NotFound { id: id.to_string() })?;
        node.title = Some(title);
        Ok(())
    }

    async fn set_manual_title(
        &self,
        id: &SessionId,
        title: Option<String>,
    ) -> Result<(), SessionError> {
        let mut map = self.sessions.write().unwrap();
        let node = map
            .get_mut(&id.to_string())
            .ok_or(SessionError::NotFound { id: id.to_string() })?;
        node.manual_title = title;
        Ok(())
    }

    async fn delete(&self, id: &SessionId) -> Result<(), SessionError> {
        let key = id.to_string();
        let mut map = self.sessions.write().unwrap();
        if map.remove(&key).is_none() {
            return Err(SessionError::NotFound { id: key });
        }
        drop(map);
        self.context_reset_indexes.write().unwrap().remove(&key);
        self.custom_system_prompts.write().unwrap().remove(&key);
        Ok(())
    }

    async fn get_context_reset_index(&self, id: &SessionId) -> Result<Option<u32>, SessionError> {
        let key = id.to_string();
        if !self.sessions.read().unwrap().contains_key(&key) {
            return Err(SessionError::NotFound { id: key });
        }
        Ok(self
            .context_reset_indexes
            .read()
            .unwrap()
            .get(&key)
            .copied())
    }

    async fn set_context_reset_index(
        &self,
        id: &SessionId,
        index: Option<u32>,
    ) -> Result<(), SessionError> {
        let key = id.to_string();
        if !self.sessions.read().unwrap().contains_key(&key) {
            return Err(SessionError::NotFound { id: key });
        }
        let mut indexes = self.context_reset_indexes.write().unwrap();
        match index {
            Some(index) => {
                indexes.insert(key, index);
            }
            None => {
                indexes.remove(&key);
            }
        }
        Ok(())
    }

    async fn get_custom_system_prompt(
        &self,
        id: &SessionId,
    ) -> Result<Option<String>, SessionError> {
        let key = id.to_string();
        if !self.sessions.read().unwrap().contains_key(&key) {
            return Err(SessionError::NotFound { id: key });
        }
        Ok(self
            .custom_system_prompts
            .read()
            .unwrap()
            .get(&key)
            .cloned())
    }

    async fn set_custom_system_prompt(
        &self,
        id: &SessionId,
        prompt: Option<String>,
    ) -> Result<(), SessionError> {
        let key = id.to_string();
        if !self.sessions.read().unwrap().contains_key(&key) {
            return Err(SessionError::NotFound { id: key });
        }
        let mut prompts = self.custom_system_prompts.write().unwrap();
        match prompt {
            Some(prompt) => {
                prompts.insert(key, prompt);
            }
            None => {
                prompts.remove(&key);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MockTranscriptStore
// ---------------------------------------------------------------------------

/// In-memory transcript store for tests.
#[derive(Debug, Default)]
pub struct MockTranscriptStore {
    transcripts: RwLock<HashMap<String, Vec<Message>>>,
}

impl MockTranscriptStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TranscriptStore for MockTranscriptStore {
    async fn append(&self, session_id: &SessionId, message: &Message) -> Result<(), SessionError> {
        let mut map = self.transcripts.write().unwrap();
        map.entry(session_id.to_string())
            .or_default()
            .push(message.clone());
        Ok(())
    }

    async fn read_all(&self, session_id: &SessionId) -> Result<Vec<Message>, SessionError> {
        let map = self.transcripts.read().unwrap();
        Ok(map
            .get(&session_id.to_string())
            .cloned()
            .unwrap_or_default())
    }

    async fn read_last(
        &self,
        session_id: &SessionId,
        count: usize,
    ) -> Result<Vec<Message>, SessionError> {
        let map = self.transcripts.read().unwrap();
        let msgs = map
            .get(&session_id.to_string())
            .cloned()
            .unwrap_or_default();
        Ok(msgs.into_iter().rev().take(count).rev().collect())
    }

    async fn message_count(&self, session_id: &SessionId) -> Result<usize, SessionError> {
        let map = self.transcripts.read().unwrap();
        Ok(map
            .get(&session_id.to_string())
            .map_or(0, std::vec::Vec::len))
    }

    async fn truncate(
        &self,
        session_id: &SessionId,
        keep_count: usize,
    ) -> Result<usize, SessionError> {
        let mut map = self.transcripts.write().unwrap();
        let msgs = map.entry(session_id.to_string()).or_default();
        if keep_count >= msgs.len() {
            return Ok(0);
        }
        let removed = msgs.len() - keep_count;
        msgs.truncate(keep_count);
        Ok(removed)
    }
}

// ---------------------------------------------------------------------------
// MockDisplayTranscriptStore
// ---------------------------------------------------------------------------

/// In-memory display transcript store for tests.
#[derive(Debug, Default)]
pub struct MockDisplayTranscriptStore {
    transcripts: RwLock<HashMap<String, Vec<Message>>>,
}

impl MockDisplayTranscriptStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl hf_core::session::DisplayTranscriptStore for MockDisplayTranscriptStore {
    async fn append(&self, session_id: &SessionId, message: &Message) -> Result<(), SessionError> {
        let mut map = self.transcripts.write().unwrap();
        map.entry(session_id.to_string())
            .or_default()
            .push(message.clone());
        Ok(())
    }

    async fn read_all(&self, session_id: &SessionId) -> Result<Vec<Message>, SessionError> {
        let map = self.transcripts.read().unwrap();
        Ok(map
            .get(&session_id.to_string())
            .cloned()
            .unwrap_or_default())
    }

    async fn message_count(&self, session_id: &SessionId) -> Result<usize, SessionError> {
        let map = self.transcripts.read().unwrap();
        Ok(map
            .get(&session_id.to_string())
            .map_or(0, std::vec::Vec::len))
    }

    async fn truncate(
        &self,
        session_id: &SessionId,
        keep_count: usize,
    ) -> Result<usize, SessionError> {
        let mut map = self.transcripts.write().unwrap();
        let msgs = map.entry(session_id.to_string()).or_default();
        if keep_count >= msgs.len() {
            return Ok(0);
        }
        let removed = msgs.len() - keep_count;
        msgs.truncate(keep_count);
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::session::SessionType;

    #[tokio::test]
    async fn test_checkpoint_write_commit_read() {
        let store = MockCheckpointStorage::new();
        let wid = WorkflowId::new();
        let sid = SessionId::new();
        let state = serde_json::json!({"step": 1});

        store.write_pending(&wid, &sid, 1, &state).await.unwrap();
        store.commit(&wid, 1).await.unwrap();

        let cp = store.read_committed(&wid).await.unwrap().unwrap();
        assert_eq!(cp.committed_state, state);
    }

    #[tokio::test]
    async fn test_session_create_and_get() {
        let store = MockSessionStore::new();
        let node = store
            .create(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("test session".into()),
            })
            .await
            .unwrap();

        let fetched = store.get(&node.id).await.unwrap();
        assert_eq!(fetched.title, Some("test session".into()));
    }

    #[tokio::test]
    async fn mock_session_tree_matches_the_persistent_store_contract() {
        let store = MockSessionStore::new();
        let root = store
            .create(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("root".into()),
            })
            .await
            .unwrap();
        let child = store
            .create(CreateSessionOptions {
                parent_id: Some(root.id.clone()),
                session_type: SessionType::Child,
                agent_id: None,
                title: Some("child".into()),
            })
            .await
            .unwrap();
        let grandchild = store
            .create(CreateSessionOptions {
                parent_id: Some(child.id.clone()),
                session_type: SessionType::Child,
                agent_id: None,
                title: Some("grandchild".into()),
            })
            .await
            .unwrap();

        assert_eq!(root.depth, 0);
        assert!(root.path.is_empty());
        assert_eq!(child.depth, 1);
        assert_eq!(child.root_id, root.id);
        assert_eq!(child.path, vec![root.id.clone()]);
        assert_eq!(grandchild.depth, 2);
        assert_eq!(grandchild.root_id, root.id);
        assert_eq!(grandchild.path, vec![root.id.clone(), child.id.clone()]);

        let ancestors = store.ancestors(&grandchild.id).await.unwrap();
        assert_eq!(
            ancestors.iter().map(|node| &node.id).collect::<Vec<_>>(),
            vec![&root.id, &child.id]
        );
        assert!(store.ancestors(&root.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn mock_session_store_rejects_a_missing_parent() {
        let store = MockSessionStore::new();
        let missing = SessionId::new();
        let result = store
            .create(CreateSessionOptions {
                parent_id: Some(missing.clone()),
                session_type: SessionType::Child,
                agent_id: None,
                title: None,
            })
            .await;

        assert!(matches!(
            result,
            Err(SessionError::NotFound { id }) if id == missing.to_string()
        ));
    }

    #[tokio::test]
    async fn mock_session_store_applies_root_filter_and_persists_optional_state() {
        let store = MockSessionStore::new();
        let first = store
            .create(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();
        store
            .create(CreateSessionOptions {
                parent_id: Some(first.id.clone()),
                session_type: SessionType::Child,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();
        store
            .create(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        let filtered = store
            .list(&SessionFilter {
                root_id: Some(first.id.clone()),
                ..SessionFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|node| node.root_id == first.id));

        store
            .set_context_reset_index(&first.id, Some(7))
            .await
            .unwrap();
        assert_eq!(
            store.get_context_reset_index(&first.id).await.unwrap(),
            Some(7)
        );
        store
            .set_custom_system_prompt(&first.id, Some("test prompt".into()))
            .await
            .unwrap();
        assert_eq!(
            store.get_custom_system_prompt(&first.id).await.unwrap(),
            Some("test prompt".into())
        );
    }

    #[tokio::test]
    async fn test_transcript_append_and_read() {
        let store = MockTranscriptStore::new();
        let sid = SessionId::new();
        let msg = crate::fixtures::make_user_message("hello");

        store.append(&sid, &msg).await.unwrap();
        store.append(&sid, &msg).await.unwrap();

        let all = store.read_all(&sid).await.unwrap();
        assert_eq!(all.len(), 2);

        let last = store.read_last(&sid, 1).await.unwrap();
        assert_eq!(last.len(), 1);

        let count = store.message_count(&sid).await.unwrap();
        assert_eq!(count, 2);
    }
}
