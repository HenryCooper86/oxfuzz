//! Tests for `ServiceContainer` construction and persistence wiring.

use std::sync::Arc;

use hf_service::ServiceContainer;

#[tokio::test]
async fn store_wiring_is_optional() {
    let rt = Arc::new(hf_runtime::StubRuntime);

    // A plain container has no store and no provider pool.
    let bare = ServiceContainer::new(rt.clone(), None);
    assert!(bare.store().is_none());
    assert!(bare.provider_pool().is_none());

    // Attaching a store makes it observable through the accessor.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("t.db"))
            .await
            .expect("connect store"),
    );
    let with_store = ServiceContainer::new(rt, None).with_store(store);
    assert!(with_store.store().is_some());
}

#[tokio::test]
async fn session_manager_persists_chat_transcript() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::Message;

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("s.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().expect("session manager wired");

    // Create a chat session (created Active) and append a turn.
    let node = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: Some("Chat".to_owned()),
        })
        .await
        .expect("create session");
    manager
        .append_message(&node.id, &Message::user("hello"))
        .await
        .expect("append user");
    manager
        .append_message(&node.id, &Message::assistant("hi there"))
        .await
        .expect("append assistant");

    // The context transcript round-trips the conversation.
    let transcript = manager.read_transcript(&node.id).await.expect("read");
    assert_eq!(transcript.len(), 2);
    assert_eq!(transcript[0].content, "hello");
    assert_eq!(transcript[1].content, "hi there");
}

#[tokio::test]
async fn chat_rollback_undoes_last_turn() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::Message;

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("cp.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().expect("session manager");

    let node = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: Some("Chat".to_owned()),
        })
        .await
        .expect("create session");

    // Turn 1: checkpoint before (0 messages), then append the exchange.
    container.chat_create_checkpoint(&node.id, 0).await;
    manager
        .append_message(&node.id, &Message::user("q1"))
        .await
        .unwrap();
    manager
        .append_message(&node.id, &Message::assistant("a1"))
        .await
        .unwrap();

    // Turn 2: checkpoint before (2 messages), then append.
    container.chat_create_checkpoint(&node.id, 2).await;
    manager
        .append_message(&node.id, &Message::user("q2"))
        .await
        .unwrap();
    manager
        .append_message(&node.id, &Message::assistant("a2"))
        .await
        .unwrap();

    assert_eq!(manager.read_transcript(&node.id).await.unwrap().len(), 4);

    // Roll back the last turn -> back to the turn-1 state.
    let removed = container.chat_rollback_last(&node.id).await;
    assert_eq!(removed, 2, "should remove the two turn-2 messages");
    let transcript = manager.read_transcript(&node.id).await.unwrap();
    assert_eq!(transcript.len(), 2);
    assert_eq!(transcript[1].content, "a1");
}

#[tokio::test]
async fn chat_checkpoint_picker_rolls_back_to_turn() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::Message;

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("pick.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().expect("session manager");

    let node = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: None,
        })
        .await
        .unwrap();

    // Three turns, each checkpointed before its messages are appended.
    for (i, (q, a)) in [("q1", "a1"), ("q2", "a2"), ("q3", "a3")]
        .iter()
        .enumerate()
    {
        container
            .chat_create_checkpoint(&node.id, u32::try_from(i * 2).unwrap())
            .await;
        manager
            .append_message(&node.id, &Message::user(*q))
            .await
            .unwrap();
        manager
            .append_message(&node.id, &Message::assistant(*a))
            .await
            .unwrap();
    }

    // The picker lists three turns, each previewing its user message.
    let checkpoints = container.chat_checkpoints(&node.id).await;
    assert_eq!(checkpoints.len(), 3);
    assert_eq!(checkpoints[0].turn_number, 1);
    assert_eq!(checkpoints[0].preview, "q1");
    assert_eq!(checkpoints[1].preview, "q2");

    // Roll back to turn 2 -> keep turn 1, drop turns 2 and 3.
    let turn2 = &checkpoints[1];
    let removed = container
        .chat_rollback_to(&node.id, &turn2.checkpoint_id)
        .await;
    assert_eq!(removed, 4, "turns 2 and 3 (4 messages) removed");
    let transcript = manager.read_transcript(&node.id).await.unwrap();
    assert_eq!(transcript.len(), 2);
    assert_eq!(transcript[1].content, "a1");

    // Only turn 1's checkpoint remains valid.
    assert_eq!(container.chat_checkpoints(&node.id).await.len(), 1);
}
