//! Branch picker behavior backed by persisted sessions and transcripts.

use std::sync::Arc;

use hf_core::session::{CreateSessionOptions, SessionState, SessionType};
use hf_core::types::{Message, SessionId};
use hf_service::ServiceContainer;

async fn setup() -> (tempfile::TempDir, ServiceContainer, SessionId) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(directory.path().join("branches.db"))
            .await
            .unwrap(),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    let id = SessionId(
        container
            .create_chat_session(Some("Generated title".into()))
            .await
            .unwrap()
            .unwrap(),
    );
    container
        .session_manager()
        .unwrap()
        .append_messages(
            &id,
            &[Message::user("question"), Message::assistant("answer")],
        )
        .await
        .unwrap();
    (directory, container, id)
}

#[tokio::test]
async fn branch_picker_uses_the_users_edited_title() {
    let (_directory, container, main) = setup().await;
    let manager = container.session_manager().unwrap();
    manager
        .set_manual_title(&main, Some("User title".into()))
        .await
        .unwrap();

    let branches = container.chat_branches(&main).await.unwrap();
    assert_eq!(branches[0].title, "User title");

    manager.set_manual_title(&main, None).await.unwrap();
    assert_eq!(
        container.chat_branches(&main).await.unwrap()[0].title,
        "Generated title"
    );
}

#[tokio::test]
async fn unnamed_branch_inherits_the_visible_parent_title() {
    let (_directory, container, main) = setup().await;
    container
        .session_manager()
        .unwrap()
        .set_manual_title(&main, Some("User title".into()))
        .await
        .unwrap();

    let branch = SessionId(container.chat_branch(&main, 2, None).await.unwrap());
    let branches = container.chat_branches(&branch).await.unwrap();
    assert_eq!(
        branches.iter().find(|node| node.active).unwrap().title,
        "User title (Branch)"
    );

    let named = SessionId(
        container
            .chat_branch(&main, 2, Some("Explicit title".into()))
            .await
            .unwrap(),
    );
    let branches = container.chat_branches(&named).await.unwrap();
    assert_eq!(
        branches.iter().find(|node| node.active).unwrap().title,
        "Explicit title"
    );
}

#[tokio::test]
async fn branch_picker_omits_deleted_sessions_but_keeps_their_descendants() {
    let (_directory, container, main) = setup().await;
    let deleted = SessionId(
        container
            .chat_branch(&main, 2, Some("Deleted branch".into()))
            .await
            .unwrap(),
    );
    let child = SessionId(
        container
            .chat_branch(&deleted, 2, Some("Surviving branch".into()))
            .await
            .unwrap(),
    );
    container.delete_chat_session(&deleted).await.unwrap();
    assert_eq!(
        container
            .session_manager()
            .unwrap()
            .get_session(&deleted)
            .await
            .unwrap()
            .state,
        SessionState::Tombstone
    );

    let branches = container.chat_branches(&child).await.unwrap();
    let ids: Vec<_> = branches.iter().map(|branch| branch.id.as_str()).collect();
    assert_eq!(ids, [main.as_str(), child.as_str()]);
    assert!(
        branches
            .iter()
            .find(|branch| branch.id == child.as_str())
            .unwrap()
            .active
    );
    assert_eq!(container.chat_history(&child).await.unwrap().len(), 2);
}

#[tokio::test]
async fn branch_picker_omits_internal_session_types() {
    let (_directory, container, main) = setup().await;
    for session_type in [
        SessionType::Child,
        SessionType::SubAgent,
        SessionType::Ephemeral,
        SessionType::Canonical,
    ] {
        container
            .session_manager()
            .unwrap()
            .create_session(CreateSessionOptions {
                parent_id: Some(main.clone()),
                session_type,
                agent_id: None,
                title: Some("Internal work".into()),
            })
            .await
            .unwrap();
    }

    let branches = container.chat_branches(&main).await.unwrap();
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0].id, main.as_str());
}
