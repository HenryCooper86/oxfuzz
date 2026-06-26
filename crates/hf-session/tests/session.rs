//! Tests for the SQLite-backed session store.

use std::sync::Arc;

use hf_core::session::SessionStore;
use hf_core::types::{Message, Role};
use hf_session::SqliteSessionStore;

#[tokio::test]
async fn create_append_history_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("s.db"))
            .await
            .unwrap(),
    );
    let sessions = SqliteSessionStore::new(store);

    let id = sessions.create(None).await.unwrap();
    sessions
        .append(id, Message::user("discover targets"))
        .await
        .unwrap();
    sessions
        .append(id, Message::assistant("found parse_value"))
        .await
        .unwrap();

    let history = sessions.history(id).await.unwrap();
    assert_eq!(history.len(), 2);
    assert!(matches!(history[0].role, Role::User));
    assert_eq!(history[0].content, "discover targets");
    assert!(matches!(history[1].role, Role::Assistant));

    // A separate session has independent history.
    let other = sessions.create(None).await.unwrap();
    assert!(sessions.history(other).await.unwrap().is_empty());
}
