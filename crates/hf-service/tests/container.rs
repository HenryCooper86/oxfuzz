//! Tests for `ServiceContainer` construction and persistence wiring.

use std::sync::Arc;

use hf_service::ServiceContainer;

/// A runtime whose streamed command blocks until the run is cancelled, so a
/// test can observe and drive the cancellation path deterministically.
struct BlockingRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for BlockingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
        })
    }

    async fn run_command_streaming(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
        cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        // Run until the caller cancels, mimicking a live fuzzer.
        cancel.cancelled().await;
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
        })
    }

    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(
        &self,
        _path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn cancel_run_stops_an_in_flight_fuzz_run() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("cancel_proj");
    fs::create_dir_all(&project).unwrap();
    let target = "parse_entry";

    // run_fuzzer requires a compiled harness binary and a corpus dir.
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    fs::create_dir_all(&corpus).unwrap();
    fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("c.db"))
            .await
            .expect("connect store"),
    );
    let container = Arc::new(
        ServiceContainer::new(Arc::new(BlockingRuntime), None).with_store(Arc::clone(&store)),
    );

    // Start the run; it will block in the runtime until cancelled.
    let runner = {
        let container = Arc::clone(&container);
        let project = project.clone();
        tokio::spawn(async move {
            container
                .run_fuzzer(
                    &project,
                    target,
                    hf_core::engine::EngineKind::LibFuzzer,
                    60,
                    &|_| {},
                )
                .await
        })
    };

    // Wait for the run to register, then cancel it.
    let mut run_id = None;
    for _ in 0..200 {
        if let Some(id) = container.active_run_ids().into_iter().next() {
            run_id = Some(id);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let run_id = run_id.expect("run should register as active");
    assert!(container.cancel_run(run_id), "cancel should find the run");

    // The run returns promptly and is recorded as cancelled.
    let summary = tokio::time::timeout(std::time::Duration::from_secs(5), runner)
        .await
        .expect("run should finish after cancel")
        .expect("task join")
        .expect("run_fuzzer ok");
    assert_eq!(summary.crashes, 0);
    assert!(container.active_run_ids().is_empty(), "registry cleaned up");

    let run = store.get_run(run_id).await.unwrap().expect("run persisted");
    assert_eq!(run.status, hf_storage::RunStatus::Cancelled);

    let _ = fs::remove_dir_all(&workspace);
}

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
async fn corpus_minimize_leaves_corpus_untouched_when_sandbox_unavailable() {
    use std::fs;

    // A unique project name keeps this test's workspace isolated.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("minimize_fallback_proj");
    fs::create_dir_all(&project).unwrap();
    let target = "parse_entry";

    // Lay down a workspace with a harness and a two-entry corpus.
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    fs::create_dir_all(&corpus).unwrap();
    fs::write(workspace.join("harness.c"), b"int main(){return 0;}").unwrap();
    fs::write(corpus.join("a"), b"aaa").unwrap();
    fs::write(corpus.join("b"), b"bbb").unwrap();

    // The stub runtime errors on every sandbox command, so minimization cannot
    // run; the corpus must be preserved rather than wiped.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let outcome = container.corpus_minimize(&project, target).await.unwrap();

    assert_eq!(outcome.before, 2);
    assert_eq!(outcome.after, 2, "corpus preserved on tooling failure");
    assert!(corpus.join("a").exists());
    assert!(corpus.join("b").exists());

    let _ = fs::remove_dir_all(&workspace);
}

#[tokio::test]
async fn corpus_absorb_crashes_feeds_reproducers_back_in() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("absorb_proj");
    fs::create_dir_all(&project).unwrap();
    let target = "parse_entry";

    // Seed a workspace: an existing corpus plus crash inputs under out/.
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    let out = workspace.join("out");
    fs::create_dir_all(&corpus).unwrap();
    fs::create_dir_all(&out).unwrap();
    fs::write(corpus.join("seed"), b"seed-input").unwrap();
    fs::write(out.join("crash-abc"), b"crashing-bytes").unwrap();
    // Engine bookkeeping that must be ignored.
    fs::write(out.join("fuzzer_stats"), b"stats").unwrap();

    // No store: absorb falls back to scanning the run output directory.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let added = container
        .corpus_absorb_crashes(&project, target)
        .await
        .unwrap();

    assert_eq!(added, 1, "the one crash input is absorbed, stats ignored");
    let entries = container.corpus_list(&project, target).unwrap().entries;
    assert_eq!(entries.len(), 2, "seed + absorbed crash");
    assert!(
        entries
            .iter()
            .any(|e| fs::read(&e.path).unwrap() == b"crashing-bytes"),
        "crash reproducer now in corpus"
    );

    let _ = fs::remove_dir_all(&workspace);
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

#[tokio::test]
async fn chat_branch_forks_an_independent_conversation() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::{Message, SessionId};

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("br.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().unwrap();

    let main = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: Some("Main".to_owned()),
        })
        .await
        .unwrap();

    // Two turns on the main thread.
    for (q, a) in [("q1", "a1"), ("q2", "a2")] {
        manager
            .append_message(&main.id, &Message::user(q))
            .await
            .unwrap();
        manager
            .append_message(&main.id, &Message::assistant(a))
            .await
            .unwrap();
    }

    // Branch after turn 1 (copy the first 2 messages) and diverge.
    let branch_id = container
        .chat_branch(&main.id, 2, Some("Experiment".to_owned()))
        .await
        .expect("branch created");
    let branch = SessionId(branch_id);
    manager
        .append_message(&branch, &Message::user("q-alt"))
        .await
        .unwrap();
    manager
        .append_message(&branch, &Message::assistant("a-alt"))
        .await
        .unwrap();

    // The branch has the fork point + its own divergence; main is untouched.
    let branch_hist = container.chat_history(&branch).await;
    assert_eq!(branch_hist.len(), 4);
    assert_eq!(branch_hist[0].content, "q1");
    assert_eq!(branch_hist[3].content, "a-alt");

    let main_hist = container.chat_history(&main.id).await;
    assert_eq!(main_hist.len(), 4);
    assert_eq!(main_hist[3].content, "a2");

    // The tree lists both sessions, main flagged.
    let tree = container.chat_branches(&main.id).await;
    assert_eq!(tree.len(), 2);
    assert!(tree.iter().any(|b| b.is_main && b.title == "Main"));
    assert!(tree.iter().any(|b| !b.is_main && b.title == "Experiment"));
}
