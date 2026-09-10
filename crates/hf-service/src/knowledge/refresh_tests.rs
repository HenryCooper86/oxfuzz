use super::*;

#[test]
fn ensured_search_refreshes_same_length_edits_and_deletions() {
    let _guard = super::test_guard();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("parser.c");
    std::fs::write(&file, "int alpha_symbol(void) { return 1; }").unwrap();
    assert!(!search_project_ensured(dir.path(), "alpha_symbol", 5).is_empty());
    std::fs::write(&file, "int bravo_symbol(void) { return 2; }").unwrap();
    assert_eq!(stats_project(dir.path()).stale, Some(true));
    assert!(!search_project_ensured(dir.path(), "bravo_symbol", 5).is_empty());
    assert!(search_project(dir.path(), "alpha_symbol", 5).is_empty());
    std::fs::remove_file(file).unwrap();
    assert!(search_project_ensured(dir.path(), "bravo_symbol", 5).is_empty());
    assert_eq!(stats_project(dir.path()).files, 0);
}

#[test]
fn refresh_reuses_unchanged_entries_and_replaces_only_changed_entries() {
    let _guard = super::test_guard();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("one.c"),
        "int first_symbol(void) { return 1; }",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("two.c"),
        "int other_symbol(void) { return 2; }",
    )
    .unwrap();
    let first = index_project(dir.path()).unwrap();
    assert_eq!(first.updated_entries, 2);
    let old = current_index(dir.path()).unwrap();
    let unchanged = index_project(dir.path()).unwrap();
    assert_eq!(unchanged.updated_entries, 0);
    assert_eq!(unchanged.reused_entries, 2);
    assert_eq!(
        current_index(dir.path()).unwrap().indexed_at,
        old.indexed_at
    );
    std::fs::write(
        dir.path().join("one.c"),
        "int newer_symbol(void) { return 3; }",
    )
    .unwrap();
    let changed = index_project(dir.path()).unwrap();
    assert_eq!(changed.updated_entries, 1);
    assert_eq!(changed.reused_entries, 1);
    // A reader that acquired the prior snapshot must retain its original postings.
    assert!(!old
        .retriever
        .search("first_symbol", &RetrievalFilter::default())
        .is_empty());
    assert!(search_project(dir.path(), "first_symbol", 5).is_empty());
    std::fs::remove_file(dir.path().join("two.c")).unwrap();
    assert_eq!(index_project(dir.path()).unwrap().removed_entries, 1);
    assert!(search_project(dir.path(), "other_symbol", 5).is_empty());
}

#[test]
fn index_status_reports_captured_configuration_and_detects_changes() {
    let _guard = super::test_guard();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("one.c"),
        "int parser_symbol(void) { return 1; }",
    )
    .unwrap();
    let config = KnowledgeConfig {
        l2_max_tokens: 23,
        ..KnowledgeConfig::default()
    };
    index_project_with_config(dir.path(), &config).unwrap();
    let status = stats_project_with_config(dir.path(), &config);
    assert_eq!(status.stale, Some(false));
    assert_eq!(status.effective.unwrap().chunk_max_tokens, 23);
    let changed = KnowledgeConfig {
        l2_max_tokens: 41,
        ..config
    };
    let status = stats_project_with_config(dir.path(), &changed);
    assert_eq!(status.stale, Some(true));
    assert_eq!(status.effective.unwrap().chunk_max_tokens, 23);
    assert_eq!(status.configured.chunk_max_tokens, 41);
    assert_eq!(
        index_project_with_config(dir.path(), &changed)
            .unwrap()
            .updated_entries,
        1
    );
}

#[test]
fn concurrent_refreshes_share_one_completed_index() {
    let _guard = super::test_guard();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("one.c"),
        "int parser_symbol(void) { return 1; }",
    )
    .unwrap();
    let start = std::sync::Barrier::new(4);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    index_project(dir.path()).unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .map(|result| result.updated_entries)
            .sum::<usize>(),
        1
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.reused_entries)
            .sum::<usize>(),
        3
    );
}

#[test]
fn an_unreadable_source_does_not_leave_its_old_text_searchable() {
    let _guard = super::test_guard();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("one.c");
    std::fs::write(&file, "int removed_symbol(void) { return 1; }").unwrap();
    index_project(dir.path()).unwrap();
    std::fs::write(file, [0xff, 0xfe]).unwrap();
    assert!(search_project_ensured(dir.path(), "removed_symbol", 5).is_empty());
    assert!(!stats_project(dir.path()).warnings.is_empty());
}

struct TestEmbedder {
    calls: std::sync::atomic::AtomicUsize,
    malformed: bool,
    fail_after: Option<usize>,
}
#[async_trait::async_trait]
impl EmbeddingProvider for TestEmbedder {
    async fn embed(
        &self,
        _: &str,
    ) -> Result<hf_core::embedding::EmbeddingResult, hf_core::embedding::EmbeddingError> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail_after.is_some_and(|limit| call >= limit) {
            return Err(hf_core::embedding::EmbeddingError::ProviderError {
                message: "injected query failure".into(),
            });
        }
        Ok(hf_core::embedding::EmbeddingResult {
            vector: if self.malformed {
                vec![f32::NAN]
            } else {
                vec![0.5, 0.5]
            },
            dimensions: 2,
            model: "captured-model".into(),
            token_count: 1,
        })
    }
    fn dimensions(&self) -> usize {
        2
    }
    fn model_name(&self) -> &'static str {
        "captured-model"
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_vectors_fall_back_to_real_keyword_search() {
    let _guard = super::test_guard();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("one.c"),
        "int visible_symbol(void) { return 1; }",
    )
    .unwrap();
    let operation = KnowledgeOperation::acquire(dir.path()).unwrap();
    let config = KnowledgeConfig {
        embedding_enabled: true,
        embedding_dimensions: 2,
        retrieval_strategy: "semantic".into(),
        ..KnowledgeConfig::default()
    };
    let embedder: Arc<dyn EmbeddingProvider> = Arc::new(TestEmbedder {
        calls: std::sync::atomic::AtomicUsize::new(0),
        malformed: true,
        fail_after: None,
    });
    index_in_operation_with_embedder(&operation, &config, Some(embedder), true).unwrap();
    let status = stats_project_with_config(dir.path(), &config);
    assert_eq!(status.effective.unwrap().retrieval_strategy, "keyword");
    assert!(!status.warnings.is_empty());
    assert!(!search_project(dir.path(), "visible_symbol", 5).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn cached_queries_use_the_indexed_provider_not_current_configuration() {
    let _guard = super::test_guard();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("one.c"),
        "int visible_symbol(void) { return 1; }",
    )
    .unwrap();
    let operation = KnowledgeOperation::acquire(dir.path()).unwrap();
    let config = KnowledgeConfig {
        embedding_enabled: true,
        embedding_dimensions: 2,
        embedding_model: "captured-model".into(),
        ..KnowledgeConfig::default()
    };
    let embedder = Arc::new(TestEmbedder {
        calls: std::sync::atomic::AtomicUsize::new(0),
        malformed: false,
        fail_after: None,
    });
    index_in_operation_with_embedder(&operation, &config, Some(embedder.clone()), true).unwrap();
    assert!(!search_project(dir.path(), "visible_symbol", 5).is_empty());
    assert_eq!(embedder.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(
        stats_project(dir.path())
            .effective
            .unwrap()
            .embedding_model
            .as_deref(),
        Some("captured-model")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn query_embedding_failure_is_reported_without_hiding_keyword_hits() {
    let _guard = super::test_guard();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("one.c"),
        "int visible_symbol(void) { return 1; }",
    )
    .unwrap();
    let operation = KnowledgeOperation::acquire(dir.path()).unwrap();
    let config = KnowledgeConfig {
        embedding_enabled: true,
        embedding_dimensions: 2,
        ..KnowledgeConfig::default()
    };
    let embedder = Arc::new(TestEmbedder {
        calls: std::sync::atomic::AtomicUsize::new(0),
        malformed: false,
        fail_after: Some(1),
    });
    index_in_operation_with_embedder(&operation, &config, Some(embedder), true).unwrap();
    assert!(!search_project(dir.path(), "visible_symbol", 5).is_empty());
    assert!(stats_project(dir.path())
        .warnings
        .iter()
        .any(|warning| warning.contains("query")));
}
