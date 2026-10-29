//! JSONL-based `TranscriptStore` implementation.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::instrument;

use hf_core::session::{SessionError, TranscriptStore};
use hf_core::types::{Message, SessionId};

/// JSONL file-based transcript store.
///
/// Each session's messages are stored in a separate `.jsonl` file
/// where each line is a JSON-serialized `Message`.
#[derive(Debug, Clone)]
pub struct JsonlTranscriptStore {
    /// Base directory for transcript files.
    base_dir: PathBuf,
    /// Write lock to serialise concurrent appends.
    ///
    /// `O_APPEND` guarantees atomic positioning but NOT atomic writes for
    /// buffers exceeding `PIPE_BUF` (~4KB). Serialising through this mutex
    /// prevents interleaved bytes when long messages are written concurrently.
    write_lock: Arc<Mutex<()>>,
}

impl JsonlTranscriptStore {
    /// Create a new transcript store with the given base directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Get the file path for a session's transcript.
    fn transcript_path(&self, session_id: &SessionId) -> Result<PathBuf, SessionError> {
        Ok(self
            .base_dir
            .join(format!("{}.jsonl", transcript_file_stem(session_id)?)))
    }

    /// Ensure the base directory exists.
    async fn ensure_dir(&self) -> Result<(), SessionError> {
        tokio::fs::create_dir_all(&self.base_dir)
            .await
            .map_err(|e| SessionError::TranscriptError {
                message: format!("create transcript dir: {e}"),
            })
    }
}

#[async_trait]
impl TranscriptStore for JsonlTranscriptStore {
    #[instrument(skip(self, message), fields(session_id = %session_id))]
    async fn append(&self, session_id: &SessionId, message: &Message) -> Result<(), SessionError> {
        let path = self.transcript_path(session_id)?;
        self.ensure_dir().await?;
        let mut line =
            serde_json::to_string(message).map_err(|e| SessionError::TranscriptError {
                message: format!("serialize message: {e}"),
            })?;
        line.push('\n');

        // Serialise writes so concurrent appends cannot interleave bytes.
        let _guard = self.write_lock.lock().await;

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|e| SessionError::TranscriptError {
                message: format!("open transcript file {}: {e}", path.display()),
            })?;

        ensure_record_separator(&mut file).await.map_err(|error| {
            SessionError::TranscriptError {
                message: format!("separate transcript tail: {error}"),
            }
        })?;
        file.write_all(line.as_bytes())
            .await
            .map_err(|e| SessionError::TranscriptError {
                message: format!("write to transcript: {e}"),
            })?;

        // `flush` only pushes bytes to the OS page cache; `sync_all` forces them
        // to stable storage so a power loss after the call cannot lose or tear
        // an already-acknowledged transcript line.
        file.sync_all()
            .await
            .map_err(|e| SessionError::TranscriptError {
                message: format!("sync transcript: {e}"),
            })?;

        Ok(())
    }

    #[instrument(skip(self), fields(session_id = %session_id))]
    async fn read_all(&self, session_id: &SessionId) -> Result<Vec<Message>, SessionError> {
        let path = self.transcript_path(session_id)?;

        if !path.exists() {
            return Ok(Vec::new());
        }

        read_messages_from_file(&path).await
    }

    #[instrument(skip(self), fields(session_id = %session_id, count = count))]
    async fn read_last(
        &self,
        session_id: &SessionId,
        count: usize,
    ) -> Result<Vec<Message>, SessionError> {
        let path = self.transcript_path(session_id)?;
        if !path.exists() {
            return Ok(Vec::new());
        }
        read_last_messages_from_file(&path, count).await
    }

    #[instrument(skip(self), fields(session_id = %session_id))]
    async fn message_count(&self, session_id: &SessionId) -> Result<usize, SessionError> {
        let path = self.transcript_path(session_id)?;

        if !path.exists() {
            return Ok(0);
        }

        count_messages_from_file(&path).await
    }

    #[instrument(skip(self), fields(session_id = %session_id, keep_count = keep_count))]
    async fn truncate(
        &self,
        session_id: &SessionId,
        keep_count: usize,
    ) -> Result<usize, SessionError> {
        // Hold the write lock across the whole read-modify-rename. Without it a
        // concurrent `append` could write to the old file after our `read_all`
        // but before the `rename`, and the rename would then silently clobber
        // that appended message. `read_all` does not take the lock, so there is
        // no re-entrancy.
        let _guard = self.write_lock.lock().await;

        let all = self.read_all(session_id).await?;
        if keep_count >= all.len() {
            return Ok(0);
        }

        let removed = all.len() - keep_count;
        let kept = &all[..keep_count];

        // Atomic rewrite: write to temp file, then rename.
        let path = self.transcript_path(session_id)?;

        let mut content = String::new();
        for msg in kept {
            let line = serde_json::to_string(msg).map_err(|e| SessionError::TranscriptError {
                message: format!("serialize message: {e}"),
            })?;
            content.push_str(&line);
            content.push('\n');
        }

        durable_rewrite(&path, &content).await?;

        Ok(removed)
    }
}

/// Separate a crash-torn final record from the next append, preserving a final
/// complete JSON record that lost only its newline. The caller holds its write
/// lock and opens the file for reading and appending.
pub(crate) async fn ensure_record_separator(file: &mut tokio::fs::File) -> std::io::Result<()> {
    if file.metadata().await?.len() == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1)).await?;
    let mut last_byte = [0];
    file.read_exact(&mut last_byte).await?;
    if last_byte[0] != b'\n' {
        file.write_all(b"\n").await?;
    }
    Ok(())
}

/// Durably publish a transcript rewrite: write the temp file, fsync it, rename
/// over the live file, then best-effort fsync the parent directory.
///
/// Both the context and display transcripts roll back on the same paths, so
/// they share this one implementation — a crash after the rename must leave
/// both files equally durable, never a fresh display transcript beside a stale
/// context transcript.
pub(crate) async fn durable_rewrite(path: &Path, content: &str) -> Result<(), SessionError> {
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);

    // Durable atomic rewrite: write the temp file and fsync its contents
    // before the rename, so the rename (which is itself durable) cannot
    // publish a temp file whose data blocks were never written back.
    let mut tmp_file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp_path)
        .await
        .map_err(|e| SessionError::TranscriptError {
            message: format!("open temp transcript: {e}"),
        })?;
    tmp_file
        .write_all(content.as_bytes())
        .await
        .map_err(|e| SessionError::TranscriptError {
            message: format!("write temp transcript: {e}"),
        })?;
    tmp_file
        .sync_all()
        .await
        .map_err(|e| SessionError::TranscriptError {
            message: format!("sync temp transcript: {e}"),
        })?;
    drop(tmp_file);

    tokio::fs::rename(&tmp_path, path)
        .await
        .map_err(|e| SessionError::TranscriptError {
            message: format!("rename temp transcript: {e}"),
        })?;

    // Best-effort fsync of the containing directory so the rename itself is
    // durable across a crash; a failure here is not fatal to the operation.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = tokio::fs::File::open(parent).await {
            // §2.17: a directory-fsync failure is swallowed because the
            // rename has already been applied; failing now would report the
            // truncate as lost when the content is already live.
            let _ = dir.sync_all().await;
        }
    }

    Ok(())
}

/// Return a platform-independent safe filename stem for a session transcript.
///
/// Session ids are generated UUIDs, but presentation APIs accept strings. A
/// strict portable alphabet prevents absolute paths, parent traversal, path
/// separators, Windows prefixes, and control characters from reaching file I/O.
pub(crate) fn transcript_file_stem(session_id: &SessionId) -> Result<&str, SessionError> {
    let value = session_id.as_str();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SessionError::TranscriptError {
            message: "invalid session identifier for transcript storage".to_owned(),
        });
    }
    Ok(value)
}

/// Visit valid messages in file order, using the same recovery rules for every read.
async fn visit_messages_from_file(
    path: &Path,
    mut visit: impl FnMut(Message),
) -> Result<(), SessionError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| SessionError::TranscriptError {
            message: format!("open transcript {}: {e}", path.display()),
        })?;

    let mut reader = tokio::io::BufReader::new(file);
    let mut line = Vec::new();

    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line).await.map_err(|e| {
            SessionError::TranscriptError {
                message: format!("read line: {e}"),
            }
        })?;
        if bytes_read == 0 {
            break;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        // Skip (don't fail on) an unparseable line. A crash mid-append can leave
        // a torn JSON or UTF-8 record; decoding bytes here keeps that damage
        // local to the record instead of making the whole session unloadable.
        match serde_json::from_slice::<Message>(&line) {
            Ok(msg) => visit(msg),
            Err(e) => tracing::warn!(
                path = %path.display(),
                error = %e,
                "skipping unparseable transcript line"
            ),
        }
    }

    Ok(())
}

/// Read all recoverable messages from a JSONL file.
pub(crate) async fn read_messages_from_file(path: &Path) -> Result<Vec<Message>, SessionError> {
    let mut messages = Vec::new();
    visit_messages_from_file(path, |message| messages.push(message)).await?;
    Ok(messages)
}

/// Count the same recoverable messages returned by transcript reads.
pub(crate) async fn count_messages_from_file(path: &Path) -> Result<usize, SessionError> {
    let mut count = 0;
    visit_messages_from_file(path, |_| count += 1).await?;
    Ok(count)
}

/// Read only the last `count` messages from a JSONL file.
///
/// Retains at most `count` parsed messages, ignoring torn records before trimming.
async fn read_last_messages_from_file(
    path: &Path,
    count: usize,
) -> Result<Vec<Message>, SessionError> {
    use std::collections::VecDeque;

    // "Last zero messages" is the empty set. Without this guard the ring-trim
    // `ring.len() == count` never fires (len is >= 1 after the first push), so
    // every line accumulates and the whole transcript is returned.
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut ring = VecDeque::new();
    visit_messages_from_file(path, |message| {
        if ring.len() == count {
            ring.pop_front();
        }
        ring.push_back(message);
    })
    .await?;
    Ok(ring.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::types::{Message, Role};

    fn test_message(content: &str) -> Message {
        Message {
            message_id: hf_core::types::generate_message_id(),
            role: Role::User,
            content: content.to_string(),
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: chrono::Utc::now(),
            metadata: serde_json::Value::Null,
        }
    }

    fn temp_store() -> (tempfile::TempDir, JsonlTranscriptStore) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let store = JsonlTranscriptStore::new(dir.path());
        (dir, store)
    }

    #[tokio::test]
    async fn test_transcript_append_and_read_all() {
        let (_dir, store) = temp_store();
        let session_id = SessionId::new();

        store
            .append(&session_id, &test_message("hello"))
            .await
            .unwrap();
        store
            .append(&session_id, &test_message("world"))
            .await
            .unwrap();
        store.append(&session_id, &test_message("!")).await.unwrap();

        let messages = store.read_all(&session_id).await.unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].content, "hello");
        assert_eq!(messages[1].content, "world");
        assert_eq!(messages[2].content, "!");
    }

    #[tokio::test]
    async fn test_transcript_read_last_n() {
        let (_dir, store) = temp_store();
        let session_id = SessionId::new();

        for i in 0..10 {
            store
                .append(&session_id, &test_message(&format!("msg-{i}")))
                .await
                .unwrap();
        }

        let last_3 = store.read_last(&session_id, 3).await.unwrap();
        assert_eq!(last_3.len(), 3);
        assert_eq!(last_3[0].content, "msg-7");
        assert_eq!(last_3[1].content, "msg-8");
        assert_eq!(last_3[2].content, "msg-9");
    }

    #[tokio::test]
    async fn test_transcript_message_count() {
        let (_dir, store) = temp_store();
        let session_id = SessionId::new();

        for i in 0..5 {
            store
                .append(&session_id, &test_message(&format!("msg-{i}")))
                .await
                .unwrap();
        }

        let count = store.message_count(&session_id).await.unwrap();
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn test_transcript_empty_session() {
        let (_dir, store) = temp_store();
        let session_id = SessionId::new();

        let messages = store.read_all(&session_id).await.unwrap();
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn transcript_session_id_cannot_escape_the_store_directory() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("context");
        std::fs::create_dir_all(&base).unwrap();
        let outside = dir.path().join("outside.jsonl");
        let original = format!(
            "{}\n",
            serde_json::to_string(&test_message("secret")).unwrap()
        );
        std::fs::write(&outside, &original).unwrap();
        let store = JsonlTranscriptStore::new(&base);
        let escaped = SessionId::from_string("../outside");

        assert!(store.read_all(&escaped).await.is_err());
        assert!(store
            .append(&escaped, &test_message("overwrite"))
            .await
            .is_err());
        assert_eq!(std::fs::read_to_string(outside).unwrap(), original);
    }

    #[tokio::test]
    async fn test_transcript_jsonl_format() {
        let (dir, store) = temp_store();
        let session_id = SessionId::new();

        store
            .append(&session_id, &test_message("test"))
            .await
            .unwrap();

        // Read the raw file and verify each line is valid JSON.
        let path = dir.path().join(format!("{}.jsonl", session_id.as_str()));
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                assert!(
                    serde_json::from_str::<serde_json::Value>(trimmed).is_ok(),
                    "line should be valid JSON: {trimmed}"
                );
            }
        }
    }

    #[tokio::test]
    async fn read_all_skips_a_torn_line_instead_of_failing() {
        let (dir, store) = temp_store();
        let session_id = SessionId::new();
        store
            .append(&session_id, &test_message("first"))
            .await
            .unwrap();

        // Simulate a crash mid-append: a valid line, a torn JSON line, then a
        // recovered valid line.
        let path = dir.path().join(format!("{}.jsonl", session_id.as_str()));
        let good = serde_json::to_string(&test_message("third")).unwrap();
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .unwrap();
        f.write_all(b"{\"role\":\"user\",\"content\":\n")
            .await
            .unwrap();
        f.write_all(format!("{good}\n").as_bytes()).await.unwrap();
        f.flush().await.unwrap();

        // The whole transcript must remain loadable; only the torn line is lost.
        let messages = store.read_all(&session_id).await.unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, "first");
        assert_eq!(messages[1].content, "third");
        assert_eq!(store.message_count(&session_id).await.unwrap(), 2);

        // read_last is just as resilient.
        let last = store.read_last(&session_id, 5).await.unwrap();
        assert_eq!(last.len(), 2);
    }

    #[tokio::test]
    async fn append_after_unterminated_tail_preserves_the_new_message() {
        for tail_is_complete in [false, true] {
            let (dir, store) = temp_store();
            let session_id = SessionId::new();
            store
                .append(&session_id, &test_message("first"))
                .await
                .unwrap();
            let path = dir.path().join(format!("{}.jsonl", session_id.as_str()));
            let tail = if tail_is_complete {
                serde_json::to_string(&test_message("second")).unwrap()
            } else {
                "{\"role\":\"user\",\"content\":".to_owned()
            };
            let mut file = tokio::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .await
                .unwrap();
            file.write_all(tail.as_bytes()).await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            store
                .append(&session_id, &test_message("next turn"))
                .await
                .unwrap();

            let messages = store.read_all(&session_id).await.unwrap();
            let expected = if tail_is_complete {
                vec!["first", "second", "next turn"]
            } else {
                vec!["first", "next turn"]
            };
            assert_eq!(
                messages
                    .iter()
                    .map(|message| message.content.as_str())
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                store.message_count(&session_id).await.unwrap(),
                expected.len()
            );
        }
    }

    #[tokio::test]
    async fn torn_utf8_tail_does_not_block_transcript_recovery() {
        let (dir, store) = temp_store();
        let session_id = SessionId::new();
        store
            .append(&session_id, &test_message("first"))
            .await
            .unwrap();
        let path = dir.path().join(format!("{}.jsonl", session_id.as_str()));
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .await
            .unwrap();
        file.write_all(b"{\"content\":\"\xe4\xb8").await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        let messages = store.read_all(&session_id).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "first");
        assert_eq!(store.message_count(&session_id).await.unwrap(), 1);
        assert_eq!(store.read_last(&session_id, 1).await.unwrap().len(), 1);

        store
            .append(&session_id, &test_message("next turn"))
            .await
            .unwrap();

        let messages = store.read_all(&session_id).await.unwrap();
        assert_eq!(
            messages
                .iter()
                .map(|message| message.content.as_str())
                .collect::<Vec<_>>(),
            ["first", "next turn"]
        );
        assert_eq!(store.message_count(&session_id).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn read_last_skips_a_torn_tail_without_losing_valid_messages() {
        let (dir, store) = temp_store();
        let session_id = SessionId::new();
        store
            .append(&session_id, &test_message("first"))
            .await
            .unwrap();
        store
            .append(&session_id, &test_message("second"))
            .await
            .unwrap();
        let path = dir.path().join(format!("{}.jsonl", session_id.as_str()));
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .await
            .unwrap();
        file.write_all(b"{\"role\":\n").await.unwrap();
        file.flush().await.unwrap();

        let messages = store.read_last(&session_id, 2).await.unwrap();

        assert_eq!(
            messages
                .iter()
                .map(|message| message.content.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[tokio::test]
    async fn truncate_keeps_the_requested_prefix() {
        let (_dir, store) = temp_store();
        let session_id = SessionId::new();
        for i in 0..5 {
            store
                .append(&session_id, &test_message(&format!("m{i}")))
                .await
                .unwrap();
        }
        let removed = store.truncate(&session_id, 2).await.unwrap();
        assert_eq!(removed, 3);
        let kept = store.read_all(&session_id).await.unwrap();
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].content, "m0");
        assert_eq!(kept[1].content, "m1");
    }

    #[tokio::test]
    async fn test_transcript_concurrent_append() {
        let (_dir, store) = temp_store();
        let session_id = SessionId::new();

        // Write from multiple tasks concurrently.
        let mut handles = Vec::new();
        for i in 0..10 {
            let store = store.clone();
            let sid = session_id.clone();
            handles.push(tokio::spawn(async move {
                store
                    .append(&sid, &test_message(&format!("concurrent-{i}")))
                    .await
                    .unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let messages = store.read_all(&session_id).await.unwrap();
        assert_eq!(
            messages.len(),
            10,
            "all concurrent messages should be present"
        );
    }
}
