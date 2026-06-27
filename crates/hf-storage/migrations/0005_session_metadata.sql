-- Session-tree metadata for hf-session's SqliteSessionStore (the GUI chat now
-- runs on hf-session: SessionManager + JSONL transcripts, replacing the simple
-- sessions/messages store). Mirrors the session_metadata block of schema.sql.

CREATE TABLE IF NOT EXISTS session_metadata (
    id              TEXT PRIMARY KEY,
    parent_id       TEXT REFERENCES session_metadata(id),
    root_id         TEXT NOT NULL REFERENCES session_metadata(id),
    depth           INTEGER NOT NULL DEFAULT 0,
    path            TEXT NOT NULL,
    session_type    TEXT NOT NULL CHECK (session_type IN (
                        'main', 'child', 'branch', 'ephemeral', 'sub_agent', 'canonical'
                    )),
    state           TEXT NOT NULL DEFAULT 'active' CHECK (state IN (
                        'active', 'paused', 'archived', 'merged', 'tombstone'
                    )),
    agent_id        TEXT,
    title           TEXT,
    manual_title    TEXT,
    token_count     INTEGER NOT NULL DEFAULT 0,
    message_count   INTEGER NOT NULL DEFAULT 0,
    transcript_path TEXT NOT NULL,
    channel         TEXT,
    label           TEXT,
    last_compaction TEXT,
    compaction_count INTEGER NOT NULL DEFAULT 0,
    context_reset_index INTEGER,
    custom_system_prompt TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_session_parent ON session_metadata(parent_id);
CREATE INDEX IF NOT EXISTS idx_session_root   ON session_metadata(root_id);
CREATE INDEX IF NOT EXISTS idx_session_state  ON session_metadata(state);
