-- Turn-level chat rollback checkpoints for hf-session's ChatCheckpointManager.
-- Previously backed by an in-memory store, so rollback silently no-op'd after a
-- restart; persisting them here lets the GUI's rollback survive restarts.
-- Mirrors the chat_checkpoints block of schema.sql.

CREATE TABLE IF NOT EXISTS chat_checkpoints (
    checkpoint_id        TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL,
    turn_number          INTEGER NOT NULL,
    message_count_before INTEGER NOT NULL,
    journal_scope_id     TEXT NOT NULL,
    invalidated          INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT unique_session_turn UNIQUE (session_id, turn_number)
);

CREATE INDEX IF NOT EXISTS idx_chat_cp_session
    ON chat_checkpoints(session_id, turn_number DESC);
