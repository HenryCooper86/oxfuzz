-- Preserve the exact operator language instruction before model dispatch.
CREATE TABLE chat_turn_languages (
    id TEXT PRIMARY KEY,
    turn_id TEXT NOT NULL,
    session_id TEXT REFERENCES session_metadata(id) ON DELETE CASCADE,
    instruction TEXT NOT NULL CHECK(length(CAST(instruction AS BLOB)) BETWEEN 1 AND 2048),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_chat_turn_languages_session ON chat_turn_languages(session_id);
