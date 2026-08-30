-- Independent pre-execution review evidence for the exact generated harness
-- source. One harness id identifies one immutable compiled source revision.
CREATE TABLE harness_ai_reviews (
    harness_id      TEXT PRIMARY KEY,
    source_sha256   TEXT NOT NULL
                    CHECK (length(source_sha256) = 64
                           AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    binary_sha256   TEXT NOT NULL
                    CHECK (length(binary_sha256) = 64
                           AND binary_sha256 NOT GLOB '*[^0-9a-f]*'),
    review_json     TEXT NOT NULL CHECK (json_valid(review_json)),
    reviewed_at     TEXT NOT NULL
);
