-- SQLite schema version 1. Run only during explicit provisioning.
-- Adapter must validate canonical models, projections, chains and head semantics.
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

CREATE TABLE store_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    review_sequence INTEGER NOT NULL CHECK (review_sequence >= 0),
    review_head_hash TEXT NOT NULL CHECK (length(review_head_hash) = 64),
    release_sequence INTEGER NOT NULL CHECK (release_sequence >= 0),
    release_head_hash TEXT NOT NULL CHECK (length(release_head_hash) = 64)
) STRICT;

CREATE TABLE reviews (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    review_id TEXT NOT NULL UNIQUE CHECK (length(trim(review_id)) > 0),
    document_id TEXT NOT NULL CHECK (length(trim(document_id)) > 0),
    version_id TEXT NOT NULL CHECK (length(trim(version_id)) > 0),
    verdict TEXT NOT NULL CHECK (verdict IN ('approved', 'rejected', 'revoked')),
    availability_fingerprint TEXT NOT NULL CHECK (length(availability_fingerprint) = 64),
    expected_head_sequence INTEGER REFERENCES reviews(sequence),
    supersedes_review_id TEXT REFERENCES reviews(review_id),
    revokes_review_id TEXT REFERENCES reviews(review_id),
    previous_entry_hash TEXT NOT NULL CHECK (length(previous_entry_hash) = 64),
    entry_hash TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64),
    -- Canonical UTF-8 JSON bytes of full StoredReviewRecord, including identity,
    -- complete availability, actor, rationale, reviewed_at and recorded_at.
    record_bytes BLOB NOT NULL CHECK (length(record_bytes) > 0),
    CHECK ((expected_head_sequence IS NULL) = (supersedes_review_id IS NULL)),
    CHECK ((verdict = 'revoked') = (revokes_review_id IS NOT NULL)),
    CHECK (expected_head_sequence IS NULL OR expected_head_sequence < sequence)
) STRICT;
CREATE INDEX reviews_version_head ON reviews(document_id, version_id, sequence DESC);

CREATE TABLE outbox (
    release_sequence INTEGER PRIMARY KEY CHECK (release_sequence > 0),
    release_id TEXT NOT NULL UNIQUE CHECK (length(trim(release_id)) > 0),
    review_sequence INTEGER NOT NULL REFERENCES reviews(sequence),
    store_revision INTEGER NOT NULL REFERENCES reviews(sequence),
    candidate_hash TEXT NOT NULL CHECK (length(candidate_hash) = 64),
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    previous_release_hash TEXT NOT NULL CHECK (length(previous_release_hash) = 64),
    entry_hash TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64),
    -- Full canonical ReleaseRequest and ReleaseReceipt, with explicit codec v1.
    request_bytes BLOB NOT NULL CHECK (length(request_bytes) > 0),
    receipt_bytes BLOB NOT NULL CHECK (length(receipt_bytes) > 0),
    payload BLOB NOT NULL,
    CHECK (review_sequence <= store_revision)
) STRICT;

-- Defensive constraints for supported SQL operations, not protection against
-- a database owner who can drop triggers or coherently replace the entire file.
CREATE TRIGGER reviews_no_update BEFORE UPDATE ON reviews
BEGIN SELECT RAISE(ABORT, 'reviews are immutable'); END;
CREATE TRIGGER reviews_no_delete BEFORE DELETE ON reviews
BEGIN SELECT RAISE(ABORT, 'reviews are immutable'); END;
CREATE TRIGGER outbox_no_update BEFORE UPDATE ON outbox
BEGIN SELECT RAISE(ABORT, 'outbox is immutable'); END;
CREATE TRIGGER outbox_no_delete BEFORE DELETE ON outbox
BEGIN SELECT RAISE(ABORT, 'outbox is immutable'); END;
CREATE TRIGGER store_state_no_delete BEFORE DELETE ON store_state
BEGIN SELECT RAISE(ABORT, 'store checkpoint cannot be deleted'); END;

INSERT INTO store_state VALUES (
    1, 1, 0, printf('%064d', 0), 0, printf('%064d', 0)
);
PRAGMA user_version = 1;
COMMIT;
