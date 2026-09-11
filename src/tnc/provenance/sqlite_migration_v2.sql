-- Explicit v1-to-v2 layout migration. Caller owns BEGIN IMMEDIATE / COMMIT.
-- Existing ledger tables and canonical bytes remain unchanged.
-- The current adapter accepts only an empty journal until its manager exists.

CREATE TABLE request_intents (
    operation_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(operation_id)) > 0),
    principal_id TEXT NOT NULL CHECK (length(trim(principal_id)) > 0),
    release_id TEXT NOT NULL UNIQUE CHECK (length(trim(release_id)) > 0),
    intent_hash TEXT NOT NULL CHECK (length(intent_hash) = 64),
    intent_bytes BLOB NOT NULL CHECK (length(intent_bytes) > 0),
    UNIQUE (operation_id, release_id)
) STRICT;
-- release_id above is a reservation, not an FK to an as-yet nonexistent outbox row.

CREATE TABLE prepared_requests (
    operation_id TEXT PRIMARY KEY NOT NULL,
    release_id TEXT NOT NULL UNIQUE,
    candidate_hash TEXT NOT NULL CHECK (length(candidate_hash) = 64),
    request_bytes BLOB NOT NULL CHECK (length(request_bytes) > 0),
    FOREIGN KEY (operation_id, release_id) REFERENCES request_intents(operation_id, release_id)
) STRICT;

CREATE TABLE request_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    operation_id TEXT NOT NULL REFERENCES request_intents(operation_id),
    kind TEXT NOT NULL CHECK (kind IN ('REGISTERED', 'CLAIMED', 'PREPARED', 'COMMITTED', 'FAILED')),
    worker_generation INTEGER NOT NULL CHECK (worker_generation >= 0),
    -- Only a COMMITTED event refers to an existing outbox row.
    receipt_release_id TEXT UNIQUE REFERENCES outbox(release_id),
    previous_entry_hash TEXT NOT NULL CHECK (length(previous_entry_hash) = 64),
    entry_hash TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64),
    event_bytes BLOB NOT NULL CHECK (length(event_bytes) > 0),
    CHECK ((kind = 'COMMITTED') = (receipt_release_id IS NOT NULL)),
    FOREIGN KEY (operation_id, receipt_release_id) REFERENCES request_intents(operation_id, release_id)
) STRICT;
CREATE INDEX request_events_head ON request_events(operation_id, sequence DESC);

CREATE TABLE journal_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    codec_version INTEGER NOT NULL CHECK (codec_version = 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    head_hash TEXT NOT NULL CHECK (length(head_hash) = 64)
) STRICT;
INSERT INTO journal_state VALUES (1, 1, 0, printf('%064d', 0));

CREATE TRIGGER request_intents_no_update BEFORE UPDATE ON request_intents
BEGIN SELECT RAISE(ABORT, 'request intents are immutable'); END;
CREATE TRIGGER request_intents_no_delete BEFORE DELETE ON request_intents
BEGIN SELECT RAISE(ABORT, 'request intents are immutable'); END;
CREATE TRIGGER prepared_requests_no_update BEFORE UPDATE ON prepared_requests
BEGIN SELECT RAISE(ABORT, 'prepared requests are immutable'); END;
CREATE TRIGGER prepared_requests_no_delete BEFORE DELETE ON prepared_requests
BEGIN SELECT RAISE(ABORT, 'prepared requests are immutable'); END;
CREATE TRIGGER request_events_no_update BEFORE UPDATE ON request_events
BEGIN SELECT RAISE(ABORT, 'request events are immutable'); END;
CREATE TRIGGER request_events_no_delete BEFORE DELETE ON request_events
BEGIN SELECT RAISE(ABORT, 'request events are immutable'); END;
CREATE TRIGGER journal_state_no_delete BEFORE DELETE ON journal_state
BEGIN SELECT RAISE(ABORT, 'journal checkpoint cannot be deleted'); END;
PRAGMA user_version = 2;
