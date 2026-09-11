-- Explicit v2-to-v3 storage-only migration; no authenticated writer enabled.
-- Requires an exactly validated v2 schema and complete validated v2 history.
-- Execute individual statements in an existing BEGIN IMMEDIATE transaction.
-- The migration runner, not this script, validates and COMMITs the transaction.
-- Transitional journal guards intentionally prevent all further journal writes.

CREATE TABLE authorization_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    event_id TEXT NOT NULL UNIQUE CHECK (length(trim(event_id)) > 0),
    kind TEXT NOT NULL CHECK (kind IN (
        'CREDENTIAL_ENROLLED', 'CREDENTIAL_DISABLED',
        'PERMISSION_GRANTED', 'PERMISSION_REVOKED',
        'EXECUTION_AUTHORIZED', 'EXECUTION_RENEWED',
        'WORKER_ASSIGNED', 'WORKER_RETIRED'
    )),
    principal_id TEXT NOT NULL CHECK (length(trim(principal_id)) > 0),
    actor_principal_id TEXT NOT NULL CHECK (length(trim(actor_principal_id)) > 0),
    previous_entry_hash TEXT NOT NULL CHECK (length(previous_entry_hash) = 64),
    entry_hash TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64),
    event_bytes BLOB NOT NULL CHECK (length(event_bytes) > 0)
) STRICT;

CREATE TABLE authorization_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    codec_version INTEGER NOT NULL CHECK (codec_version = 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    head_hash TEXT NOT NULL CHECK (length(head_hash) = 64)
) STRICT;
INSERT INTO authorization_state VALUES (1, 1, 0, printf('%064d', 0));

-- Canonical event bytes carry full credential/grant data and evidence of the
-- host-authenticated administrative action. These are not client assertions.
-- No bootstrap identity or permission is manufactured during migration.

CREATE TABLE execution_authorizations (
    authorization_sequence INTEGER PRIMARY KEY REFERENCES authorization_events(sequence),
    operation_id TEXT NOT NULL REFERENCES request_intents(operation_id),
    generation INTEGER NOT NULL CHECK (generation > 0),
    principal_id TEXT NOT NULL CHECK (length(trim(principal_id)) > 0),
    credential_id TEXT NOT NULL CHECK (length(credential_id) = 64),
    intent_hash TEXT NOT NULL CHECK (length(intent_hash) = 64),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes) > 0),
    UNIQUE (operation_id, generation),
    UNIQUE (operation_id, authorization_sequence)
) STRICT;

CREATE TABLE execution_assignments (
    assignment_sequence INTEGER PRIMARY KEY REFERENCES authorization_events(sequence),
    operation_id TEXT NOT NULL,
    execution_authorization_sequence INTEGER NOT NULL,
    worker_principal_id TEXT NOT NULL CHECK (length(trim(worker_principal_id)) > 0),
    worker_id TEXT NOT NULL CHECK (length(trim(worker_id)) > 0),
    worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
    claim_event_sequence INTEGER NOT NULL UNIQUE REFERENCES request_events(sequence),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes) > 0),
    UNIQUE (operation_id, worker_generation),
    UNIQUE (operation_id, assignment_sequence),
    FOREIGN KEY (operation_id, execution_authorization_sequence)
        REFERENCES execution_authorizations(operation_id, authorization_sequence)
) STRICT;

-- Avoid cyclic hashes: this companion is hashed AFTER the existing outbox and
-- COMMITTED event are computed. Its bytes include both of their hashes plus the
-- exact authorization decision and policy prefix. Existing codecs stay intact.
CREATE TABLE release_authorizations (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    operation_id TEXT NOT NULL UNIQUE,
    release_id TEXT NOT NULL UNIQUE REFERENCES outbox(release_id),
    terminal_event_sequence INTEGER NOT NULL UNIQUE REFERENCES request_events(sequence),
    assignment_sequence INTEGER NOT NULL,
    policy_sequence INTEGER NOT NULL REFERENCES authorization_events(sequence),
    candidate_hash TEXT NOT NULL CHECK (length(candidate_hash) = 64),
    previous_entry_hash TEXT NOT NULL CHECK (length(previous_entry_hash) = 64),
    entry_hash TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64),
    receipt_bytes BLOB NOT NULL CHECK (length(receipt_bytes) > 0),
    FOREIGN KEY (operation_id, release_id) REFERENCES request_intents(operation_id, release_id),
    FOREIGN KEY (operation_id, assignment_sequence)
        REFERENCES execution_assignments(operation_id, assignment_sequence)
) STRICT;

CREATE TABLE release_authorization_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    codec_version INTEGER NOT NULL CHECK (codec_version = 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    head_hash TEXT NOT NULL CHECK (length(head_hash) = 64)
) STRICT;
INSERT INTO release_authorization_state VALUES (1, 1, 0, printf('%064d', 0));

-- Immutable migration boundary distinguishes old unauthenticated history from
-- future protected operations. Runner fills and validates this inside the lock.
CREATE TABLE authorization_migration_boundary (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    legacy_journal_sequence INTEGER NOT NULL CHECK (legacy_journal_sequence >= 0),
    legacy_journal_hash TEXT NOT NULL CHECK (length(legacy_journal_hash) = 64),
    legacy_release_sequence INTEGER NOT NULL CHECK (legacy_release_sequence >= 0),
    legacy_release_hash TEXT NOT NULL CHECK (length(legacy_release_hash) = 64)
) STRICT;
INSERT INTO authorization_migration_boundary
    SELECT 1, j.sequence, j.head_hash, s.release_sequence, s.release_head_hash
    FROM journal_state AS j CROSS JOIN store_state AS s
    WHERE j.singleton = 1 AND s.singleton = 1;

CREATE TRIGGER authorization_events_no_update BEFORE UPDATE ON authorization_events
BEGIN SELECT RAISE(ABORT, 'immutable authorization history'); END;
CREATE TRIGGER authorization_events_no_delete BEFORE DELETE ON authorization_events
BEGIN SELECT RAISE(ABORT, 'immutable authorization history'); END;
CREATE TRIGGER execution_authorizations_no_update BEFORE UPDATE ON execution_authorizations
BEGIN SELECT RAISE(ABORT, 'immutable execution authorization'); END;
CREATE TRIGGER execution_authorizations_no_delete BEFORE DELETE ON execution_authorizations
BEGIN SELECT RAISE(ABORT, 'immutable execution authorization'); END;
CREATE TRIGGER execution_assignments_no_update BEFORE UPDATE ON execution_assignments
BEGIN SELECT RAISE(ABORT, 'immutable assignment'); END;
CREATE TRIGGER execution_assignments_no_delete BEFORE DELETE ON execution_assignments
BEGIN SELECT RAISE(ABORT, 'immutable assignment'); END;
CREATE TRIGGER release_authorizations_no_update BEFORE UPDATE ON release_authorizations
BEGIN SELECT RAISE(ABORT, 'immutable authorization receipt'); END;
CREATE TRIGGER release_authorizations_no_delete BEFORE DELETE ON release_authorizations
BEGIN SELECT RAISE(ABORT, 'immutable authorization receipt'); END;
CREATE TRIGGER authorization_state_no_delete BEFORE DELETE ON authorization_state
BEGIN SELECT RAISE(ABORT, 'authorization checkpoint required'); END;
CREATE TRIGGER release_authorization_state_no_delete BEFORE DELETE ON release_authorization_state
BEGIN SELECT RAISE(ABORT, 'authorization receipt checkpoint required'); END;
CREATE TRIGGER authorization_boundary_no_update BEFORE UPDATE ON authorization_migration_boundary
BEGIN SELECT RAISE(ABORT, 'immutable migration boundary'); END;
CREATE TRIGGER authorization_boundary_no_delete BEFORE DELETE ON authorization_migration_boundary
BEGIN SELECT RAISE(ABORT, 'immutable migration boundary'); END;

-- Initial migration is storage-only. A subsequent explicit schema version must
-- replace these guards together with the enforced transaction APIs and validator.
CREATE TRIGGER v3_intents_closed BEFORE INSERT ON request_intents
BEGIN SELECT RAISE(ABORT, 'authenticated journal writes not enabled'); END;
CREATE TRIGGER v3_preparation_closed BEFORE INSERT ON prepared_requests
BEGIN SELECT RAISE(ABORT, 'authenticated journal writes not enabled'); END;
CREATE TRIGGER v3_events_closed BEFORE INSERT ON request_events
BEGIN SELECT RAISE(ABORT, 'authenticated journal writes not enabled'); END;
CREATE TRIGGER v3_outbox_closed BEFORE INSERT ON outbox
BEGIN SELECT RAISE(ABORT, 'authenticated release writes not enabled'); END;

CREATE TRIGGER v3_authorization_events_closed BEFORE INSERT ON authorization_events
BEGIN SELECT RAISE(ABORT, 'authorization writes not enabled'); END;
CREATE TRIGGER v3_execution_authorizations_closed BEFORE INSERT ON execution_authorizations
BEGIN SELECT RAISE(ABORT, 'authorization writes not enabled'); END;
CREATE TRIGGER v3_execution_assignments_closed BEFORE INSERT ON execution_assignments
BEGIN SELECT RAISE(ABORT, 'authorization writes not enabled'); END;
CREATE TRIGGER v3_release_authorizations_closed BEFORE INSERT ON release_authorizations
BEGIN SELECT RAISE(ABORT, 'authorization writes not enabled'); END;

PRAGMA user_version = 3;
