-- Administration-only activation: runner owns BEGIN IMMEDIATE and seed insertion.
-- Requires exactly validated, empty-authority v3. Never execute independently.
-- The runner inserts bootstrap + both seed events, validates and commits atomically.

CREATE TABLE administration_bootstrap (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    deployment_id TEXT NOT NULL UNIQUE CHECK (length(trim(deployment_id)) > 0),
    manifest_hash TEXT NOT NULL CHECK (length(manifest_hash) = 64),
    receipt_hash TEXT NOT NULL CHECK (length(receipt_hash) = 64),
    record_bytes BLOB NOT NULL CHECK (length(record_bytes) > 0)
) STRICT;

CREATE TRIGGER administration_bootstrap_no_update BEFORE UPDATE ON administration_bootstrap
BEGIN SELECT RAISE(ABORT, 'bootstrap is immutable'); END;
CREATE TRIGGER administration_bootstrap_no_delete BEFORE DELETE ON administration_bootstrap
BEGIN SELECT RAISE(ABORT, 'bootstrap is immutable'); END;

-- Remove only the administrative-event insert guard. All seven execution-related
-- guards, all existing immutable-history triggers and old table codecs remain.
DROP TRIGGER v3_authorization_events_closed;

CREATE TRIGGER v4_administrative_kinds_only BEFORE INSERT ON authorization_events
WHEN NEW.kind NOT IN ('CREDENTIAL_ENROLLED', 'CREDENTIAL_DISABLED',
                     'PERMISSION_GRANTED', 'PERMISSION_REVOKED')
BEGIN SELECT RAISE(ABORT, 'execution authorization is not enabled'); END;

-- These SQL constraints are structural only; they do not authenticate the actor.
-- A valid v4 target MUST contain exactly one validated bootstrap record, exactly
-- the bound two-event seed prefix, and a valid canonical authorization ledger.
-- Empty v4 after these statements is an intermediate state, never a valid target.
PRAGMA user_version = 4;
