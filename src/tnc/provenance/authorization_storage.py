"""Transaction-local v4 canonical history/projection validation. No connections opened."""
from tnc.provenance.authorization_models import (
    AuthorizationEvent, AuthorizationCheckpoint, BootstrapRecord, CredentialEnrolled,
    CredentialDisabled, PermissionGranted, canonical_bytes, decode_canonical,
)
from tnc.provenance.authorization_validator import validate_authorization_ledger


def event_values(event, credentials, grants):
    payload = event.payload
    if isinstance(payload, CredentialEnrolled):
        principal = payload.credential.principal_id
    elif isinstance(payload, CredentialDisabled):
        principal = credentials[payload.credential_id]
    elif isinstance(payload, PermissionGranted):
        principal = payload.permission.principal_id
    else:
        principal = grants[payload.grant_id]
    actor = event.actor
    actor_id = actor.operator_id if actor.kind == 'provisioning' else actor.principal_id
    return (event.sequence, event.event_id, payload.kind, principal, actor_id,
            event.previous_entry_hash, event.entry_hash, canonical_bytes(event))


def projection_maps(events):
    credentials, grants = {}, {}
    for event in events:
        payload = event.payload
        if isinstance(payload, CredentialEnrolled):
            credentials[payload.credential.credential_id] = payload.credential.principal_id
        elif isinstance(payload, PermissionGranted):
            grants[payload.grant_id] = payload.permission.principal_id
    return credentials, grants


def read_administration(connection, anchor):
    if connection.execute('PRAGMA user_version').fetchone() != (4,):
        raise ValueError('Administration schema required')
    rows = connection.execute('SELECT * FROM administration_bootstrap').fetchall()
    if len(rows) != 1:
        raise ValueError('Bootstrap required')
    row = rows[0]
    bootstrap = decode_canonical(BootstrapRecord, row[4])
    if row != (1, bootstrap.manifest.deployment_id, bootstrap.receipt.manifest_hash,
               bootstrap.receipt.receipt_hash, canonical_bytes(bootstrap)):
        raise ValueError('Invalid bootstrap projection')
    boundary = connection.execute('SELECT * FROM authorization_migration_boundary').fetchall()
    manifest = bootstrap.manifest
    if boundary != [(1, manifest.legacy_journal_sequence, manifest.legacy_journal_hash,
                     manifest.legacy_release_sequence, manifest.legacy_release_hash)]:
        raise ValueError('Manifest boundary mismatch')
    checkpoint_rows = connection.execute('SELECT * FROM authorization_state').fetchall()
    if len(checkpoint_rows) != 1 or checkpoint_rows[0][:2] != (1, 1):
        raise ValueError('Invalid authorization checkpoint')
    checkpoint = AuthorizationCheckpoint(sequence=checkpoint_rows[0][2], head_hash=checkpoint_rows[0][3])
    event_rows = connection.execute('SELECT * FROM authorization_events ORDER BY sequence').fetchall()
    events = tuple(decode_canonical(AuthorizationEvent, row[7]) for row in event_rows)
    state = validate_authorization_ledger(events=events, bootstrap=bootstrap,
                                          trust_anchor=anchor, checkpoint=checkpoint)
    credentials, grants = {}, {}
    for row, event in zip(event_rows, events):
        if row != event_values(event, credentials, grants):
            raise ValueError('Invalid event projection')
        if isinstance(event.payload, CredentialEnrolled):
            credentials[event.payload.credential.credential_id] = event.payload.credential.principal_id
        elif isinstance(event.payload, PermissionGranted):
            grants[event.payload.grant_id] = event.payload.permission.principal_id
    return bootstrap, events, state
