"""Synthetic attestations exercise policy contracts, not TLS authentication."""
from datetime import datetime, timedelta, timezone
from itertools import product

import pytest
from pydantic import ValidationError

from tnc.provenance.host_auth import (
    Action, AuthenticationError, AuthorizationError, AuthorizationState,
    CredentialEnrollment, PermissionGrant, PolicyAuthorizer,
    RegistryCredentialVerifier, ResourceScope, TrustedTransportEvidence,
    WorkerAssignment,
)


NOW = datetime(2026, 9, 11, 12, tzinfo=timezone.utc)
BEFORE = NOW - timedelta(hours=1)
AFTER = NOW + timedelta(hours=1)
FINGERPRINT = "a" * 64
VERSION = ResourceScope(corpus_id="corpus", document_id="doc", version_id="v1")
RECOVERY = ResourceScope(corpus_id="corpus", operation_id="op", owner_principal_id="alice")
WORK = ResourceScope(**VERSION.model_dump(exclude_none=True), operation_id="op",
                     owner_principal_id="owner", assignment_id="job")


class MemoryReader:
    def __init__(self, state):
        self.state = state

    def read(self):
        return self.state


def setup(action=Action.SUBMIT):
    enrollment = CredentialEnrollment(credential_id=FINGERPRINT, principal_id="alice",
                                      enabled=True, valid_from=BEFORE, valid_until=AFTER)
    grant = PermissionGrant(principal_id="alice", action=action,
                            corpus_id=None if action == Action.MANAGE_HOST else "corpus",
                            valid_from=BEFORE, valid_until=AFTER)
    assignment = WorkerAssignment(assignment_id="job", worker_principal_id="alice",
                                  resource=WORK, valid_until=AFTER)
    reader = MemoryReader(AuthorizationState(revision=1, credentials=(enrollment,),
                                            grants=(grant,), assignments=(assignment,)))
    evidence = TrustedTransportEvidence(credential_id=FINGERPRINT, connection_id="connection",
                                        verified_at=NOW, credential_valid_from=BEFORE,
                                        credential_valid_until=AFTER)
    verifier = RegistryCredentialVerifier(reader, clock=lambda: NOW)
    authorizer = PolicyAuthorizer(reader, clock=lambda: NOW)
    return reader, evidence, verifier, authorizer


def scope(action):
    return {Action.SUBMIT: VERSION, Action.APPEND_REVIEW: VERSION,
            Action.RECOVER_OWN: RECOVERY, Action.EXECUTE_WORK: WORK,
            Action.MANAGE_HOST: ResourceScope()}[action]


@pytest.mark.parametrize("granted,requested", tuple(product(Action, Action)))
def test_independent_role_matrix(granted, requested):
    reader, evidence, verifier, authorizer = setup(granted)
    identity = verifier.verify(evidence)
    if granted == requested:
        result = authorizer.authorize(identity, requested, scope(requested))
        assert result.identity.principal_id == "alice"
        assert result.resource == scope(requested)
        assert result.valid_until == NOW + timedelta(minutes=5)
    else:
        with pytest.raises(AuthorizationError, match="^Access denied$"):
            authorizer.authorize(identity, requested, scope(requested))


@pytest.mark.parametrize("change", [
    {"credential_id": "b" * 64},
    {"verified_at": NOW + timedelta(microseconds=1)},
    {"verified_at": NOW - timedelta(minutes=5)},
    {"credential_valid_until": NOW},
    {"credential_valid_from": NOW + timedelta(microseconds=1)},
    {"verified_at": NOW.replace(tzinfo=None)},
    {"method": "jwt"},
])
def test_invalid_or_stale_attestation(change):
    _, evidence, verifier, _ = setup()
    with pytest.raises(AuthenticationError, match="^Authentication failed$"):
        verifier.verify(evidence.model_copy(update=change))


@pytest.mark.parametrize("change", [
    {"enabled": False}, {"valid_until": NOW},
    {"valid_from": NOW + timedelta(microseconds=1)},
])
def test_current_enrollment_required(change):
    reader, evidence, verifier, _ = setup()
    credential = reader.state.credentials[0].model_copy(update=change)
    reader.state = reader.state.model_copy(update={"credentials": (credential,)})
    with pytest.raises(AuthenticationError):
        verifier.verify(evidence)


def test_raw_headers_and_identity_dictionaries_are_not_internal_evidence():
    _, evidence, verifier, authorizer = setup()
    for value in (None, evidence.model_dump(), {"X-User": "alice", "roles": ["admin"]}):
        with pytest.raises(AuthenticationError):
            verifier.verify(value)
    with pytest.raises(AuthorizationError):
        authorizer.authorize(verifier.verify(evidence).model_dump(), Action.SUBMIT, VERSION)


def test_rotation_keeps_principal_but_disabled_old_credential_cannot_reconnect():
    reader, evidence, verifier, authorizer = setup()
    old_identity = verifier.verify(evidence)
    old = reader.state.credentials[0]
    reader.state = reader.state.model_copy(update={"revision": 2, "credentials": (
        old.model_copy(update={"enabled": False}), old.model_copy(update={"credential_id": "b" * 64}))})
    with pytest.raises(AuthenticationError):
        verifier.verify(evidence)
    with pytest.raises(AuthorizationError):
        authorizer.authorize(old_identity, Action.SUBMIT, VERSION)
    new_identity = verifier.verify(evidence.model_copy(update={"credential_id": "b" * 64}))
    assert new_identity.principal_id == old_identity.principal_id
    authorizer.authorize(new_identity, Action.SUBMIT, VERSION)


def test_policy_change_requires_fresh_identity_and_current_grant():
    reader, evidence, verifier, authorizer = setup()
    identity = verifier.verify(evidence)
    reader.state = reader.state.model_copy(update={"revision": 2, "grants": ()})
    for value in (identity, verifier.verify(evidence)):
        with pytest.raises(AuthorizationError):
            authorizer.authorize(value, Action.SUBMIT, VERSION)


@pytest.mark.parametrize("resource", [
    VERSION.model_copy(update={"corpus_id": "other"}),
    VERSION.model_copy(update={"version_id": None}),
    VERSION.model_copy(update={"operation_id": "extra"}),
    ResourceScope(),
])
def test_wrong_or_incomplete_resource(resource):
    _, evidence, verifier, authorizer = setup()
    with pytest.raises(AuthorizationError):
        authorizer.authorize(verifier.verify(evidence), Action.SUBMIT, resource)


def test_cross_principal_recovery_generic_deny():
    _, evidence, verifier, authorizer = setup(Action.RECOVER_OWN)
    with pytest.raises(AuthorizationError, match="^Access denied$"):
        authorizer.authorize(verifier.verify(evidence), Action.RECOVER_OWN,
                             RECOVERY.model_copy(update={"owner_principal_id": "bob"}))


@pytest.mark.parametrize("change", [
    {"worker_principal_id": "other"}, {"valid_until": NOW},
    {"resource": WORK.model_copy(update={"operation_id": "other"})},
    {"resource": WORK.model_copy(update={"owner_principal_id": "other"})},
])
def test_worker_permission_does_not_replace_assignment(change):
    reader, evidence, verifier, authorizer = setup(Action.EXECUTE_WORK)
    reader.state = reader.state.model_copy(update={"assignments": (
        reader.state.assignments[0].model_copy(update=change),)})
    with pytest.raises(AuthorizationError):
        authorizer.authorize(verifier.verify(evidence), Action.EXECUTE_WORK, WORK)


@pytest.mark.parametrize("part", ["credentials", "assignments"])
def test_duplicate_registry_entries_fail_closed(part):
    reader, evidence, verifier, _ = setup()
    entries = getattr(reader.state, part)
    reader.state = reader.state.model_copy(update={part: entries + entries})
    with pytest.raises(AuthenticationError):
        verifier.verify(evidence)


def test_unavailable_state_sanitized_at_both_boundaries():
    reader, evidence, verifier, authorizer = setup()
    identity = verifier.verify(evidence)
    def unavailable():
        raise OSError("SECRET filesystem path")
    reader.read = unavailable
    with pytest.raises(AuthenticationError, match="^Authentication failed$"):
        verifier.verify(evidence)
    with pytest.raises(AuthorizationError, match="^Access denied$"):
        authorizer.authorize(identity, Action.SUBMIT, VERSION)


def test_historical_query_time_cannot_extend_authentication():
    reader, evidence, verifier, _ = setup()
    identity = verifier.verify(evidence)
    expired = PolicyAuthorizer(reader, clock=lambda: NOW + timedelta(minutes=5))
    with pytest.raises(AuthorizationError):
        expired.authorize(identity, Action.SUBMIT, VERSION)
    with pytest.raises(ValidationError):
        ResourceScope(**VERSION.model_dump(), query_time="2013-05-21T12:00:16Z")


def test_expiration_is_bounded_by_shortest_permission_or_assignment():
    reader, evidence, verifier, authorizer = setup(Action.EXECUTE_WORK)
    limit = NOW + timedelta(seconds=20)
    reader.state = reader.state.model_copy(update={"assignments": (
        reader.state.assignments[0].model_copy(update={"valid_until": limit}),)})
    assert authorizer.authorize(verifier.verify(evidence), Action.EXECUTE_WORK, WORK).valid_until == limit
    reader.state = reader.state.model_copy(update={"grants": (
        reader.state.grants[0].model_copy(update={"valid_until": NOW + timedelta(seconds=10)}),)})
    assert authorizer.authorize(verifier.verify(evidence), Action.EXECUTE_WORK, WORK).valid_until == NOW + timedelta(seconds=10)


@pytest.mark.parametrize("change", [
    {"principal_id": "bob"}, {"registry_revision": 2},
    {"valid_until": AFTER}, {"verified_at": NOW + timedelta(seconds=1)},
])
def test_identity_binding_and_lifetime(change):
    _, evidence, verifier, authorizer = setup()
    identity = verifier.verify(evidence).model_copy(update=change)
    with pytest.raises(AuthorizationError):
        authorizer.authorize(identity, Action.SUBMIT, VERSION)


def test_utc_normalization_audit_ids_and_immutable_results():
    _, evidence, verifier, authorizer = setup()
    eastern = timezone(timedelta(hours=-4))
    evidence = TrustedTransportEvidence(**(evidence.model_dump() | {"verified_at": NOW.astimezone(eastern)}))
    identity = verifier.verify(evidence)
    assert identity.verified_at == NOW and identity.verified_at.tzinfo == timezone.utc
    assert identity.audit_id != verifier.verify(evidence).audit_id
    decision = authorizer.authorize(identity, Action.SUBMIT, VERSION)
    with pytest.raises(ValidationError):
        decision.action = Action.MANAGE_HOST


@pytest.mark.parametrize("clock", [lambda: NOW.replace(tzinfo=None), lambda: None])
def test_invalid_host_clock(clock):
    reader, evidence, verifier, _ = setup()
    identity = verifier.verify(evidence)
    with pytest.raises(AuthenticationError):
        RegistryCredentialVerifier(reader, clock=clock).verify(evidence)
    with pytest.raises(AuthorizationError):
        PolicyAuthorizer(reader, clock=clock).authorize(identity, Action.SUBMIT, VERSION)


def test_default_deny_unknown_action_and_empty_policy():
    reader, evidence, verifier, authorizer = setup()
    identity = verifier.verify(evidence)
    with pytest.raises(AuthorizationError):
        authorizer.authorize(identity, "replay.submit", VERSION)
    reader.state = reader.state.model_copy(update={"grants": ()})
    with pytest.raises(AuthorizationError):
        authorizer.authorize(identity, Action.SUBMIT, VERSION)


@pytest.mark.parametrize("change", [{"valid_from": NOW + timedelta(seconds=1)}, {"valid_until": NOW}])
def test_grant_time_boundaries(change):
    reader, evidence, verifier, authorizer = setup()
    reader.state = reader.state.model_copy(update={"grants": (
        reader.state.grants[0].model_copy(update=change),)})
    with pytest.raises(AuthorizationError):
        authorizer.authorize(verifier.verify(evidence), Action.SUBMIT, VERSION)


def test_missing_worker_assignment_blocks_even_with_permission():
    reader, evidence, verifier, authorizer = setup(Action.EXECUTE_WORK)
    reader.state = reader.state.model_copy(update={"assignments": ()})
    with pytest.raises(AuthorizationError):
        authorizer.authorize(verifier.verify(evidence), Action.EXECUTE_WORK, WORK)


def test_valid_from_is_inclusive_and_credential_expiry_caps_identity():
    reader, evidence, verifier, authorizer = setup()
    limit = NOW + timedelta(seconds=30)
    reader.state = reader.state.model_copy(update={"credentials": (
        reader.state.credentials[0].model_copy(update={"valid_from": NOW, "valid_until": limit}),),
        "grants": (reader.state.grants[0].model_copy(update={"valid_from": NOW}),)})
    identity = verifier.verify(evidence)
    assert identity.valid_until == limit
    assert authorizer.authorize(identity, Action.SUBMIT, VERSION).valid_until == limit
