"""Internal identity and authorization contracts, not a TLS/token verifier.

TrustedTransportEvidence must be built by a host transport adapter after actual
credential verification. Never deserialize it or VerifiedIdentity from a client.
Python models are not a boundary against hostile code inside the host process.
"""
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Callable, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AuthenticationError(Exception):
    """Generic public authentication failure; no enrollment details."""


class AuthorizationError(Exception):
    """Generic public authorization failure; no resource existence details."""


class Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def aware_times(self):
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, datetime):
                if value.utcoffset() is None:
                    raise ValueError("Authentication timestamps must be timezone-aware")
                object.__setattr__(self, name, value.astimezone(timezone.utc))
        return self


class Action(StrEnum):
    SUBMIT = "replay.submit"
    RECOVER_OWN = "replay.recover_own"
    APPEND_REVIEW = "review.append"
    EXECUTE_WORK = "worker.execute"
    MANAGE_HOST = "host.manage"


class CredentialEnrollment(Model):
    credential_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    principal_id: str = Field(min_length=1, pattern=r"\S")
    enabled: bool = Field(strict=True)
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def interval(self):
        if self.valid_from >= self.valid_until:
            raise ValueError("Invalid credential interval")
        return self


class TrustedTransportEvidence(Model):
    """Host-only attestation of a completed mTLS verification, never raw proof."""
    credential_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    method: Literal["mtls"] = "mtls"
    connection_id: str = Field(min_length=1, pattern=r"\S")
    verified_at: datetime
    credential_valid_from: datetime
    credential_valid_until: datetime


class VerifiedIdentity(Model):
    principal_id: str = Field(min_length=1, pattern=r"\S")
    credential_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    method: Literal["mtls"] = "mtls"
    connection_id: str = Field(min_length=1, pattern=r"\S")
    verified_at: datetime
    valid_until: datetime
    registry_revision: int = Field(strict=True, gt=0)
    audit_id: str = Field(min_length=1, pattern=r"\S")


class ResourceScope(Model):
    """Host-resolved resource coordinates; owner/assignment are not client claims."""
    corpus_id: str | None = Field(default=None, min_length=1, pattern=r"\S")
    document_id: str | None = Field(default=None, min_length=1, pattern=r"\S")
    version_id: str | None = Field(default=None, min_length=1, pattern=r"\S")
    operation_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,128}$")
    owner_principal_id: str | None = Field(default=None, min_length=1, pattern=r"\S")
    assignment_id: str | None = Field(default=None, min_length=1, pattern=r"\S")


class PermissionGrant(Model):
    principal_id: str = Field(min_length=1, pattern=r"\S")
    action: Action
    corpus_id: str | None = Field(default=None, min_length=1, pattern=r"\S")
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def scope_and_interval(self):
        if (self.action == Action.MANAGE_HOST) != (self.corpus_id is None):
            raise ValueError("Only host management has no corpus scope")
        if self.valid_from >= self.valid_until:
            raise ValueError("Invalid grant interval")
        return self


class WorkerAssignment(Model):
    assignment_id: str = Field(min_length=1, pattern=r"\S")
    worker_principal_id: str = Field(min_length=1, pattern=r"\S")
    resource: ResourceScope
    valid_until: datetime


class AuthorizationState(Model):
    """One coherent host snapshot. Increment revision on every state change."""
    revision: int = Field(strict=True, gt=0)
    credentials: tuple[CredentialEnrollment, ...] = ()
    grants: tuple[PermissionGrant, ...] = ()
    assignments: tuple[WorkerAssignment, ...] = ()

    @model_validator(mode="after")
    def unique_keys(self):
        for values in (
            [c.credential_id for c in self.credentials],
            [a.assignment_id for a in self.assignments],
        ):
            if len(values) != len(set(values)):
                raise ValueError("Ambiguous host registry")
        return self


class AuthorizedAction(Model):
    identity: VerifiedIdentity
    action: Action
    resource: ResourceScope
    policy_revision: int
    authorized_at: datetime
    valid_until: datetime


class CredentialVerifier(Protocol):
    def verify(self, transport_evidence: TrustedTransportEvidence) -> VerifiedIdentity: ...


class Authorizer(Protocol):
    def authorize(self, identity: VerifiedIdentity, action: Action,
                  resource: ResourceScope) -> AuthorizedAction: ...


class AuthorizationStateReader(Protocol):
    def read(self) -> AuthorizationState: ...


def _now(clock):
    value = clock()
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("Invalid host clock")
    return value.astimezone(timezone.utc)


def _validated(value, cls):
    if type(value) is not cls:
        raise ValueError("Internal typed value required")
    # Also reject malformed model_copy/model_construct objects, including children.
    return cls.model_validate(value.model_dump())


def _credential(state, credential_id, now):
    matches = [c for c in state.credentials if c.credential_id == credential_id]
    if len(matches) != 1:
        raise ValueError("Credential unavailable")
    credential = matches[0]
    if not credential.enabled or not credential.valid_from <= now < credential.valid_until:
        raise ValueError("Credential unavailable")
    return credential


class RegistryCredentialVerifier:
    """Map *already verified* transport evidence to current host enrollment.

    Does not validate TLS, certificate chains, signatures, or JWTs. A real adapter
    must supply fresh evidence for each request, including reused connections.
    """
    def __init__(self, state_reader: AuthorizationStateReader, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 identity_lifetime: timedelta = timedelta(minutes=5)):
        if not timedelta(0) < identity_lifetime <= timedelta(minutes=5):
            raise ValueError("Identity lifetime must be positive and at most five minutes")
        self._reader = state_reader
        self._clock = clock
        self._lifetime = identity_lifetime

    def verify(self, transport_evidence: TrustedTransportEvidence) -> VerifiedIdentity:
        try:
            evidence = _validated(transport_evidence, TrustedTransportEvidence)
            now = _now(self._clock)
            state = _validated(self._reader.read(), AuthorizationState)
            credential = _credential(state, evidence.credential_id, now)
            if not (evidence.credential_valid_from <= evidence.verified_at <= now
                    < evidence.credential_valid_until
                    and now < evidence.verified_at + self._lifetime):
                raise ValueError("Invalid transport attestation interval")
            return VerifiedIdentity(
                principal_id=credential.principal_id, credential_id=credential.credential_id,
                connection_id=evidence.connection_id, verified_at=evidence.verified_at,
                valid_until=min(credential.valid_until, evidence.credential_valid_until,
                                evidence.verified_at + self._lifetime),
                registry_revision=state.revision, audit_id=str(uuid4()))
        except Exception:
            raise AuthenticationError("Authentication failed") from None


class PolicyAuthorizer:
    """Current, default-deny action checks; no journal access or context minting.

    Decisions are bounded snapshots, not durable authority. Final release still
    needs transactional coordination with authorization revocation in a later step.
    """
    def __init__(self, state_reader: AuthorizationStateReader, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._reader = state_reader
        self._clock = clock

    def authorize(self, identity: VerifiedIdentity, action: Action,
                  resource: ResourceScope) -> AuthorizedAction:
        try:
            identity = _validated(identity, VerifiedIdentity)
            resource = _validated(resource, ResourceScope)
            if type(action) is not Action:
                raise ValueError("Unknown action")
            now = _now(self._clock)
            state = _validated(self._reader.read(), AuthorizationState)
            credential = _credential(state, identity.credential_id, now)
            if (identity.registry_revision != state.revision
                    or credential.principal_id != identity.principal_id
                    or not identity.verified_at <= now < identity.valid_until
                    or identity.valid_until > identity.verified_at + timedelta(minutes=5)
                    or identity.valid_until > credential.valid_until):
                raise ValueError("Stale or mismatched identity")
            fields = {k for k, v in resource.model_dump().items() if v is not None}
            version_fields = {"corpus_id", "document_id", "version_id"}
            required = {
                Action.SUBMIT: version_fields,
                Action.APPEND_REVIEW: version_fields,
                Action.RECOVER_OWN: {"corpus_id", "operation_id", "owner_principal_id"},
                Action.EXECUTE_WORK: version_fields | {"operation_id", "owner_principal_id", "assignment_id"},
                Action.MANAGE_HOST: set(),
            }[action]
            if fields != required:
                raise ValueError("Invalid resource scope")
            if action == Action.RECOVER_OWN and resource.owner_principal_id != identity.principal_id:
                raise ValueError("Resource unavailable")
            expiry = min(identity.valid_until, credential.valid_until)
            if action == Action.EXECUTE_WORK:
                assignments = [a for a in state.assignments if a.assignment_id == resource.assignment_id]
                if (len(assignments) != 1 or assignments[0].worker_principal_id != identity.principal_id
                        or assignments[0].resource != resource or now >= assignments[0].valid_until):
                    raise ValueError("Assignment unavailable")
                expiry = min(expiry, assignments[0].valid_until)
            grants = [g for g in state.grants if g.principal_id == identity.principal_id
                      and g.action == action and g.corpus_id == resource.corpus_id
                      and g.valid_from <= now < g.valid_until]
            if not grants:
                raise ValueError("Permission unavailable")
            return AuthorizedAction(identity=identity, action=action, resource=resource,
                                    policy_revision=state.revision, authorized_at=now,
                                    valid_until=min(expiry, max(g.valid_until for g in grants)))
        except Exception:
            raise AuthorizationError("Access denied") from None
