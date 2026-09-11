"""Pure administration-only record contracts. No storage or identity verification."""
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Annotated, Literal, TypeVar

from pydantic import Field, model_validator

from tnc.provenance.host_auth import Model as HostModel, Action, CredentialEnrollment, PermissionGrant


ZERO = "0" * 64
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")]
Positive = Annotated[int, Field(strict=True, gt=0)]
Nonnegative = Annotated[int, Field(strict=True, ge=0)]


class Model(HostModel):
    @model_validator(mode="before")
    @classmethod
    def strict_versions(cls, value):
        if isinstance(value, dict):
            for name in ("codec_version", "source_schema_version"):
                if name in value and type(value[name]) is not int:
                    raise ValueError("Version must be an exact integer")
        return value


class CredentialEnrolled(Model):
    kind: Literal["CREDENTIAL_ENROLLED"] = "CREDENTIAL_ENROLLED"
    credential: CredentialEnrollment
    enrollment_evidence_hash: Digest

    @model_validator(mode="after")
    def initially_enabled(self):
        if not self.credential.enabled:
            raise ValueError("Enrollment must begin enabled")
        return self


class CredentialDisabled(Model):
    kind: Literal["CREDENTIAL_DISABLED"] = "CREDENTIAL_DISABLED"
    credential_id: Digest
    expected_enrollment_sequence: Positive
    rationale: str = Field(min_length=1, pattern=r"\S")


class PermissionGranted(Model):
    kind: Literal["PERMISSION_GRANTED"] = "PERMISSION_GRANTED"
    grant_id: Identifier
    permission: PermissionGrant


class PermissionRevoked(Model):
    kind: Literal["PERMISSION_REVOKED"] = "PERMISSION_REVOKED"
    grant_id: Identifier
    expected_grant_sequence: Positive
    rationale: str = Field(min_length=1, pattern=r"\S")


AdminPayload = Annotated[
    CredentialEnrolled | CredentialDisabled | PermissionGranted | PermissionRevoked,
    Field(discriminator="kind"),
]


class BootstrapManifest(Model):
    codec_version: Literal[1] = 1
    request_id: Identifier
    deployment_id: Identifier
    service_identity: Identifier
    source_schema_version: Literal[3] = 3
    legacy_journal_sequence: Nonnegative
    legacy_journal_hash: Digest
    legacy_release_sequence: Nonnegative
    legacy_release_hash: Digest
    trust_configuration_hash: Digest
    admin_policy_hash: Digest
    valid_from: datetime
    valid_until: datetime
    initial_enrollment: CredentialEnrolled
    initial_grant: PermissionGranted

    @model_validator(mode="after")
    def seed_contract(self):
        credential = self.initial_enrollment.credential
        grant = self.initial_grant.permission
        if (self.valid_from >= self.valid_until or grant.action != Action.MANAGE_HOST
                or grant.principal_id != credential.principal_id):
            raise ValueError("Invalid bootstrap manifest")
        for sequence, digest in ((self.legacy_journal_sequence, self.legacy_journal_hash),
                                 (self.legacy_release_sequence, self.legacy_release_hash)):
            if (sequence == 0) != (digest == ZERO):
                raise ValueError("Invalid legacy checkpoint")
        return self


class ProvisioningActor(Model):
    kind: Literal["provisioning"] = "provisioning"
    operator_id: Identifier
    session_id: Identifier
    manifest_hash: Digest


class AdministrativeActor(Model):
    """Recorded host-verified session facts, not cryptographic proof by themselves."""
    kind: Literal["administrative"] = "administrative"
    principal_id: Identifier
    credential_id: Digest
    verified_at: datetime
    valid_until: datetime
    registry_revision: Positive
    permission_grant_id: Identifier
    audit_id: Identifier


Actor = Annotated[ProvisioningActor | AdministrativeActor, Field(discriminator="kind")]


class AuthorizationEvent(Model):
    codec_version: Literal[1] = 1
    sequence: Positive
    event_id: Identifier
    actor: Actor
    expected_head_sequence: Nonnegative
    expected_head_hash: Digest
    recorded_at: datetime
    payload: AdminPayload
    previous_entry_hash: Digest
    entry_hash: Digest


class BootstrapReceipt(Model):
    codec_version: Literal[1] = 1
    manifest_hash: Digest
    deployment_id: Identifier
    operator_id: Identifier
    provisioning_session_id: Identifier
    provisioned_at: datetime
    first_event_hash: Digest
    second_event_hash: Digest
    receipt_hash: Digest


class BootstrapRecord(Model):
    manifest: BootstrapManifest
    receipt: BootstrapReceipt


class BootstrapTrustAnchor(Model):
    """Independent protected-host input; never inferred from ledger contents.

    Verifies binding to a host-approved manifest/session, not OS identity, TLS
    signatures or the manifest's real source database. Those are adapter duties.
    """
    deployment_id: Identifier
    manifest_hash: Digest
    operator_id: Identifier
    provisioning_session_id: Identifier
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def interval(self):
        if self.valid_from >= self.valid_until:
            raise ValueError("Invalid provisioning interval")
        return self


class AuthorizationCheckpoint(Model):
    sequence: Nonnegative
    head_hash: Digest


class ValidatedCredential(Model):
    enrollment_sequence: Positive
    credential: CredentialEnrollment


class ValidatedGrant(Model):
    grant_sequence: Positive
    grant_id: Identifier
    permission: PermissionGrant
    revoked: bool = Field(strict=True)


class ValidatedAuthorizationLedger(Model):
    checkpoint: AuthorizationCheckpoint
    credentials: tuple[ValidatedCredential, ...]
    grants: tuple[ValidatedGrant, ...]


T = TypeVar("T", bound=Model)


def canonical_bytes(record: Model) -> bytes:
    """Exact canonical representation; revalidate constructed/copied children."""
    if not isinstance(record, Model):
        raise ValueError("Typed record required")
    record = type(record).model_validate(record.model_dump())

    def normalize(value):
        if isinstance(value, datetime):
            if value.utcoffset() is None:
                raise ValueError("Aware timestamp required")
            return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [normalize(item) for item in value]
        return value

    return json.dumps(normalize(record.model_dump()), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def decode_canonical(kind: type[T], data: bytes) -> T:
    if type(data) is not bytes:
        raise ValueError("Exact bytes required")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("Non-finite JSON number")

    value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)
    record = kind.model_validate(value)
    if canonical_bytes(record) != data:
        raise ValueError("Noncanonical record")
    return record


def record_digest(record: Model) -> str:
    return sha256(canonical_bytes(record)).hexdigest()


def event_digest(event: AuthorizationEvent) -> str:
    return record_digest(event.model_copy(update={"entry_hash": ZERO}))


def bootstrap_receipt_digest(receipt: BootstrapReceipt) -> str:
    return record_digest(receipt.model_copy(update={"receipt_hash": ZERO}))
