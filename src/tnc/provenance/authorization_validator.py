"""Pure historical administration-ledger validation; no I/O or current clock."""
from datetime import timedelta

from tnc.provenance.host_auth import Action
from tnc.provenance.authorization_models import (
    ZERO, AdministrativeActor, AuthorizationCheckpoint, AuthorizationEvent,
    BootstrapRecord, BootstrapTrustAnchor, CredentialDisabled, CredentialEnrolled,
    PermissionGranted, PermissionRevoked, ProvisioningActor, ValidatedCredential,
    ValidatedGrant, ValidatedAuthorizationLedger, canonical_bytes, decode_canonical,
    record_digest, event_digest, bootstrap_receipt_digest,
)


class AuthorizationValidationError(ValueError):
    """The supplied ledger cannot be used as authority."""


def _require(condition):
    if not condition:
        raise AuthorizationValidationError("Invalid authorization ledger")


def _copy(value, kind):
    _require(type(value) is kind)
    return decode_canonical(kind, canonical_bytes(value))


def _active(credential, at):
    return credential.enabled and credential.valid_from <= at < credential.valid_until


def validate_authorization_ledger(*, events: tuple[AuthorizationEvent, ...],
                                  bootstrap: BootstrapRecord,
                                  trust_anchor: BootstrapTrustAnchor,
                                  checkpoint: AuthorizationCheckpoint) -> ValidatedAuthorizationLedger:
    """Replay in sequence order and validate each actor against its prior prefix.

    Bootstrap anchor and checkpoint must come from trusted host state. Hashes do
    not authenticate their source or protect against wholesale database rollback.
    An empty v3 store is not a valid bootstrapped administrative ledger.
    """
    try:
        _require(type(events) is tuple and len(events) >= 2)
        events = tuple(_copy(event, AuthorizationEvent) for event in events)
        bootstrap = _copy(bootstrap, BootstrapRecord)
        anchor = _copy(trust_anchor, BootstrapTrustAnchor)
        checkpoint = _copy(checkpoint, AuthorizationCheckpoint)
        manifest, receipt = bootstrap.manifest, bootstrap.receipt
        manifest_hash = record_digest(manifest)
        _require(manifest_hash == receipt.manifest_hash == anchor.manifest_hash)
        _require(manifest.deployment_id == receipt.deployment_id == anchor.deployment_id)
        _require(receipt.operator_id == anchor.operator_id)
        _require(receipt.provisioning_session_id == anchor.provisioning_session_id)
        _require(anchor.valid_from <= receipt.provisioned_at < anchor.valid_until)
        _require(manifest.valid_from <= receipt.provisioned_at < manifest.valid_until)
        _require(receipt.receipt_hash == bootstrap_receipt_digest(receipt))
        _require((receipt.first_event_hash, receipt.second_event_hash) ==
                 (events[0].entry_hash, events[1].entry_hash))
        _require(checkpoint.sequence == len(events) and checkpoint.head_hash == events[-1].entry_hash)

        credentials, grants, event_ids = {}, {}, set()
        previous_hash, previous_time = ZERO, None
        for sequence, event in enumerate(events, start=1):
            at = event.recorded_at
            _require(event.sequence == sequence and event.event_id not in event_ids)
            _require(event.expected_head_sequence == sequence - 1)
            _require(event.expected_head_hash == event.previous_entry_hash == previous_hash)
            _require(event.entry_hash == event_digest(event))
            _require(previous_time is None or at >= previous_time)
            if sequence <= 2:
                actor = event.actor
                _require(type(actor) is ProvisioningActor)
                _require((actor.operator_id, actor.session_id, actor.manifest_hash) ==
                         (anchor.operator_id, anchor.provisioning_session_id, manifest_hash))
                _require(at == receipt.provisioned_at)
                _require(event.payload == (manifest.initial_enrollment if sequence == 1 else manifest.initial_grant))
                _require(_active(manifest.initial_enrollment.credential, at))
                permission = manifest.initial_grant.permission
                _require(permission.valid_from <= at < permission.valid_until)
            else:
                actor = event.actor
                _require(type(actor) is AdministrativeActor)
                _require(actor.registry_revision == sequence - 1)
                entry = credentials.get(actor.credential_id)
                _require(entry is not None)
                credential = entry.credential
                _require(credential.principal_id == actor.principal_id and _active(credential, at))
                _require(credential.valid_from <= actor.verified_at <= at < actor.valid_until)
                _require(actor.valid_until <= credential.valid_until)
                _require(actor.valid_until <= actor.verified_at + timedelta(minutes=5))
                grant = grants.get(actor.permission_grant_id)
                _require(grant is not None and not grant.revoked)
                permission = grant.permission
                _require(permission.principal_id == actor.principal_id)
                _require(permission.action == Action.MANAGE_HOST and permission.corpus_id is None)
                _require(permission.valid_from <= at < permission.valid_until)

            payload = event.payload
            if isinstance(payload, CredentialEnrolled):
                credential = payload.credential
                _require(credential.credential_id not in credentials)
                _require(credential.valid_until > at)
                credentials[credential.credential_id] = ValidatedCredential(
                    enrollment_sequence=sequence, credential=credential)
            elif isinstance(payload, CredentialDisabled):
                entry = credentials.get(payload.credential_id)
                _require(entry is not None and entry.credential.enabled)
                _require(entry.enrollment_sequence == payload.expected_enrollment_sequence)
                credentials[payload.credential_id] = entry.model_copy(update={
                    "credential": entry.credential.model_copy(update={"enabled": False})})
            elif isinstance(payload, PermissionGranted):
                _require(payload.grant_id not in grants and payload.permission.valid_until > at)
                _require(any(entry.credential.principal_id == payload.permission.principal_id
                             for entry in credentials.values()))
                grants[payload.grant_id] = ValidatedGrant(grant_sequence=sequence,
                    grant_id=payload.grant_id, permission=payload.permission, revoked=False)
            elif isinstance(payload, PermissionRevoked):
                grant = grants.get(payload.grant_id)
                _require(grant is not None and not grant.revoked)
                _require(grant.grant_sequence == payload.expected_grant_sequence)
                grants[payload.grant_id] = grant.model_copy(update={"revoked": True})
            else:
                _require(False)
            event_ids.add(event.event_id)
            previous_hash, previous_time = event.entry_hash, at

        return ValidatedAuthorizationLedger(checkpoint=checkpoint,
            credentials=tuple(credentials[key] for key in sorted(credentials)),
            grants=tuple(grants[key] for key in sorted(grants)))
    except AuthorizationValidationError:
        raise
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError, RecursionError):
        raise AuthorizationValidationError("Invalid authorization ledger") from None
