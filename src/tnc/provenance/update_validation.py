"""Pure proposed transitions. No signing, I/O, clocks, locks, or durable commits."""
from datetime import datetime
import ntpath

from tnc.provenance.authorization_models import canonical_bytes, decode_canonical, record_digest
from tnc.provenance.deployment_validation import validate_installation_records
from tnc.provenance.update_models import (
    UPDATE_RECORD_LIMIT, UpdateCandidate, UpdateIntent, UpdateAuthorityHead,
    SyntheticInstallerEvidence, InstallerEvidenceClaims, PreparedUpdateEvidence, SyntheticDrainEvidence,
    UpdateReceipt, LocatorObservation, UpdateOperation, UpdateCommand,
    UpdateTransitionResult, UpdateRecoveryResult,
)


_KINDS = (InstallerEvidenceClaims, UpdateCandidate, UpdateIntent, UpdateAuthorityHead, SyntheticInstallerEvidence,
          PreparedUpdateEvidence, SyntheticDrainEvidence, UpdateReceipt, LocatorObservation,
          UpdateOperation, UpdateCommand, UpdateTransitionResult, UpdateRecoveryResult)


class _Rejected(ValueError):
    def __init__(self, reason):
        self.reason = reason


def _require(condition, reason='INVALID_RECORD'):
    if not condition:
        raise _Rejected(reason)


def decode_update_record(kind, data):
    if kind not in _KINDS or type(data) is not bytes or not 0 < len(data) <= UPDATE_RECORD_LIMIT:
        raise ValueError('Invalid update record')
    return decode_canonical(kind, data)


def _copy(value, kind):
    _require(type(value) is kind)
    return decode_update_record(kind, canonical_bytes(value))


def _time(now):
    _require(isinstance(now, datetime) and now.utcoffset() is not None)


def _active(value, now):
    _require(value.valid_from <= now < value.valid_until, 'EXPIRED_VALIDITY_INTERVAL')


def _authority(evidence, intent, now):
    _require(evidence.authenticated, 'UNAUTHENTICATED_INSTALLER')
    _active(evidence, now)
    _require(evidence.may_publish and evidence.principal_id == intent.publisher_id
             and evidence.deployment_id == intent.deployment_id, 'PUBLISH_PERMISSION_DENIED')


def _candidate(intent, at, *, check_intent=True):
    c = intent.candidate
    records = (c.policy, c.checkpoint, c.anchor, c.envelope)
    for record in ((intent,) + records if check_intent else records):
        _active(record, at)
        _require(record.deployment_id == intent.deployment_id, 'DEPLOYMENT_MISMATCH')
    _require(c.checkpoint.policy_hash == record_digest(c.policy), 'CANDIDATE_MISMATCH')
    _require(c.checkpoint.anchor_hash == record_digest(c.anchor), 'ANCHOR_MISMATCH')
    _require(c.envelope.generation == c.anchor.minimum_generation == c.checkpoint.high_water_generation,
             'CANDIDATE_MISMATCH')
    validate_installation_records(c.envelope, c.anchor, c.descriptor, now=at)
    _require(c.policy.request.target_phase == c.envelope.phase, 'CANDIDATE_MISMATCH')
    _require(set(c.policy.installer_sids) == set(c.envelope.maintenance_sids), 'CANDIDATE_MISMATCH')
    objects = {o.role:o for o in c.envelope.objects}
    _require(ntpath.normcase(c.policy.request.descriptor_path) == ntpath.normcase(objects['descriptor'].path),
             'CANDIDATE_MISMATCH')
    state = ntpath.normcase(objects['state'].path)
    for path in (c.policy.installation_root, c.policy.request.envelope_path,
                 c.policy.request.external_anchor_path, c.policy.request.descriptor_path):
        normalized = ntpath.normcase(path)
        _require(normalized != state and not normalized.startswith(state + '\\'), 'CANDIDATE_MISMATCH')


def _head_matches(intent, head):
    _require(intent.deployment_id == head.checkpoint.deployment_id, 'DEPLOYMENT_MISMATCH')
    _require((intent.expected_head_sequence, intent.expected_checkpoint_hash) ==
             (head.sequence, record_digest(head.checkpoint)), 'HEAD_CONFLICT')
    _require(intent.candidate.envelope.generation > head.checkpoint.high_water_generation, 'GENERATION_TOO_OLD')
    _require(ntpath.normcase(intent.candidate.policy.installation_root) != ntpath.normcase(head.generation_location),
             'CANDIDATE_MISMATCH')


def _prepared(intent, evidence, at):
    _active(evidence, at)
    _require(evidence.intent_hash == record_digest(intent), 'PREFLIGHT_NOT_CONFORMING')
    report, envelope = evidence.report, intent.candidate.envelope
    _require(report.status == 'CONFORMS' and (report.envelope_hash, report.deployment_id, report.generation, report.phase) ==
             (record_digest(envelope), intent.deployment_id, envelope.generation, envelope.phase), 'PREFLIGHT_NOT_CONFORMING')
    _require(report.inspected_object_ids == tuple(o.object_id for o in envelope.objects), 'PREFLIGHT_NOT_CONFORMING')
    _require(evidence.valid_from <= report.started_at <= report.finished_at <= at, 'PREFLIGHT_NOT_CONFORMING')
    _require(report.started_at >= max(v.valid_from for v in (intent, intent.candidate.policy,
             intent.candidate.checkpoint, intent.candidate.anchor, envelope)), 'PREFLIGHT_NOT_CONFORMING')


def _drained(intent, evidence, preparation, at):
    _active(evidence, at)
    _require(evidence.intent_hash == record_digest(intent)
             and evidence.expected_head_sequence == intent.expected_head_sequence
             and evidence.expected_checkpoint_hash == intent.expected_checkpoint_hash
             and evidence.admissions_fenced and evidence.processes_terminated and evidence.handles_released
             and evidence.valid_from >= preparation.report.finished_at, 'DRAIN_INCOMPLETE')


def _locator_matches(locator, sequence, checkpoint_hash, location, deployment_id):
    return locator.state == 'PRESENT' and locator.target_state == 'VALID' and (
        locator.authority_sequence, locator.checkpoint_hash, ntpath.normcase(locator.generation_location), locator.deployment_id
    ) == (sequence, checkpoint_hash, ntpath.normcase(location), deployment_id)


def _operation(operation, head, now):
    intent = operation.intent
    _require(intent.deployment_id == head.checkpoint.deployment_id, 'DEPLOYMENT_MISMATCH')
    if operation.preparation:
        _prepared(intent, operation.preparation, operation.preparation.report.finished_at)
    if operation.receipt:
        r = operation.receipt
        _require((r.operation_id, r.deployment_id, r.publisher_id, r.intent_hash, r.checkpoint_hash,
                  r.authority_sequence, r.generation) == (
            intent.operation_id, intent.deployment_id, intent.publisher_id, record_digest(intent),
            record_digest(intent.candidate.checkpoint), intent.expected_head_sequence + 1, intent.candidate.envelope.generation))
        _require(r.committed_at <= now and r.authority_sequence <= head.sequence)
        _candidate(intent, r.committed_at)
        _prepared(intent, operation.preparation, r.committed_at)
        _drained(intent, operation.drain, operation.preparation, r.committed_at)
        if r.authority_sequence == head.sequence:
            _require(r.checkpoint_hash == record_digest(head.checkpoint)
                     and ntpath.normcase(head.generation_location) == ntpath.normcase(intent.candidate.policy.installation_root))
    if operation.publication:
        r, locator = operation.receipt, operation.publication
        _require(r.committed_at <= locator.observed_at <= now)
        _candidate(intent, locator.observed_at, check_intent=False)
        _require(_locator_matches(locator, r.authority_sequence, r.checkpoint_hash,
                                 intent.candidate.policy.installation_root, intent.deployment_id))


def evaluate_update_transition(*, head, existing, command, authority, now):
    return _evaluate_transition(head=head, existing=existing, command=command, authority=authority, now=now,
                                evidence_kind=SyntheticInstallerEvidence)


def _evaluate_checked_update_transition(*, head, existing, command, authority, now):
    return _evaluate_transition(head=head, existing=existing, command=command, authority=authority, now=now,
                                evidence_kind=InstallerEvidenceClaims)


def _evaluate_transition(*, head, existing, command, authority, now, evidence_kind):
    """Return a proposed immutable operation/head; caller-supplied state must be trusted.

    A backend must serialize and durably recheck the same expected head. This
    function neither authenticates synthetic evidence nor commits the proposal.
    """
    try:
        _time(now)
        command = _copy(command, UpdateCommand)
        authority = _copy(authority, evidence_kind)
        intent = command.intent
        _authority(authority, intent, now)  # Do not expose stored operation to an unauthorized caller.
        _require(head is not None, 'AUTHORITY_UNAVAILABLE')
        head = _copy(head, UpdateAuthorityHead)
        if existing is not None:
            existing = _copy(existing, UpdateOperation)
            _require(existing.intent.publisher_id == authority.principal_id, 'PUBLISH_PERMISSION_DENIED')
            _require(canonical_bytes(existing.intent) == canonical_bytes(intent), 'OPERATION_CONFLICT')
            _operation(existing, head, now)
            # Historical receipts survive candidate expiry and later generations.
            # A new currently authorized key may recover its principal's receipt.
            if command.action == 'RECOVER' or command.action == 'REGISTER' or (
                    command.action == 'COMMIT' and existing.receipt is not None):
                return UpdateTransitionResult(status='RECOVERED' if existing.receipt else 'UNCHANGED', operation=existing)
        else:
            _require(command.action == 'REGISTER', 'OPERATION_UNAVAILABLE')
        if command.action == 'PUBLISH':
            _require(existing.stage in ('COMMITTED', 'PUBLISHED'), 'INVALID_TRANSITION')
            r, locator = existing.receipt, command.locator
            _require(r.authority_sequence == head.sequence and r.checkpoint_hash == record_digest(head.checkpoint), 'HEAD_CONFLICT')
            _require(r.committed_at <= locator.observed_at <= now, 'RECOVERY_REQUIRED')
            _active(head.checkpoint, now)
            _candidate(intent, now, check_intent=False)
            _require(_locator_matches(locator, head.sequence, r.checkpoint_hash, head.generation_location,
                                     intent.deployment_id), 'RECOVERY_REQUIRED')
            if existing.stage == 'PUBLISHED':
                return UpdateTransitionResult(status='UNCHANGED', operation=existing)
            return UpdateTransitionResult(status='PROPOSED', operation=existing.model_copy(update={
                'stage':'PUBLISHED', 'publication':locator}))
        _require(authority.signer_key_hash == intent.signer_key_hash, 'PUBLISH_PERMISSION_DENIED')
        _candidate(intent, now)
        _head_matches(intent, head)
        if command.action == 'REGISTER':
            return UpdateTransitionResult(status='PROPOSED', operation=UpdateOperation(intent=intent, stage='REGISTERED'))
        _require(existing.stage in ('REGISTERED', 'PREPARED'), 'INVALID_TRANSITION')
        _prepared(intent, command.preparation, now)
        if existing.preparation is not None:
            _require(command.preparation.report.finished_at >= existing.preparation.report.finished_at,
                     'PREFLIGHT_NOT_CONFORMING')
        if command.action == 'PREPARE':
            return UpdateTransitionResult(status='PROPOSED', operation=existing.model_copy(update={
                'stage':'PREPARED', 'preparation':command.preparation}))
        _require(command.action == 'COMMIT' and existing.stage == 'PREPARED', 'INVALID_TRANSITION')
        _drained(intent, command.drain, command.preparation, now)
        receipt = UpdateReceipt(operation_id=intent.operation_id, deployment_id=intent.deployment_id,
            publisher_id=intent.publisher_id, intent_hash=record_digest(intent),
            checkpoint_hash=record_digest(intent.candidate.checkpoint), authority_sequence=head.sequence + 1,
            generation=intent.candidate.envelope.generation, committed_at=now)
        operation = existing.model_copy(update={'stage':'COMMITTED', 'preparation':command.preparation,
                                              'drain':command.drain, 'receipt':receipt})
        proposed_head = UpdateAuthorityHead(sequence=head.sequence + 1, checkpoint=intent.candidate.checkpoint,
            generation_location=intent.candidate.policy.installation_root)
        return UpdateTransitionResult(status='PROPOSED', operation=operation, proposed_head=proposed_head)
    except _Rejected as exc:
        reason = exc.reason
    except Exception:
        reason = 'INVALID_RECORD'
    return UpdateTransitionResult(status='DENIED', reason_code=reason)


def evaluate_update_recovery(*, head, locator, now):
    """Classify authority/locator agreement; never perform a repair or permit startup."""
    try:
        _time(now)
        _require(head is not None, 'AUTHORITY_UNAVAILABLE')
        head = _copy(head, UpdateAuthorityHead)
        locator = _copy(locator, LocatorObservation)
        _active(head.checkpoint, now)
        _require(locator.observed_at <= now, 'RECOVERY_REQUIRED')
        if locator.state == 'MISSING':
            return UpdateRecoveryResult(disposition='REPAIR_REQUIRED', reason_code='RECOVERY_REQUIRED')
        _require(locator.state == 'PRESENT', 'RECOVERY_REQUIRED')
        _require(locator.deployment_id == head.checkpoint.deployment_id, 'DEPLOYMENT_MISMATCH')
        if locator.authority_sequence < head.sequence:
            return UpdateRecoveryResult(disposition='REPAIR_REQUIRED', reason_code='RECOVERY_REQUIRED')
        _require(_locator_matches(locator, head.sequence, record_digest(head.checkpoint),
                                 head.generation_location, head.checkpoint.deployment_id), 'RECOVERY_REQUIRED')
        return UpdateRecoveryResult(disposition='MATCHED')
    except _Rejected as exc:
        reason = exc.reason
    except Exception:
        reason = 'INVALID_RECORD'
    return UpdateRecoveryResult(disposition='BLOCKED', reason_code=reason)
