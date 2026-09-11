"""Temporary-store transaction harness. No production authority or publisher.

The local checkpoint profile deliberately cannot detect a rewritten whole store.
Synthetic providers are host test dependencies, never request capabilities.
"""
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from tnc.provenance.authorization_models import ZERO, canonical_bytes, record_digest, decode_canonical
from tnc.provenance.host_auth import VerifiedIdentity
from tnc.provenance.update_durable_store import UpdateDurableStore, UpdateStoreError, _rows
from tnc.provenance.update_storage_models import (
    IMAGE_LIMIT, EVENT_LIMIT, UpdateStorageImage, UpdateStorageCheckpoint, StoredUpdateEvent,
    RecordedUpdateAuthority, StoredUpdateRegistration, StoredUpdatePreparation, StoredUpdateCommit,
)
from tnc.provenance.update_storage_validation import (
    decode_update_storage_record, update_storage_event_hash, validate_update_storage_image, _claims,
)
from tnc.provenance.update_models import UpdateIntent, UpdateOperation, UpdateCommand
from tnc.provenance.update_validation import _evaluate_checked_update_transition
from tnc.provenance.update_verification import SignatureEnvelope, CommittedSignatureBinding, verify_update_intent_signature
from tnc.provenance.update_integration import ArchivedUpdateSignature, SyntheticUpdateObservations


class UpdateWriteError(ValueError):
    pass


def _require(condition, reason='ACCESS_DENIED'):
    if not condition:
        raise UpdateWriteError(reason)


def _copy(value, kind):
    _require(type(value) is kind, 'INVALID_REQUEST')
    data = canonical_bytes(value)
    _require(len(data) <= EVENT_LIMIT, 'CAPACITY_EXCEEDED')
    return decode_canonical(kind, data)


def _checkpoint(image):
    return UpdateStorageCheckpoint(deployment_id=image.deployment_id, image_hash=record_digest(image),
        event_count=len(image.events), event_head_hash=image.events[-1].entry_hash if image.events else ZERO,
        authority_head_hash=record_digest(image.head))


class LocalCheckpointForTesting:
    """Consistency only. This is NOT an independent current trust provider."""
    def read(self, connection):
        sizes = connection.execute('SELECT length(checkpoint) FROM store_state').fetchall()
        _require(len(sizes) == 1 and 0 < sizes[0][0] <= EVENT_LIMIT, 'INVALID_STORE')
        data = connection.execute('SELECT checkpoint FROM store_state').fetchone()[0]
        return decode_update_storage_record(UpdateStorageCheckpoint, data)


@dataclass(frozen=True)
class TestWriteResult:
    __test__ = False
    status: str
    checkpoint: UpdateStorageCheckpoint
    receipt_bytes: bytes | None = None


def _current(image, operation_id):
    authority, revision, existing, signature = None, 0, None, None
    for event in image.events:
        p = event.payload
        if p.kind == 'AUTHORITY':
            authority, revision = p, event.sequence
        elif p.kind == 'REGISTER' and p.intent.operation_id == operation_id:
            existing, signature = UpdateOperation(intent=p.intent, stage='REGISTERED'), p.signature
        elif getattr(p, 'operation_id', None) == operation_id and existing is not None:
            if p.kind == 'PREPARE':
                existing = existing.model_copy(update={'stage':'PREPARED', 'preparation':p.preparation})
            elif p.kind == 'COMMIT':
                existing = existing.model_copy(update={'stage':'COMMITTED', 'preparation':p.preparation,
                    'drain':p.drain, 'receipt':p.receipt})
            elif p.kind == 'PUBLISH':
                existing = existing.model_copy(update={'stage':'PUBLISHED', 'publication':p.locator})
    return authority, revision, existing, signature


class TestUpdateStoreWriter:
    """Explicit test-provider methods; no caller callbacks or SQL contexts.

    Providers: identity.verify(), administration.verify()/read(), and
    observations.observe(intent, action, image). All are synthetic test inputs.
    """
    __test__ = False

    def __init__(self, path, *, identity_provider, administration_provider, observation_provider,
                 checkpoint_provider, clock=None, busy_timeout=1.0):
        _require(type(checkpoint_provider) is LocalCheckpointForTesting, 'INVALID_TEST_PROFILE')
        _require(type(busy_timeout) in (int, float) and 0 < busy_timeout <= 5, 'INVALID_TEST_PROFILE')
        self.path = Path(path).absolute()
        self.identity = identity_provider
        self.administration = administration_provider
        self.observations = observation_provider
        self.checkpoints = checkpoint_provider
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.timeout = busy_timeout

    def register(self, intent, signature):
        return self._execute('REGISTER', intent, signature)

    def prepare(self, intent, signature):
        return self._execute('PREPARE', intent, signature)

    def commit(self, intent, signature):
        return self._execute('COMMIT', intent, signature)

    def recover(self, intent, signature):
        return self._execute('RECOVER', intent, signature)

    def record_authority(self, *, expected_revision):
        _require(type(expected_revision) is int and expected_revision >= 0, 'INVALID_REQUEST')
        return self._execute('AUTHORITY', expected_revision=expected_revision)

    def _now(self):
        value = self.clock()
        _require(type(value) is datetime and value.utcoffset() is not None, 'INVALID_CLOCK')
        return value.astimezone(timezone.utc)

    def _session(self, intent, at):
        value = self.identity.verify()
        _require(type(value) is VerifiedIdentity)
        value = VerifiedIdentity.model_validate(value.model_dump())
        _require(value.principal_id == intent.publisher_id and value.verified_at <= at < value.valid_until)
        return value

    def _hook(self, stage):
        """Private fault-injection seam for transaction/process tests."""

    def _execute(self, action, intent=None, signature=None, expected_revision=None):
        committed = False
        commit_attempted = False
        try:
            if action == 'AUTHORITY':
                _require(self.administration.verify() is True)
                session = None
            else:
                intent, signature = _copy(intent, UpdateIntent), _copy(signature, SignatureEnvelope)
                session = self._session(intent, self._now())
            with closing(sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                                        isolation_level=None, timeout=self.timeout)) as connection:
                connection.execute('PRAGMA foreign_keys=ON')
                connection.execute('PRAGMA trusted_schema=OFF')
                connection.execute('PRAGMA synchronous=FULL')
                _require(connection.execute('PRAGMA synchronous').fetchone()[0] == 2, 'INVALID_STORE')
                connection.execute('BEGIN IMMEDIATE')
                try:
                    self._hook('locked')
                    cp = self.checkpoints.read(connection)
                    image = UpdateDurableStore._load(connection, cp)
                    at = self._now()
                    _require(not image.events or at >= image.events[-1].recorded_at, 'CLOCK_REGRESSION')
                    payload, receipt, status = self._evaluate(image, action, intent, signature, session, at, expected_revision)
                    new_image = image
                    if payload is not None:
                        _require(len(image.events) < 256, 'CAPACITY_EXCEEDED')
                        event = StoredUpdateEvent(sequence=len(image.events)+1, recorded_at=at,
                            previous_hash=cp.event_head_hash, entry_hash=ZERO, payload=payload)
                        event = event.model_copy(update={'entry_hash':update_storage_event_hash(event)})
                        _require(len(canonical_bytes(event)) <= EVENT_LIMIT, 'CAPACITY_EXCEEDED')
                        new_image = image.model_copy(update={'events':image.events+(event,),
                            'head':payload.head if type(payload) is StoredUpdateCommit else image.head})
                        _require(len(canonical_bytes(new_image)) <= IMAGE_LIMIT, 'CAPACITY_EXCEEDED')
                        new_cp = _checkpoint(new_image)
                        _require(validate_update_storage_image(new_image, trusted_checkpoint=new_cp).status == 'CONSISTENT', 'INVALID_TRANSITION')
                        old_rows, new_rows = _rows(image, cp), _rows(new_image, new_cp)
                        for name, rows in new_rows.items():
                            if name in ('store_metadata', 'store_state'): continue
                            for row in rows[len(old_rows[name]):]:
                                connection.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})", row)
                                self._hook('insert:' + name)
                        state = new_rows['store_state'][0]
                        connection.execute('UPDATE store_state SET event_count=?,event_hash=?,authority_revision=?,head=?,image_hash=?,checkpoint=? WHERE id=1', state[1:])
                        self._hook('state')
                        UpdateDurableStore._load(connection, new_cp)
                        cp = new_cp
                    self._hook('before_recheck')
                    end = self._now()
                    _require(end >= at, 'CLOCK_REGRESSION')
                    # Recheck against the same serialized pre-event authority. A
                    # self-revoking authority update need not authorize itself.
                    self._evaluate(image, action, intent, signature, session, end, expected_revision,
                                   fixed_payload=payload)
                    result = TestWriteResult(status, cp, receipt)
                    self._hook('before_commit')
                    commit_attempted = True
                    connection.execute('COMMIT')
                    committed = True
                    self._hook('after_commit')
                    return result
                except BaseException:
                    if connection.in_transaction: connection.execute('ROLLBACK')
                    raise
        except UpdateWriteError:
            raise
        except sqlite3.OperationalError:
            raise UpdateWriteError('OUTCOME_UNKNOWN' if commit_attempted else 'STORE_UNAVAILABLE') from None
        except UpdateStoreError:
            raise UpdateWriteError('INVALID_STORE') from None
        except Exception:
            raise UpdateWriteError('OUTCOME_UNKNOWN' if committed else 'WRITE_FAILED') from None

    def _evaluate(self, image, action, intent, signature, session, at, expected_revision, fixed_payload=None):
        authority, revision, existing, original_signature = _current(image, intent.operation_id if intent else None)
        if action == 'AUTHORITY':
            _require(self.administration.verify() is True)
            value = _copy(self.administration.read(), RecordedUpdateAuthority)
            if fixed_payload is not None:
                _require(canonical_bytes(value) == canonical_bytes(fixed_payload), 'STALE_CONTEXT')
            _require(value.trust_store.valid_from <= at < value.trust_store.valid_until and
                     value.trust_checkpoint.valid_from <= at < value.trust_checkpoint.valid_until, 'EXPIRED_EVIDENCE')
            if authority is not None and canonical_bytes(value) == canonical_bytes(authority):
                revisions = [e.sequence for e in image.events if e.payload.kind == 'AUTHORITY']
                previous_revision = revisions[-2] if len(revisions) > 1 else 0
                _require(expected_revision in (revision, previous_revision), 'AUTHORITY_CONFLICT')
                return None, None, 'UNCHANGED'
            _require(expected_revision == revision, 'AUTHORITY_CONFLICT')
            return value, None, 'APPENDED'
        live = self._session(intent, at)
        _require((live.principal_id, live.credential_id, live.connection_id, live.registry_revision) ==
                 (session.principal_id, session.credential_id, session.connection_id, session.registry_revision), 'STALE_CONTEXT')
        recovery = action == 'RECOVER' or (existing is not None and existing.receipt is not None)
        try:
            claims = _claims(authority, live.credential_id, intent, at, recovery=recovery)
        except Exception:
            raise UpdateWriteError('ACCESS_DENIED') from None
        recorded = next(i for i in authority.identities if i.credential_id == live.credential_id)
        _require(recorded.registry_revision == live.registry_revision)
        if existing is not None:
            _require(existing.intent.publisher_id == live.principal_id)
            _require(canonical_bytes(existing.intent) == canonical_bytes(intent) and
                     canonical_bytes(original_signature) == canonical_bytes(signature), 'OPERATION_CONFLICT')
            if existing.receipt is not None:
                # Historical replay already checked archive bindings at stored
                # times. No current candidate, signing-key or observations needed.
                return None, canonical_bytes(existing.receipt), 'RECOVERED'
        if action == 'RECOVER':
            _require(existing is not None)
            return None, None, 'UNCHANGED'
        verification = verify_update_intent_signature(intent, signature, authority.trust_store,
            trusted_checkpoint=authority.trust_checkpoint, now=at)
        _require(verification.status == 'VERIFIED', 'SIGNATURE_REJECTED')
        if existing is not None and action == 'REGISTER':
            return None, None, 'UNCHANGED'
        _require(action == 'REGISTER' or existing is not None)
        if action == 'REGISTER':
            command = UpdateCommand(action=action, intent=intent)
        else:
            if fixed_payload is None:
                observed = _copy(self.observations.observe(intent, action, image), SyntheticUpdateObservations)
                preparation, drain = observed.preparation, observed.drain
            else:
                preparation = fixed_payload.preparation
                drain = fixed_payload.drain if action == 'COMMIT' else None
            if action == 'COMMIT':
                _require(existing.preparation is not None and
                    canonical_bytes(preparation) == canonical_bytes(existing.preparation), 'PREPARATION_CONFLICT')
            command = UpdateCommand(action=action, intent=intent, preparation=preparation, drain=drain)
        proposed = _evaluate_checked_update_transition(head=image.head, existing=existing, command=command,
            authority=claims, now=at)
        _require(proposed.status == 'PROPOSED', 'INVALID_TRANSITION')
        if action == 'REGISTER':
            payload = StoredUpdateRegistration(intent=intent, signature=signature, credential_id=live.credential_id)
        elif action == 'PREPARE':
            if existing.preparation is not None and canonical_bytes(existing.preparation) == canonical_bytes(command.preparation):
                return None, None, 'UNCHANGED'
            payload = StoredUpdatePreparation(operation_id=intent.operation_id,
                preparation=command.preparation, credential_id=live.credential_id)
        else:
            receipt = proposed.operation.receipt
            archive = ArchivedUpdateSignature(signature=signature, trust_store=authority.trust_store,
                trust_checkpoint=authority.trust_checkpoint, binding=CommittedSignatureBinding(
                    deployment_id=intent.deployment_id, receipt_hash=record_digest(receipt),
                    signature_envelope_hash=record_digest(signature), trust_checkpoint_hash=record_digest(authority.trust_checkpoint)))
            payload = StoredUpdateCommit(operation_id=intent.operation_id, authority_revision=revision,
                credential_id=live.credential_id, preparation=command.preparation, drain=command.drain,
                receipt=receipt, head=proposed.proposed_head, archive=archive)
        return payload, canonical_bytes(payload.receipt) if action == 'COMMIT' else None, 'APPENDED'
