"""Transactional synthetic authority adapter. No production credentials or signing."""
from contextlib import closing
from dataclasses import dataclass
import math
import sqlite3

from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.reconciliation_simulation import (
    AuthoritySimulationCommand, SyntheticAuthorityCaller, SyntheticBatchAuthorization,
    SyntheticAuthorityPolicy, decode_simulation_record, simulate_authority,
    validate_simulation_state,
)
from tnc.provenance.reconciliation_durable_store import TestCheckpointAuthorityStore, _rows


class AuthorityWriteError(ValueError):
    """Sanitized error; uncertain commit completion must be resolved by retry."""


@dataclass(frozen=True)
class TestAuthorityWriteResult:
    __test__ = False
    status: str
    acceptance_bytes: bytes | None = None
    synthetic: bool = True
    audit_only: bool = True


def _copy(value, kind):
    if type(value) is not kind:
        raise AuthorityWriteError('INVALID_INPUT')
    return decode_simulation_record(kind, canonical_bytes(value))


class TestCheckpointAuthorityWriter(TestCheckpointAuthorityStore):
    """Explicit fixture capability, sharing the authority database serialization gate."""
    __test__ = False

    def __init__(self, path, *, trusted_initial_envelope, busy_timeout=1):
        super().__init__(path, trusted_initial_envelope=trusted_initial_envelope)
        if type(busy_timeout) not in (int, float) or not math.isfinite(busy_timeout) or not 0 <= busy_timeout <= 5:
            raise ValueError('INVALID_TIMEOUT')
        self.busy_timeout = busy_timeout

    def _hook(self, point):
        """Private fault seam for isolated tests."""

    def _transaction(self, operation, now):
        commit_attempted = False
        try:
            with closing(sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                    isolation_level=None, timeout=self.busy_timeout)) as connection:
                connection.execute('PRAGMA foreign_keys=ON')
                connection.execute('PRAGMA trusted_schema=OFF')
                connection.execute('PRAGMA synchronous=FULL')
                if connection.execute('PRAGMA synchronous').fetchone() != (2,):
                    raise AuthorityWriteError('STORE_UNAVAILABLE')
                connection.execute('BEGIN IMMEDIATE')
                try:
                    self._hook('locked')
                    current = self._load(connection, now=now)
                    proposed, status, request_id = operation(current)
                    if proposed is not None:
                        validate_simulation_state(proposed, trusted_initial_envelope=self._anchor, now=now)
                        rows = _rows(proposed)
                        for row in rows['authority_acceptances'][len(current.history):]:
                            connection.execute('INSERT INTO authority_acceptances VALUES (?,?,?,?,?,?,?)', row)
                            self._hook('acceptance_inserted')
                        row = rows['authority_state'][0]
                        connection.execute('UPDATE authority_state SET canonical=?,digest=?,revision=?,envelope_digest=?,policy_revision=?,policy_digest=? WHERE id=?', row[1:] + (row[0],))
                        self._hook('state_updated')
                    validated = self._load(connection, now=now)
                    if canonical_bytes(validated) != canonical_bytes(proposed if proposed is not None else current):
                        raise AuthorityWriteError('INVALID_STATE')
                    receipt = None
                    if request_id is not None:
                        receipt = connection.execute('SELECT acceptance FROM authority_acceptances WHERE request_id=?', (request_id,)).fetchone()[0]
                    result = TestAuthorityWriteResult(status, receipt)
                    self._hook('before_commit')
                    commit_attempted = True
                    connection.execute('COMMIT')
                    self._hook('after_commit')
                    return result
                except BaseException:
                    if connection.in_transaction:
                        connection.execute('ROLLBACK')
                    raise
        except Exception as exc:
            if commit_attempted:
                raise AuthorityWriteError('OUTCOME_UNKNOWN') from None
            if isinstance(exc, AuthorityWriteError):
                raise
            if isinstance(exc, sqlite3.OperationalError) and getattr(exc, 'sqlite_errorcode', 0) & 255 in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise AuthorityWriteError('STORE_BUSY') from None
            raise AuthorityWriteError('STORE_UNAVAILABLE') from None

    def submit(self, command, *, caller, batch_authorization=None, now):
        """Accept a new request or recover its original bytes under current rights."""
        try:
            command = _copy(command, AuthoritySimulationCommand)
            caller = _copy(caller, SyntheticAuthorityCaller)
            if command.action not in ('SUBMIT', 'RECOVER'):
                raise AuthorityWriteError('INVALID_INPUT')
            # Retried historical requests need no candidate or new batch evidence.
            if batch_authorization is not None:
                batch_authorization = _copy(batch_authorization, SyntheticBatchAuthorization)
        except Exception:
            raise AuthorityWriteError('INVALID_INPUT') from None

        def operation(current):
            outcome = simulate_authority(current, command, caller=caller,
                batch_authorization=batch_authorization, trusted_initial_envelope=self._anchor, now=now)
            if outcome.status == 'DENIED':
                raise AuthorityWriteError(outcome.reason_code)
            return outcome.proposed_state, outcome.status, command.request.request_id
        return self._transaction(operation, now)

    def replace_policy_for_testing(self, policy, *, expected_policy_revision, expected_policy_digest, now):
        """Host fixture only. Identical-current no-op still requires exact current CAS."""
        try:
            policy = _copy(policy, SyntheticAuthorityPolicy)
            if (type(expected_policy_revision) is not int or expected_policy_revision < 1
                    or type(expected_policy_digest) is not str or len(expected_policy_digest) != 64
                    or any(c not in '0123456789abcdef' for c in expected_policy_digest)):
                raise ValueError()
        except Exception:
            raise AuthorityWriteError('INVALID_INPUT') from None

        def operation(current):
            prior = current.policy
            if expected_policy_revision != prior.revision or expected_policy_digest != record_digest(prior):
                raise AuthorityWriteError('POLICY_CONFLICT')
            if canonical_bytes(policy) == canonical_bytes(prior):
                return None, 'UNCHANGED', None
            if (policy.revision <= prior.revision or policy.deployment_id != prior.deployment_id
                    or policy.store_instance_id != prior.store_instance_id
                    or not policy.valid_from <= now < policy.valid_until):
                raise AuthorityWriteError('INVALID_POLICY')
            return current.model_copy(update={'policy': policy}), 'POLICY_REPLACED', None
        return self._transaction(operation, now)
