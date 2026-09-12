"""Read-only synthetic authority recovery and observation; no authentication."""
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import sqlite3

from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.reconciliation_models import ReconciliationEnvelope, ReconciliationRequest
from tnc.provenance.reconciliation_simulation import (
    AuthoritySimulationCommand, SyntheticAuthorityCaller, decode_simulation_record,
    simulate_authority, evaluate_client_observation,
    SyntheticCurrentObservation, SyntheticAuthorityPolicy,
)
from tnc.provenance.reconciliation_durable_store import TestCheckpointAuthorityStore


class AuthorityReadError(ValueError):
    """Fixed reasons without request contents or filesystem diagnostics."""


@dataclass(frozen=True)
class CurrentAuthoritySnapshot:
    """Host-only test authority data, captured from one validated read transaction."""
    observation: SyntheticCurrentObservation
    policy: SyntheticAuthorityPolicy


def _copy(value, kind):
    if type(value) is not kind:
        raise ValueError('Exact record required')
    return decode_simulation_record(kind, canonical_bytes(value))


class ReadOnlyAuthorityAdapter:
    """Test-only responses reflecting one SQLite read snapshot, not release-time authority."""

    def __init__(self, store_path, *, trusted_initial_envelope):
        self.path = Path(store_path).absolute()
        self._anchor = _copy(trusted_initial_envelope, ReconciliationEnvelope)

    def _read(self, command, caller, now, *, include_snapshot=False):
        try:
            caller = _copy(caller, SyntheticAuthorityCaller)
            command = _copy(command, AuthoritySimulationCommand)
        except Exception:
            raise AuthorityReadError('INVALID_INPUT') from None
        try:
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True,
                    isolation_level=None,timeout=1)) as connection:
                connection.execute('PRAGMA query_only=ON')
                connection.execute('PRAGMA trusted_schema=OFF')
                connection.execute('PRAGMA foreign_keys=ON')
                connection.execute('BEGIN')
                try:
                    state = TestCheckpointAuthorityStore(self.path,
                        trusted_initial_envelope=self._anchor)._load(connection,now=now)
                    result = simulate_authority(state, command, caller=caller,
                        trusted_initial_envelope=self._anchor,now=now)
                    if result.status == 'DENIED':
                        raise AuthorityReadError(result.reason_code)
                    if result.status == 'CURRENT':
                        if include_snapshot:
                            return CurrentAuthoritySnapshot(result.observation, state.policy)
                        return result.observation
                    if result.status != 'RECOVERED':
                        raise AuthorityReadError('INVALID_STATE')
                    # Fetch original bytes only after permission and exact-request checks,
                    # from the same snapshot used to validate the ledger and projections.
                    raw = connection.execute('SELECT acceptance FROM authority_acceptances WHERE request_id=?',
                        (command.request.request_id,)).fetchone()[0]
                    if raw != canonical_bytes(result.acceptance):
                        raise AuthorityReadError('INVALID_STATE')
                    return raw
                finally:
                    connection.execute('ROLLBACK')
        except AuthorityReadError:
            raise
        except Exception:
            raise AuthorityReadError('AUTHORITY_UNAVAILABLE') from None

    def recover_historical(self, request, *, caller, now):
        """Full canonical request required; returns original unsigned acceptance bytes."""
        try:
            request = _copy(request, ReconciliationRequest)
            command = AuthoritySimulationCommand(action='RECOVER',request=request)
        except Exception:
            raise AuthorityReadError('INVALID_INPUT') from None
        return self._read(command,caller,now)

    def observe_current(self, challenge, *, caller, now):
        """Challenge must be a canonical 64-character lowercase hex digest."""
        try:
            command = AuthoritySimulationCommand(action='OBSERVE_CURRENT',challenge=challenge)
        except Exception:
            raise AuthorityReadError('INVALID_INPUT') from None
        return self._read(command,caller,now)

    def observe_current_snapshot(self, challenge, *, caller, now):
        """Return observation and policy from the same synthetic authority snapshot."""
        try:
            command = AuthoritySimulationCommand(action='OBSERVE_CURRENT', challenge=challenge)
        except Exception:
            raise AuthorityReadError('INVALID_INPUT') from None
        return self._read(command, caller, now, include_snapshot=True)

    @staticmethod
    def evaluate_client_observation(observation, client_high_water, *, expected_challenge,
            principal_id, chain=(), now):
        """Pure comparison only; caller supplies independently trusted synthetic links."""
        return evaluate_client_observation(client_high_water,observation,
            expected_challenge=expected_challenge,principal_id=principal_id,chain=chain,now=now)
