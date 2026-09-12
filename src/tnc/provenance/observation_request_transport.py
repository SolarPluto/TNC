"""Host-only mTLS request binding. No signer, authority lookup, or storage writes."""
from datetime import datetime, timezone
import math
from time import monotonic

from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.mtls import MtlsConnection
from tnc.provenance.observation_request_binding import (
    BindingOutcome, ObservationPolicy, ObservationHostContext,
    REQUEST_LIMIT, bind_observation_request, decode_binding_record,
)


def _check(deadline):
    if monotonic() >= deadline:
        raise TimeoutError('Request deadline exceeded')


def _read_exact(connection, length, deadline):
    data = bytearray()
    while len(data) < length:
        _check(deadline)
        chunk = connection.recv_before(length - len(data), deadline)
        _check(deadline)
        if not chunk:
            raise ValueError('Truncated frame')
        data.extend(chunk)
    return bytes(data)


def _frame(connection, deadline):
    length = int.from_bytes(_read_exact(connection, 4, deadline), 'big')
    if not 0 < length <= REQUEST_LIMIT:
        raise ValueError('Invalid frame length')
    return _read_exact(connection, length, deadline)


def _snapshot(provider, kind):
    value = provider()
    if type(value) is not kind:
        raise ValueError('Host record required')
    return decode_binding_record(kind, canonical_bytes(value))


class ObservationRequestTransport:
    """One host worker per accepted connection; all providers are host-owned.

    The deadline begins after the existing TLS handshake. Callbacks must be
    bounded by their host implementations; late results are never accepted.
    A successful binding describes checked snapshots, not release authority.
    """
    def __init__(self, *, policy_reader, context_reader, timeout=10.0,
                 clock=lambda: datetime.now(timezone.utc)):
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 30 or not all(map(callable, (policy_reader, context_reader, clock)))):
            raise ValueError('Invalid transport configuration')
        self._policy_reader = policy_reader
        self._context_reader = context_reader
        self._timeout = timeout
        self._clock = clock

    def _process(self, connection):
        """Read one frame from the very connection whose identity is verified.

        All failures close the stream to prevent framing desynchronization.
        No response or article data is sent by this adapter.
        """
        result = BindingOutcome(status='DENIED', reason_code='ACCESS_DENIED')
        if type(connection) is not MtlsConnection:
            return result, None, None
        try:
            deadline = monotonic() + self._timeout
            started = self._clock()
            first = connection.verify()
            _check(deadline)
            raw = _frame(connection, deadline)
            policy = _snapshot(self._policy_reader, ObservationPolicy)
            _check(deadline)
            context = _snapshot(self._context_reader, ObservationHostContext)
            _check(deadline)
            initial = bind_observation_request(raw, identity=first, policy=policy,
                host_context=context, now=self._clock())
            if initial.status != 'BOUND':
                return result, None, None
            # Detect intervening enrollment and policy changes before returning.
            current = connection.verify()
            _check(deadline)
            fields = ('principal_id', 'credential_id', 'connection_id', 'registry_revision')
            if any(getattr(first, f) != getattr(current, f) for f in fields):
                return result, None, None
            if (_snapshot(self._policy_reader, ObservationPolicy) != policy
                    or _snapshot(self._context_reader, ObservationHostContext) != context):
                return result, None, None
            _check(deadline)
            now = self._clock()
            if now < started:
                return result, None, None
            checked = bind_observation_request(raw, identity=current, policy=policy,
                host_context=context, now=now)
            _check(deadline)
            if checked.status == 'BOUND':
                result = checked
            return result, raw if result.status == 'BOUND' else None, deadline
        except Exception:
            return result, None, None
        finally:
            if result.status != 'BOUND':
                connection.close()

    def bind(self, connection):
        """Return serializable audit data only, never a bridge capability."""
        return self._process(connection)[0]

    def receive_handoff(self, connection):
        """Read and validate a frame, retaining exact bytes in a transient handoff."""
        from tnc.provenance.observation_handoff import _mint
        result, raw, deadline = self._process(connection)
        if result.status != 'BOUND':
            return None
        try:
            return _mint(self, connection, raw, result.binding, deadline)
        except Exception:
            connection.close()
            return None

    def _revalidate(self, raw, prior, connection, deadline):
        _check(deadline)
        identity = connection.verify()
        policy = _snapshot(self._policy_reader, ObservationPolicy)
        _check(deadline)
        context = _snapshot(self._context_reader, ObservationHostContext)
        current = connection.verify()
        identity_fields = ('principal_id', 'credential_id', 'connection_id', 'registry_revision')
        if any(getattr(identity, f) != getattr(current, f) for f in identity_fields):
            raise ValueError('Changed identity')
        identity = current
        now = self._clock()
        if not prior.valid_from <= now < prior.valid_until:
            raise ValueError('Expired binding')
        result = bind_observation_request(raw, identity=identity, policy=policy,
            host_context=context, now=now)
        _check(deadline)
        if result.status != 'BOUND':
            raise ValueError('Access denied')
        fields = ('request_digest', 'principal_id', 'credential_id', 'connection_id',
            'registry_revision', 'deployment_id', 'store_instance_id', 'issuer_id',
            'policy_revision', 'policy_digest', 'grant_id')
        if any(getattr(prior, f) != getattr(result.binding, f) for f in fields):
            raise ValueError('Changed binding')
        return result.binding.model_copy(update={'valid_until': min(prior.valid_until, result.binding.valid_until)})
