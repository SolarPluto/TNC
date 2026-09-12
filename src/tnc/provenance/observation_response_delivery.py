"""Test-only framed response delivery. No signing, retry cache, ACK, or persistence."""
import math
import ssl
from time import monotonic

from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.mtls import MtlsConnection
from tnc.provenance.reconciliation_verifier import SignedObservation, decode_v2_record

MAX_RESPONSE_SIZE = 32768


class ResponseDeliveryError(ValueError):
    pass


def _remaining(deadline):
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ResponseDeliveryError('Delivery failed')
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise ResponseDeliveryError('Delivery failed')
    return remaining


def encode_signed_response(response):
    """Exact canonical v2 container, with a narrower delivery-profile size cap."""
    try:
        if type(response) is not SignedObservation:
            raise ValueError()
        raw = canonical_bytes(response)
        if not 0 < len(raw) <= MAX_RESPONSE_SIZE:
            raise ValueError()
        decode_v2_record(SignedObservation, raw)
        return len(raw).to_bytes(4, 'big') + raw
    except Exception:
        raise ResponseDeliveryError('Delivery failed') from None


def send_signed_response(connection, response, *, deadline):
    """Frame existing signed data for its enrolled principal, without re-signing.

    Successful send does not prove receipt or client commitment. Failure closes
    the stream, since partial delivery cannot be undone or resumed here.
    """
    try:
        _remaining(deadline)
        if type(connection) is not MtlsConnection:
            raise ValueError()
        frame = encode_signed_response(response)
        identity = connection.verify()
        if response.payload.principal_id != identity.principal_id:
            raise ValueError()
        _remaining(deadline)
        connection.send_before(frame, deadline, expected_identity=identity)
        _remaining(deadline)
    except Exception:
        if type(connection) is MtlsConnection:
            connection.close()
        raise ResponseDeliveryError('Delivery failed') from None


def receive_signed_response(connection, *, trusted_context, deadline):
    """Return exact canonical bytes, not a cryptographic acceptance or receipt.

    The test host owns the client context and expected hostname used at handshake.
    Client-store admission must verify signatures and retained request bindings.
    """
    valid_socket = type(connection) is ssl.SSLSocket
    previous = None
    success = False
    try:
        _remaining(deadline)
        if (not valid_socket or connection.server_side or connection.context is not trusted_context
                or trusted_context.verify_mode != ssl.CERT_REQUIRED or not trusted_context.check_hostname
                or trusted_context.minimum_version != ssl.TLSVersion.TLSv1_3
                or not trusted_context.verify_flags & ssl.VERIFY_X509_STRICT
                or connection.version() != 'TLSv1.3' or not connection.getpeercert(binary_form=True)):
            raise ValueError()
        previous = connection.gettimeout()
        def exact(length):
            data = bytearray()
            while len(data) < length:
                remaining = _remaining(deadline)
                connection.settimeout(remaining if previous is None else min(previous, remaining))
                chunk = connection.recv(length - len(data))
                _remaining(deadline)
                if not chunk:
                    raise ValueError()
                data.extend(chunk)
            return bytes(data)
        size = int.from_bytes(exact(4), 'big')
        if not 0 < size <= MAX_RESPONSE_SIZE:
            raise ValueError()
        raw = exact(size)
        decode_v2_record(SignedObservation, raw)
        _remaining(deadline)
        success = True
        return raw
    except Exception:
        raise ResponseDeliveryError('Delivery failed') from None
    finally:
        if valid_socket:
            if success:
                connection.settimeout(previous)
            else:
                connection.close()
