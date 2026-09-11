"""Host-only Windows provisioning assembly. No CLI or remote bootstrap route."""
from datetime import datetime, timezone
import math
import ntpath
import os
import threading
import time

from tnc.provenance.authorization_models import BootstrapManifest, canonical_bytes, record_digest
from tnc.provenance.authorization_writer import ProvisioningAuthorization
from tnc.provenance.host_auth import AuthorizationError
from tnc.provenance.provisioning_models import HostProvisioningDescriptor
from tnc.provenance.provisioning_validation import decode_provisioning_record, calculate_provisioning_lease
from tnc.provenance.protected_provisioning import load_protected_provisioning
from tnc.provenance.provisioning_certificates import validate_nominated_certificate
from tnc.provenance.windows_identity import read_windows_operator_identity


def _utcnow():
    return datetime.now(timezone.utc)


def _monotonic():
    return time.monotonic()


class WindowsProvisioningSession:
    """Thread-confined session constructed from independently installed host input.

    Retains protected snapshot handles until replacement or explicit close. A fresh
    verification replaces prior authority; failures invalidate it. Never construct
    from a caller-provided descriptor, proof, SID, clock or certificate evidence.
    """
    def __init__(self, descriptor):
        try:
            if type(descriptor) is not HostProvisioningDescriptor:
                raise ValueError('Host descriptor required')
            self._descriptor = decode_provisioning_record(HostProvisioningDescriptor, canonical_bytes(descriptor))
        except Exception:
            raise AuthorizationError('Access denied') from None
        self._owner = (os.getpid(), threading.get_native_id())
        self._snapshot = None
        self._proof = None
        self._deadline = None
        self._last_utc = None
        self._last_mono = None
        self._closed = False

    def _thread(self):
        if self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise AuthorizationError('Access denied')

    def _clocks(self):
        utc, mono = _utcnow(), _monotonic()
        if (not isinstance(utc, datetime) or utc.utcoffset() is None
                or type(mono) not in (int, float) or not math.isfinite(mono)
                or self._last_utc is not None and utc < self._last_utc
                or self._last_mono is not None and mono < self._last_mono):
            raise AuthorizationError('Access denied')
        self._last_utc, self._last_mono = utc.astimezone(timezone.utc), mono
        return self._last_utc, mono

    def _invalidate(self):
        self._proof, self._deadline = None, None
        snapshot, self._snapshot = self._snapshot, None
        if snapshot is not None:
            snapshot.close()

    def verify_activation(self, manifest):
        try:
            self._thread()
            self._invalidate()
            if type(manifest) is not BootstrapManifest:
                raise ValueError('Typed manifest required')
            manifest = decode_provisioning_record(BootstrapManifest, canonical_bytes(manifest))
            _, started = self._clocks()
            first = read_windows_operator_identity()
            if (first.process_id, first.thread_id) != self._owner:
                raise AuthorizationError('Access denied')
            if first.user_sid != self._descriptor.bootstrap_anchor.operator_id:
                raise AuthorizationError('Access denied')
            self._snapshot = load_protected_provisioning(self._descriptor)
            snapshot = self._snapshot
            if snapshot.manifest != manifest:
                raise AuthorizationError('Access denied')
            certificate_time, certificate_mono = self._clocks()
            evidence = validate_nominated_certificate(snapshot, now=certificate_time)
            second = read_windows_operator_identity()
            if second != first:
                raise AuthorizationError('Access denied')
            bounds = calculate_provisioning_lease(descriptor=self._descriptor, policy=snapshot.policy,
                manifest=manifest, snapshot=snapshot.record, evidence=evidence,
                operator_sid=first.user_sid, now=certificate_time)
            self._deadline = min(started + snapshot.policy.authorization_seconds,
                certificate_mono + (bounds.valid_until-certificate_time).total_seconds())
            now, mono = self._clocks()
            if mono >= self._deadline or not bounds.valid_from <= now < bounds.valid_until:
                raise AuthorizationError('Access denied')
            proof = ProvisioningAuthorization(operator_id=first.user_sid,
                session_id=self._descriptor.bootstrap_anchor.provisioning_session_id,
                manifest_hash=record_digest(manifest), deployment_id=manifest.deployment_id,
                valid_from=bounds.valid_from, valid_until=bounds.valid_until)
            self._proof = canonical_bytes(proof)
            return proof
        except Exception:
            try:
                self._invalidate()
            finally:
                raise AuthorizationError('Access denied') from None

    def verify_commit(self, proof, *, database_path):
        """Pure live-state/clock check inside the writer transaction; no native I/O.

        The database pathname must match trusted host configuration. This does not
        validate its ACLs or pin SQLite/WAL/SHM files; deployment must protect those.
        """
        try:
            self._thread()
            now, mono = self._clocks()
            if (type(proof) is not ProvisioningAuthorization or self._proof is None
                    or canonical_bytes(proof) != self._proof or self._snapshot is None
                    or mono >= self._deadline or not proof.valid_from <= now < proof.valid_until
                    or type(database_path) is not str
                    or ntpath.normcase(database_path) != ntpath.normcase(self._descriptor.database_path)):
                raise AuthorizationError('Access denied')
            # Detect externally closed snapshots without touching the filesystem.
            self._snapshot.artifacts
        except Exception:
            # Do not perform handle cleanup while the database transaction is locked.
            self._proof, self._deadline = None, None
            raise AuthorizationError('Access denied') from None

    def close(self):
        if self._closed:
            return
        self._thread()
        self._closed = True
        try:
            self._invalidate()
        except Exception:
            raise AuthorizationError('Access denied') from None

    def __enter__(self):
        self._thread()
        return self

    def __exit__(self, *args):
        self.close()
