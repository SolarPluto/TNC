"""Transient host-process handoff, never an exported authorization credential."""
import os
from threading import Lock, get_ident
from time import monotonic

_MINT = object()


class ObservationHandoff:
    __slots__ = ('_owner', '_connection', '_raw', '_binding', '_deadline', '_pid', '_thread', '_used', '_lock')

    def __init__(self, key, owner, connection, raw, binding, deadline):
        if key is not _MINT:
            raise TypeError('Host-created handoff required')
        for name, value in dict(_owner=owner, _connection=connection, _raw=raw,
                _binding=binding, _deadline=deadline, _pid=os.getpid(),
                _thread=get_ident(), _used=False, _lock=Lock()).items():
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise TypeError('Immutable handoff')

    def __reduce_ex__(self, protocol):
        raise TypeError('Handoff serialization is forbidden')

    def __copy__(self):
        raise TypeError('Handoff copying is forbidden')

    def __deepcopy__(self, memo):
        raise TypeError('Handoff copying is forbidden')

    def _take(self, owner, connection):
        # Burn every consumption attempt, including detached or expired attempts.
        with self._lock:
            if self._used:
                raise ValueError('Invalid handoff')
            object.__setattr__(self, '_used', True)
            if (self._owner is not owner or self._connection is not connection
                    or self._pid != os.getpid() or self._thread != get_ident()
                    or monotonic() >= self._deadline):
                raise ValueError('Invalid handoff')
            return self._raw, self._binding, self._deadline


def _mint(owner, connection, raw, binding, deadline):
    now = monotonic()
    if now >= deadline:
        raise ValueError('Expired handoff')
    return ObservationHandoff(_MINT, owner, connection, raw, binding, min(deadline, now + 5.0))
