"""Transactional temporary witness submissions with synthetic provider evidence.

No production authentication, signing, networking or checkpoint publication.
SQLite serializes this file; the provider gate coordinates only its own instance.
"""
from contextlib import closing, contextmanager
from dataclasses import dataclass
import math
import sqlite3
import threading
import time
from typing import Literal

from pydantic import model_validator
from tnc.provenance.authorization_models import Model, canonical_bytes
from tnc.provenance.external_witness_logic import (
    SyntheticWitnessPolicy, SyntheticCallerEvidence, SyntheticLineageEvidence,
    WitnessAdvanceRequest, authorized, checked, evaluate_witness_advance,
    policy_progress, valid_time, witness_digest,
)
from tnc.provenance.external_witness_store import TestExternalWitnessStore, WitnessStoreError, _rows


class WitnessWriterError(ValueError):
    """Fixed reason codes; no database or caller payload diagnostics."""


def _require(condition, reason):
    if not condition: raise WitnessWriterError(reason)


def _timeout(value):
    _require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 5, 'INVALID_INPUT')
    return value


def _copy(kind, value):
    _require(type(value) is kind, 'INVALID_INPUT')
    try: return checked(value)
    except ValueError: raise WitnessWriterError('INVALID_INPUT') from None


class TestWitnessProviderInputs(Model):
    """Caller evidence is a request-bound fixture, never a real credential."""
    __test__ = False
    policy: SyntheticWitnessPolicy
    caller: SyntheticCallerEvidence

    @model_validator(mode='after')
    def bindings(self):
        if self.caller.context != self.policy.context or self.caller.policy_digest != witness_digest(self.policy):
            raise ValueError('Synthetic input binding mismatch')
        return self


class TestWitnessPolicyProvider:
    __test__ = False

    def __init__(self, inputs):
        self._inputs = _copy(TestWitnessProviderInputs, inputs)
        self._lock = threading.RLock()
        self._generation = 0

    def snapshot_for_testing(self, *, timeout=1):
        with self._lease(_timeout(timeout)) as (inputs, _): return inputs

    def replace_for_testing(self, inputs, *, expected_inputs_digest, timeout=1):
        replacement = _copy(TestWitnessProviderInputs, inputs)
        with self._lease(_timeout(timeout)) as (current, _):
            _require(witness_digest(current) == expected_inputs_digest, 'POLICY_CONFLICT')
            _require(replacement.policy.context == current.policy.context, 'POLICY_CONFLICT')
            _require(policy_progress(current.policy, replacement.policy), 'POLICY_REGRESSION')
            self._inputs = replacement
            self._generation += 1

    @contextmanager
    def _lease(self, timeout):
        _require(self._lock.acquire(timeout=timeout), 'POLICY_BUSY')
        try:
            inputs = _copy(TestWitnessProviderInputs, self._inputs)
            generation, digest = self._generation, witness_digest(inputs)
            def recheck():
                _require(self._generation == generation and witness_digest(self._inputs) == digest, 'POLICY_CHANGED')
            yield inputs, recheck
        finally:
            self._lock.release()


@dataclass(frozen=True)
class WitnessWriteResult:
    status: Literal['SUCCESS', 'HISTORICAL_RECEIPT']
    receipt_bytes: bytes
    audit_only: Literal[True] = True
    signature_verified: Literal[False] = False


class TestExternalWitnessWriter:
    __test__ = False

    def __init__(self, path, *, trusted_initial, clock=None, busy_timeout=1, provider_timeout=1):
        self._store = TestExternalWitnessStore(path, trusted_initial=trusted_initial)
        self.path = self._store.path
        self._initial = self._store._initial
        self.busy_timeout = _timeout(busy_timeout)
        self.provider_timeout = _timeout(provider_timeout)
        self.clock = clock if clock is not None else lambda: time.time_ns() // 1_000_000_000

    def _hook(self, point):
        """Private test seams at logical transaction boundaries."""

    def _now(self, previous=None):
        now = self.clock()
        try: valid_time(now)
        except ValueError: raise WitnessWriterError('CLOCK_INVALID') from None
        _require(previous is None or now >= previous, 'CLOCK_REGRESSION')
        return now

    def submit(self, request, *, provider, evidence=None):
        attempted = False
        try:
            request = _copy(WitnessAdvanceRequest, request)
            _require(type(provider) is TestWitnessPolicyProvider, 'INVALID_INPUT')
            # Historical retries must not depend on validating original evidence.
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True,
                                         isolation_level=None, timeout=self.busy_timeout)) as db:
                db.execute('PRAGMA trusted_schema=OFF')
                db.execute('PRAGMA foreign_keys=ON')
                db.execute('PRAGMA synchronous=FULL')
                _require(db.execute('PRAGMA synchronous').fetchone() == (2,), 'INVALID_WITNESS_STORE')
                db.execute('BEGIN IMMEDIATE')
                try:
                    self._hook('locked')
                    with provider._lease(self.provider_timeout) as (inputs, check_provider):
                        now = self._now()
                        caller, policy = inputs.caller, inputs.policy
                        _require(request.context == self._initial.context and
                            (authorized(request, caller, policy, 'advance', now) or
                             authorized(request, caller, policy, 'recovery', now)), 'UNAUTHORIZED_CLIENT')
                        before = self._store._load(db, now=now)
                        # Detect an exact retry before interpreting optional lineage.
                        existing = any(r.request.request_id == request.request_id for r in before.receipts)
                        lineage = None if existing or evidence is None else _copy(SyntheticLineageEvidence, evidence)

                        def evaluate(at):
                            result = evaluate_witness_advance(before, request, trusted_initial=self._initial,
                                caller=caller, policy=policy, evidence=lineage, now=at)
                            _require(result.status in ('SUCCESS', 'HISTORICAL_RECEIPT'), result.status)
                            return result

                        result = evaluate(now)
                        new = result.status == 'SUCCESS'
                        receipt = result.receipt
                        expected = result.proposed_image if new else before
                        if new:
                            rows = _rows(expected)
                            row = rows['witness_receipts'][-1]
                            db.execute('INSERT INTO witness_receipts VALUES (?,?,?,?,?,?,?,?)', row)
                            self._hook('receipt_inserted')
                            for table in ('witness_image', 'witness_head'):
                                columns = [r[1] for r in db.execute(f'PRAGMA table_info({table})')]
                                db.execute(f"UPDATE {table} SET {','.join(c+'=?' for c in columns[1:])} WHERE id=1", rows[table][0][1:])
                            self._hook('image_written')

                        def guard(previous):
                            current_time = self._now(previous)
                            check_provider()
                            # Always re-evaluate against PRE-APPEND image. A new
                            # acceptance must not acquire historical-retry semantics.
                            current = evaluate(current_time)
                            _require(current.status == result.status, 'INVALID_WITNESS_STORE')
                            if new:
                                _require(current.receipt.request == receipt.request and
                                    current.receipt.resulting_state.head == receipt.resulting_state.head,
                                    'INVALID_WITNESS_STORE')
                            else:
                                _require(canonical_bytes(current.receipt) == canonical_bytes(receipt), 'INVALID_WITNESS_STORE')
                            return current_time

                        self._hook('before_recheck')
                        final_now = guard(now)
                        _require(self._store._load(db, now=final_now) == expected, 'INVALID_WITNESS_STORE')
                        raw = db.execute('SELECT receipt FROM witness_receipts WHERE request_id=?',
                                         (request.request_id,)).fetchone()[0]
                        _require(raw == canonical_bytes(receipt), 'INVALID_WITNESS_STORE')
                        self._hook('before_commit')
                        commit_now = guard(final_now)
                        if new:
                            attempted = True
                            db.execute('COMMIT')
                            self._hook('after_commit')
                        else:
                            # Historical lookup deliberately changes no table.
                            db.execute('ROLLBACK')
                            self._hook('after_retry')
                        guard(commit_now)
                        return WitnessWriteResult(result.status, raw)
                except BaseException:
                    if db.in_transaction: db.execute('ROLLBACK')
                    raise
        except Exception as error:
            if attempted: raise WitnessWriterError('OUTCOME_UNKNOWN') from None
            if isinstance(error, WitnessWriterError): raise
            if isinstance(error, WitnessStoreError):
                raise WitnessWriterError('INVALID_WITNESS_STORE') from None
            if isinstance(error, sqlite3.Error) and getattr(error, 'sqlite_errorcode', 0) & 255 in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise WitnessWriterError('STORE_BUSY') from None
            raise WitnessWriterError('INVALID_WITNESS_STORE') from None
