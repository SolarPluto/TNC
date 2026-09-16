# TNC Windows Test Reliability Inventory

This document records intermittent or timing-sensitive Windows test surfaces so that a retry does not erase diagnostic evidence. It is an inventory, not a waiver: strict assertions remain strict until a mechanism is identified.

## Measurement semantics: process handle counts

The native Windows tests use `_NativeChecks.handles()` in `tests/test_windows_pipe_process.py`. The helper is a direct call to `GetProcessHandleCount(GetCurrentProcess(), ...)`. It has no completion drain, synchronization barrier, retry, or wait-for-stability step.

`GetProcessHandleCount` counts live entries in the process handle table. A `delta=1` observed after a user-facing `CloseHandle` therefore should not be described as delayed kernel-object destruction after the process handle was closed. At sample time, the extra count instead means that a process handle is still open, a new handle was created after the baseline and remains open, or a runtime mechanism closed/re-opened or otherwise introduced another live handle.

This makes whole-process `delta == 0` a deliberately strong invariant. Do not weaken it or add silent retries until failure-path instrumentation distinguishes a real leak, a sample-point race, and an invariant that is broader than the TNC-owned resources it intends to police.

## Recorded surfaces

### 1. CRL positive expiry boundary

- **Test:** `tests/test_provisioning_certificates.py::test_crl_expiry_boundary[1]` (historical parameterization; the positive case is now widened by #24).
- **Observed failure shape:** a CRL only one second beyond `pki.now` can become rejected after real wall-clock time advances. The controlled reproduction held `pki.now` fixed, slept three seconds, and then failed certificate validation with outer `CertificateVerificationError: Nominated certificate unavailable` caused by inner `CertificateVerificationError: Chain rejected`.
- **First preserved observation:** 2026-09-16, Actions run `35112451453` (controlled one-off reproduction; the earlier incidental flake's run ID was not preserved in this inventory).
- **Retry/reproduction:** the one-off wall-clock reproduction intentionally reproduced the failure. The stabilized test subsequently passed with a clearly-valid positive margin.
- **Status:** **fixed by #24**. The rejection anchors at offsets `0` and `-1` remain; the positive acceptance case uses a `+3600s` margin instead of `+1s`.
- **Relationship to handle-count semantics:** none known. This surface was a certificate/CRL wall-clock boundary issue, not a `GetProcessHandleCount` failure.

### 2. Native token capture `[impersonation]` handle count

- **Test:** `tests/test_windows_pipe_native_token.py::test_native_token_capture_and_reversion[impersonation]`.
- **Observed failure shape:** final cleanup reported `delta=1` where the test deliberately requires `delta == 0`.
- **First observed:** 2026-09-16. **Run ID: not recovered.** The observation was recorded as one failure in three attempts, with the reruns passing; no trustworthy Actions run ID was preserved, so this document does not invent one.
- **Retry/reproduction:** did not reproduce on the two reruns; the `identification` parameter did not reproduce it.
- **Status:** **pending investigation; documented by #26**. #26 keeps the strict `delta == 0` assertion and records the occurrence beside it.
- **Relationship to handle-count semantics:** this test samples the same unsynchronized whole-process handle count. The extra live handle may be a TNC leak, a still-running cleanup/finalizer path, or an unrelated/runtime handle present at the sample point. Do not assume its mechanism matches the `cancel_write` occurrence merely because both report `delta=1`.

### 3. Pending-I/O `cancel_write` handle count

- **Test:** `tests/test_windows_pipe_process.py::test_native_pending_io_cancellation_or_disconnect[cancel_write]`.
- **Observed failure shape:** the final close message was `{'kind': 'closed', 'delta': 1}` while the assertion expected `{'kind': 'closed', 'delta': 0}`.
- **First observed:** 2026-09-16, Actions run `35121176638`, attempt 1.
- **Retry/reproduction:** attempt 1 finished `1 failed, 3279 passed, 1 warning`; attempt 2 of the same run passed the full suite with `3280 passed, 1 warning`.
- **Status:** **pending investigation; no local test comment yet**. The failure was discovered while validating docstring-only #25 and is unrelated to that diff.
- **Relationship to handle-count semantics:** because this path exercises cancellation of pending overlapped I/O, its mechanism may differ from `[impersonation]` even though both report `delta=1`. A still-open event/pipe/runtime handle at the sample point is plausible, but must be identified rather than inferred.

## Next reliability investigation

The first reliability change should be **instrumentation-only**. Do not change invariants, add retry-based acceptance, or introduce synchronization as a fix before observing the extra handle.

On a `delta != 0` failure path, capture:

1. **Extra handle identity.** Enumerate the current process handle table, preferably with `NtQuerySystemInformation(SystemExtendedHandleInformation)`, and record enough type/name information to distinguish token, event, pipe, process/thread, section, and other handles.
2. **Persistence.** Sample the handle delta and identified extra handles at failure time **T**, **T+100ms**, and **T+1000ms**. Persistence to +1000ms is evidence against a short sample-point race; disappearance is evidence that steady-state synchronization may matter.
3. **Concurrent activity.** Record relevant worker/thread/finalizer state available to the test harness so a live handle can be correlated with pending async completion, thread cleanup, or runtime activity.

The evidence should determine the eventual fix:

- synchronize the measurement point if TNC-owned cleanup is still legitimately in flight;
- narrow the invariant to TNC-owned handle classes if unrelated process/runtime handles make whole-process equality overspecified; or
- fix a real leak if a TNC-owned handle remains persistently open.

Until that evidence exists, `delta == 0` remains intentionally strict.