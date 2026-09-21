# TNC Windows Test Reliability Inventory

**As of 2026-09-16.** Update this inventory as reliability investigations progress, fixes accumulate validation runs, or new flaky surfaces are observed.

This document records intermittent or timing-sensitive Windows test surfaces so that a retry does not erase diagnostic evidence. It is an inventory, not a waiver: strict assertions remain strict until a mechanism is identified.

## Measurement semantics: process handle counts

The native Windows tests use `_NativeChecks.handles()` in `tests/test_windows_pipe_process.py`. The helper is a direct call to `GetProcessHandleCount(GetCurrentProcess(), ...)`. It has no completion drain, synchronization barrier, retry, or wait-for-stability step.

`GetProcessHandleCount` counts live entries in the process handle table. A `delta=1` observed after a user-facing `CloseHandle` therefore should not be described as delayed kernel-object destruction after the process handle was closed. At sample time, the extra count instead means that a process handle is still open, a new handle was created after the baseline and remains open, or a runtime mechanism closed/re-opened or otherwise introduced another live handle.

This makes whole-process `delta == 0` a deliberately strong invariant. Do not weaken it or add silent retries until failure-path instrumentation distinguishes a real leak candidate, a sample-point race, and an invariant that is broader than the TNC-owned resources it intends to police.

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
- **First observed:** 2026-09-16. **Run ID: not recovered.** The provenance is a deliberate three-attempt window around that occurrence on 2026-09-16: one failure followed by two passing reruns. It is **not** a repository-wide flake-rate estimate. No trustworthy Actions run ID for that window was preserved, so this document does not invent one.
- **Retry/reproduction:** did not reproduce on the two reruns; the `identification` parameter did not reproduce it.
- **Status:** **pending investigation; documented by #26**. The code-level record is the inline comment immediately above the strict assertion in `tests/test_windows_pipe_native_token.py`; that comment points back to this inventory as the authoritative cross-surface record.
- **Relationship to handle-count semantics:** this test samples the same unsynchronized whole-process handle count. The extra live handle may be a TNC leak, a still-running cleanup/finalizer path, or an unrelated/runtime handle present at the sample point. Do not assume its mechanism matches the `cancel_write` occurrence merely because both report `delta=1`.

### 3. Pending-I/O `cancel_write` handle count

- **Test:** `tests/test_windows_pipe_process.py::test_native_pending_io_cancellation_or_disconnect[cancel_write]`.
- **Observed failure shape:** the final close message was `{'kind': 'closed', 'delta': 1}` while the assertion expected `{'kind': 'closed', 'delta': 0}`.
- **First observed:** 2026-09-16, Actions run `35121176638`, attempt 1.
- **Retry/reproduction:** attempt 1 finished `1 failed, 3279 passed, 1 warning`; attempt 2 of the same run passed the full suite with `3280 passed, 1 warning`.
- **Status:** **pending investigation**. A code-level comment immediately above the strict assertion in `tests/test_windows_pipe_process.py` points to this inventory; the failure was discovered while validating docstring-only #25 and is unrelated to that diff.
- **Relationship to handle-count semantics:** because this path exercises cancellation of pending overlapped I/O, its mechanism may differ from `[impersonation]` even though both report `delta=1`. A still-open event/pipe/runtime handle at the sample point is plausible, but must be identified rather than inferred.

## Current handle-count instrumentation

Native handle-count producers now keep `_NativeChecks.handles()` as the raw `GetProcessHandleCount` primitive and use a separate failure-path sampler before the measured child exits. The sampler takes the original **T** measurement immediately. If `delta == 0`, it returns without sleeping or changing happy-path timing. If `delta != 0`, it samples again at approximately **T+100ms** and **T+1000ms** using a monotonic elapsed-time clock.

The child reports the original delta and the persistence samples to the parent. The parent removes the diagnostic field before evaluating the existing assertion, so the assertion expression and expected payload shape remain unchanged. When the assertion is specifically failing with a nonzero handle delta, the parent attaches the samples to the original `AssertionError` with `BaseException.add_note()` and re-raises the same exception.

Interpret persistence conservatively:

- **nonzero at T, zero later:** transient handle-count behavior; the original strict assertion still fails and the later zero is diagnostic only;
- **nonzero through T+1000ms:** a persistent handle-count difference and therefore a stronger leak candidate, but **not a confirmed leak** until handle ownership/type is identified;
- **fluctuating values** such as `1 -> 2 -> 0`: concurrent handle activity occurred during the diagnostic window and should be recorded rather than smoothed into a monotonic story.

The sampler runs in the measured child because parent-side persistence sampling would be meaningless once that child exits. Tests that only assert a control-message kind, rather than a handle-count invariant, discard the diagnostic transport field and do not attach handle notes to unrelated failures.

Synthetic tests force the nonzero sampler path and the parent annotation path so the diagnostic machinery is exercised without waiting for an intermittent CI failure.

## Python runtime handles and strict process baselines

Windows `GetProcessHandleCount` observes kernel-backed handles created by the Python runtime as well as handles opened explicitly by TNC native adapters. Resource-owning objects that remain alive at the measurement point can therefore move a strict process baseline even after their explicit native cleanup has completed. In particular, synchronization and worker primitives such as `threading.Lock`, `threading.Event`, `threading.Semaphore`, `threading.Condition`, `queue.Queue`, `multiprocessing` primitives, and `concurrent.futures` executors may allocate Windows kernel objects depending on the CPython implementation and version.

On Python 3.12.10 for Windows, a direct `GetProcessHandleCount` probe around `threading.Lock()` observed one additional handle at construction, no further change across acquire/release, and return to baseline only after the lock object was deleted and collected. This means a strict `delta == 0` assertion can correctly detect a new per-instance runtime handle even when there is no leaked pipe, process, token, or overlapped-I/O handle.

Do not weaken the strict invariant or force garbage collection to hide such changes. Prefer designs that keep long-lived synchronization resources outside per-instance native-resource accounting when that preserves the same locking semantics, and verify the affected native tests return to exact `delta == 0` after any change. Treat that rerun as a residual audit: a remaining nonzero delta means another kernel-backed allocation or cleanup defect is still present.

## Handle identity escalation

Do not treat the persistence sampler as the fix. Its purpose is to determine whether the next observed nonzero delta is transient, persistent, or fluctuating while preserving the strict invariant.

The native-token surface can also take three current-process handle snapshots with `NtQuerySystemInformation(SystemExtendedHandleInformation)`: immediately before inspector construction, immediately after the primary inspect/capture outcome and before retry/probe work, and immediately after cleanup. Internally each snapshot retains `(handle value, object pointer)` only as an opaque equality identity so numeric handle-slot reuse does not hide a survivor. The object pointer never leaves the snapshot/analysis path and is never emitted in notes, artifacts, or assertion data. Enumeration is opt-in via `TNC_HANDLE_ENUMERATION=1`; normal CI leaves it disabled so the strict handle-count assertion and cheap persistence sampler retain their prior timing. The pre-cleanup placement intentionally excludes the boundary-consumption retry from inspect-phase attribution. For identity sets `baseline`, `pre_cleanup`, and `post_cleanup`, diagnostics report handle values for:

- `added_during_inspect = pre_cleanup - baseline`;
- `released_by_cleanup = pre_cleanup - post_cleanup`; and
- `persisted_past_cleanup = post_cleanup - baseline`.

Normally `persisted_past_cleanup == added_during_inspect - released_by_cleanup`. A difference is reported separately as a cleanup-originated survivor rather than being mislabeled as an inspect leak. If the same numeric handle value exists at baseline and post-cleanup but maps to a different object identity, the diagnostic names that case explicitly as `prior instance closed, new instance opened (different object)`. This is the main reason the pre-cleanup snapshot exists: it localizes the phase that created the surviving handle instance instead of collapsing slot reuse into a false pre-existing match.

Only a failing strict handle-count assertion triggers metadata resolution. Strict survivors receive `ObjectTypeInformation`; TOKEN survivors additionally receive `TokenType` and, for impersonation tokens, `TokenImpersonationLevel`. A handle that returns `STATUS_INVALID_HANDLE` during this later resolution is retained in the note as "vanished between snapshot and resolution": it was live at the post-cleanup snapshot even if asynchronous cleanup closed it milliseconds later. Baseline/post-cleanup overlap is type-checked only for the special suspicious case where a TOKEN occupies a value that predates inspector work, which can indicate reuse or unexpected pre-existing token state.

Enumeration and metadata are supporting evidence only. Buffer negotiation failures, `NtQuerySystemInformation` failures, unexpected `NtQueryObject` errors, or other diagnostic exceptions are converted into an `enumeration unavailable: <reason>` note; they never replace the original assertion failure. The original `GetProcessHandleCount` delta at T remains the test signal and `delta == 0` remains unchanged. Each enabled enumeration logs its elapsed time even on a passing path so runner-specific cost or blocking is observable.

### Snapshot-cost attribution and validation

Run `35341483523` measured **26-34 seconds end-to-end per snapshot**, including allocation, native buffer negotiation, and Python parsing. Its ~155 current-process handles were the result of PID filtering, not the system table's entry count. The run did not measure native-call duration separately, and therefore did not establish a 26-34 second syscall cost or an inherent shared-runner limitation. The opt-in native-token job did fail before producing survivor evidence (`DEADLINE_OR_CLOCK`, a 60-second control timeout, and changed fatal-worker exit paths); the enumeration-disabled suite passed.

The parser in that version evaluated `buffer.raw[start:start + entry_size]` inside the per-system-entry loop. `buffer.raw` copies the entire allocation each time, making copying approximately quadratic as the system handle table grows. The corrected parser uses `from_buffer_copy(buffer, start)` and reads the header directly from the buffer. The initial 64 KiB allocation and eight-attempt negotiation remain unchanged for measurement comparability, with an added 64 MiB allocation cap. The next allocation uses `max(2 * size, ReturnLength + 4096)`, not blind doubling; two native calls are common but are not guaranteed if the table changes. Returned lengths and table bounds are checked before parsing.

Each enabled snapshot now logs pointer-free metrics: `query_calls`, `resize_retries` (length-mismatch responses), per-call duration/status/allocated and returned bytes, aggregate `query_ms`, `parse_ms`, `total_ms`, system-entry count, and filtered process-handle count. Total time also includes allocations and Python bookkeeping; it is not relabeled as syscall time. Partial metrics are retained on unavailable/error paths. Unexpected exception text is not serialized because it could include an opaque address.

`SystemExtendedHandleInformation` and its extended-entry layout are NT-internal, not a stable public Windows ABI contract. Microsoft warns that [NtQuerySystemInformation may change or become unavailable](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation); a future version/layout failure must be reported as unavailable evidence, not treated as a TNC leak. Before reading any entry, the parser requires a nonzero `ReturnLength`, checks it against allocation capacity, and requires `header_size + count * sizeof(entry) == ReturnLength`. Zero returned length is rejected outright; allocation size is never substituted for payload size. A shorter payload is reported as truncated; unexplained extra payload is reported as `table extent mismatch; unsupported layout`. Oversized allocations are allowed when the reported payload has the exact expected extent. This is a sanity check, not ABI verification: same-size field rearrangements remain undetectable, and the parser does not guess a new stride.

Ordinary native-token CI remains enumeration-disabled and keeps the strict original T assertion, baseline-relative lifecycle count deltas, and T/+100ms/+1000ms count samples. Lifecycle deltas describe net changes across intervals, not the identity, owner, or cause of any particular handle. In particular, the post-inspect interval includes retry/probe work as well as cleanup.

`tests/test_windows_handle_enumeration.py` validates the diagnostic without waiting for a random flake. Synthetic cases cover PID filtering, offset-only parsing (the `.raw` accessor is forbidden), resize negotiation, bounds/status/exception failures, set algebra, slot reuse, TOKEN type/levels, and handles vanishing after a snapshot. The copy regression uses a real ctypes array filled by `memmove`, not a Python buffer fake, and leaves `from_buffer_copy` unmocked. Additional synthetic payloads include zero returned length, enlarged entries, and trailing bytes; they must return unavailable evidence before even the first entry is parsed. Exact empty/nonempty payloads in oversized allocations must still succeed. Both the real assertion-note helper and the separate evidence-file writer are checked for decimal and hexadecimal synthetic pointer leakage. A baseline handle absent from the post snapshot is released, not a resolution-time disappearance; an overlap handle still present in the post snapshot may subsequently vanish and is explicitly recorded.

One Windows-only self-test runs in a disposable subprocess with a 60-second parent timeout. Only that child enables enumeration. It takes three real snapshots around test-owned event handles, deliberately retains handles to produce nonzero T, closes one after the post snapshot to force the vanished path, verifies the strict assertion note and evidence file, and closes every remaining owned handle in `finally`. It emits timing metrics even on success. This isolated test is not a return of enumeration to the pipe/inspector critical path, nor a nightly workload. Run it locally with:

```powershell
uv run pytest -q -s tests/test_windows_handle_enumeration.py::test_native_enumeration_self_test
```

A passing self-test establishes the controlled Event/vanished/output paths, not the intermittent leak's cause or every native object class. TOKEN metadata and numeric-slot reuse are exercised synthetically, not claimed as real native TOKEN/reuse captures. Treat the chosen **100ms total snapshot budget** under representative system load as the criterion for reconsidering in-lifecycle use; the self-test reports `snapshot_budget_met` separately from functional success rather than hiding slow samples or turning timing variability into a test failure. A single fast result is not a universal performance guarantee. No decision to re-enable ordinary CI enumeration follows automatically.

#### First controlled Windows result (before exact-extent guard)

On 2026-09-19, run `35448301113`, attempt 1, completed **3309 passed in 856.64s** on PR head `0d35d4d83dc0e285dfe7eb63f782d00a8727e443` (Actions tested merge ref `fcd729ad9b70d90e1e77820e8e5c49c9a42b7a14`). Both `pytest-windows` and `text-hygiene` passed. The host was Windows Server 2025, build 26100, runner image `windows-2025-vs2026` version `20260907.229.1`, Python 3.12.10.

| Snapshot | System entries | Process handles | Native calls / mismatches | Query ms | Parse ms | Total ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 46308 | 148 | 2 / 1 | 4.0093 | 18.2382 | 22.7885 |
| Pre-cleanup | 46311 | 151 | 2 / 1 | 3.0719 | 19.3594 | 23.0070 |
| Post-cleanup | 46310 | 150 | 2 / 1 | 3.3186 | 18.8882 | 22.7967 |

Each successful native response reported exactly `16 + 40 * system_entries` bytes (1852336, 1852456, 1852416), independently of the larger allocation. This is an observed compatible payload, not a guarantee about other Windows versions. The controlled test observed `T=2, +100ms=1, +1000ms=1`, with three added instances, one released instance, and two post-cleanup candidates. It identified the retained Event, recorded the deliberately vanished handle, checked both the assertion note and evidence file for pointer leakage, and reported `snapshot_budget_met=true`. The evidence file was checked in the test's temporary directory; no workflow artifact uploader was added.

This run demonstrates the copy fix and controlled diagnostic paths under this runner's load. It predates the exact-extent guard, so it does not validate that amendment. All three snapshots met the reported 100ms target, but this does not establish busy-day performance, diagnose the original intermittent flake, or authorize enabling enumeration in ordinary native-token CI. The guard amendment requires its own fresh Windows run.

Gating enumeration only after a count mismatch cannot preserve the frozen three-snapshot identity algebra: by the time the final mismatch is known, the pre-inspect object identities no longer exist retroactively. A post-failure enumeration could identify current handles but could not reliably distinguish pre-existing instances, inspect-created survivors, cleanup-created survivors, or numeric slot reuse.

Handles absent from the post-cleanup snapshot are excluded from the survivor set. A runtime handle present only in that final snapshot is still a candidate; set algebra does not identify ownership or filter all unrelated activity. Identical handle/object-pointer pairs also cannot rule out reuse of both the slot and the object address. Interpret this evidence conservatively without adding synchronization to make a strict failure disappear.

The evidence should determine the eventual fix:

- synchronize the measurement point if TNC-owned cleanup is still legitimately in flight;
- narrow the invariant to TNC-owned handle classes if unrelated process/runtime handles make whole-process equality overspecified; or
- fix a real leak if a TNC-owned handle remains persistently open.

## Zero-step Actions failures

A GitHub Actions job that completes in a few seconds with `steps: []`, `runner_id: 0`, and an empty runner name failed before any runner executed workflow logic. When the same shape appears across independent jobs and runner labels, do not start by debugging pytest or individual workflow steps.

Use this discriminator first:

1. Create a scratch branch from the default branch.
2. Add a minimal independent push-triggered workflow with one `ubuntu-latest` job that only runs `echo hello`.
3. Push once and inspect the resulting job.

Interpretation:

- if the smoke job receives a real runner and executes steps, the original workflow is implicated; inspect workflow schema, expressions, `needs:`, permissions, environment references, reusable workflows, and trigger structure;
- if the smoke job also finishes with zero steps and `runner_id: 0`, the failure is upstream of workflow content; investigate account/repository Actions state such as included minutes or spending limits, Actions enablement/policy, organization restrictions, account holds, or a GitHub-hosted runner provisioning incident.

This smoke test is the preferred first discriminator because it separates workflow-content failures from account/repository runner-provisioning failures with one minimal run. Do not repeatedly retry an unchanged zero-step workflow after the shape has reproduced.

## What not to do

Until the instrumentation identifies the mechanism, do **not**:

- silently narrow or weaken `delta == 0` assertions;
- add retry-until-zero behavior to `_NativeChecks.handles()` or its callers;
- mark these tests flaky, xfail, skip-on-failure, or otherwise convert an unexplained failure into acceptance;
- widen timing/sample windows merely to make the failure disappear; or
- assume two `delta=1` surfaces share a mechanism without matching handle identity and persistence evidence.

Those changes can erase the distinction between a real TNC-owned leak, cleanup that is still legitimately in flight, and an invariant that is measuring unrelated process/runtime handles.

Until that evidence exists, `delta == 0` remains intentionally strict.
