# Native-shaped peer evidence audit bridge

`windows_pipe_auth_bridge.py` compares token capture records and host-supplied
correlation records against independent policy and read bindings. It uses the
existing `windows_custody_peer.py` field comparisons; it does not introduce the
nonexistent `windows_pipe_peer_policy.py` engine or relabel native claims as fake
Windows observations.

## Explicit audit boundary

The bridge is pure. It opens no handles, queries no usernames, reads no clocks,
loads no configuration, and evaluates no live grants. Source labels and frozen
records are not attestations: a caller can construct them. Results always carry
`audit_only=True`, `authorization_granted=False`, and `grants_evaluated=False`.
The result profile permits only `VIOLATIONS` and `INDETERMINATE`. Matching fields
do not create an authorization token or reusable handoff.

`NativePeerAuditPolicy` wraps the existing identity policy with an explicit
integrity floor of at least medium (8192). `PeerReadBinding` independently retains
the expected operation ID and preamble digest. `PeerCorrelationAudit` records
before/after process, endpoint, and security descriptor observations and a UTC
epoch observation time. These are bounded audit inputs, not a replacement for a
future acquisition adapter holding and checking real process handles. The bridge
uses no PID-to-username lookup and does not infer identity from a friendly name.

## Comparisons and quarantine

Exact model types are reconstructed through bounded canonical validation,
including nested values. Missing/failed/fake capture, malformed inputs, and
invalid clocks yield sanitized indeterminate results. Read bindings must match
exactly. Process observations must agree and remain running; endpoint observations
must agree and identify a local server end; descriptor observations must agree.

AppContainer reports, either restriction indicator, and integrity below the
explicit floor are denied. `TokenHasRestrictions` is filtering history; it is
kept distinct from restricting SIDs and conservatively denied in this profile.
This can deny ordinary filtered operator tokens and is intentional. The v1
identification-level requirement is preserved; it is not silently broadened to
accept impersonation or delegation tokens.

The shared identity comparison enforces time, deployment/store/pipe scope, exact
protected DACL, expected process lifetime/session, user SID, logon SID, and
authentication LUID. The old fake evaluator retains its prior behavior and source
type. Native-shaped input is never wrapped in a `WindowsPeerObservation`.

Finally, otherwise matching records return
`INDETERMINATE / APP_CONTAINER_EXCLUSION_UNPROVEN`. Current `CapturedTokenFacts`
explicitly fixes exclusion proof to false. A false reported flag cannot be
upgraded into proof for an identification-level token. A later reviewed policy
and acquisition contract must resolve this limitation before admission is possible.

## Tests and remaining integration

43 new tests cover sandbox and identity mismatches, process/endpoint changes,
descriptor checks, read binding, exact clocks, scope, forged nested models,
untrusted object rejection, immutable results, and side-effect guards. The 59
existing fake policy tests continue to pass after extracting shared comparisons.

This milestone does not connect the bridge to a live transport worker. Retained
native process-handle correlation, mutual server authentication, sandbox-exclusion
evidence, and a separately authorized live-grant gate remain pending. Signing
and custody remain disconnected. Host-supplied timestamps do not create a native
freshness guarantee, and same-process or privileged compromise is not addressed.
