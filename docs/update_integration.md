# Authenticated update evaluation adapter

`AuthenticatedUpdateEvaluator` integrates live identity verification, explicit
installer permission checks, pinned provider state, Ed25519 verification, and pure
transition evaluation. Every output has `audit_only=True`. No write, signing,
pointer replacement, process control, network route, or startup path is added.

## Request and host providers

`UpdateEvaluationRequest` accepts only the action, full canonical intent, and an
optional signature envelope. Its decoder enforces a one-MiB limit. Extra fields
for identity, authority heads, preparation, drain, or trust checkpoints are rejected.
Without a supplied signature, pending/new evaluation requires the signature from
the trusted provider snapshot; committed recovery uses the archive's exact signature.

The constructor takes four trusted host providers:

- Identity: `verify()` returns a freshly verified `VerifiedIdentity`. Its shape is
  compatible with existing transport verification; this module does not create a
  listener or authenticate a client-supplied identity record.
- Permission: `resolve()` returns a deployment-, operation-, principal-, and
  transport-credential-bound permission snapshot; `is_current()` checks freshness.
- State: `read()` returns one consistent authority/operation/trust/archive snapshot;
  `is_current()` must detect a change to any bound authority or trust revision.
- Observation: returns explicitly synthetic preparation/drain/locator evidence for
  this audit integration. No real process-drain provider is implemented.

These interfaces specify provider obligations. No durable consistent-snapshot
backend or production installer permission provider is supplied by this milestone.
Provider implementations must be trusted host code, never request callbacks.
Snapshot records are limited to four MiB; other integration records to one MiB.

## Permission and identity separation

The new local permission contract uses `UPDATE_EVALUATE` and
`UPDATE_RECOVER_OWN`. It does not extend production grants or reinterpret
`host.manage` as installer authority. The live caller must equal the intent's
publisher. The transport credential and registry revision must match the permission
snapshot. These checks occur before reading authority/operation state.

RECOVER requires recovery permission. Other evaluations require evaluation
permission; returning an existing committed operation additionally requires
recovery permission. Missing and foreign operations yield the same generic denial
on recovery. No rejected result contains a proposal, receipt, or snapshot revisions.

mTLS certificate fingerprints identify the transport credential. Ed25519 SPKI
digests identify signing keys. They are bound through the authorized principal,
never compared as interchangeable hashes.

## Checked claims and shared transition logic

For new work the adapter computes CURRENT signature verification internally.
For committed work it verifies the exact archive-bound HISTORICAL signature and
separately enforces the current caller's permission. Historical verification alone
cannot grant access. A supplied conflicting signature is rejected during recovery.

Only after those checks does the adapter construct internal
`InstallerEvidenceClaims` and call the shared private transition evaluator.
`SyntheticInstallerEvidence` remains the input to the original public pure-test
API. The two paths share rules; they do not silently relabel synthetic evidence as
verified credentials. Neither Python record is a security capability against
untrusted code running inside the host process.

Preparation and drain remain explicitly synthetic observations. A COMMIT action
only evaluates a proposal. For exact committed retries, recorded evidence and the
original receipt are reused without requesting another drain or proposing a new
head. PUBLISH only evaluates a locator observation.

## Freshness and output

The adapter verifies provider freshness before evaluation and again before
returning data. It re-verifies the live transport identity, checks credential,
connection and registry continuity, verifies current signature validity again
where applicable, and reevaluates transitions at the final trusted clock time.
Clock rollback, expiry, or changed provider state discards the proposal.

Success returns the immutable proposal, current provider/permission/trust revisions,
and signature mode. Proposal contents can include the caller's authorized operation
and receipt; sensitive internal exception details and trust-store contents are not
included. Denials use fixed coarse reasons.

These checks detect changes reported during an audit. They are not a lock or atomic
release authorization; state may change after the final check. A future write
backend must recheck authority and expected heads under its serialized commit
protocol. Nothing here permits skipping that requirement.

## Tests

Tests use real temporary Ed25519 signatures with controlled identity, permission,
snapshot, and observation providers. They cover complete proposal flow, early
permission denials, identity/key separation, revocation, stale snapshots, exact
retries, rotated transport credentials, archive failures, drain/expiry rejection,
and request evidence injection. Existing pure transition tests continue to pass.
No new live mTLS listener, persistent store, service drain, or machine deployment
is exercised or enabled by this test suite.
