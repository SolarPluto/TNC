# Pure bootstrap and administration-ledger contracts

This layer defines records and validates historical administrative authority. It
does not write to SQLite, enable version 4, authenticate an OS operator, verify a
certificate, expose transport routes or grant real permissions.

## Typed records and encoding

`authorization_models.py` defines frozen, extra-forbidden models for the four
administrative payloads, provisioning and ordinary actors, BootstrapManifest,
BootstrapReceipt/Record, a host trust anchor and an authorization checkpoint.

The manifest binds deployment/service identity, source version-3 legacy checkpoints,
trust/policy digests, its validity window, one initial enrollment and one host.manage
grant. The seed grant must belong to the initial credential's principal. There is
no implicit review, replay or worker grant.

Canonical encoding uses sorted compact UTF-8 JSON and UTC timestamps with exactly
six fractional digits and Z. Decoding requires byte-for-byte canonical equality,
rejecting duplicate JSON keys, extra fields, non-finite numbers, alternative spacing,
timestamp spellings and invalid UTF-8. Digest fields are lowercase SHA-256 hex;
sequence and version fields reject boolean/float/string substitutes.

Event hashes are SHA-256 of the canonical complete event with entry_hash set to
64 zeros. Receipt hashes use the same convention for receipt_hash. Seed events
bind the manifest digest; the receipt binds both final seed event hashes, avoiding
a circular hash. These are unkeyed integrity hashes, not signatures.

## Validation contract

`validate_authorization_ledger(events=..., bootstrap=..., trust_anchor=...,
checkpoint=...)` takes a tuple of events and returns immutable credential/grant
state with its checkpoint. It performs no I/O and consults no wall clock. Input
objects are reconstructed and validated, including nested model_copy/model_construct
values. Invalid inputs raise AuthorizationValidationError.

The trust anchor and checkpoint are required independent protected-host inputs.
Do not derive them from the same untrusted ledger being checked. The anchor binds
the deployment, reviewed manifest digest, provisioning operator/session and bounded
provisioning interval. The validator checks those bindings; it cannot prove the
operator's OS identity, certificate validity, trust configuration or actual source
database. Real adapters must establish those facts before supplying the anchor.

The sequence must begin at 1, remain contiguous, have unique event IDs and match
both its chained hashes and supplied terminal checkpoint. Events are consumed in
provided sequence order, never sorted by timestamp. Recorded times may be equal
but cannot move backwards. A writer facing a backwards host clock must reject or
wait through a separately defined policy, not backdate an event silently.

Exactly events 1 and 2 may use the provisioning actor. They must equal the manifest's
enrollment and host.manage grant, at the receipt's provisioning time, bound to the
exact operator/session/manifest. Both seed credential and permission must be valid
at that time. Empty v3 state is not a valid bootstrapped ledger.

For every later event, the validator uses the prior ledger prefix. Its actor must
have an enabled exact credential bound to that principal and a named, unrevoked,
currently valid host.manage grant. The recorded session must cover the event time,
stay within credential validity, be at most five minutes long and bind the previous
registry revision. The expected head must match that same previous sequence/hash.

Host.manage includes unrestricted grant administration in this initial design.
It does not itself authorize review or replay execution. Narrower delegation or
dual approval is not implemented.

## Lifecycle rules

- A fingerprint can be enrolled only once and cannot be reassigned. Disablement
  references the exact enrollment sequence and is terminal. Rotation enrolls a new
  fingerprint explicitly, which may retain the same principal.
- A grant ID can be used only once. Revocation references its exact grant sequence;
  it does not expose an older positive state. Other independent grants remain valid.
- Grants require a known enrolled principal. Future-dated credentials and grants
  may be recorded before activation, but already expired new records are rejected.
  Granting a known disabled principal is not re-enrollment and cannot bypass the
  actor credential check.
- Self-disablement and self-revocation are valid when authorized before the event.
  Later actions require a different active credential/grant. There is no automatic
  last-administrator rescue or bootstrap reuse.

The returned state retains disabled credentials and revoked grants for audit.
Permission validity is checked at each historical event time, so old valid history
does not become corrupt merely because a credential expires today. The caller must
still evaluate current authority for new operations. This output is not a live
AuthorizationStateReader or database authorization writer.

## Verification and remaining work

61 unit cases cover canonical encoding/decoding, seed semantics (including mutated
but rehashed seeds), external anchor mismatch, actor/session/revision binding,
credential rotation, grant independence, terminal lifecycle rules, expected heads,
sequence integrity, checkpoint truncation, time boundaries and immutable models.
Synthetic anchors are explicitly test data, not authenticated provisioning.

These models and the pure validator are not yet installed as a database codec.
Version-3 closed-write guards remain unchanged. A future version-4 migration/writer
must validate SQL projections, trusted operator/session evidence, append idempotency,
atomic bootstrap and transaction-scoped authority. Existing real ABC captures gain
no approvals. Passing unit tests are evidence for these rules, not a formal proof
or protection against wholesale replacement of both ledger and trusted checkpoint.
