# Pure independent-checkpoint reconciliation contracts

`reconciliation_models.py` defines frozen envelope, request, acceptance, synthetic
evidence, relationship-result, and acceptance-result records. All are strict
canonical JSON using the existing normalization rules. The decoder accepts a
fixed type whitelist and at most 64 KiB per reconciliation record. Logical images
retain their existing sixteen-MiB / 256-event bounds.

An envelope binds a deployment, store-instance identifier, authority revision,
predecessor-envelope hash, issuer/key identifiers, validity interval, and exact
`UpdateStorageCheckpoint`. These issuer/key fields are data only: no signature
format or signature verification is implemented. Revision 1 uses a zero
predecessor hash; later revisions require a nonzero predecessor hash.

## Relationship classification

`classify_checkpoint_relationship(image, envelope, observed_store_instance_id=...,
evidence=..., now=...)` first validates synthetic evidence of the current envelope
and its freshness. It then checks the host-supplied observed store identity,
bounded canonical image, timestamps, and internal replay consistency.

For an image with at least the accepted event count, it reconstructs the exact
accepted prefix with the original base head and derives its resulting head from
the last prefix COMMIT. It compares the complete prefix checkpoint, not numerical
digest ordering. The outcomes are:

- MATCHED: exact logical image/checkpoint match, eligible only for further checks.
- DATABASE_EXTENSION_PENDING: exact accepted prefix and internally consistent
  suffix; independent acceptance still required.
- CHECKPOINT_AHEAD: fewer observed events than the supplied fresh checkpoint;
  rollback or data-loss suspicion, not proof of a particular cause.
- FORK_OR_MISMATCH: identity, prefix, or internal replay mismatch.
- INDETERMINATE: invalid/missing inputs, future observation times, or unavailable
  freshness evidence.

Every result is audit-only. Only MATCHED and DATABASE_EXTENSION_PENDING expose
bounded observation hashes/counts. No result returns an authorization token,
accepted successor envelope, or independently trusted checkpoint. Internally
derived checkpoints support consistency comparisons only.

Pending suffixes use a deterministic batch digest: SHA-256 over the v1 domain,
big-endian uint32 event count, then each canonical event preceded by its big-endian
uint64 byte length. The helper requires a nonempty bounded tuple and preserves
event order. Every event kind changes the image and participates in this binding.

The function receives logical records, not SQLite projections. It does not inspect
disk or authenticate observed store identity. Projection verification remains the
existing loader's responsibility; accepting an ahead image through that loader is
not implemented here.

## Historical acceptance binding

Requests bind the principal, deployment/store, stable request ID, exact expected
predecessor revision/hash, successor checkpoint, and suffix digest. Acceptance
records bind the exact request digest, successor envelope, predecessor, accepted
time, policy revision, and independent evidence digest.

`verify_reconciliation_acceptance(request, acceptance, evidence=..., now=...)`
requires synthetic current recovery scope before inspecting the acceptance. It
checks exact request/acceptance/evidence hashes, all cross-record bindings, and
validity at the historical acceptance time. Exact repeated checks return the same
acceptance hash. Changed requests conflict with the original evidence binding.
Expired historical envelopes/requests may still have valid archival bindings
under current recovery scope; future acceptance times are rejected.

VALID_BINDING is not VALID_ADVANCEMENT. This checker does not prove lineage,
evaluate an event batch, query the latest authority revision, execute compare-and-
swap, or permit an old envelope to be republished. Those are separate protocol
requirements. An old acceptance can be recovered without changing current state.

## Synthetic boundary

`SyntheticCheckpointEvidence` asserts a current independent envelope binding.
`SyntheticAcceptanceEvidence` combines a test assertion of an independent archival
binding with test current principal/request recovery scope. Real adapters must
establish both separately through authenticated sources. Caller-supplied hashes
cannot establish trust. Existing local update receipts and locator observations
cannot be substituted for these exact typed test records.

Tests cover prefix/hash disagreement, store/deployment substitution, all event
kinds, freshness and validity, historical retries and conflicting bindings,
canonical bounds, immutable result shape, and deterministic execution with file
opening and SQLite connections disabled. They do not prove external authority
authentication, non-atomic persistence reconciliation, CAS ordering, signed-file
distribution recovery, or whole-store rollback resistance.

No persistent writes, clocks, signing tools, networking, provider wiring, database
schema changes, or execution routes are added. Existing journal guards and real
ABC capture quarantine remain unchanged.
