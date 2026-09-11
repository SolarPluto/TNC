# Durable request journal manager

`tnc.provenance.request_journal.RequestJournalManager` implements immutable
registration, scoped recovery, worker claims, private preparation, coordinated
commit and terminal failure on the migrated SQLite version-2 schema. There is
no new CLI flag and no real administrative approval is added.

## Host-only identities and intent

Construct the manager with a SqliteReviewStore and allowed_principals. CallerContext
is a host assertion; neither its principal string nor the allowlist authenticates
a person. WorkerFence likewise comes from trusted orchestration, not public query
input. Production authentication and service isolation remain separate requirements.
Cross-principal operations and absent-operation lookups return the same generic
JournalAccessError. Operation IDs are globally unique idempotency keys, not credentials.

BoundIntent stores QueryIdentity, parser/policy versions, exact configuration bytes
and their SHA-256, availability (or explicit missing state), and initial expected
review sequence/hash (or both missing). Configuration bytes from
engine_configuration_bytes include frozen corpus/index bytes, availability records
and the complete ordered transition mapping. Registration checks the current review
binding under the write transaction, including explicit absence. An exact registered
intent retry returns its original release reservation; changed input conflicts.

The manager allocates release_id internally. It does not infer idempotency from
query equality. Different operations can intentionally have the same query. Version
2 migration remains explicit; a manager does not upgrade a version-1 store on use.

## Supported flow

```python
view = journal.register(operation_id=stable_id, caller=caller, intent=bound_intent)
fence = journal.claim(
    operation_id=stable_id, caller=caller, worker_id=host_worker_id,
    expected_head_sequence=view.head_sequence,
)
prepared = journal.prepare(fence=fence, engine=configured_engine)
if prepared.state == "PREPARED":
    result = journal.commit(fence=fence)
```

REGISTERED, PREPARED, COMMITTED and FAILED are derived from append-only events.
CLAIMED increments the worker generation without changing processing state. Claims
compare the expected operation event sequence, not a timestamp. A host-authorized
takeover can happen while the old worker is alive; every mutator checks the current
worker/generation. There is no automatic timeout-based takeover or implicit lease.

prepare checks ownership and exact engine configuration before running the existing
historical pipeline outside a write transaction. The engine must use the same
configured SQLite store. A private engine preparation path returns a ReleaseRequest
without inserting into the outbox. After parsing, the manager rechecks ownership in
a write transaction, checks the complete candidate against the registered binding,
and inserts the canonical candidate and PREPARED event together. It never accepts
arbitrary candidate bytes from a public caller. A changed review cannot silently
replace the initial bound review. Once prepared, another prepare call reads state
without rerunning the parser or replacing bytes.

Input/policy blocks from the pipeline become FAILED with structured codes. A missing
review therefore produces a failed operation whose reason is MISSING_REVIEW; the
underlying evidence remains unverified and no approval is manufactured. Known store
availability/integrity blocks do not become terminal failure. Unexpected exceptions
propagate without inventing successful or terminal output.

commit loads the exact saved candidate and checks the current fence. The internal
adapter release routine uses the already-open BEGIN IMMEDIATE transaction to check
current approval and insert the outbox. The COMMITTED event and both checkpoints
are written before the one COMMIT. Validation of the complete resulting history
also occurs before commit. A changed/revoked review blocks release, leaving the
prepared candidate available for inspection. The caller may record an appropriate
terminal failure explicitly; the manager does not treat uncertain I/O as FAILED.

fail requires a current fence, nonempty structured reason codes, nonterminal state
and no committed outbox result. Exact same-reason failure retries are idempotent.
Terminal operations cannot be reclaimed or rewritten. Concurrent commit attempts
under the same current fence recover the same receipt rather than inserting twice.

## Recovery and integrity

recover(operation_id=..., caller=..., expected_query=...) returns JournalView with
status, head sequence, release reservation, optional historical ReleaseReceipt and
failure reasons. It never calls parsing, loads today's configuration or creates an
outbox row. expected_query is optional but must match the original query when supplied.
Receipt metadata includes hashes; no source payload, spans or snapshot are returned.
Revocation after commit does not invalidate historical receipt acknowledgement.

Intent, candidate and event BLOBs use the adapter's canonical codec. Every relevant
operation validates projections, fingerprints, the event chain/checkpoint, legal
state transitions, worker generations, immutable candidate binding and registration
completeness. Release/read operations additionally require one matching outbox record
exactly when an operation is COMMITTED. Orphan/mismatched receipts fail closed.
Legacy non-journal outbox rows remain valid; standalone release cannot use any
journal-reserved ID, including one already committed.

Ledger-only reads/appends validate structural journal history without reading outbox
payloads, so outbox corruption still permits a valid administrative revocation.
Journal corruption blocks adapter operations. These hashes detect inconsistent
history, not coherent replacement of all files/checkpoints by a privileged actor.

## Remaining integration work

The CLI still creates its empty in-memory store. It has no operation-token or
authenticated journal recovery command. Public operation IDs must be persisted by
the client before relying on crash recovery; a server-generated ID lost before
acknowledgement cannot be guessed safely. Preparation after a REGISTERED crash
requires the host to reconstruct the exact saved configuration; this manager stores
those bytes but does not yet provide a deployment loader to reconstruct an engine.
A PREPARED operation can be claimed and committed without re-parsing. No automatic
restart worker or retry loop is installed.

The engine's private preparation hook and adapter's transaction-scoped release are
internal trust boundaries, not Python access controls. Keep writer contexts, fences,
database handles and engine construction away from untrusted callers. Authenticated
administrative loading, OS permissions, network delivery, multi-document replay and
rollback-resistant backup policy remain separate work.

## Tests

Tests use synthetic principals/reviews and temporary databases. They verify exact
registration, cross-principal denial, configuration/review drift, missing reviews,
stale workers before and during parsing, competing claims across processes, duplicate
commits, immutable preparation, receipt-only restart recovery, revocation on both
sides of commit, failed-finalization rollback and corrupted journals/outbox. Process
termination at registration, preparation and finalization commit boundaries is
coordinated with IPC events. All three real ABC captures produce MISSING_REVIEW and
zero review/outbox records. These are process-crash tests, not hardware power-loss
proofs or authentication tests.
