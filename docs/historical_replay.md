# Single-version historical replay integration

`tnc.provenance.historical_replay.HistoricalReplayEngine` integrates admission,
parsing, recorded claim transitions, and coordinated in-memory release. This is
a host-configured integration API; it is not yet a production service or CLI gate.

## Host construction and public request

```python
engine = HistoricalReplayEngine(
    corpus=frozen_corpus,
    availability=availability_records,
    transitions=transition_inventories,
    review_store=coordinated_store,
)
outcome = engine.execute(
    document_id="doc",
    version_id="version",
    query_time=aware_datetime,
)
```

Construction reconstructs nested frozen models and retains immutable bytes and
tuples. Malformed configuration raises validation errors. Public execution accepts
only the three shown fields, rejects blank identities and naive time, and normalizes
time to UTC. Caller-supplied reviews, evidence, histories, and release IDs are not
accepted. Host configuration and Python objects are not a hostile-process boundary.

The configured store must implement both ReviewReader and ReleaseCommitter using
the same authoritative ledger. InMemoryReviewStore is the tested implementation.
The protocol cannot prove a third-party backend's coordination or authenticity.

## Processing and release

The wrapper resolves the current version review head, checks its complete evidence
binding, and invokes evaluate_historical_admission. Only ADMITTED proceeds. Missing
reviews are UNVERIFIED when technical validation passes; invalid bytes and future
captures still reject. Revocations, store failures, ambiguous bindings and rejected
reviews cannot reach parsing. Older approvals are never selected by query time.

The parser receives a strict UTF-8 decode of the same retained FrozenVersion.body
that passed admission. There is no second file read or network fetch. Decode and
parse failures block release. Empty parses also block in this initial contract.

Span validation requires contiguous version-specific coordinates, unique IDs,
matching version identity, normalized text and content hashes, and capture-bound
availability. The existing parser produces no offsets, internal links or expiry;
unexpected populated fields are rejected. Supporting those fields later requires
a defined coordinate/expiry contract rather than guessed validation.

Each TransitionInventory explicitly binds one document/version to an event and
recorded transitions. No claim transitions are inferred from parsing. Missing or
ambiguous mappings block; an explicitly empty history is valid. Only transitions
at or before the query clock are replayed. Every eligible transition must have
nonempty, unique references to this version's validated spans, available by the
transition time. All configured transition IDs must be unique and times aware.
For each assertion, eligible transitions must have strictly increasing times and
from_state must match the preceding state, beginning with None. Ambiguous ties
and histories requiring outside-version evidence block. Future transitions are
excluded, not back-projected; their evidence is evaluated when they become eligible.

The wrapper always supplies a generated evidence availability map to replay_snapshots.
The private payload records admission, validated spans, eligible transitions and
the snapshot. A release candidate binds the initial review sequence/hash, complete
availability, query time, and parser/policy versions. commit_release checks that
approval again and inserts into the outbox under the ledger lock. A changed head
blocks the attempt even if the replacement is another approval.

ReplayOutcome contains released/rejected/unverified status, reasons, the admission
decision when available, and a receipt only after successful commit. Blocked outcomes
contain no spans, article text or partial snapshot. Unexpected programming failures
propagate rather than being converted into successful empty output. Known store or
commit errors produce blocked outcomes. An admission status of ADMITTED in a blocked
outcome describes the earlier check; it is not a successful release.

## Release and retry limits

Outbox insertion is the release point. Revocation before insertion blocks a new
release; later revocation cannot retract that release or control network delivery.
The wrapper generates a new UUID for each execute call. It does not automatically
retry uncertain commits. Repeating execute is a new operation and may create a
second result. The lower-level primitive supports exact candidate retries, but
durable end-to-end request recovery is deferred. A lost acknowledgement may mean
an entry exists despite an execution failure; host audit/recovery must inspect the
outbox rather than assume every failure guarantees no prior commit.

No real ABC approvals are created. Integration tests exercise their real frozen
bytes/indexes with an empty review store and verify UNVERIFIED without parsing.
All approved integration histories are synthetic. Tests also cover temporal and
binding failures, parser/span failures, missing/ambiguous transitions, evidence
coordinates, store failures, and revocation while a parser is paused using events.

## Remaining boundaries

Persistence, authenticated reviewer access, durable request recovery, multiple
versions/documents, transport delivery and mandatory routing of production entry
points remain separate work. Existing low-level parse/replay APIs remain callable.
Parser/policy version identifiers must be updated when their behavior changes.

Run `uv run pytest -q tests/test_historical_replay.py` or the full test suite.
