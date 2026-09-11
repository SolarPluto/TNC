# Pure update storage consistency

This milestone defines a bounded logical storage image and replays it in memory.
It does not implement a database, migration, writer, serialization lock, snapshot
provider, or filesystem publication mechanism.

## Records and bounds

`update_storage_models.py` defines five event payloads:

- AUTHORITY: recorded trust store/checkpoint, transport identities, and scoped
  permission snapshots.
- REGISTER: immutable canonical intent, original signature, and actor credential.
- PREPARE: another append-only preparation observation for an operation.
- COMMIT: current authority revision, preparation/drain evidence, receipt,
  resulting deployment head, and complete archival signature association.
- PUBLISH: a separate locator publication observation.

Each event has a contiguous image-local sequence, UTC recording time, previous
event hash, and its own hash computed with the entry-hash field set to ZERO.
Global event order includes authority changes; checkpoint authority sequence only
advances on update commitment. The latest AUTHORITY event's sequence is the
authority revision required by a COMMIT record.

An image contains a trusted base head, up to 256 events, and an asserted final head.
Individual canonical records are bounded to four MiB; an entire image is bounded
to sixteen MiB. Authority views allow up to 64 identities and 128 permissions.
Existing candidate/trust record limits also apply. These are finite fixture/image
bounds, not a retention or pagination scheme for an unbounded production ledger.

An independent `UpdateStorageCheckpoint` pins the complete image digest, deployment,
event count, event chain head, and resulting authority head digest. It sits outside
the image, avoiding circular hashes. Its authentic/current distribution remains a
host responsibility. A caller cannot establish trust by hashing its own image.

## Replay validation

`validate_update_storage_image(image, trusted_checkpoint=...)` verifies canonical
records, checkpoint binding, contiguous chain order, nondecreasing event times,
and event hashes. It then replays each operation against the latest recorded
authority view and current proposed head using the shared transition rules.

Authority snapshots must bind the trust store and checkpoint, retain key history,
advance trust revision when store content changes, preserve revocation membership,
and prevent retired keys from becoming active again. Transport and permission
scopes must agree. For registration, preparation, and commitment, signature and
current recorded authority checks run at the event's recorded time.

COMMIT requires the latest recorded authority revision. Its receipt and resulting
head must exactly match a replayed new commit proposal. Its archive must contain
the original signature and exact trust snapshot/checkpoint from that authority
view; historical signature verification validates the receipt associations.
Duplicated registrations or commitments are invalid stored history: an exact
retry should recover an existing operation rather than append those events again.

Publication is checked separately against committed authority and current recorded
recovery permission. Repeated publication observations may be retained without
creating another commitment. Post-commit key revocation preserves the earlier
receipt and its signature evidence; pre-commit revocation blocks the new commit.

The asserted final head must equal replay's result. Successful validation returns
counts and sorted committed-but-unpublished operation IDs. Invalid images return
a fixed reason and no validated counts or operation identifiers. A consistent
unpublished image is an expected crash-gap state, not permission to use an older
generation. Current locator repair/readiness remains a separate check.

## Trust and persistence limits

AUTHORITY events are recorded trusted inputs. This validator checks their internal
continuity and commit ordering; it does not authenticate the administrator who
changed authority. Recorded `VerifiedIdentity` values do not prove a live TLS
session, and synthetic drain evidence does not prove real process termination.
The permission snapshots retain the read-only evaluation/recovery permission
profile. This is not a new production commit authorization grant.

Co-locating receipt, head, and archive in one logical event makes missing or
inconsistent components detectable. It does not prove that a future database
writes them atomically. Two histories can each be internally valid against
different external checkpoints; only a real serialized authority resolves which
one is current. Hash chains alone do not detect full-store rollback when the
trusted checkpoint is also replaced.

Tests model before/after revocation, competing proposals, missing preparation,
orphan/duplicate commits, corrupt receipts and archives, head disagreement,
publication gaps, canonical bounds, and deterministic no-I/O replay. They do not
exercise concurrent threads/processes, SQL rollback, process kills, or power loss.
Those tests belong to the later backend acceptance gate.

All existing production execution, provisioning, journal, and ABC quarantine
restrictions remain unchanged. No storage schema or migration is added.
