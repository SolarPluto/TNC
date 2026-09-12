# Pure client high-water transitions

`client_high_water_logic.py` models a bounded synthetic client state and proposes
immutable transitions. It performs no file, SQLite, network, or high-water writes.
There is no provisioning command or transaction lock in this pure layer.

An independently supplied ClientAnchor pins deployment/store, principal, initial
authority revision/digest and time. The state retains that anchor, current authority
revision/digest, latest locally accepted timestamp/key, a local evidence sequence,
and up to 64 receipt/history entries. The state and result are bounded to 16 MiB;
requests to 2 MiB, entries to 2 MiB plus 64 KiB, and small records to 64 KiB. V2
verification retains its own stricter component limits.

AdvancementRequest carries an operation ID, original signed response, full retained
v2 request, trust store and pinned checkpoint. These are host-fixture inputs, not
self-authenticating client capabilities. A future host must obtain trust snapshots
independently rather than accepting arbitrary caller-supplied stores. The explicitly
supplied caller principal models scoping only, not authentication or current grants.

New operations invoke the v2 verifier at supplied current time. Equal authority
revision/digest yields UNCHANGED; it can append a new evidence receipt and increment
the local sequence. This permits policy-only changes to be recorded without making
policy revision another high-water axis. Lower revisions are STALE, equal-revision
digest disagreement is CONFLICT_FORK, and advancement requires exactly revision+1
with the exact prior envelope digest. Skipped revisions return PREDECESSOR_MISMATCH
until an authenticated intermediate-chain mechanism exists.

Receipt entries retain the exact request/response/trust evidence. State validation
replays all accepted entries using their historical local acceptance times and
recomputes receipts, sequence, head and evidence metadata. Exact operation retries
require identical canonical request bytes and return RECOVERED with the original
receipt only, including after expiry or later advancement. This is historical
fixture recovery, not new current observation acceptance; current production
recovery authorization is not implemented. Conflicting operation reuse is rejected.

Trust snapshots in stored history are assumed to have been independently accepted
by the fixture host. Revalidation is internal consistency checking and signature
verification, not proof that those snapshots were authentic host inputs. Neither
the initial anchor nor the local sequence can detect restoration of an older valid
state. Pure proposed outcomes do not demonstrate durable crash consistency or CAS
serialization. Those require the later explicit storage adapter and independent
rollback/freshness mechanisms.

Tests cover unchanged evidence, strict succession, stale/fork cases, missing links,
historical retries and conflicts, policy shifts, corrupt state/receipts, wrong anchors,
caller scope, exact time types, signature failure, canonical/frozen records, bounds
and no-I/O operation. No existing production or synthetic writer/reader is rewired.
