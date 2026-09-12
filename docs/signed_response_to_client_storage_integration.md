# Signed response to client storage integration harness

This test-only harness connects the real loopback mTLS transport, request and
signing handoffs, temporary authority bridge, and ephemeral Ed25519 signer to
`TestClientHighWaterStore`. It adds no application adapter, schema, production
listener, key storage, or checkpoint publication.

## Recovery contract

An exact historical retry requires the original operation ID and the full
canonical `AdvancementRequest`: signed response, retained observation request,
public trust store, and independent trust checkpoint. Digest/revision equality
alone is insufficient. A changed trust checkpoint under an existing operation
conflicts; a new operation ID is a new acceptance attempt, not receipt recovery.

The client validates its stored history using the recorded acceptance times and
retained public verification inputs. It returns the original receipt bytes
without contacting mTLS enrollment, the authority reader, bridge, or signer.
The test disposes of the private key, disables upstream entry points, prevents
authority-database access, reopens the client store, advances the client clock
past signature and trust expiry, and checks exact recovery with unchanged rows.

This is independent of upstream availability, not authentication-free access.
The local host still supplies the pinned initial client anchor and matching
caller principal. Those remain test fixtures, not a new production client
authentication mechanism. Recovery uses the existing `apply` transaction path
(`BEGIN IMMEDIATE`) and performs no application-row mutation on an exact retry;
it is not a new read-only SQLite API.

If no receipt committed before a crash, an expired response cannot be recovered
as accepted history. A fresh valid upstream response would be needed; this
harness neither re-signs automatically nor initializes replacement storage.

## Store and signer boundaries

The normal harness has two distinct, unattached SQLite files with different
application IDs: temporary authority and client high-water storage. It uses the
existing authority writer to produce real accepted revisions, including split
advances for skipped-revision and post-advancement retry cases.

A dedicated fork test creates an additional alternate temporary authority with
a different valid same-revision envelope. Its observation traverses the full
bridge and signer path; the client rejects the resulting signed fork. No payload
modification or private-key bypass is used to create that test response.

Only public canonical anchor/request bytes cross the spawned client-process
boundary. No connection, handoff, signer object, or private key is passed.

## Coverage and limits

The tests cover valid advancement and receipt projection, lost acknowledgement,
offline expired exact retry, later-head preservation, tampering, request/trust
mismatch, stale and skipped revisions, signed forks, principal isolation, and
new-operation rejection for an expired previously committed response.

Spawned processes terminate immediately after verification, before commit, and
after commit. Reopening proves rollback versus durable local receipt recovery.
Separate checks compare authority and client table contents and ensure invalid
client operations leave both stores unchanged.

TLS and process exits are real; application clocks, authority policy, client
principal, and trust configuration are controlled fixtures. These tests do not
model network response delivery, arbitrary WAN delays, power-loss durability on
all hardware, external whole-database rollback detection, or production trust
distribution. Successful local retries do not reauthorize runtime execution.
