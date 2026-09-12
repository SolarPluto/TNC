# Delivery-to-journal integration harness — test-only

`TestDeliveryJournalIntegration` is a small, host-owned orchestration scaffold.
It connects the existing bounded response receiver to the isolated SQLite journal
and exposes explicit local application/reconciliation steps. It is not a
production client, background dispatcher, retry service, or authentication gate.

## Explicit lifecycle

1. `register_intent` delegates to the journal's locked pure transition wrapper.
   It persists intent before the test opens a socket. Registration does not prove
   the request was sent or observed by the server.
2. `request_frame` loads the validated awaiting entry and frames **its stored
   request bytes** with the existing four-byte big-endian length prefix. It does
   not accept replacement request fields, open a network connection, or record a
   dispatched marker. It is not a single-use dispatch token.
3. `receive_and_retain` requires an awaiting, unexpired local intent, receives a
   canonical response through the existing 32 KiB/deadline/TLS-context checks,
   then delegates exact bytes to `retain_response`. The journal validates the
   signature, request, trust inputs and time under its own write lock.
4. `recover` delegates to local journal recovery. `READY_TO_APPLY` remains an
   audit proposal, with no high-water write. Existing high-water receipts can
   instead be reconciled immediately, including after expiry.
5. `apply_retained` is an **explicit caller action**. It obtains a fresh local
   recovery result internally; it accepts no caller-supplied proposal object.
   Only `READY_TO_APPLY` invokes the existing high-water store's `apply`, which
   re-verifies under its own transaction lock. Successful new application leaves
   the journal retained and returns the high-water result and original receipt
   bytes. It does not acknowledge that new receipt in the journal.
6. A subsequent explicit `recover` reconciles the receipt into
   `COMMITTED_RECEIPT`. Repeated local calls return the exact original bytes.

If an earlier high-water receipt already exists, `apply_retained`'s initial
recovery can acknowledge it without calling the high-water writer again. A stale,
expired, missing-evidence, or otherwise rejected proposal is returned without an
application attempt. High-water rejection or uncertain-commit errors preserve
the underlying store's result/exception semantics.

## Three separate databases

The complete harness uses a temporary authority database, client high-water
database, and client request journal database. They remain distinct files and
schemas. There are no attached databases, cross-database foreign keys, shared
write transactions, or distributed commit coordinator.

The journal's retained response and full public request/trust records replace
the earlier response-delivery tests' standalone request-retention files **in this
new harness**. Existing historical tests remain unchanged. Temporary TLS
certificate/key files are still PKI fixtures; they are not response storage.

## Crash matrix exercised with real child processes

The parent hosts a bounded loopback mTLS server using the actual request binding,
bridge, authority snapshot and ephemeral signer. Spawned client processes receive
only public intent/anchor records, temporary database paths, endpoint coordinates,
and paths to their temporary mTLS credential fixtures. They do not receive the
authority state or Ed25519 signing key.

| Exit point | Expected durable journal | Expected high-water state |
| --- | --- | --- |
| After registration, before dispatch | Awaiting | Unchanged |
| Complete receive, before retention starts | Awaiting | Unchanged |
| Before retention transaction commits | Awaiting | Unchanged |
| After retention commits | Retained | Unchanged |
| Before high-water transaction commits | Retained | Unchanged |
| After high-water commit, before journal acknowledgement | Retained | Receipt committed |
| Before journal acknowledgement transaction commits | Retained | Receipt committed |
| After both commits | Committed receipt | Receipt committed |

Clients terminate with `os._exit` at those boundaries and are reopened through
validated loaders. No standalone retained-response file is supplied on restart.
The tests verify exact local receipt bytes, authority-state preservation and
separate journal/high-water sequencing.

## Failure and recovery rules

- Framing truncation, oversized responses and delivery loss leave awaiting state.
- A structurally complete response with an invalid signature is not retained.
- An awaiting intent does not reconstruct response bytes lost before retention.
  An unexpired awaiting request can be explicitly dispatched by the host; no
  automatic retry or at-most-once dispatch guarantee is introduced.
- Retained/terminal entries refuse another request-frame operation and direct the
  caller to local recovery. Retention still resolves concurrent response attempts
  using the underlying immutable-response conflict rules.
- Expired, uncommitted responses remain retained and blocked. A test explicitly
  starts a new operation with a new challenge and observation; the old entry is
  preserved. The helper never initiates that fresh signing cycle itself.
- A committed high-water receipt is discovered before expiry rejection. Journal
  acknowledgement can finish without re-applying or contacting upstream.
- Fully committed journal recovery needs only the journal, its independent client
  anchor and the host caller context. Tests prohibit network, signer, bridge,
  authority-reader and nonlocal database access. Journal-only recovery also
  prohibits opening the high-water database.

Host-owned caller strings, clocks, trust checkpoints and signer fixtures remain
test inputs. Application time is controlled; real socket deadlines bound
transport work. These tests validate local component integration and process-exit
recovery, not trusted distributed time, universal power-loss durability, external
rollback detection, protected key custody, or production activation.

## Test coverage

The 24 integration cases cover valid advancement with exact response/receipt bytes,
registration-before-dispatch, delivery failure, invalid signatures, no redispatch
after retention, retention rollback, explicit fresh observation after expiry,
terminal journal-only recovery, committed-receipt reconciliation without reapply,
unavailable high-water evidence, principal denial before storage reads, all eight
process-exit stages, expiry after a retention-process exit, lost journal completion
acknowledgement, and high-water expiry re-verification after a ready proposal.
