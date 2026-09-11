# Version-4 administration-only activation and writer

AdministrationWriter provides host-only atomic bootstrap and administrative append.
It is not an installed service, CLI command or authenticated network endpoint.
ProvisioningSession and AdministrativeSession are required adapter protocols;
there is no permissive default implementation. Tests supply explicitly synthetic
sessions. A real OS provisioning verifier and certificate-validation procedure
remain prerequisites before exposing activation to operators.

## Explicit activation

Open the existing store with a BootstrapTrustAnchor supplied from independently
protected host configuration. migrate_to_v4(provisioning=..., manifest=...) verifies
the provisioning adapter result before locking, then rechecks its time and binding
inside BEGIN IMMEDIATE. Only v3 is a valid new activation source. A valid v4 retry
returns the historical bootstrap receipt after current provisioning authorization.

The transaction validates the complete source, executes individual v4 DDL statements,
inserts the two seed events at one store timestamp, records their BootstrapReceipt
and advances the authorization checkpoint. Complete target and foreign-key validation
precede COMMIT. An empty or partial v4 state is invalid. Exceptions and interrupted
transactions leave the old v3 layout intact.

The new administration_bootstrap row contains canonical BootstrapRecord bytes and
verified deployment/hash projections. It does not replace the external trust anchor.
The anchor's original provisioning interval validates the historical seed time;
a later retry needs fresh authorized provisioning but does not rewrite that interval
or require the original live session ID.

No old review/outbox/journal records or codec versions are rewritten. Initial seed
events and checkpoint advancement are the only newly created authority. Seven
execution-related guards remain, and a new SQL kind guard admits only the four
implemented administrative event kinds. Other authorization tables remain empty.

## Transactional writer

append(session=..., request=...) accepts an event ID, full typed payload and expected
head sequence/hash. Session verification happens outside the lock. The writer then
reads current canonical authority from the same locked connection used to append.
It checks current enrollment, principal/credential binding, session expiry, registry
revision and host.manage permission. It never authorizes writes from a cached
reader or a second connection.

The writer selects a valid host.manage grant deterministically by grant ID, constructs
the complete historical actor, assigns sequence/time, computes the event hash, and
pure-validates the proposed chain. SQL projection insertion and checkpoint CAS occur
atomically; the resulting state is validated before commit. A backwards clock is
rejected by historical validation rather than silently backdating the event.

For exact retries, current authority must still succeed. Compare original payload,
event ID, expected head and actor principal/fingerprint; preserve the old recorded
session and permission evidence. Fresh verification/audit IDs do not prevent recovery.
Changed requests or credentials conflict. A current independent host.manage grant
can authorize recovery after the original event's grant has been revoked; this does
not revive that original grant. Returned checkpoint is the historical append head.

## Canonical storage and isolation

authorization_storage validates every canonical record and SQL projection. For
disablement and revocation, the target principal is resolved from the historical
enrollment/grant prefix. Supplied projection fields cannot change ownership.

AdministrationWriter.read supplies a validated AuthorizationState for preliminary
enrollment checks, while append independently revalidates under lock. history is a
host-only audit read, not a public recovery route. An unanchored v4 store cannot open.
Legacy v1-v3 stores retain their existing behavior.

Bootstrap requires full legacy integrity. Administrative writes use the intact
review/authorization structures without requiring valid outbox payloads, allowing
credential disablement during an outbox fault. Authorization corruption blocks all
administrative authority. Existing governed review administration is unchanged;
host.manage does not itself grant review.append.

Journal mutation and standalone release APIs remain blocked on v4, including exact
write retries. Existing principal-scoped host-library journal recovery remains
available; it is not an authenticated dispatcher. No real ABC capture receives an
approval and no execution route is activated by the administrative writer.

## Verification

42 new tests cover bootstrap and fresh-session retries, false provisioning claims,
unanchored reads, append conflicts, stale heads, disabled actors, all seven retained
guards, execution event-kind rejection, canonical projection/checkpoint corruption,
rollback after each DDL statement and seed/receipt/checkpoint write, and wrong
manifest boundary rejection.

Process tests terminate workers before/after bootstrap and append commit, then
recover exact receipts. Two-actor process tests order revocation before and after
a competing append. Populated legacy history remains byte-identical, and an outbox
payload fault still allows an authorized credential disablement.

These tests establish the transaction implementation's behavior with synthetic
trusted sessions. They do not authenticate Windows users, provision certificates,
enforce OS file permissions or implement the administrative transport. Host-provided
session objects and anchors remain part of the trusted process boundary.
