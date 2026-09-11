# Pure installer update records and transitions

This milestone implements a pure design model. It performs no signing, filesystem
access, process control, pointer replacement, authority-store writes, or database
mutation. It does not enable provisioning, service startup, or journal execution.

## Records

`update_models.py` defines frozen, extra-field-rejecting models for a candidate
bundle, canonical domain-tagged update intent, authoritative head, preparation
evidence, synthetic installer and drain evidence, receipt, operation, command,
locator observation, and transition/recovery results. Canonical decoding is
restricted to these types and one MiB per top-level record. Existing canonical
JSON rules enforce exact bytes, UTC timestamps, duplicate-key rejection, and
strict field validation.

An intent includes the full candidate policy/checkpoint/anchor/envelope/descriptor
bundle, operation and publisher IDs, signer key digest, validity, and expected
head sequence/checkpoint digest. Thus the canonical intent digest binds the
candidate's final location and every nested record. No signature field is treated
as verified evidence; the real signature profile remains unimplemented.

## Transition semantics

`evaluate_update_transition(head, existing, command, authority, now)` is keyword-only
and requires an explicit aware evaluation time. It returns `PROPOSED`, `UNCHANGED`,
`RECOVERED`, or `DENIED`. A proposed result is an immutable value, not a committed
update. Denials include a fixed reason and expose no operation or proposed head.

- `REGISTER`: validates current publisher authority, candidate bindings, validity,
  strictly newer generation, distinct final generation directory, and expected
  head. The update profile requires envelope generation, anchor minimum generation,
  and checkpoint high-water generation to be equal.
- `PREPARE`: requires a complete conforming report bound to the intent, exact
  envelope, generation, phase, and complete inventory. Preparation evidence is
  time-bounded. A later preparation cannot move the report timestamp backward.
- `COMMIT`: requires prepared state, refreshed current preparation, matching
  synthetic drain evidence, and the same expected head. Fenced admissions,
  terminated processes, and released handles are all required assertions. It
  proposes a receipt and a head advanced by exactly one authority sequence.
- `PUBLISH`: records a validated locator observation for the current committed
  head, with a valid candidate and target. It never advances authority. It does
  not perform replacement or prove physical durability.
- `RECOVER`: returns an existing operation after current authorization and exact
  canonical intent comparison. Historical receipts retain their original bytes.

REGISTER retries and committed COMMIT retries also recover the exact existing
operation without a new head. Changes to canonical intent produce
`OPERATION_CONFLICT`. Refreshed evidence is not part of immutable intent identity;
it cannot change an already committed candidate or receipt. New equal/lower
generation operations fail. Competing updates evaluated sequentially against the
first proposed head fail their old expected-head comparison.

Receipt recovery is allowed after the intent expires or after later generations
become current, provided the installer is currently authorized. It cannot regress
the head or republish an older generation. The same principal may use a rotated
authorized key for recovery and locator publication of an existing commitment.
New registration/preparation/commit still requires the intent's signer key.
Publication checks candidate validity even when the historical intent has expired.

## Recovery matrix

`evaluate_update_recovery(head, locator, now)` produces a classification only:

| Observation | Classification |
| --- | --- |
| Current authority and valid locator target agree | MATCHED |
| Locator missing or names an older authority sequence | REPAIR_REQUIRED |
| Locator unreadable, ahead of authority, mismatched, or target invalid/unknown | BLOCKED |
| Authority unavailable or checkpoint expired | BLOCKED |

MATCHED does not authorize startup. REPAIR_REQUIRED does not perform or authorize
a repair. A committed-but-unpublished operation already raises the proposed floor;
recovery cannot select an older generation merely because its files remain valid.

## Trust and implementation limits

Installer and drain evidence are explicitly synthetic host assertions. The pure
validator checks their scope and internal bindings but does not authenticate a
principal, verify a signature, observe process termination, or hold a lock.
Head and existing operation must come from a trusted authority store. The validator
checks receipt associations but does not authenticate an entire historical ledger.

A future backend must load that state consistently, repeat the expected-head and
authorization checks under serialized durable commitment, and persist the receipt
and head together. Two independent pure calls against the same old head can both
return proposals; these tests do not constitute cross-process locking tests.
Likewise, recovery tests model crash states without process termination or power
failure. Windows replacement durability remains a separate acceptance gate.

The observation's freshness and completeness ultimately depend on trusted
acquisition; booleans and digests alone cannot prove live OS facts. There are no
new production routes using these models. All existing execution restrictions and
real ABC capture quarantine remain unchanged.
