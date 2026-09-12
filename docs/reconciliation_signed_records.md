# Structural signed-observation records

This pure milestone implements the integer-timestamp profile requested in the
implementation brief: `tnc-authority-v1`, with preimage prefix
`TNC-SIGNED-OBSERVATION-v1:` followed by exact canonical payload bytes.
It does not implement the earlier UTC-string, length-prefixed observation design.
The two formats must not be treated as interchangeable or wired into a verifier
without a separately reviewed protocol decision.

Frozen Pydantic records reuse repository canonical JSON validation. Key inventories
are sorted unique tuples, not mutable dictionaries. Public keys, signature bytes,
and the embedded canonical payload are represented by exact lowercase hex for
unambiguous JSON encoding. Payloads are limited to 64 KiB; container encoding allows
twice that plus 1 KiB for hex expansion and headers. Trust records are limited to
64 KiB and 64 keys. All supported record decoders reject noncanonical input,
duplicate JSON keys, extra fields, malformed hex and invalid exact integer types.

`compute_preimage` first validates exact canonical payload bytes, then prefixes the
fixed domain. Hand-specified golden JSON and preimage bytes test deterministic
encoding independently of the encoder under test.

Structural evaluation requires matching deployment/store and challenge, a known
active key record, observation time at or after key creation, and
timestamp <= current_time < expiry. Intervals must be positive. Boolean, string,
and float timestamps are rejected; exact expiry is expired.

A success is STRUCTURALLY_VALID, with signature_verified=False and audit_only=True.
No public-key/digest relationship, signature validity, issuer permission, trust
checkpoint currentness, envelope contents, or actual policy digest is authenticated.
The simplified profile has no independent trust checkpoint, retained request
digest/principal binding, full envelope, or maximum response lifetime. Those remain
requirements to resolve before a future authenticated observation protocol.

Repeated structural evaluation neither consumes a challenge nor prevents replay.
There are no signers, crypto-verification calls, filesystem/network operations,
runtime route integrations, or client high-water writes in this module.
