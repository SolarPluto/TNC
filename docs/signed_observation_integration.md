# Test-only signed observation integration

`tests/test_signed_observation_integration.py` connects the existing SQLite reader,
temporary authority writer and v2 verifier, using ephemeral in-memory Ed25519 keys.
It adds no production signing route or application-code changes.

The public reader returns an envelope observation but no policy. A scoped test
interception of its validated `_load` call retains the exact immutable state used
inside that read transaction. The fixture assembler takes only that captured state
and observation, not a separately loaded policy. It checks envelope equality and
request principal/challenge binding before producing the v2 payload. This seam is
a test technique, not a new authenticated snapshot acquisition API.

An interleaved policy transaction demonstrates that the old snapshot keeps its old
policy even after the database advances. A second reader observes the newer policy.
An envelope from a different captured head is rejected by assembly. The same envelope
may legitimately accompany different policies, so digest equality cannot prove that
arbitrarily supplied policy records came from the same read transaction. Trusted
fixture assembly, not a cryptographic inference, enforces their common origin.

The suite deliberately tests two limits: a trusted signer can sign an incorrect
policy claim and it still verifies; and an old unexpired observation can verify
against its original retained request after head advancement. New challenges reject
old responses. Unsigned historical receipt bytes cannot be passed off as v2 responses.

Other tests cover valid round trips, post-signing tampering, exact expiry, independent
trust-checkpoint mismatches, denied reader permissions, and unchanged application
tables. Trust configuration is supplied independently by fixtures before assembly;
responses do not nominate their own trusted checkpoint.

No private keys are saved, no network calls occur, and no checkpoint, high-water
record or runtime state is published. The existing snapshot-authority limitations
remain: this is not a release-time authorization gate or a latest-state guarantee.
