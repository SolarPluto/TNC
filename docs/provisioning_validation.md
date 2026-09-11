# Pure provisioning contracts

`provisioning_models.py` and `provisioning_validation.py` define immutable host
descriptor, policy, artifact observation, snapshot, certificate evidence and lease
bounds records. They do not load files, verify ACLs, inspect Windows tokens, parse
certificates, check signatures/CRLs, read clocks, or write databases.

The policy binds artifact names, exact byte lengths/digests, deployment/service SID,
operator SIDs, validity, a fixed certificate profile and a lifetime of at most 60
seconds. The independent descriptor and bootstrap anchor bind the manifest digest.
The policy deliberately has no manifest hash: the manifest already contains the
policy hash, and reciprocal hashes would create an unsatisfiable circular binding.

Canonical decoding reuses the administration codec and rejects extra fields,
duplicate JSON keys, noncanonical bytes and invalid timestamps. JSON records are
limited to 64 KiB before parsing. Artifact bundles are limited to 4 MiB each and the
snapshot to 16 MiB including descriptor, policy and manifest. Collections are bounded;
the future certificate parser must enforce actual parsed certificate/CRL counts.

`validate_provisioning_snapshot` compares supplied artifact bytes with the policy
and supplied observation records and creates a domain-separated snapshot record.
`calculate_provisioning_lease` checks descriptor/policy/manifest/snapshot/evidence
bindings, exact operator membership and current validation time. It intersects all
policy, manifest, anchor, enrollment, grant and evidence deadlines with the configured
60-second maximum. Certificate evidence must carry the earliest backend-established
certificate/CRL validity deadline. This function does not establish its authenticity.

The resulting ProvisioningLeaseBounds is intentionally not ProvisioningAuthorization:
it lacks the fields needed by the writer. No adapter or route consumes these new
records yet. In particular, serialized certificate evidence and artifact observations
must never be accepted from clients as proof of successful verification.

SID validation supports canonical decimal SIDs only. Paths receive lexical checks
only; their existence, filesystem, ownership, ACLs, hard links and ancestor stability
are not verified. The future protected loader owns retained handles separately;
ProvisioningSnapshotRecord is only an immutable description, not a handle owner.
Monotonic deadlines also remain a future live-session responsibility.

The trust_configuration_hash remains an independently approved opaque binding to
the existing manifest field. This layer does not invent or verify a trust bundle
format for that digest. Protected installation and native certificate verification
remain required before real provisioning.

Tests use synthetic bytes and certificate evidence. They cover canonical decoding,
SID/path shapes, tampered bindings, exact artifact sets and byte integrity, size
bounds, evidence shape and all expiry intersections. They do not demonstrate real
Windows file protection or cryptographic validity. Existing execution guards and
unreviewed real ABC captures are unaffected.
