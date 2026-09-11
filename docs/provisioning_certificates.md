# Nominated certificate verification

`validate_nominated_certificate(open_snapshot, now=host_utc_time)` verifies the
nominated administrator certificate from the retained provisioning artifacts. This
is a host-only interface. It returns CertificateValidationEvidence, not a
ProvisioningAuthorization, and does not enroll anyone or activate a database.
The time must be the current trusted host clock, not a replay query timestamp.

## Two required checks

Windows CryptoAPI builds and validates the chain in a private engine with an
exclusive in-memory root store and explicitly supplied intermediate/CRL material.
It requires client authentication usage, checks SSL client policy without ignore
flags, and rejects native trust errors. Chain URL retrieval and revocation URL
retrieval are independently cache-only; AIA retrieval is disabled. No certificate
or CRL is installed in a persistent Windows store.
[Microsoft chain configuration](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_engine_config).

On this Windows runtime, combining exclusive-root mode with restricted trust/other
stores returned invalid-parameter errors. The implementation therefore supplies
the additional material to the per-call store and independently verifies every
selected chain element against the supplied DER bytes. The final element must
match a supplied self-signed root exactly. Cached or system material cannot supply
a missing intermediate/root for an accepted result. Native caches can still affect
which chain is attempted or cause a conservative rejection; success is not inferred
from the native result alone.

The second check uses the maintained cryptography library for strict X.509 parsing,
root self-signature checks and signature verification of each exact supplied CRL.
It is a runtime dependency now. This is not a custom chain-building implementation:
Windows remains responsible for chain signatures, constraints and client policy.
TNC additionally enforces its explicit, narrower certificate/CRL profile.

## Supplied evidence profile

- Bounded DER or strict PEM bundles, no extra text, duplicate entries or duplicate
  certificate roles. At most 32 total certificates and 32 CRLs.
- Exact leaf DER SHA-256 matches the manifest enrollment. Every certificate is
  currently valid. Root self-signatures are verified and root subjects equal issuers.
- RSA 2048–8192 or P-256/P-384 keys; RSA PKCS#1 v1.5 or ECDSA signatures using
  SHA-256/384/512. SHA-1, MD5, RSA-PSS and other unsupported algorithms are rejected
  in this initial profile. RSA-PSS exclusion is a scope restriction, not a claim
  that RSA-PSS is insecure.
- Explicit leaf client-auth EKU and digital-signature usage; CA/basic constraints
  and certificate-signing/CRL-signing usage. Unsupported critical certificate
  extensions are rejected; native constraints remain mandatory.
- Exactly one supplied full CRL per selected issuing CA, including the issuer of
  each intermediate. Verify issuer name, signature and any AKI against the issuer.
  Require lastUpdate <= now < nextUpdate and the configured maximum CRL age.
  Missing CRLs, stale CRLs, conflicting multiple issuer CRLs and unused CRLs reject.
- Reject delta/indirect/partitioned CRL extensions and unsupported entry extensions.
  Reject revoked serials, duplicate serials and delta-only removeFromCRL entries.
  Distribution-point reason/issuer/relative-name scopes are outside this profile.

Evidence includes actual selected chain fingerprints, supplied CRL DER digests,
snapshot/profile digests and the earliest certificate/CRL/freshness expiry. Artifact
file digests remain separately bound by the snapshot; a CRL DER digest need not
equal its PEM file digest. No private keys are loaded by this adapter.

## Acceptance evidence and limits

Tests exercise real Windows validation for direct/intermediate chains, exclusive
roots, supported keys, expired/future certificates, client EKUs, path length,
revoked intermediates and stale/invalid CRLs. A valid call followed by missing
intermediate/CRL inputs remains rejected. Successful-backend doubles separately
prove that supplied CRL and exact-chain checks cannot be bypassed by native success.
They do not assert that a particular global Windows cache was populated.

Native API wrappers audit the exact offline/client-policy flags and check cleanup
on failures across store, context, engine, chain and policy operations. Loopback TLS
and provisioning agree on tested valid/revoked leaf cases. This is not evidence of
complete semantic equivalence with OpenSSL; provisioning checks every non-root CRL,
whereas the existing optional TLS CRL profile checks the leaf.

The test suite does not monitor every machine network packet or alter persistent
Windows trust stores. Offline behavior is enforced by inspected native flags and
the independent supplied-evidence requirements. Unknown native revocation results
remain failures even if the supplied CRL check could otherwise pass. Future CRL
publication cannot be learned from an older offline snapshot.

Real WindowsProvisioningSession assembly, protected installation, operator checks
and live monotonic lease handling remain separate work. Existing execution guards
and the real ABC quarantine are unchanged.
