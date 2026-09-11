# Protected host installation and deployment boundary

Design specification — 11 September 2026. Baseline: `14bd5bc`, with 1,052 tests last verified. This document does not install a service, change permissions, create accounts, distribute certificates or activate a database. Proposed deployment controls below are not implied to exist in the current code.

## 1. Supported initial deployment

The first profile is one Windows host, local NTFS storage, one reviewed deployment identity and one SQLite database. Start with supervised local administration only. Journal execution and remote provisioning remain disabled. A network dispatcher is a separate release requiring authenticated framing and transactional execution authorization.

The trusted computing base includes Windows/kernel, the installer and designated maintenance administrators, installed Python/runtime/dependencies, and the process holding database write access. A compromised member can bypass application checks. Hash chains detect supported integrity faults; they do not authenticate a replacement history rewritten by an attacker with full control of the database and its trust configuration.

## 2. Roles and ownership

Use exact enrolled SIDs, never display names, environment variables or inferred membership. The installation record resolves these symbols to reviewed concrete values:

| Symbol | Role | Authority |
|---|---|---|
| I | Installer/maintenance principal | Installs code, owns deployment directories, deploys reviewed descriptor/anchor packages and performs controlled maintenance |
| O | Local bootstrap operator | Exact TokenUser SID allowed by the manifest/anchor and policy; reads configuration and temporarily writes the selected database during activation |
| S | Dedicated runtime service identity | Reads installed code/configuration; modifies its database and designated logs; cannot change code, trust packages or descriptor |
| A | Remote administrative certificate principal | May receive explicit application permissions after mTLS; receives no filesystem permissions merely by enrollment |
| B | Backup operator | Reads approved consistent backups through the backup process; no general database/configuration write permission |

SYSTEM and local administrators are part of host maintenance trust, not automatically TNC application administrators. Include their concrete SIDs in owner/writer allowlists only as explicitly required by the approved ACL layout. Do not run the service as a broadly privileged account merely to make access checks pass. A service SID may scope object access, but its configuration and token behavior must be tested for the selected service account. [Microsoft service-account and service-SID guidance](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17).

O necessarily has raw database mutation capability while running the current direct SQLite bootstrap flow. During that maintenance window O is trusted for database integrity, not constrained solely by the Python writer. If this is unacceptable, a separate privileged broker is required; silently running as S and treating its token as O would violate the implemented identity contract.

## 3. Physical layout

Illustrative paths use `V:` as a placeholder for a separately approved local NTFS volume, not a request to allocate a drive:

```text
V:\TNC\deploy-001\
    install\                 installer-owned launcher, pinned runtime and code
    host\                    descriptor envelope, installation record, active generation pointer
    bootstrap\generation-001\
        policy.json
        manifest.json
        leaf.der
        roots.pem
        intermediates.pem    optional
        revocations.crl
    state\                   sole SQLite database directory
        governance.sqlite
        governance.sqlite-wal
        governance.sqlite-shm
    runtime-trust\generation-001\   separately reviewed operational roots/CRLs
    service-key\             runtime TLS server key only, if/when a server is deployed
    logs\
    backup-staging\
```

The flat bootstrap generation fits the current loader. Descriptor configuration_root and database_path are literal reviewed absolute paths. Do not use Documents, Downloads, synced folders, network shares, junctions, substituted subdirectory drives, alternate streams or environment-dependent resolution.

Every ancestor from the volume root must satisfy the loader's owner/DACL policy. A locked-down leaf directory beneath an unsafe ancestor is rejected. Prefer an independently secured deployment volume if an ordinary system-volume ancestor cannot meet the policy. Do not automatically rewrite broad Windows root/Users/ProgramData ACLs, or trust additional writer SIDs just to pass preflight.

Record the expected volume GUID/serial and directory identities in a proposed installation receipt. The current loader verifies that the root is a local NTFS volume GUID root; it does not compare that GUID with a descriptor-pinned expected volume. A deployment preflight must add that comparison before relying on fixed drive-letter identity. A drive letter alone is not the physical pin.

## 4. ACL contract

Use installer-controlled ownership and explicit ordinary allow ACEs. Disable uncontrolled inherited grants at deployment directories and deliberately configure inheritance for their children. Keep the supported ACL form narrow; conditional/object ACEs cannot be used as a workaround because the current loader rejects them.

| Object | I / approved maintenance | O | S | Other ordinary users |
|---|---|---|---|---|
| Install binaries, runtime, dependency paths | Full control | Read/execute | Read/execute | No modification |
| Host descriptor, anchor, installation record | Full control | Read | Read | No modification |
| Bootstrap and runtime trust generations | Full control | Read | Read | No modification |
| State directory and DB sidecars | Full control | Modify only in stopped bootstrap window | Modify during runtime | No access |
| Server private-key directory/file | Full control or dedicated key custodian | No access by default | Required key-read access only | No access |
| Logs | Maintenance/read | No access by default | Create/write under a bounded retention policy | No access |
| Consistent backups | Maintenance/restore | No access by default | Only backup mechanism needs access | B may read approved backups |

Here Modify means required data creation/read/write/delete rights, without an intended grant of WRITE_DAC or WRITE_OWNER. Directory rights must account for child creation and delete-child, not only the main file's contents. Windows ownership and privileges can confer additional control; verify effective behavior under actual tokens rather than claiming an ACE label is complete isolation.

No untrusted principal may replace ancestors, deployment directories, code or trust files, or take ownership/change their DACLs. The descriptor's trusted_owner_sids/trusted_writer_sids must come from this reviewed installation plan. Never populate them by scanning current ACLs as some native test fixtures do.

The bootstrap loader's read-only sharing policy applies to configuration, not to SQLite files. Do not open the live DB/WAL/SHM with a write-denying snapshot handle: SQLite needs its normal transaction and sidecar behavior.

## 5. SQLite and recovery boundary

Protect the whole state directory before creating/opening the database. Its ACL must ensure newly created `-wal`, `-shm` and any rollback-journal files inherit the intended protection. Explicitly test sidecar creation, deletion and recreation under S and during O's bootstrap window. WAL files may contain committed changes not yet checkpointed into the main database. [SQLite WAL documentation](https://www.sqlite.org/wal.html).

The implemented session compares the requested database pathname; it does not verify DB ownership, hard links, reparse status, directory identity or sidecar ACLs. Add a read-only host preflight for those properties and an installer-controlled lifecycle before exposing the real command. SQLite continues opening its own paths, so the security argument rests on protected directories and trusted writers, not an application claim that every SQLite open is handle-relative.

Keep one controlled deployment instance per database. Refuse unintended duplicate service launches or alternate path aliases. Do not change directory ACLs or database locations while instances are running. Stop and drain the host before restore, ownership transitions or path changes.

Use SQLite's supported consistent backup mechanism or a verified stopped/checkpointed backup procedure. Do not copy only the live main database. Preserve the independent anchor, installation generation and expected ledger checkpoints with each approved backup. A restore must validate schema, chains, authorization records and external bindings before restart. An older but internally valid backup is still a rollback; preventing undetected rollback requires an independently retained high-water mark. That external rollback protection is not implemented by the current hash chains.

## 6. Descriptor and anchor distribution

Introduce a proposed installer-owned deployment envelope outside the bootstrap directory. It binds deployment ID, service/operator SIDs, absolute paths, expected volume identity, code/runtime package digest, descriptor bytes/digest, reviewed bootstrap anchor and installation generation.

The envelope's authenticity must be established independently: a reviewed offline installation ceremony and protected launcher location, or a signed package whose verification key is pinned in that installer/launcher. A descriptor cannot authenticate its own signature key. Signature support and envelope loading are future implementation work; do not mark an unsigned JSON file trusted merely because it contains a digest.

Preserve the acyclic binding order:

1. Assemble exact certificate/CRL artifacts and their lengths/digests.
2. Canonicalize policy with those artifact bindings, operator/service/deployment identity and lease rules.
3. Canonicalize the manifest containing the policy hash and independently defined trust-configuration hash.
4. Bind the manifest hash, deployment, operator, session and validity into the reviewed external anchor.
5. Canonicalize the descriptor and bind it into the externally authenticated deployment envelope.

The existing trust_configuration_hash is an opaque reviewed binding. Standardize its canonical source record/version before real installation; no current component invents a trust package format from it. A generated or copied descriptor from a test is not an installation envelope.

## 7. CA, keys and CRL distribution

Keep CA private keys off the TNC host. The nominated administrator's client key stays with that administrator, ideally under a separately verified key-protection mechanism. TNC stores public certificates and CRLs only for bootstrap. Enrollment nominates a certificate; it does not prove client-key possession until later mTLS.

If a runtime TLS server is deployed, its server key is a distinct asset. The existing Python SSL adapter supports protected PEM key loading; hardware-token/CNG integration is not implemented. Do not claim hardware-backed handling for a PEM deployment.

Distribute reviewed root bundles and issuer-authenticated CRLs out of band through I. An online downloader, if added later, must write only to untrusted staging; it must never overwrite active trust files directly. Validation must check signatures, issuer/scope, profile support, freshness and expected package binding before promotion. Transport encryption alone does not make a root-bundle update authorized.

Root addition/removal requires explicit maintenance authorization. A valid self-signature is not permission to add a root. Define a CRL refresh interval shorter than the strictest accepted nextUpdate/max-age limit, with sufficient operational margin. If a fresh acceptable CRL is unavailable, affected operations remain denied. Never turn off revocation checks to restore availability.

## 8. Immutable bootstrap versus operational updates

Changing bootstrap CRL bytes changes artifact digests, the policy hash, manifest hash and descriptor/anchor binding. Therefore a CRL update is not an in-place edit compatible with the original bootstrap receipt.

Before first activation, a replacement generation requires a newly reviewed complete package and anchor. After activation, preserve the original bootstrap generation and anchor as historical evidence. Do not change them to describe a later runtime trust update or attempt to bootstrap the same database again with a new manifest.

Exact activation retries require fresh session verification of the original package and remain available only while its policy/anchor/certificate/CRL windows permit. They are not indefinite recovery credentials. Historical receipt inspection after those windows requires a separately authenticated read/status operation; such a public deployment route has not been implemented.

Operational mTLS trust/CRL rotation uses a separate reviewed runtime generation. Stop admitting affected work, drain connections/leases, close retained configuration handles, validate the complete new generation, and switch the protected generation pointer under maintenance control. Rebuild TLS contexts and require new sessions. Existing connections do not automatically acquire a changed CRL policy. This procedure and its host coordinator are proposed, not implemented.

## 9. Installation and activation sequence

1. Review the concrete SIDs, physical volume, package authenticity, directory layout and recovery policy. Resolve every symbolic value; do not run templates with placeholders.
2. Install immutable code/runtime and the protected launcher/envelope location. Validate import/dependency search paths so writable working directories or user packages cannot replace trusted code.
3. Create protected directories and confirm owner/DACL/ancestor/volume expectations using the actual O and S tokens. Test denied access with an unrelated ordinary account in an isolated deployment test environment.
4. Stage and validate a complete canonical bootstrap generation. Verify root/CRL provenance, reviewed anchor and expected source database checkpoint.
5. Stop S, restrict concurrent writers, and temporarily grant O the narrowly selected state-directory access required by the current local bootstrap model.
6. Run the host-only session and v4 writer with retained snapshot handles. Capture the resulting immutable receipt and validate resulting ledger state. Failure must leave the source state unchanged or recoverable through the defined exact retry.
7. Close sessions, verify the database/sidecar ACLs, remove O's temporary direct write grant, and record the handoff. Start S only after validation. A failure during handoff leaves the host stopped; it does not launch with broader permissions.
8. Verify restart and consistent-backup recovery before enabling any separately approved administrative service route. Journal execution stays blocked throughout this milestone.

These steps describe an operational contract, not commands to execute now. The real installer, preflight, handoff coordinator and launch path still need implementation and tests.

## 10. Required acceptance tests

- Installation rejects unsafe ancestors, substituted volumes, reparse/hard-link aliases, unexpected owners and unsupported ACLs; it does not repair them automatically.
- O/S cannot alter installed code, descriptors or trust generations. A cannot gain file access through certificate enrollment. Removed bootstrap write grants are ineffective after handoff.
- New/recreated WAL/SHM/journal files have the required ACLs; untrusted replacement attempts fail. A mismatched database or external anchor prevents startup.
- Package tampering, unapproved roots, expired CRLs and old generation pointers fail closed. A downloaded file cannot directly become active trust material.
- Crash tests cover staging, pointer promotion, bootstrap commit, stopped-host ACL handoff and restart. Interrupted maintenance never starts the host in an intermediate state.
- Backups restore consistently; old valid ledgers are detected against an independent high-water mark where rollback protection is claimed.
- Runtime key access, TLS context rebuild and stale-connection handling match the selected implementation; no assumed hardware-key support.
- Native-call supervision enforces real process-level time budgets. Existing cooperative Python checks alone are not described as hard deadlines.
- Existing 1,052 tests remain green, execution insert guards remain active, and real ABC captures stay unreviewed.

## Next implementation boundary

Start with typed installation-envelope/preflight records and a read-only deployment validator. It should report which exact owner, ACL, volume, path or package binding fails without changing the host. Resolve the envelope authentication and independent checkpoint mechanisms before implementing an installer or exposing a provisioning command. Real SIDs, credentials and deployment directories require concrete reviewed choices at that later step.
