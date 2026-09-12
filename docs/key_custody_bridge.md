# Test-only custody observation bridge

`TestCustodyObservationBridge` consumes the existing private observation signing
handoff and connects it to `TestCustodyProvider`. It does not change the existing
signer, transport, reader, verifier or storage modules, or enable a production route.

The constructor receives a host-owned observation bridge, ephemeral provider and
configuration callback. `CustodyObservationConfiguration` groups the signer ID,
custody handle, capabilities, independent custody anchor and observation trust
store/checkpoint in one frozen snapshot. The callback must return a coherent,
independently trusted host snapshot. No network field selects these pins.

## Signing sequence

1. Consume the original handoff before validation. Its existing checks bind the
   creating bridge, connection, process and thread and reject repeated use.
2. Match the retained request and read bounded canonical host configuration.
3. Revalidate live mTLS identity and observation grants. Require exact provider
   public-key equality with the custody descriptor and observation trust record.
4. Construct the v2 payload from the captured envelope/policy snapshot. Apply the
   existing exact epoch conversion: ceil lower bounds, floor upper bounds and
   intersect the remaining original monotonic lease with all validity windows.
5. Evaluate pure custody compatibility, recheck configuration and live grants,
   mint the provider's separate test handoff with the **original deadline**, then
   call the provider once. There is no retry or alternate mechanism.
6. Recheck host configuration, require exact returned payload equality, revalidate
   live grants, and independently run the full v2 signature verifier against the
   pinned observation trust. Perform a final live check and deadline/configuration
   check before returning the signed observation.

Any failure returns the existing sanitized `ObservationSigningError`. Reuse of the
original consumed handoff returns `CandidateAlreadyConsumedError`. Provider fault
status is not exposed as a reusable permission or retried. Ambiguous or late output
is suppressed; this bridge does not recover a provider signature.

## Scope of authorization and snapshots

The original envelope and authority policy remain the atomic observation captured
by the reader. The bridge does not reread authority state or assert that no later
authority advancement exists. Live checks apply to current transport enrollment
and observation grants; host configuration changes during this attempt reject
release, including otherwise valid rotations.

These are discrete pre/post checks, not a global serialization lock shared by all
policy writers. They suppress observed revocation and changed configuration; they
do not promise that a concurrent change cannot occur after the final check. The
host callback's authenticity, coherent publication and unseen freshness remain
external requirements. Python private attributes are not a hostile-process boundary.

The provider remains in-memory and test-only. Its public fixture minting API is
not promoted to production authorization by this adapter. The synchronous fake
does not establish bounded execution of a future blocking hardware driver.

## Integration tests

Real loopback mTLS tests cover the full signing/verifier round trip, preservation
of the exact original deadline, successful and failed handoff reuse, grant and
credential revocation before/during dispatch, configuration changes, descriptor
substitution, unsupported mechanisms, payload bounds, wrong/malformed signatures,
provider claims of verification, late completion, expiry and ambiguous results.

A separate client-store test commits a response then disposes of the provider,
forbids upstream callbacks, and recovers the same local receipt after expiry. This
offline path neither calls the custody bridge nor requests a fresh signature.
