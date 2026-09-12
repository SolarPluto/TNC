# Two-store recovery test harness

`tests/test_two_store_recovery.py` exercises the runtime test writer and temporary
authority writer together. Both databases are created separately with their own
schemas. No application module, schema, production route, checkpoint distributor,
or cross-store transaction is introduced.

The runtime writer performs actual REGISTER, PREPARE, COMMIT and later AUTHORITY
transactions using existing synthetic providers. The initial authority envelope
pins the runtime's initial authority event. The fixture host reads the committed
runtime image and builds an exact handoff request against the retained authority
predecessor. Synthetic caller and batch approvals remain explicit test evidence;
they are not authenticated by a receipt or by the request's own fields.

One spawned process exits after runtime commitment and before contacting the
authority. The surviving test host reopens the committed image and constructs the
handoff. This tests recovery from committed runtime bytes, not a persisted request
coordinator. Once constructed, exact request/candidate/evidence records are retained
by the parent fixture for authority crash tests and retries. No automatic durable
request reconstruction service is provided.

Separate process exits immediately before and after authority COMMIT distinguish
rollback from lost acknowledgement. The latter recovers the original saved
acceptance bytes. Tests also accept a later runtime AUTHORITY event and recover
the earlier acceptance without changing the newer authority head. Runtime exact
retries and authority exact retries each preserve their own saved receipts.

Other cases cover conflicting request reuse, stale competing predecessors,
permission removal before handoff or retry, missing/negative synthetic approval,
and unchanged runtime checkpoints and publication tables after authority acceptance.
The MATCHED comparison uses synthetic freshness and is an audit result only; it
does not distribute a trusted external checkpoint or enable runtime execution.

These tests demonstrate process-exit recovery and explicit non-atomic ordering
in temporary stores. They do not establish physical power-loss durability,
authenticated independent authorization, live process drain, whole-store rollback
protection, or production end-to-end recovery.
