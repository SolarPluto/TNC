# Historical replay CLI

Run from the TNC source checkout:

```powershell
uv run tnc historical-replay --document abc-early --version abc-early-archive-20130521120016 --time 2013-05-21T12:00:16Z
```

The only query options are `--document`, `--version`, and `--time` (plus help).
Time must contain Z or a UTC offset. Abbreviated options and custom configuration,
review, or evidence paths are rejected.

The source-hosted loader reads three fixed ABC archive sidecars, the source
inventory, and retrieval manifest. It resolves object hashes only within the
configured corpus root, retains the bytes, and constructs FrozenCorpus,
InMemoryReviewStore, and HistoricalReplayEngine internally. It uses the source
checkout location, not the current directory or environment variables. The
evaluator still verifies body/index hashes and archive payload matching.

Every invocation starts with an empty review store and no transition mappings.
No review authority is imported from sidecar metadata. All three configured ABC
captures therefore remain UNVERIFIED at or after capture time. Before capture,
technical validation rejects them. Unknown versions are rejected. This initial
command cannot release a real capture until trusted host review and transition
configuration are implemented; it has no user-accessible approval switch.

Blocked executions print a single JSON object with status, reason_codes and
evidence_record_ids, without article text, spans or partial snapshots. Exit code
2 indicates rejected/unverified results or argument errors; argument errors use
argparse's stderr usage message. Exit code 3 indicates host initialization or
execution failure; those errors are sanitized JSON and do not include exception
text, paths, or source content. Evidence IDs are empty when failure occurs before
an admission decision exists.

Success exits 0 and prints a JSON snapshot with its receipt ID, retrieved from
the validated committed outbox. Approved behavior is tested using an internally
configured synthetic host, never an approval for a real capture. Success output
is prepared before printing. Outbox insertion remains the release point; later
printing is not atomic with administrative review and does not retract a prior
release. A post-commit failure can leave an outbox entry despite unsuccessful
CLI output. The in-memory store disappears when the process exits; durable
recovery and end-to-end request retries remain deferred.

This is a source-checkout integration. A wheel without the adjacent repository
corpus fails closed instead of searching the current directory for substitutes.
Host file ownership, authenticated persistent review storage, and deployment
isolation remain operational requirements. Python configuration is not an
operating-system security boundary.

The existing `parse` and `assertions` commands retain their local-file behavior.
They are not historical replay and do not issue historical release receipts.
