# ABC archive-observation fixture

`abc_capture_timeline.json` is an offline, test-only visibility model for three
verified ABC archive captures. It is not admission of the real corpus into
historical claim replay.

A capture establishes existence by that time (an upper bound on first availability).
We conservatively use it as the test's earliest visible time. First publication
and exact edit times remain null; actual 2026 retrieval times remain observed_at.

The early report is a separate document from the correction report. The correction
has two observed versions. At each of the three capture times, checkpoints test
one microsecond before, exactly at, and one microsecond after. Expected versions
are listed per query; a capture has no universal expected_visible boolean.

Tests first verify body/index SHA-256, matching archive timestamp/original URL/status/
MIME type/payload digest, manifest retrieval links, and pending admission flags.
They select a version per document before selecting its spans. No end date or exact
edit time is fabricated for the earlier version; version selection expresses the
conservative observation policy, not a proven continuous history between captures.

Replay integration uses explicitly synthetic observation markers linked to real
span IDs, always with an evidence-availability map. FIRST_REPORTED in those markers
is a test of the existing state API, not automatic extraction, a casualty judgment,
or a declaration of first historical publication. Earlier probes and missing
coordinates must fail. The generic replay API still permits omission of the map;
this fixture does not add a production historical-admission entry point.

Run from the repository root:

```powershell
uv run pytest -q tests/test_abc_capture_timeline.py
```

The existing synthetic Run A fixtures, engine code, frozen corpus bytes, and
historical admission records are unchanged.
