# TNC

TNC is a command-line tool for turning saved news articles into traceable source
spans and extracting source-attributed assertions from them. It also includes
tools for comparing source relationships and for gated historical replay. It is
intended for researchers and fact-checkers working with saved news archives.

TNC does **not** decide whether a news claim is true. It also does not
automatically determine that two publishers are independent sources.

## See it work

The included example article first reports three injuries and later updates that
number to five.

```powershell
uv run tnc assertions tests/fixtures/article_v1.html
```

Output from the current version:

```text
Admitted: 2
  Officials said three people were injured.
    Source spans: 2
  Officials said five people were injured.
    Source spans: 6
Rejected: 0
```

Each number after `Source spans:` is a zero-based source-span ordinal. If an
assertion references multiple spans, their ordinals are comma-separated; the
field is not a count.

This preserves both the earlier statement and the later update rather than
collapsing them into one claim.

## What TNC does

TNC currently provides three main workflows:

- **Parse saved article HTML into traceable source spans.** Structural types
  include headings, paragraphs, quotes, corrections, update notices, list items,
  table cells, and captions.
- **Extract supported assertions from those spans.** Assertions are admitted
  only when their source coordinates and verbatim support validate.
- **Run gated historical replay.** Archived evidence can be evaluated against
  capture time, review state, and replay policy before a historical snapshot is
  released.

The first two workflows operate directly on local HTML files. Historical replay
has a stricter trust model and is described separately below.

## Try it from a source checkout

TNC is not yet published to PyPI. The current supported usage is from a source
checkout.

An unrelated PyPI distribution named `tnc` exists; this project uses the
distribution name `tnc-provenance` to avoid ambiguity.

Requirements:

- Python 3.12 or newer
- `uv`

From the project root:

```powershell
uv sync --locked
```

Then run:

```powershell
uv run tnc assertions tests/fixtures/article_v1.html
```

or parse the article into source spans:

```powershell
uv run tnc parse tests/fixtures/article_v1.html
```

To use your own saved article:

```powershell
uv run tnc parse "C:\path\to\saved article.html"
```

The included fixture requires no API key or article download. The input must be
a local UTF-8 HTML file using a supported article structure. URLs, PDFs,
screenshots, and plain-text files are not inputs to these commands.

For local `parse` and `assertions` runs, TNC records the parsing time as an
observation time. That does not establish when the article was first published
or historically available.

## Source spans

A source span is an ordered, immutable piece of article text.

TNC recognizes these structural types:

<!-- The vocabulary lists below are machine-checked by tests/test_readme_vocabulary_contract.py. Edit the list and the corresponding runtime definition in the same change. -->
<!-- vocabulary: span-types -->
- `paragraph`
- `heading`
- `quote`
- `caption`
- `list_item`
- `table_cell`
- `correction`
- `update_notice`
<!-- /vocabulary: span-types -->

`tnc parse` prints tab-separated ordinal, structural type, and normalized
text. The ordinal is the coordinate used by extracted assertions, not an HTML
line number. For example, `Source spans: 6` means the assertion is supported by
source-span ordinal 6.

To inspect one span directly:

```powershell
uv run tnc parse tests/fixtures/article_v1.html --span 6
```

Omit `--span` to show all spans. If the ordinal does not exist, TNC reports an
error.

## Assertions

Run:

```powershell
uv run tnc assertions path\to\article.html
```

The current extractor deliberately recognizes a narrow attribution pattern:

```text
<speaker> <operator> <proposition>
```

Supported source-text operators are:

<!-- vocabulary: source-operators -->
- `reported`
- `confirmed`
- `denied`
- `estimated`
- `alleged`
- `expected`
- `said`
<!-- /vocabulary: source-operators -->

The current source-text mapping is:

<!-- vocabulary: operator-mappings -->
- `said` → `REPORTED` (the extracted predicate remains `said`)
<!-- /vocabulary: operator-mappings -->

An assertion is **admitted** when its source coordinates exist and its recorded
verbatim support is present in those source spans.

Admission does **not** mean TNC verified that the proposition is true. Rejected
candidates are listed with reasons; unsupported or ambiguous wording may be
skipped rather than guessed. Only the first sentence of each span is considered. Sentence detection has limited
punctuation rules, including support for common titles and decimal numbers;
ambiguous initials and dotted abbreviations cause the span to be skipped.

## Source relationships and provenance

TNC also contains a provenance pipeline for examining relationships between
documents. The Python API measures overlap separately from the relationship
rules; it is not currently exposed as a `tnc provenance` CLI command.

Existing document-level judgments are:

<!-- vocabulary: relation-types -->
- `explicitly_cites`
- `likely_derived_from`
- `reprint_of`
<!-- /vocabulary: relation-types -->

The classifier may also return no judgment. No judgment does not establish that
two sources are independent.

Reviewed `shared_source_evidence` can account for common wire-service,
syndication, or underlying-authority material without treating similar wording
as proof that one publisher copied another. When supplied, it prevents overlap
alone from triggering reprint or derivation labels, even for identical wording;
an explicit citation still takes priority. Without that annotation, the existing
overlap rules remain in effect.

Callers must supply reviewed evidence to `infer_source_relation` or
`measure_provenance_signals`. The API does not automatically load review files
or infer lineage from a wire-service name. The reviewed comparisons are recorded
in [the casualty provenance review](corpus/tib_run_a/casualty_provenance_review.md)
and its [pair annotations](corpus/tib_run_a/shared_source_pairs.json).

For a complete CLI-to-Python example using those frozen inputs, see
[the source-provenance walkthrough](docs/source_provenance_walkthrough.md).

## Historical replay

Historical replay is an advanced, fail-closed workflow.

Historical replay requires a trusted review store and transition configuration;
the included source-hosted examples return `MISSING_REVIEW` until that host
configuration exists.

The repository currently includes archived ABC captures and machinery that
checks exact saved body hashes, archive index evidence, capture-time constraints,
review state, transition configuration, and release receipts.

The source-hosted CLI intentionally starts with no trusted review authority.
Real included captures therefore remain blocked with `MISSING_REVIEW` rather
than being released automatically. Archive presence alone is not promoted into
an approved historical claim.

Example:

```powershell
uv run tnc historical-replay --document abc-early --version abc-early-archive-20130521120016 --time 2013-05-21T12:00:16Z
```

A real capture without trusted review currently returns an `unverified`
result. Passing the synthetic replay tests does not establish that the saved live
articles were available at a particular historical time.

See [the historical replay CLI documentation](docs/historical_cli.md) for the
complete trust and release model.

## Limits

TNC is intentionally conservative.

It does not:

- determine whether a proposition is true;
- infer source independence automatically;
- fetch articles from URLs or accept non-HTML input such as PDFs, screenshots,
  or plain text;
- treat archive capture as proof of first publication time;
- release historical evidence without the required review state;
- act as a general natural-language claim extractor.

The current assertion extractor uses deliberately limited grammatical and
sentence-boundary rules. An empty extraction result does not mean an article
contains no claims.

## Project map

| Location | Purpose |
| --- | --- |
| `src/tnc/` | CLI entry points and top-level package integration |
| `src/tnc/ingestion/` | Saved content, article parsing, and ingestion |
| `src/tnc/spans/` | Source spans, assertions, state transitions, and replay |
| `src/tnc/provenance/` | Source relationships, review, admission, and historical evidence logic |
| `tests/fixtures/` | Small deterministic examples and replay fixtures |
| `tests/golden/` | Expected parsed output used to detect changes |
| `corpus/tib_run_a/` | Frozen Moore tornado reporting, archive evidence, and review material |

Frozen corpus objects are evidence and should not be reformatted or modified
casually. Their hashes identify their exact bytes. See
[the corpus guide](corpus/tib_run_a/README.md) for acquisition history,
availability uncertainty, and review requirements.

## Help

```powershell
uv run tnc --help
uv run tnc parse --help
uv run tnc assertions --help
uv run tnc historical-replay --help
```

| Message or symptom | What to check |
| --- | --- |
| `uv` is not recognized | Ensure `uv` is installed and available in the current terminal. |
| Project configuration cannot be found | Run commands from the checkout containing `pyproject.toml`. |
| File cannot be opened | Check the path and quote it if it contains spaces. |
| File cannot be decoded or layout is unsupported | Use UTF-8 HTML with a supported article structure; try an included fixture first. |
| No source span with that ordinal | Parse without `--span` to see the available ordinals. |
| `Admitted: 0` | The extractor may not support the wording; inspect the parsed text. |

Input and argument errors return a nonzero exit code. In PowerShell,
`$LASTEXITCODE` shows the exit code of the command that just ran.

## Development

Run the test suite from the repository root:

```powershell
uv run pytest -q
```

Tests cover parsing, CLI behavior, assertions, provenance, temporal behavior,
replay fixtures, and frozen-body integrity. A passing suite verifies those
checks, not the truth of the underlying reporting.

Some native Windows tests skip on non-Windows platforms. Non-doc PRs are
validated by the full Windows CI suite.

Install `pre-commit` as a `uv` tool once, then install the repository hook:

```powershell
uv tool install pre-commit
pre-commit install
```

To run the text-hygiene checks manually across the repository:

```powershell
pre-commit run --all-files
```

Before committing a change, also inspect the diff:

```powershell
git diff
git diff --check
```

PRs that change only `docs/**` and/or lowercase Markdown files use the
docs-only CI route; other changes run the full Windows suite. See
[the Windows test reliability inventory](docs/TNC_Test_Reliability.md) for the
routing rule and reliability notes.

Do not apply automatic formatting to frozen corpus objects.
