# TNC

TNC is a Python project for examining what news articles say, where statements
come from, and how source content changes. It turns saved article HTML into
traceable pieces of text and extracts statements that match supported wording.

The command-line tools currently read local HTML files. They do not decide
whether a news claim is true or automatically determine that two publishers are
independent sources.

## Start here

The examples below use small HTML files included in this repository. You do not
need to download an article or enter an API key to try them.

### 1. Open the project folder

On the Windows computer used for this project, open PowerShell and run:

```powershell
cd C:\Users\Admin\Documents\TNC
```

If you saved the project elsewhere, use that folder instead. Run the remaining
commands from the folder containing `pyproject.toml`.

### 2. Check the environment

This project uses Python 3.12 and `uv` to manage its Python environment and
packages. `pyproject.toml` permits Python 3.12 or newer; `.python-version` selects
3.12 for this checkout. Check that `uv` is available:

```powershell
uv --version
```

On a new checkout, install the project and its development dependencies from the
existing lockfile:

```powershell
uv sync --locked
```

This setup step may download Python or packages. The included examples operate
on local files once the environment is ready. On an already configured checkout,
`uv run` uses the project environment; you do not need to activate `.venv` manually.

### 3. Run your first example

```powershell
uv run tnc parse tests/fixtures/article_v1.html
```

You should see eight lines. The first is:

```text
0    heading    Bridge closes after structural failure
```

The actual output separates columns with tabs. Each line contains:

| Column | Meaning |
| --- | --- |
| Ordinal | The piece's position in the parsed article, starting at 0. |
| Structural type | For example, heading, paragraph, quote, correction, or update_notice. |
| Normalized text | The extracted wording with repeated whitespace collapsed. |

A **source span** is one of these pieces of article text. The number lets you
refer back to the piece that supports a statement. It is not an HTML line number.

## Examine one piece of the article

```powershell
uv run tnc parse tests/fixtures/article_v1.html --span 6
```

Expected output, with tabs shown here as spaces:

```text
6    update_notice    Update: Officials later said five people were injured.
```

Omit `--span` to show all spans. If the ordinal does not exist, TNC reports an
error. This example preserves both the earlier report of three injuries and the
later update to five; parsing alone does not decide which claim is true.

## Extract supported statements

```powershell
uv run tnc assertions tests/fixtures/assertions_v1.html
```

Expected output:

```text
Admitted: 2
  Officials reported five people were injured.
    Source spans: 0
  Engineers confirmed inspections were underway.
    Source spans: 1
Rejected: 0
```

An **assertion** is a structured statement extracted from the source text.
**Admitted** means it passed the current source-reference and verbatim-support
checks. It does not mean TNC independently verified the statement.

The source-span numbers match the ordinals from `tnc parse` for the same file.
Rejected candidates are listed with reasons. Unsupported wording is skipped
rather than necessarily appearing as a rejection.

### Extraction limits

The current extractor recognizes this structure:

```text
<speaker> <operator> <proposition>
```

Supported operators are `reported`, `confirmed`, `denied`, `estimated`,
`alleged`, `expected`, and `said`. The word `said` maps to the REPORTED category
while remaining `said` in the extracted predicate.

Only the first sentence of each span is considered. Sentence detection uses
limited punctuation rules, with support for common titles and decimal numbers;
it is not a general language parser. Ambiguous initials and dotted abbreviations
cause the span to be skipped. An empty result does not mean an article contains
no claims.

## Use your own saved HTML

Replace the fixture path with a local UTF-8 HTML file. Quote paths containing
spaces:

```powershell
uv run tnc parse "C:\path\to\saved article.html"
```

That path is an example; replace it with a file that exists on your computer.
The parser supports particular article structures and publisher layouts, not
every web page. A URL, PDF, screenshot, or plain-text article is not a supported
input to these commands.

The CLI records the local parsing time as an observation time. It does not
establish when the article was first published or historically available.

## Understand source relationships

**Provenance** means where information came from and how documents relate.
The Python provenance pipeline measures overlap, then separately applies
relationship rules. It is not currently exposed as a `tnc provenance` command.

The existing document judgments are `explicitly_cites`, `reprint_of`, and
`likely_derived_from`. The classifier can also return `None`, meaning that it
makes no document-level judgment. `None` does not establish independence.

Reviewed `shared_source_evidence` can explain similar wording through a common
wire service, syndication lineage, or underlying authority. When supplied, it
prevents overlap alone from triggering reprint or derivation labels, even for
identical wording. An explicit citation still takes priority. Without that
annotation, the existing overlap rules remain in effect.

For example, two publishers quoting the same medical examiner do not provide
two independent confirmations just because they have different names. Similar
wording also does not establish that one copied the other.

Callers must supply the reviewed evidence to `infer_source_relation` or
`measure_provenance_signals`. The API does not automatically load review files
or infer lineage from a wire-service name. The reviewed comparisons are recorded
in [the casualty provenance review](corpus/tib_run_a/casualty_provenance_review.md)
and its [pair annotations](corpus/tib_run_a/shared_source_pairs.json).

For a complete CLI-to-Python example using those frozen inputs, see the
[source-provenance walkthrough](docs/source_provenance_walkthrough.md).

## Project map

| Location | Purpose |
| --- | --- |
| `src/tnc/__init__.py` | The `parse` and `assertions` commands. |
| `src/tnc/ingestion/` | Retrieval, saved bodies, manifests, and article parsing. |
| `src/tnc/spans/` | Span models, assertion processing, version comparison, and temporal/replay logic. |
| `src/tnc/provenance/` | Source measurements and document-relationship judgments. |
| `tests/fixtures/` | Small examples and synthetic replay fixtures. |
| `tests/golden/` | Expected parsed output used to detect changes. |
| `corpus/tib_run_a/` | Frozen Moore tornado reporting, archive evidence, and review notes. |

Frozen corpus files are evidence: do not edit or reformat them. Their SHA-256
fingerprints identify their exact bytes. See the [corpus guide](corpus/tib_run_a/README.md)
for acquisition history, availability uncertainty, and review requirements.

Historical replay admission for the real corpus remains pending. Passing the
synthetic replay tests does not establish that the saved live articles were
available at a particular historical time.

## Help and troubleshooting

```powershell
uv run tnc --help
uv run tnc parse --help
uv run tnc assertions --help
```

| Message or symptom | What to check |
| --- | --- |
| `uv` is not recognized | Ensure uv is installed and available in the current terminal. |
| Project configuration cannot be found | Open the TNC folder containing `pyproject.toml`. |
| File cannot be opened | Check the path and quote it if it contains spaces. |
| File cannot be decoded or layout is unsupported | Use UTF-8 HTML with supported article structure; try an included fixture first. |
| No source span with that ordinal | Parse without `--span` to see the available numbers. |
| `Admitted: 0` | The extractor may not support the wording; inspect the parsed text. |

Input and argument errors return a nonzero exit code. In PowerShell,
`$LASTEXITCODE` shows the exit code of the command that just ran. Running
`uv run tnc` without a subcommand displays a usage error; choose `parse` or
`assertions`.

## Development checks

Run the existing test suite from the project root:

```powershell
uv run pytest -q
```

Tests cover parsing, CLI behavior, assertions, provenance, temporal behavior,
replay fixtures, and frozen-body integrity. A passing suite verifies those checks,
not the truth of the underlying reporting.

Before saving a code change, inspect it and check formatting:

```powershell
git diff
git diff --check
```

Then stage only the intended files, inspect the staged changes, commit, and push
when ready. Do not apply automatic formatting to the frozen corpus objects.
