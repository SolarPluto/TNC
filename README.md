# TNC

TNC parses article HTML into source spans and extracts supported source assertions.

## Parse an HTML file

Run from the TNC project folder:

    uv run tnc parse tests/fixtures/article_v1.html

Each output line contains the span's ordinal, structural type, and normalized text.

To display one source span, use its ordinal (starting at 0):

    uv run tnc parse tests/fixtures/article_v1.html --span 6

Omit --span to display all spans. A nonexistent ordinal produces an error.

## Extract assertions

    uv run tnc assertions tests/fixtures/assertions_v1.html

The command prints admitted assertions, rejected candidates, and rejection reasons.

Each admitted assertion includes source-span numbers. These numbers start at 0 and match the ordinals printed by `tnc parse` for the same HTML file.

The current extractor recognizes this structure:

    <speaker> <operator> <proposition>

Supported operators: reported, confirmed, denied, estimated, alleged, expected, said.

The word "said" maps to the REPORTED category while remaining "said" in the extracted predicate.

Only the first sentence of each source span is considered. Later sentences in the same span are not extracted. Sentence detection uses limited punctuation rules, with support for common titles and decimal numbers; it is not a general language parser. Ambiguous initials and dotted abbreviations cause the span to be skipped.

Unsupported wording is skipped. An empty result does not mean the article contains no claims.

Admission checks source references and verbatim support. It does not verify whether a statement is true.

## Input requirements

Use a local UTF-8 HTML file with article structure supported by the parser. The example fixtures above are included in this repository.

## Run tests

    uv run pytest
