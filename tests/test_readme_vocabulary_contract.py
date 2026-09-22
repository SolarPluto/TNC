"""Pin README vocabulary lists to the runtime definitions they document.

README sections marked with ``vocabulary: ...`` are intentionally machine-read.
Keep their bullet format stable, or update this parser and the README together.
"""

import re
from pathlib import Path

from tnc.provenance.models import SourceRelationType
from tnc.spans.assertions import EpistemicOperator
from tnc.spans.extractor import OPERATOR_MAP
from tnc.spans.models import SpanType


README = Path(__file__).parents[1] / "README.md"


def marked_block(text: str, name: str) -> str:
    start = f"<!-- vocabulary: {name} -->"
    end = f"<!-- /vocabulary: {name} -->"

    assert text.count(start) == 1, f"expected one start marker for {name!r}"
    assert text.count(end) == 1, f"expected one end marker for {name!r}"

    start_index = text.index(start)
    end_index = text.index(end)
    assert start_index < end_index, f"markers out of order for {name!r}"
    return text[start_index + len(start):end_index]


def marked_tokens(text: str, name: str) -> set[str]:
    block = marked_block(text, name)
    lines = [line for line in block.splitlines() if line.strip()]

    tokens = []
    for line in lines:
        match = re.fullmatch(r"- `([^`]+)`", line)
        assert match, f"unexpected content in {name!r}: {line!r}"
        tokens.append(match.group(1))

    assert tokens, f"no tokens in {name!r}"
    assert len(tokens) == len(set(tokens)), f"duplicate tokens in {name!r}"
    return set(tokens)


def test_readme_span_types_match_runtime():
    text = README.read_text(encoding="utf-8")
    assert marked_tokens(text, "span-types") == {
        member.value for member in SpanType
    }


def test_readme_source_operators_match_extractor():
    text = README.read_text(encoding="utf-8")
    assert marked_tokens(text, "source-operators") == set(OPERATOR_MAP)


def test_readme_relation_types_match_runtime():
    text = README.read_text(encoding="utf-8")
    assert marked_tokens(text, "relation-types") == {
        member.value for member in SourceRelationType
    }


def test_readme_said_mapping_matches_extractor():
    text = README.read_text(encoding="utf-8")
    block = marked_block(text, "operator-mappings")
    lines = [line for line in block.splitlines() if line.strip()]

    assert len(lines) == 1, f"expected one operator mapping, found: {lines!r}"

    # README mapping syntax uses U+2192 RIGHTWARDS ARROW (→), not ASCII ->.
    match = re.fullmatch(
        r"- `([^`]+)` → `([^`]+)`[^\n]*",
        lines[0],
    )
    assert match, f"malformed operator-mapping line: {lines[0]!r}"
    assert match.group(1) == "said"
    assert match.group(2) == "REPORTED"
    assert OPERATOR_MAP["said"] is EpistemicOperator.REPORTED
