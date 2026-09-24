"""Prevent README links from breaking when rendered outside GitHub."""

import re
from pathlib import Path


README = Path(__file__).parents[1] / "README.md"


def test_readme_has_no_relative_links_or_images():
    text = README.read_text(encoding="utf-8")

    inline_pattern = re.compile(
        r"\]\((?!#|https?://|mailto:)([^)]+)\)"
    )
    relative_inline = inline_pattern.findall(text)

    reference_defs = re.findall(
        r"^\s*\[[^\]]+\]:\s*(\S+)",
        text,
        re.MULTILINE,
    )
    relative_refs = [
        target
        for target in reference_defs
        if not target.startswith(("http://", "https://", "#", "mailto:"))
    ]

    assert not relative_inline, (
        f"relative inline links or images found: {relative_inline}"
    )
    assert not relative_refs, (
        f"relative reference-style links or images found: {relative_refs}"
    )
