import hashlib
import re
from datetime import datetime

from selectolax.lexbor import LexborHTMLParser

from tnc.spans.models import SourceSpan, SpanType


def normalize_text(text: str) -> str:
    """Collapse repeated whitespace while preserving the text itself."""
    return re.sub(r"\s+", " ", text).strip()


def hash_text(text: str) -> str:
    """Return a stable SHA-256 hash for text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def classify_node(tag: str, class_name: str | None) -> SpanType | None:
    """Map structural HTML signals to TNC span types."""
    classes = set((class_name or "").lower().split())

    if "correction" in classes:
        return SpanType.CORRECTION

    if "update" in classes:
        return SpanType.UPDATE_NOTICE

    if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
        return SpanType.HEADING

    if tag == "blockquote":
        return SpanType.QUOTE

    if tag == "li":
        return SpanType.LIST_ITEM

    if tag in {"td", "th"}:
        return SpanType.TABLE_CELL

    if tag == "figcaption":
        return SpanType.CAPTION

    if tag == "p":
        return SpanType.PARAGRAPH

    return None


def parse_article(
    html: str,
    document_version_id: str,
    available_from: datetime,
) -> list[SourceSpan]:
    """Convert article HTML into ordered immutable SourceSpan records."""

    tree = LexborHTMLParser(html)
    article = tree.css_first("article")

    if article is None:
        raise ValueError("No <article> element found")

    selectors = (
        "h1, h2, h3, h4, h5, h6, "
        "p, blockquote, li, td, th, figcaption, "
        ".update, .correction"
    )

    nodes = article.css(selectors)

    spans: list[SourceSpan] = []

    for node in nodes:
        # Avoid producing a paragraph twice when it is already contained
        # inside a blockquote.
        if node.tag == "p" and node.parent is not None:
            if node.parent.tag == "blockquote":
                continue

        raw_text = node.text(separator=" ", strip=True)
        normalized_text = normalize_text(raw_text)

        if not normalized_text:
            continue

        span_type = classify_node(
            node.tag,
            node.attributes.get("class"),
        )

        if span_type is None:
            continue

        ordinal = len(spans)
        content_hash = hash_text(normalized_text)

        span = SourceSpan(
            span_id=f"{document_version_id}:span:{ordinal}",
            document_version_id=document_version_id,
            ordinal=ordinal,
            span_type=span_type,
            raw_text=raw_text,
            normalized_text=normalized_text,
            available_from=available_from,
            content_hash=content_hash,
        )

        spans.append(span)

    return spans