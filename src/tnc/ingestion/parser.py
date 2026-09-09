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

    selectors = (
        "h1, h2, h3, h4, h5, h6, "
        "p, blockquote, li, td, th, figcaption, "
        ".update, .correction"
    )

    article = tree.css_first("article")

    if article is not None:
        # MPR embeds fundraising, gallery, and related-link UI
        # inside the article container. Preserve the headline and
        # substantive story body while excluding those injected blocks.
        is_mpr_story = (
            "content" in (article.attributes.get("class") or "").split()
            and "story" in (article.attributes.get("class") or "").split()
            and tree.css_first(".story-body.userContent") is not None
        )

        if is_mpr_story:
            mpr_headline = article.css_first("header.story-header h1")
            mpr_body = article.css_first(".story-body.userContent")

            nodes = [mpr_headline] if mpr_headline is not None else []
            nodes.extend(mpr_body.css(selectors))

            filtered_nodes = []

            for node in nodes:
                ancestor = node.parent
                excluded = False

                while ancestor is not None and ancestor is not article:
                    classes = set(
                        (ancestor.attributes.get("class") or "").split()
                    )

                    if "donate-ask" in classes or "apm-gallery" in classes:
                        excluded = True
                        break

                    ancestor = ancestor.parent

                if excluded:
                    continue

                if node.tag == "p":
                    node_text = normalize_text(
                        node.text(separator=" ", strip=True)
                    )

                    if (
                        node.css_first("em") is not None
                        and node_text.endswith(
                            "contributed to this report."
                        )
                    ):
                        continue

                    if (
                        "Photos: Tornado hits Moore, Okla." in node_text
                        and "Interactive: Monstrous tornado strikes"
                        in node_text
                    ):
                        continue

                filtered_nodes.append(node)

            nodes = filtered_nodes
        else:
            article_classes = set(
                (article.attributes.get("class") or "").split()
            )
            is_cbs_story = (
                "content-article" in article_classes
                and article.css_first("section.content__body") is not None
            )

            if is_cbs_story:
                cbs_body = article.css_first("section.content__body")
                cbs_headline = article.css_first("h1.content__title")
                cbs_timestamp = article.css_first(
                    "p.content__meta--timestamp"
                )

                nodes = [cbs_headline] if cbs_headline is not None else []
                if cbs_timestamp is not None:
                    nodes.append(cbs_timestamp)
                nodes.extend(cbs_body.css(selectors))

                filtered_nodes = []

                for node in nodes:
                    ancestor = node.parent
                    excluded = False

                    while ancestor is not None and ancestor is not article:
                        classes = set(
                            (ancestor.attributes.get("class") or "").split()
                        )

                        if "arrows" in classes and "gray" in classes:
                            excluded = True
                            break

                        ancestor = ancestor.parent

                    if excluded:
                        continue

                    node_classes = set(
                        (node.attributes.get("class") or "").split()
                    )

                    if (
                        node.tag == "figcaption"
                        and "embed__caption-container" in node_classes
                        and node.css_first("a.embed__headline-link")
                        is not None
                    ):
                        continue

                    if (
                        node.tag == "p"
                        and "content__copyright" in node_classes
                    ):
                        continue

                    filtered_nodes.append(node)

                nodes = filtered_nodes
            else:
                nodes = article.css(selectors)
    else:
        # ABC stores its headline and story in separate containers.
        abc_container = tree.css_first(".FITT_Article_main__body")
        abc_body = (
            abc_container.css_first('[data-testid="prism-article-body"]')
            if abc_container is not None
            else None
        )

        if abc_body is not None:
            abc_headline = abc_container.css_first(
                '[data-testid="prism-headline"]'
            )
            nodes = (
                abc_headline.css(selectors)
                if abc_headline is not None
                else []
            )

            for node in abc_body.css(selectors):
                ancestor = node.parent
                excluded = False

                while ancestor is not None and ancestor is not abc_body:
                    classes = set(
                        (ancestor.attributes.get("class") or "").split()
                    )

                    if "MobileContentPromo" in classes:
                        excluded = True
                        break

                    ancestor = ancestor.parent

                if excluded:
                    continue

                if node.tag == "p":
                    strong = node.css_first("strong")
                    link = node.css_first("a")

                    if strong is not None and link is not None:
                        promo_text = normalize_text(
                            strong.text(separator=" ", strip=True)
                        )

                        if promo_text.startswith(
                            ("RELATED:", "PHOTOS:", "VIDEO:")
                        ):
                            continue

                nodes.append(node)
        else:
            # NWS historical event pages store substantive content
            # inside the tabbed event-content container.
            nws_content = tree.css_first("#tabs > .links")

            if nws_content is None:
                raise ValueError("No supported article content found")

            nws_headline = tree.css_first("h1.location-pagetitle")
            nodes = [nws_headline] if nws_headline is not None else []
            nodes.extend(nws_content.css(selectors))

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
