from datetime import datetime, timezone
from pathlib import Path

from tnc.ingestion.parser import parse_article
from tnc.spans.models import SpanType


FIXTURE = Path(__file__).parent / "fixtures" / "article_v1.html"


def test_parser_preserves_article_structure():
    html = FIXTURE.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="version-001",
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert len(spans) == 8

    assert [span.span_type for span in spans] == [
        SpanType.HEADING,
        SpanType.PARAGRAPH,
        SpanType.PARAGRAPH,
        SpanType.QUOTE,
        SpanType.HEADING,
        SpanType.PARAGRAPH,
        SpanType.UPDATE_NOTICE,
        SpanType.CORRECTION,
    ]


def test_parser_preserves_document_order():
    html = FIXTURE.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="version-001",
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert [span.ordinal for span in spans] == list(range(8))


def test_parser_preserves_update_and_correction_text():
    html = FIXTURE.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="version-001",
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert spans[6].normalized_text == (
        "Update: Officials later said five people were injured."
    )

    assert spans[7].normalized_text == (
        "Correction: An earlier version of this article misstated "
        "the time of the incident."
    )

def test_parser_handles_frozen_abc_article():
    abc_fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "a4c4100c7c2af0e994b1bcea7e234615c19d845dfaaf7df5b9dd193dc89e9f00"
    )

    html = abc_fixture.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="abc-test",
        available_from=datetime(2013, 5, 21, tzinfo=timezone.utc),
    )

    assert len(spans) == 23
    assert spans[0].span_type == SpanType.HEADING
    assert spans[0].normalized_text == (
        "Oklahoma Tornado Deaths Revised Down to 24, Including 9 Children"
    )
    assert spans[1].span_type == SpanType.PARAGRAPH
    assert spans[1].normalized_text == (
        "The tornado destroyed homes and businesses in a 12-mile path."
    )


def test_parser_handles_frozen_mpr_article():
    mpr_fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "542607b75d87b2be33810bc444ea3a6b01fe420d91b8c15dcc37f77ba72ae525"
    )

    html = mpr_fixture.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="mpr-test",
        available_from=datetime(2013, 5, 20, tzinfo=timezone.utc),
    )

    assert len(spans) == 44
    assert spans[0].span_type == SpanType.HEADING
    assert spans[0].normalized_text == (
        "Huge tornado hits Oklahoma City suburb, kills 51"
    )
    assert spans[1].span_type == SpanType.CAPTION
    assert spans[2].normalized_text == "By TIM TALLEY Associated Press"
    assert spans[3].normalized_text.startswith(
        "MOORE, Okla. (AP) -- A monstrous tornado"
    )

    texts = [span.normalized_text for span in spans]

    assert not any("Turn Up Your Support" in text for text in texts)
    assert not any("Create an account or log in" in text for text in texts)
    assert not any(
        "Photos: Tornado hits Moore, Okla." in text
        and "Interactive: Monstrous tornado strikes" in text
        for text in texts
    )
    assert not any("Gallery Fullscreen Slideshow" in text for text in texts)


def test_parser_handles_frozen_nws_event_page():
    nws_fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "9e356c3b438265ea409fd40f4a3b9bf5eba667065f0af97986f477da83499840"
    )

    html = nws_fixture.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="nws-test",
        available_from=datetime(2013, 5, 20, tzinfo=timezone.utc),
    )

    assert len(spans) == 396
    assert spans[0].span_type == SpanType.HEADING
    assert spans[0].normalized_text == (
        "The Tornado Outbreak of May 20, 2013"
    )
    assert spans[1].span_type == SpanType.HEADING
    assert spans[1].normalized_text == "Summary"
    assert any(
        span.normalized_text == "Fast Facts"
        for span in spans
    )
    assert any(
        "A rating of EF-5 has been given to the tornado"
        in span.normalized_text
        for span in spans
    )


def test_parser_excludes_nws_resource_and_gallery_chrome():
    nws_fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "9e356c3b438265ea409fd40f4a3b9bf5eba667065f0af97986f477da83499840"
    )

    html = nws_fixture.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="nws-adjudication-filter-test",
        available_from=datetime(2013, 5, 20, tzinfo=timezone.utc),
    )

    texts = [span.normalized_text for span in spans]

    assert len(spans) == 396

    # Fast Facts keeps substantive factual content but excludes
    # resource/index material.
    assert "Fast Facts" in texts
    assert (
        "Most Tornadoes to Occur on Any May 20th "
        "in Oklahoma (1950-Present)"
        in texts
    )
    assert "GIS Data" not in texts
    assert "Severe Weather Safety Information" not in texts
    assert not any(
        text.startswith("Web Pages and Reports Related")
        for text in texts
    )
    assert not any(
        text.startswith("Research Articles")
        for text in texts
    )

    # IDSS keeps the substantive support description while dropping
    # the external FEMA resource pointer.
    assert not any(
        text.startswith(
            "Checkout the Incident Command Structure"
        )
        for text in texts
    )

    # Damage section keeps its evidentiary provenance paragraph.
    assert any(
        text.startswith(
            "The following photos show damage produced by "
            "the May 20, 2013 EF-5 tornado."
        )
        for text in texts
    )

    # Other substantive NWS evidence remains present.
    assert any(
        "A rating of EF-5 has been given to the tornado"
        in text
        for text in texts
    )


def test_parser_excludes_abc_promotional_content():
    abc_fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "a4c4100c7c2af0e994b1bcea7e234615c19d845dfaaf7df5b9dd193dc89e9f00"
    )

    html = abc_fixture.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="abc-promo-filter-test",
        available_from=datetime(2013, 5, 20, tzinfo=timezone.utc),
    )

    texts = [span.normalized_text for span in spans]

    assert "Popular Reads" not in texts
    assert not any(
        text.startswith(("RELATED:", "PHOTOS:", "VIDEO:"))
        for text in texts
    )


def test_parser_excludes_cbs_article_chrome():
    cbs_fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "7d3fd4d11470ee0e8b9694ef95faf1ee16ab6151e64cfac2ff342244c2c4af53"
    )

    html = cbs_fixture.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="cbs-chrome-filter-test",
        available_from=datetime(2013, 5, 20, tzinfo=timezone.utc),
    )

    texts = [span.normalized_text for span in spans]

    assert "How to help those hit by Oklahoma tornado" not in texts
    assert "KWTV Oklahoma City's Storm Tracker Radar" not in texts
    assert "National Weather Service Storm Prediction Center" not in texts
    assert "Four things you need to know about tornado season" not in texts
    assert "Massive tornado hits Oklahoma 53 photos" not in texts

    assert not any(
        text.startswith("\u00a9 2013 CBS Interactive Inc.")
        for text in texts
    )

    assert any(
        text.startswith("A child is pulled from the rubble")
        for text in texts
    )
    assert any(
        text.startswith("A tornado rips through the Oklahoma City area")
        for text in texts
    )


def test_parser_excludes_mpr_contributor_credit():
    mpr_fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "542607b75d87b2be33810bc444ea3a6b01fe420d91b8c15dcc37f77ba72ae525"
    )

    html = mpr_fixture.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="mpr-contributor-filter-test",
        available_from=datetime(2013, 5, 20, tzinfo=timezone.utc),
    )

    texts = [span.normalized_text for span in spans]

    assert (
        "Associated Press writers Sean Murphy, Nomaan Merchant and "
        "Sue Ogrocki contributed to this report."
        not in texts
    )

    assert any(
        text.startswith("DEADLIEST US TORNADOES SINCE 1900")
        for text in texts
    )


def test_parser_handles_archived_abc_2013_layout():
    fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "39eff51df623753297b9f12d7a00bdf6f0b04c0d1164f128cc1a5f1ea1055704"
    )

    spans = parse_article(
        html=fixture.read_text(encoding="utf-8"),
        document_version_id="abc-2013-layout-test",
        available_from=datetime(2026, 9, 10, tzinfo=timezone.utc),
    )

    assert spans[0].span_type == SpanType.HEADING
    assert spans[0].normalized_text == (
        "Oklahoma Tornado Deaths Revised Down to 24, Including 7 Children"
    )
    assert spans[1].span_type == SpanType.PARAGRAPH
    assert spans[1].normalized_text.startswith(
        "First responders are in a race against time"
    )
    assert "including nine children." in spans[1].normalized_text
    assert spans[2].normalized_text.startswith(
        "Oklahoma medical examiner spokeswoman Amy Elliot said"
    )


def test_archived_abc_parser_excludes_page_navigation():
    fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "39eff51df623753297b9f12d7a00bdf6f0b04c0d1164f128cc1a5f1ea1055704"
    )

    spans = parse_article(
        html=fixture.read_text(encoding="utf-8"),
        document_version_id="abc-2013-navigation-test",
        available_from=datetime(2026, 9, 10, tzinfo=timezone.utc),
    )

    texts = [span.normalized_text for span in spans]
    assert not any(text in {"1", "|", "2", "Next Page"} for text in texts)
    assert spans[-1].normalized_text.startswith(
        '"I was pulling walls off of people,"'
    )


def test_archived_abc_early_excludes_live_updates_link():
    fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "d1410eb00ab2c487e0dbc3da645f1f6be4e83a2ff0096e8d95dc14013985884f"
    )
    spans = parse_article(
        html=fixture.read_text(encoding="utf-8"),
        document_version_id="abc-early-navigation-test",
        available_from=datetime(2026, 9, 10, tzinfo=timezone.utc),
    )

    texts = [span.normalized_text for span in spans]
    assert "LIVE UPDATES: Tornado Damage in Oklahoma" not in texts
    assert texts[0] == (
        "Oklahoma Tornado: 20 Children Among at Least 51 Dead, "
        "'Horrific' Damage"
    )
    assert texts[1].startswith("At least 20 of the 51 people killed")
    assert "the Oklahoma Chief Medical Examiner said" in texts[1]
