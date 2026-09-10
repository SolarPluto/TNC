from datetime import datetime, timezone

from tnc.spans.assertions import (
    AssertionType,
    EpistemicOperator,
)
from tnc.spans.extractor import extract_assertion_candidates
from tnc.spans.models import SourceSpan, SpanType


def make_span(
    span_id: str,
    text: str,
) -> SourceSpan:
    return SourceSpan(
        span_id=span_id,
        document_version_id="version-001",
        ordinal=0,
        span_type=SpanType.PARAGRAPH,
        raw_text=text,
        normalized_text=text,
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        content_hash=f"hash-{span_id}",
    )


def test_extracts_simple_reported_assertion():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported five people were injured.",
        )
    ]

    candidates = extract_assertion_candidates(spans)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.span_ids == ["version-001:span:1"]
    assert candidate.subject == "Officials"
    assert candidate.predicate == "reported"
    assert candidate.object == "five people were injured."
    assert candidate.assertion_type == AssertionType.SOURCE_ASSERTION
    assert candidate.epistemic_operator == EpistemicOperator.REPORTED
    assert candidate.speaker == "Officials"
    assert candidate.attribution_chain == ["Officials"]


def test_extracts_confirmed_assertion():
    spans = [
        make_span(
            "version-001:span:1",
            "Police confirmed the road was closed.",
        )
    ]

    candidates = extract_assertion_candidates(spans)

    assert len(candidates) == 1
    assert candidates[0].epistemic_operator == EpistemicOperator.CONFIRMED
    assert candidates[0].predicate == "confirmed"


def test_candidate_preserves_verbatim_source_support():
    text = "Officials estimated repairs would take three days."

    spans = [
        make_span(
            "version-001:span:1",
            text,
        )
    ]

    candidates = extract_assertion_candidates(spans)

    assert len(candidates) == 1
    assert candidates[0].verbatim_support == [text]
    assert candidates[0].span_ids == ["version-001:span:1"]


def test_unsupported_text_is_not_guessed_into_assertion():
    spans = [
        make_span(
            "version-001:span:1",
            "The bridge remained closed throughout the afternoon.",
        )
    ]

    candidates = extract_assertion_candidates(spans)

    assert candidates == []


def test_multiple_spans_produce_separate_provenance_bound_candidates():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported five people were injured.",
        ),
        make_span(
            "version-001:span:2",
            "Engineers confirmed inspections were underway.",
        ),
    ]

    candidates = extract_assertion_candidates(spans)

    assert len(candidates) == 2

    assert candidates[0].span_ids == ["version-001:span:1"]
    assert candidates[1].span_ids == ["version-001:span:2"]

    assert candidates[0].assertion_id == "version-001:assertion:0"
    assert candidates[1].assertion_id == "version-001:assertion:1"

def test_passive_expected_wording_is_not_treated_as_attribution():
    spans = [
        make_span(
            "version-001:span:1",
            "The death toll was expected to rise.",
        )
    ]

    candidates = extract_assertion_candidates(spans)

    assert candidates == []


def test_assertion_does_not_include_unrelated_second_sentence():
    first_sentence = (
        "The weather service estimated that Monday's tornado "
        "was at least a half-mile wide."
    )
    spans = [
        make_span(
            "version-001:span:1",
            first_sentence + " The 1999 storm had winds clocked at 300 mph.",
        )
    ]

    candidates = extract_assertion_candidates(spans)

    assert len(candidates) == 1
    assert candidates[0].subject == "The weather service"
    assert candidates[0].object == (
        "that Monday's tornado was at least a half-mile wide."
    )
    assert candidates[0].verbatim_support == [first_sentence]
    assert candidates[0].span_ids == ["version-001:span:1"]


def test_sentence_handling_preserves_abbreviations_and_decimals():
    text = "Dr. Smith reported repairs would cost 2.5 million dollars."
    spans = [
        make_span(
            "version-001:span:1",
            text + " The bridge remained closed.",
        )
    ]

    candidates = extract_assertion_candidates(spans)

    assert len(candidates) == 1
    assert candidates[0].subject == "Dr. Smith"
    assert candidates[0].object == (
        "repairs would cost 2.5 million dollars."
    )
    assert candidates[0].verbatim_support == [text]


def test_extracts_simple_said_assertion():
    text = "Authorities said the school was damaged."
    spans = [
        make_span(
            "version-001:span:1",
            text,
        )
    ]

    candidates = extract_assertion_candidates(spans)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.subject == "Authorities"
    assert candidate.speaker == "Authorities"
    assert candidate.predicate == "said"
    assert candidate.object == "the school was damaged."
    assert candidate.epistemic_operator == EpistemicOperator.REPORTED
    assert candidate.verbatim_support == [text]
    assert candidate.span_ids == ["version-001:span:1"]
