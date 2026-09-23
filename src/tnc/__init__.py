import argparse
import sys
from importlib.metadata import version as distribution_version
from datetime import datetime, timezone
from pathlib import Path

from tnc.ingestion.parser import hash_text, parse_article
from tnc.spans.pipeline import process_assertion_spans
from tnc.historical_cli import aware_time, run_historical


def main() -> None:
    prog = Path(sys.argv[0]).stem or "tnc"
    parser = argparse.ArgumentParser(prog=prog, allow_abbrev=False)
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {distribution_version('tnc-provenance')}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    parse_command = commands.add_parser(
        "parse", help="Parse local HTML into spans"
    )
    parse_command.add_argument("html_file", type=Path)
    parse_command.add_argument(
        "--span",
        type=int,
        help="Show only the source span with this ordinal (starting at 0)",
    )

    assertions_command = commands.add_parser(
        "assertions", help="Extract assertions from local HTML"
    )
    assertions_command.add_argument("html_file", type=Path)

    historical_command = commands.add_parser(
        "historical-replay", help="Query a host-configured archived version", allow_abbrev=False,
    )
    historical_command.add_argument("--document", required=True)
    historical_command.add_argument("--version", required=True)
    historical_command.add_argument("--time", required=True, type=aware_time)

    args = parser.parse_args()

    if args.command == "historical-replay":
        raise SystemExit(run_historical(document_id=args.document, version_id=args.version, query_time=args.time))

    try:
        html = args.html_file.read_text(encoding="utf-8")
        spans = parse_article(
            html=html,
            document_version_id=f"local:{hash_text(html)}",
            # Local observation time, not the article's publication time.
            available_from=datetime.now(timezone.utc),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))

    if args.command == "parse":
        if args.span is not None:
            spans = [span for span in spans if span.ordinal == args.span]
            if not spans:
                parser.error(f"No source span with ordinal {args.span}")
        for span in spans:
            print(
                f"{span.ordinal}\t{span.span_type.value}"
                f"\t{span.normalized_text}"
            )
        return

    result = process_assertion_spans(spans)
    span_ordinals = {span.span_id: span.ordinal for span in spans}

    print(f"Admitted: {len(result.admitted)}")
    for assertion in result.admitted:
        print(
            f"  {assertion.subject} {assertion.predicate} "
            f"{assertion.object}"
        )
        source_ordinals = ", ".join(
            str(span_ordinals[span_id]) for span_id in assertion.span_ids
        )
        print(f"    Source spans: {source_ordinals}")

    print(f"Rejected: {len(result.rejected)}")
    for rejected in result.rejected:
        candidate = rejected.candidate
        print(
            f"  {candidate.subject} {candidate.predicate} "
            f"{candidate.object}"
        )
        for error in rejected.validation.errors:
            print(f"    Reason: {error}")
