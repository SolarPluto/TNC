import argparse
from datetime import datetime, timezone
from pathlib import Path

from tnc.ingestion.parser import hash_text, parse_article


def main() -> None:
    parser = argparse.ArgumentParser(prog="tnc")
    commands = parser.add_subparsers(dest="command", required=True)
    parse_command = commands.add_parser("parse", help="Parse local HTML into spans")
    parse_command.add_argument("html_file", type=Path)
    args = parser.parse_args()

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

    for span in spans:
        print(f"{span.ordinal}\t{span.span_type.value}\t{span.normalized_text}")
