#!/usr/bin/env python3
"""PhishLens — Phishing URL & Email Header Analyzer.

Stdlib only, no API keys, no network requests. Scores a URL or an
email's headers/body for phishing risk (0-100) and explains *why*.

Usage:
    python phishlens.py url <url>
    python phishlens.py email --file samples/phishing_email.txt
    python phishlens.py batch --file samples/urls.txt --output report.json
    python phishlens.py batch --file samples/urls.txt --output report.html
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.email_analyzer import analyze_email  # noqa: E402
from src.report import (  # noqa: E402
    render_html, render_terminal, render_terminal_summary, results_to_json,
)
from src.url_analyzer import analyze_url  # noqa: E402


def cmd_url(args):
    result = analyze_url(args.url)
    print(render_terminal(result))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.score < 60 else 2


def cmd_email(args):
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    result = analyze_email(path.read_bytes(), target=str(path))
    print(render_terminal(result))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.score < 60 else 2


def cmd_batch(args):
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    targets = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    results = [analyze_url(t) for t in targets]
    print(render_terminal_summary(results))
    for r in results:
        print(render_terminal(r))

    if args.output:
        out = Path(args.output)
        if out.suffix.lower() == ".html":
            out.write_text(render_html(results), encoding="utf-8")
        else:
            out.write_text(json.dumps(results_to_json(results), indent=2),
                           encoding="utf-8")
        print(f"\nReport written to {out}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="Score a URL or email for phishing risk (0-100) "
                    "and explain why. Heuristic only — not a verdict.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_url = sub.add_parser("url", help="Analyse a single URL")
    p_url.add_argument("url", help="URL to analyse (never fetched)")
    p_url.add_argument("--json", action="store_true",
                       help="Also print the JSON result")
    p_url.set_defaults(func=cmd_url)

    p_email = sub.add_parser("email", help="Analyse a raw email file")
    p_email.add_argument("--file", required=True,
                         help="Path to a raw .eml / .txt email file")
    p_email.add_argument("--json", action="store_true",
                         help="Also print the JSON result")
    p_email.set_defaults(func=cmd_email)

    p_batch = sub.add_parser("batch", help="Analyse URLs, one per line")
    p_batch.add_argument("--file", required=True,
                         help="Text file with one URL per line (# = comment)")
    p_batch.add_argument("--output",
                         help="Write report.json or report.html to this path")
    p_batch.set_defaults(func=cmd_batch)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
