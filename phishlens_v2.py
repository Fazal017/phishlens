#!/usr/bin/env python3
"""PhishLens v2 — Adversarial: kit fingerprinting + BEC detection.

v1 (phishlens.py) is untouched and still works. v2 adds three layers:

  kit    -- score a URL as a phishing *kit* (template + redirect chain
            + password-form / favicon mismatch), not just as a URL.
  bec    -- score an email as Business Email Compromise (first-time
            sender, thread hijack, authority+urgency+payment, style
            deviation vs sender history).
  evade  -- adversarial evasion harness: 10 evasion variants of a
            phishing URL, scored with the full v2 scorer, report to
            evasion_report.json. Pass bar: >= 9/10 still caught (>=60).

Usage:
    python phishlens_v2.py kit https://paypa1.com/login/verify/account
    python phishlens_v2.py kit --file samples/kit_urls.txt
    python phishlens_v2.py bec --file samples/bec_phishing.txt
    python phishlens_v2.py bec --file samples/bec_legit_thread.txt
    python phishlens_v2.py evade --output evasion_report.json
Stdlib only, no network, no fetching.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.bec import analyze_bec  # noqa: E402
from src.evasion import run_evasion_harness  # noqa: E402
from src.kit import analyze_kit, fingerprint_kit  # noqa: E402
from src.report import render_terminal  # noqa: E402
from src.v2 import analyze_v2_url  # noqa: E402


def cmd_kit(args):
    targets = []
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 1
        targets = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]
    elif args.url:
        targets = [args.url]
    else:
        print("Error: give a URL or --file", file=sys.stderr)
        return 1
    rc = 0
    for url in targets:
        result = analyze_kit(url, page_title=args.title, html_snippet=args.html)
        fp = fingerprint_kit(url, page_title=args.title, html_snippet=args.html)
        print(render_terminal(result))
        print(f"Kit template: {fp['template_name'] or 'none'} "
              f"({fp['template'] or '-'}) | signature: {fp['signature_short']} "
              f"| path pattern: {fp['path_pattern']}")
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        if result.score >= 60:
            rc = 2
    return rc


def cmd_bec(args):
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    result = analyze_bec(path.read_bytes(), history_path=args.history, target=str(path))
    print(render_terminal(result))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.score < 60 else 2


def cmd_evade(args):
    report = run_evasion_harness(args.base_url, output_path=args.output)
    print(f"\nEvasion harness: {report['caught']}/{report['total']} variants "
          f"still caught (>=60) — pass rate {report['pass_rate']:.0%} "
          f"— {'PASSED' if report['passed'] else 'FAILED'} (bar: 9/10)")
    for c in report["cases"]:
        mark = "caught" if c["caught"] else "MISSED"
        print(f"  [{mark:6}] {c['score']:3d}  {c['variant']:<24} {c['url']}")
    if args.output:
        print(f"\nReport written to {args.output}")
    return 0 if report["passed"] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="phishlens_v2",
        description="PhishLens v2 — phishing-kit fingerprinting, BEC "
                    "detection, and an adversarial evasion harness.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_kit = sub.add_parser("kit", help="Analyse a URL as a phishing kit")
    p_kit.add_argument("url", nargs="?", help="URL to analyse (never fetched)")
    p_kit.add_argument("--file", help="File with one URL per line")
    p_kit.add_argument("--title", help="Page title (for form/brand check)")
    p_kit.add_argument("--html", help="HTML snippet (for password-form check)")
    p_kit.add_argument("--json", action="store_true")
    p_kit.set_defaults(func=cmd_kit)

    p_bec = sub.add_parser("bec", help="Analyse an email as BEC")
    p_bec.add_argument("--file", required=True, help="Raw .eml / .txt email file")
    p_bec.add_argument("--history", help="Sender-history JSON (default samples/bec_history.json)")
    p_bec.add_argument("--json", action="store_true")
    p_bec.set_defaults(func=cmd_bec)

    p_ev = sub.add_parser("evade", help="Run the evasion harness")
    p_ev.add_argument("--base-url", default="https://paypa1.com/login/verify/account")
    p_ev.add_argument("--output", default="evasion_report.json")
    p_ev.set_defaults(func=cmd_evade)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
