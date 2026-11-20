"""Output rendering: terminal table, JSON and a standalone HTML report."""

import html as html_lib
import json
from datetime import datetime, timezone

RISK_COLOURS = {"Critical": "#b91c1c", "High": "#ea580c",
                "Medium": "#ca8a04", "Low": "#15803d"}


def risk_colour(risk):
    return RISK_COLOURS.get(risk, "#475569")


def render_terminal(result):
    """Human-readable terminal report for one analysis."""
    bar_len = 20
    filled = int(round(result.score / 100 * bar_len))
    bar = "#" * filled + "-" * (bar_len - filled)
    lines = [
        "",
        f"PhishLens  |  {result.kind.upper()}  |  {result.target}",
        f"Score: {result.score:3d}/100  [{bar}]  Risk: {result.risk}",
        f"Verdict: {result.verdict}",
        "-" * 72,
    ]
    if not result.findings:
        lines.append("No findings.")
    for f in result.findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule_id} (+{f.weight}) — {f.title}")
        lines.append(f"           {f.explanation}")
        lines.append(f"           Fix: {f.remediation}")
    lines.append("-" * 72)
    return "\n".join(lines)


def render_terminal_summary(results):
    lines = ["", "PhishLens batch summary", "-" * 72]
    lines.append(f"{'Score':>5}  {'Risk':<8}  Target")
    for r in sorted(results, key=lambda x: -x.score):
        lines.append(f"{r.score:>5}  {r.risk:<8}  {r.target}")
    lines.append("-" * 72)
    counts = {}
    for r in results:
        counts[r.risk] = counts.get(r.risk, 0) + 1
    lines.append("Counts: " + ", ".join(f"{k}={v}" for k, v in
                                        sorted(counts.items())))
    return "\n".join(lines)


def results_to_json(results):
    return [r.to_dict() for r in results]


def render_html(results, title="PhishLens Report"):
    """Standalone HTML report (no external assets, no JS)."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for r in results:
        findings_html = "".join(
            "<li><strong>[{sev}] {rid} (+{w}) — {t}</strong><br>{e}<br>"
            "<em>Fix: {fix}</em></li>".format(
                sev=html_lib.escape(f.severity.upper()),
                rid=html_lib.escape(f.rule_id), w=f.weight,
                t=html_lib.escape(f.title),
                e=html_lib.escape(f.explanation),
                fix=html_lib.escape(f.remediation))
            for f in r.findings)
        rows.append(
            "<section><h2>{t}</h2>"
            "<p><span class=\"badge\" style=\"background:{c}\">{risk} — "
            "{s}/100</span> {v}</p>"
            "<ul>{fh}</ul></section>".format(
                t=html_lib.escape(r.target),
                c=risk_colour(r.risk), risk=r.risk, s=r.score,
                v=html_lib.escape(r.verdict), fh=findings_html))
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{html_lib.escape(title)}</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;max-width:900px;margin:2rem auto;
padding:0 1rem;color:#1e293b}} h1{{font-size:1.6rem}}
section{{border:1px solid #cbd5e1;border-radius:8px;padding:1rem;margin:1rem 0}}
.badge{{color:#fff;padding:.2rem .6rem;border-radius:999px;font-weight:700}}
li{{margin:.6rem 0}} .muted{{color:#64748b;font-size:.9rem}}
</style></head><body>
<h1>PhishLens Report</h1>
<p class="muted">Generated {generated} &middot; {len(results)} target(s) analysed &middot;
Heuristic analysis only — not a final verdict. Confirm with VirusTotal or
the organisation's official channel before acting.</p>
{''.join(rows)}
</body></html>
"""
