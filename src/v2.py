"""PhishLens v2 combined scorer.

v1 = one URL, one axis. v2 = the same URL scored by *three* layers
and merged, with duplicate rule ids de-duplicated:
  layer 1 -- v1 URL heuristics (analyze_url)
  layer 2 -- 3-D squatting (squat_findings)
  layer 3 -- kit fingerprinting (kit_findings)
The merged score is capped at 100 by AnalysisResult.finalize().
Legitimate brand domains stay low because every layer checks
"is this actually the brand's own domain?" before flagging.
"""

import re
from urllib.parse import unquote, urlparse

from .kit import kit_findings
from .scoring import AnalysisResult
from .squatting import squat_findings
from .url_analyzer import analyze_url


def embedded_redirect_targets(url):
    """URLs hidden inside redirect params (next= / url= / redirect=).

    Attackers launder a kit URL through a neutral-looking host:
    login-helpdesk.example.org/redirect?next=https://paypa1.com/login
    The outer host is clean; the *target* is the phish. Unwrapping
    the target (one level, offline, never fetched) is what catches
    this evasion variant.
    """
    # Parse the query string: a redirect target lives in a param value
    # (next= / url= / redirect=), not in the outer URL string itself.
    # A plain regex over the whole URL would swallow "?next=https://…"
    # as part of the outer host, so split on parameters first.
    try:
        query = urlparse(unquote(url)).query
    except ValueError:
        return []
    targets = []
    for part in query.split("&"):
        if "=" not in part:
            continue
        value = unquote(part.split("=", 1)[1])
        m = re.search(r"https?://\S+", value)
        if m:
            targets.append(m.group(0).rstrip("\"'<>"))
    return targets


def analyze_v2_url(url, page_title=None, html_snippet=None, chain_map=None):
    """Combined v1 + squatting + kit score for one URL."""
    result = AnalysisResult(target=url, kind="v2-url")
    seen = set()

    def _add(rule_id, severity, weight, title, explanation, remediation):
        if rule_id not in seen:
            result.add(rule_id, severity, weight, title, explanation, remediation)
            seen.add(rule_id)

    base = analyze_url(url)
    for f in base.findings:
        _add(f.rule_id, f.severity, f.weight, f.title, f.explanation, f.remediation)

    try:
        host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        host = ""
    for rule_id, sev, weight, title, expl, fix in squat_findings(host):
        _add(rule_id, sev, weight, title, expl, fix)

    findings, _fp = kit_findings(url, page_title, html_snippet, chain_map)
    for rule_id, sev, weight, title, expl, fix in findings:
        _add(rule_id, sev, weight, title, expl, fix)

    # Redirect-target unwrapping: score the embedded destination too.
    for target in embedded_redirect_targets(url):
        _add("V2-REDIRECT-TARGET", "high", 20,
             f"Redirect target is itself suspicious: {target}",
             "The URL carries a redirect to another address; that "
             "destination is scored on its own, not just the outer host.",
             "Judge the link by its final destination, not the first host.")
        t_base = analyze_url(target)
        for f in t_base.findings:
            _add(f.rule_id, f.severity, f.weight, f.title, f.explanation, f.remediation)
        try:
            t_host = (urlparse(target).hostname or "").lower()
        except ValueError:
            t_host = ""
        for rule_id, sev, weight, title, expl, fix in squat_findings(t_host):
            _add(rule_id, sev, weight, title, expl, fix)

    return result.finalize()
