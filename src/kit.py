"""Phishing-kit fingerprinting (PhishLens v2).

A phishing *kit* is a reusable template sold / shared by attackers:
the same login page, the same URL path pattern, the same redirect
chain, reused across hundreds of domains. v1 judged a URL in
isolation; v2 fingerprints the *kit behind it*, so a fresh domain
running a known kit is caught on its structure alone.

Three fingerprints, all offline (no fetching):
1. URL-structure templates -- path / query patterns characteristic
   of credential-harvest, payment, crypto-seed and Microsoft-365 kits.
2. Redirect-chain simulation -- a supplied chain map (e.g. harvested
   from a mail / SMS link) is followed hop by hop; a shortener ->
   brand-impersonation -> kit chain is itself a fingerprint, and the
   number of cross-domain hops is scored.
3. Form / page analysis -- a supplied HTML snippet / title is checked
   for a password field whose page claims a brand the domain does
   not own, plus a favicon/domain mismatch heuristic.
A kit signature is a SHA-256 hash of the *normalised* path pattern
(digits, hex strings and random segments replaced by {id}), so two
URLs from the same kit share a signature even on different domains.
"""

import hashlib
import re
from urllib.parse import urlparse, unquote

from .brands import BRAND_ALIASES, is_legitimate_brand_domain, registered_domain
from .url_analyzer import analyze_url

KIT_TEMPLATES = [
    {
        "id": "KIT-CRED-HARVEST",
        "name": "Credential harvest (login / verify / signin)",
        "patterns": [r"/(login|signin|sign-in|verify|verification|auth|account|secure|update|confirm)/?",
                     r"\b(login|verify|signin)\b"],
        "weight": 30,
    },
    {
        "id": "KIT-MS365",
        "name": "Microsoft 365 login kit",
        "patterns": [r"microsoft|office365|outlook|onedrive",
                     r"/(login|auth|owa|common/oauth2)/?"],
        "weight": 30,
    },
    {
        "id": "KIT-PAYMENT",
        "name": "Payment / invoice kit",
        "patterns": [r"/(payment|pay|invoice|billing|checkout|wallet)/?",
                     r"\b(invoice|payment|billing)\b"],
        "weight": 30,
    },
    {
        "id": "KIT-CRYPTO-SEED",
        "name": "Crypto wallet seed-phrase kit",
        "patterns": [r"(seed|mnemonic|recovery.?phrase|wallet.?connect|metamask|trust.?wallet)",
                     r"/(import|restore|connect|validate)/?"],
        "weight": 35,
    },
    {
        "id": "KIT-DOC-SHARE",
        "name": "Document-share / voicemail lure kit",
        "patterns": [r"(document|doc.?share|voicemail|voice.?mail|shared.?file)",
                     r"/(view|open|download|listen)/?"],
        "weight": 25,
    },
]


def normalise_path_pattern(url):
    """Replace variable segments in a URL path with {id}.

    e.g. /login/9f3a2b/verify?u=abc123 -> /login/{id}/verify
    Two URLs from the same kit normalise to the same pattern.
    """
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
    except ValueError:
        return url.lower()
    path = unquote(parsed.path or "/").lower()
    path = re.sub(r"/[0-9a-f]{8,}", "/{id}", path)
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(r"[0-9a-f]{16,}", "{id}", path)
    return path


def kit_signature(url):
    """SHA-256 of the normalised path pattern (first 16 hex chars used)."""
    pattern = normalise_path_pattern(url)
    return hashlib.sha256(pattern.encode()).hexdigest()


def match_kit_templates(url):
    """Return (template, matched_patterns) for the best kit template."""
    hay = url.lower()
    best, best_hits = None, []
    for tpl in KIT_TEMPLATES:
        hits = [p for p in tpl["patterns"] if re.search(p, hay)]
        if len(hits) > len(best_hits):
            best, best_hits = tpl, hits
    return best, best_hits


def simulate_redirect_chain(start_url, chain_map, max_hops=5):
    """Follow a supplied redirect map hop by hop (no network).

    ``chain_map`` maps a URL (or its registrable domain) to the next
    URL. Returns a dict with the hop list, cross-domain hop count and
    whether the chain ends on a brand-impersonating host.
    """
    hops = [start_url]
    seen = {start_url}
    current = start_url
    for _ in range(max_hops):
        nxt = chain_map.get(current) or chain_map.get(
            registered_domain(urlparse(current).hostname or "") if "://" in current else current)
        if not nxt or nxt in seen:
            break
        hops.append(nxt)
        seen.add(nxt)
        current = nxt
    hosts = []
    for h in hops:
        try:
            hosts.append((urlparse(h if "://" in h else "https://" + h).hostname or "").lower())
        except ValueError:
            hosts.append("")
    cross = sum(1 for a, b in zip(hosts, hosts[1:])
                if registered_domain(a) != registered_domain(b) and a and b)
    final_host = hosts[-1] if hosts else ""
    brand_in_final = any(alias in final_host for alias in BRAND_ALIASES)
    return {
        "hops": hops, "hop_count": len(hops) - 1, "cross_domain_hops": cross,
        "final_host": final_host, "final_brand_mention": brand_in_final,
        "chain": " -> ".join(hops),
    }


def analyze_form(html_snippet, page_title, url):
    """Check a supplied HTML snippet / title for kit form signals.

    Returns a list of finding tuples (same shape as squat_findings).
    The page is never fetched -- the caller supplies the snippet.
    """
    findings = []
    html = (html_snippet or "").lower()
    title = (page_title or "").lower()
    try:
        host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        host = ""
    has_password = bool(re.search(r'type\s*=\s*["\']password["\']', html))
    has_login_form = bool(re.search(r"<form", html)) and (
        "password" in html or "login" in html or "signin" in html)
    brand_in_title = None
    for alias, brand in BRAND_ALIASES.items():
        if alias in title or alias in html[:500]:
            brand_in_title = brand
            break
    if has_password and brand_in_title and not is_legitimate_brand_domain(host, brand_in_title):
        findings.append((
            "KIT-FORM-BRAND-MISMATCH", "critical", 45,
            f"Password form claims '{brand_in_title}' but host is {host or 'unknown'}",
            "The page asks for a password and names a brand in its "
            "title/form, but the domain is not that brand's. That is "
            "the kit's job: harvest credentials under a borrowed brand.",
            "Never enter a password on a page whose domain is not the brand's."))
    elif has_login_form and brand_in_title and not is_legitimate_brand_domain(host, brand_in_title):
        findings.append((
            "KIT-LOGIN-FORM", "high", 30,
            f"Login form for '{brand_in_title}' on a non-brand host",
            "A login form naming a brand, served from a domain the "
            "brand does not own.",
            "Navigate to the brand yourself instead of logging in here."))
    # Favicon / domain mismatch is supplied by the caller as a hint in
    # the title string, e.g. page_title="PayPal — favicon: paypal.com".
    fav = re.search(r"favicon:\s*([a-z0-9.-]+)", title)
    if fav and host:
        fav_domain = fav.group(1)
        if registered_domain(fav_domain) != registered_domain(host):
            findings.append((
                "KIT-FAVICON-MISMATCH", "medium", 15,
                f"Favicon domain {fav_domain} does not match host {host}",
                "The page's favicon is served from a different domain "
                "than the page itself — kits often hotlink the real "
                "brand's favicon to look legitimate.",
                "Check the address bar, not the favicon."))
    return findings


def fingerprint_kit(url, page_title=None, html_snippet=None,
                    chain_map=None):
    """Full kit fingerprint for one URL. Returns a dict (not a result)."""
    tpl, hits = match_kit_templates(url)
    sig = kit_signature(url)
    pattern = normalise_path_pattern(url)
    chain = simulate_redirect_chain(url, chain_map or {}) if chain_map else None
    form_findings = analyze_form(html_snippet, page_title, url)
    return {
        "url": url, "template": tpl["id"] if tpl else None,
        "template_name": tpl["name"] if tpl else None,
        "template_weight": tpl["weight"] if tpl else 0,
        "matched_patterns": hits,
        "path_pattern": pattern, "kit_signature": sig,
        "signature_short": sig[:12],
        "redirect_chain": chain, "form_findings": form_findings,
    }


def kit_findings(url, page_title=None, html_snippet=None, chain_map=None):
    """Finding tuples for kit fingerprinting on one URL."""
    fp = fingerprint_kit(url, page_title, html_snippet, chain_map)
    findings = list(fp["form_findings"])
    # A kit template on the brand's *own* domain is just the brand's
    # real login page (paypal.com/signin) — never flag it as a kit.
    try:
        _host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        _host = ""
    _is_real_brand = any(is_legitimate_brand_domain(_host, b)
                         for b in BRAND_ALIASES.values())
    if fp["template"] and not _is_real_brand:
        findings.append((
            fp["template"], "high", fp["template_weight"],
            f"URL matches phishing-kit template: {fp['template_name']}",
            f"Path/query matches {len(fp['matched_patterns'])} kit pattern(s); "
            f"normalised path pattern is '{fp['path_pattern']}' "
            f"(kit signature {fp['signature_short']}). The same "
            "signature recurs across kit domains.",
            "A known kit structure on an untrusted domain is a strong "
            "phishing signal — verify through the official channel."))
    if fp["redirect_chain"] and fp["redirect_chain"]["hop_count"] >= 2:
        ch = fp["redirect_chain"]
        findings.append((
            "KIT-REDIRECT-CHAIN", "high", 25,
            f"Redirect chain: {ch['hop_count']} hops, {ch['cross_domain_hops']} cross-domain",
            f"Chain: {ch['chain']}. Shortener / redirect hops are used "
            "to launder a kit destination past link scanners.",
            "Follow the chain to its final host and judge that host."))
    return findings, fp


def analyze_kit(url, page_title=None, html_snippet=None, chain_map=None):
    """Score one URL as a phishing kit (v1 URL score + kit findings)."""
    from .scoring import AnalysisResult
    base = analyze_url(url)
    result = AnalysisResult(target=url, kind="kit")
    seen = set()
    for f in base.findings:
        if f.rule_id not in seen:
            result.add(f.rule_id, f.severity, f.weight, f.title,
                       f.explanation, f.remediation)
            seen.add(f.rule_id)
    findings, fp = kit_findings(url, page_title, html_snippet, chain_map)
    for rule_id, sev, weight, title, expl, fix in findings:
        if rule_id not in seen:
            result.add(rule_id, sev, weight, title, expl, fix)
            seen.add(rule_id)
    result.finalize()
    # Attach the fingerprint for callers that need it (not in to_dict).
    result.kit_fingerprint = fp  # type: ignore[attr-defined]
    return result
