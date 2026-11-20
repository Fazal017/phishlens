"""URL phishing heuristics (stdlib only, no network requests).

PhishLens never fetches the URL. Everything is decided from the
string itself: host, scheme, labels, TLD, path and query. That is a
deliberate safety choice — analysing a phishing link must never
require visiting it.

Weighting philosophy: one *critical* impersonation signal (a 1-edit
typosquat of a major brand, a punycode homograph, a bare-IP host, a
brand name abused as a subdomain of someone else's domain) is worth
40-50 points, because on its own it is already very likely malicious.
Ordinary signals (HTTP, a suspicious TLD, a long URL) are worth 5-15
and can only push a score into High when they stack up.
"""

import ipaddress
import math
import re
from urllib.parse import urlparse, unquote

from .brands import (
    BRAND_ALIASES, SUSPICIOUS_TLDS, URL_SHORTENERS,
    SUSPICIOUS_PATH_KEYWORDS, closest_brand, is_legitimate_brand_domain,
    registered_domain,
)
from .scoring import AnalysisResult

# Confusable (homoglyph) characters: Cyrillic / Greek lookalikes for
# Latin letters, commonly used in IDN homograph attacks.
HOMOGLYPHS = set(
    "аеорсхквнмт"          # Cyrillic a e o p c x k b h m t lookalikes
    "οрνχ"                  # Greek o p v x
    "ı"                     # dotless i
)

# Digits that are visually swapped for letters in typosquats.
DIGIT_FOR_LETTER = {"0": "o", "1": "l", "5": "s", "3": "e"}


def shannon_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / len(text)) * math.log2(c / len(text))
                for c in freq.values())


def _normalise_label(label):
    """Strip digits/hyphens and map lookalike digits back to letters."""
    out = []
    for ch in label.lower():
        if ch in DIGIT_FOR_LETTER:
            out.append(DIGIT_FOR_LETTER[ch])
        elif ch.isalnum():
            out.append(ch)
    return "".join(out)


def _brand_in_host(host):
    """Brand whose name appears in any label of *host*, else None."""
    for label in host.lower().split("."):
        norm = _normalise_label(label)
        if norm in BRAND_ALIASES:
            return BRAND_ALIASES[norm]
    return None


def analyze_url(raw_url):
    """Score one URL string. Returns an :class:`AnalysisResult`."""
    url = (raw_url or "").strip()
    result = AnalysisResult(target=url, kind="url")
    if not url:
        result.add("URL-EMPTY", "info", 0, "Empty URL",
                   "No URL was supplied.", "Supply a URL to analyse.")
        return result.finalize()

    # Tolerate a missing scheme ("paypal.com/login") for analysis.
    work = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "https://" + url
    try:
        parsed = urlparse(work)
    except ValueError:
        result.add("URL-PARSE", "high", 25, "URL could not be parsed",
                   "The URL is malformed.", "Do not trust a malformed link.")
        return result.finalize()

    host = (parsed.hostname or "").lower().strip(".")
    path_query = unquote((parsed.path or "") + "?" + (parsed.query or ""))
    labels = host.split(".") if host else []
    reg_domain = registered_domain(host) if host else ""
    host_brand = _brand_in_host(host)
    is_real_brand = bool(host_brand and
                         is_legitimate_brand_domain(host, host_brand))

    # --- U01: IP address as host -------------------------------------
    try:
        ipaddress.ip_address(host)
        result.add(
            "URL-IP-HOST", "critical", 50,
            "IP address used instead of a domain name",
            "Legitimate brands use named domains; phishing kits often "
            f"hide behind a raw IP ({host}) so there is no brand to check.",
            "Never log in via a bare-IP link. Type the brand's real "
            "domain yourself or use a bookmark.")
    except ValueError:
        pass

    # --- U02: no HTTPS ------------------------------------------------
    if parsed.scheme == "http":
        result.add(
            "URL-NO-HTTPS", "medium", 10,
            "Plain HTTP, no TLS encryption",
            "The connection is not encrypted, so credentials can be "
            "intercepted. Most major sites enforce HTTPS everywhere now.",
            "Do not enter credentials on an http:// page.")
    elif parsed.scheme not in ("http", "https"):
        result.add(
            "URL-ODD-SCHEME", "medium", 10,
            f"Unusual scheme: {parsed.scheme}",
            "Legitimate login pages use https://.",
            "Treat non-https login links as suspicious.")

    # --- U03: '@' in URL (everything before it is ignored) -----------
    if "@" in url:
        result.add(
            "URL-AT-SIGN", "high", 25,
            "'@' in the URL hides the real host",
            "In https://brand.com@evil.com/ the browser goes to evil.com; "
            "everything before '@' is just a username decoy.",
            "Read the host *after* the last '@' — that is where the "
            "browser actually goes.")
        # U03b: brand name used as the decoy before '@'.
        if not host_brand:
            decoy = url.rsplit("@", 1)[0].lower()
            for alias, brand in BRAND_ALIASES.items():
                if alias in decoy:
                    result.add(
                        "URL-BRAND-BEFORE-AT", "critical", 35,
                        f"Brand '{brand}' used as decoy before '@'",
                        f"The part before '@' pretends to be {brand}, but "
                        f"the real host is {host}. The brand text is "
                        "there only to fool a quick glance.",
                        "Ignore everything before '@' and judge the link "
                        "by the host after it.")
                    break

    # --- U04: punycode / IDN homograph --------------------------------
    if "xn--" in host:
        result.add(
            "URL-PUNYCODE", "critical", 50,
            "Punycode (xn--) domain — possible IDN homograph attack",
            "The domain is encoded internationalised text. Attackers use "
            "Cyrillic/Greek letters that look identical to Latin ones "
            "(e.g. 'pаypal' with a Cyrillic 'а') to fake a brand.",
            "Copy the domain into a punycode decoder or check the "
            "certificate; never trust an xn-- login page at face value.")
    elif any(ord(ch) > 127 for ch in host):
        result.add(
            "URL-NON-ASCII-HOST", "high", 20,
            "Non-ASCII characters in the domain",
            "Unicode letters in a brand domain are a classic homoglyph "
            "signal — the domain only *looks* like the brand.",
            "Inspect the domain character by character before logging in.")
    elif any(ch in HOMOGLYPHS for ch in host):
        result.add(
            "URL-HOMOGLYPH", "high", 20,
            "Possible homoglyph characters in the domain",
            "The domain contains characters visually identical to Latin "
            "letters from another script.",
            "Type the brand domain yourself instead of clicking through.")

    # --- U05: URL shortener -------------------------------------------
    if reg_domain in URL_SHORTENERS or host in URL_SHORTENERS:
        result.add(
            "URL-SHORTENER", "high", 30,
            "Link shortener hides the real destination",
            f"{reg_domain} hides where the link really goes, so the "
            "domain checks below cannot see the true target. A shortener "
            "alone is not proof of phishing — but a shortened *login* "
            "link is, because a real brand never needs to hide its "
            "own login page.",
            "Expand the short link (e.g. with a URL expander) and "
            "analyse the destination before clicking.")

    # --- U06: excessive subdomains ------------------------------------
    if len(labels) >= 5:
        result.add(
            "URL-MANY-SUBDOMAINS", "high", 15,
            f"{len(labels)} domain labels — excessive subdomains",
            "Phishing pages stack subdomains (brand.com.attacker.tld) to "
            "make the address look familiar at a glance.",
            "Read the registrable domain (last two labels) — that is "
            "who actually owns the site.")
    elif len(labels) == 4:
        result.add(
            "URL-MANY-SUBDOMAINS", "medium", 8,
            "4 domain labels — many subdomains",
            "More subdomains than a normal brand login page needs; often "
            "used to bury the real domain.",
            "Check the registrable domain, not the leftmost labels.")

    # --- U07: suspicious TLD ------------------------------------------
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        result.add(
            "URL-SUSPICIOUS-TLD", "medium", 12,
            f"Suspicious TLD: .{tld}",
            f".{tld} domains are cheap/free and disproportionately used "
            "for phishing kits. A legit site can use one, so this is "
            "only a supporting signal.",
            "Combine with the other findings; a .xyz login page for a "
            "major brand is a red flag.")

    # --- U08: length / entropy ----------------------------------------
    if len(url) > 120:
        result.add(
            "URL-VERY-LONG", "medium", 10,
            f"Very long URL ({len(url)} chars)",
            "Long URLs bury the real host and often carry tracking / "
            "redirect payloads.",
            "Shorten nothing — inspect the host, not the tail.")
    elif len(url) > 75:
        result.add(
            "URL-LONG", "low", 5,
            f"Long URL ({len(url)} chars)",
            "Longer than a typical brand login link.",
            "Check the host carefully before proceeding.")
    entropy = shannon_entropy(host + parsed.path)
    if entropy > 4.2 and len(host) > 12:
        result.add(
            "URL-HIGH-ENTROPY", "medium", 10,
            f"High-entropy host/path ({entropy:.2f})",
            "Random-looking strings in the host or path are typical of "
            "auto-generated phishing domains and encoded payloads.",
            "A real brand domain is readable; random strings are not.")

    # --- U09: brand impersonation / lookalike / typosquat -------------
    brand_found_in_subdomain = False
    for label in labels[:-2] if len(labels) > 2 else []:
        norm = _normalise_label(label)
        if norm in BRAND_ALIASES:
            brand_found_in_subdomain = True
            brand = BRAND_ALIASES[norm]
            if not is_legitimate_brand_domain(host, brand):
                result.add(
                    "URL-BRAND-IN-SUBDOMAIN", "critical", 45,
                    f"Brand '{brand}' in a subdomain of a different domain",
                    f"The address starts with {brand} but the registrable "
                    f"domain is {reg_domain} — the brand does not own "
                    "this site. This is the single most common phishing "
                    "pattern of 2026.",
                    "Only trust the brand on its own domain. Navigate "
                    "there yourself; never log in from a lookalike.")
            break

    if not brand_found_in_subdomain:
        reg_label = labels[-2] if len(labels) >= 2 else host
        norm_reg = _normalise_label(reg_label)
        if norm_reg in BRAND_ALIASES and reg_label.lower() != norm_reg:
            # Digit/character substitution typosquat: the label only
            # *becomes* the brand after mapping lookalike digits back
            # (paypa1 -> paypal, g00gle -> google). The raw label is
            # not the brand — that is exactly the attack.
            brand = BRAND_ALIASES[norm_reg]
            if not is_legitimate_brand_domain(host, brand):
                result.add(
                    "URL-LOOKALIKE-DOMAIN", "critical", 50,
                    f"Lookalike domain: '{reg_label}' mimics '{brand}' "
                    "with substituted characters",
                    f"'{reg_label}' only reads as '{brand}' after "
                    "undoing a character substitution (e.g. 1 for l, "
                    "0 for o). The real domain is not the brand's.",
                    "Type the brand's domain yourself; do not trust a "
                    "near-miss spelling.")
        elif norm_reg not in BRAND_ALIASES:
            brand, dist = closest_brand(norm_reg)
            if brand and dist == 1 and len(norm_reg) >= 4:
                result.add(
                    "URL-LOOKALIKE-DOMAIN", "critical", 50,
                    f"Lookalike domain: '{reg_label}' is 1 edit from '{brand}'",
                    f"'{reg_label}' is a single keystroke away from the "
                    f"real brand '{brand}' — a typosquat domain built to "
                    "catch mistypes and careless clicks.",
                    "Type the brand's domain yourself; do not trust a "
                    "near-miss spelling.")
            elif brand and dist == 2 and len(norm_reg) >= 4:
                result.add(
                    "URL-LOOKALIKE-DOMAIN", "critical", 40,
                    f"Lookalike domain: '{reg_label}' is 2 edits from '{brand}'",
                    f"'{reg_label}' is two keystrokes away from the real "
                    f"brand '{brand}' — a likely typosquat.",
                    "Type the brand's domain yourself; do not trust a "
                    "near-miss spelling.")
        # Brand name glued into the registrable domain: paypal-secure.com
        for alias, brand in BRAND_ALIASES.items():
            if alias in norm_reg and norm_reg != alias:
                if not is_legitimate_brand_domain(host, brand):
                    result.add(
                        "URL-BRAND-IN-DOMAIN", "high", 35,
                        f"Brand '{brand}' embedded in a non-brand domain",
                        f"'{reg_label}' contains the brand name but the "
                        f"site is not {brand}'s — e.g. paypal-secure.com "
                        "is not PayPal.",
                        "A brand name inside a longer domain name does "
                        "not make it the brand's site.")
                break

    # Brand name in the path/query of a non-brand site (decoy path).
    if not is_real_brand:
        low_path = path_query.lower()
        for alias, brand in BRAND_ALIASES.items():
            if alias in low_path:
                result.add(
                    "URL-BRAND-IN-PATH", "medium", 20,
                    f"Brand '{brand}' in the path of a non-brand site",
                    f"The path mentions {brand} but the site ({host}) "
                    "is not the brand's. Attackers use this to make "
                    "a link look official in a message preview.",
                    "Judge a link by its host, never by its path.")
                break

    # --- U10: suspicious keywords (host + path) on non-brand hosts ----
    if not is_real_brand:
        haystack = (host + " " + path_query).lower()
        hits = sorted({k for k in SUSPICIOUS_PATH_KEYWORDS if k in haystack})
        if len(hits) >= 3:
            result.add(
                "URL-SUSPICIOUS-KEYWORDS", "medium", 15,
                f"Suspicious keywords in URL: {', '.join(hits)}",
                "login / verify / secure / account language in the URL "
                "is typical of credential-harvesting pages.",
                "Go to the service's official site instead of following "
                "a 'verify your account' link.")
        elif hits:
            result.add(
                "URL-SUSPICIOUS-KEYWORDS", "low", 5,
                f"Suspicious keyword in URL: {', '.join(hits)}",
                "A credential-related word in the URL, on a host that "
                "is not the brand's own domain.",
                "Verify the host before entering any credentials.")

    # --- U11: redirect hint -------------------------------------------
    if re.search(r"(redirect|url|next|continue|return)=https?%3a|"
                 r"(redirect|url|next|continue|return)=https?://",
                 url.lower()):
        result.add(
            "URL-REDIRECT-PARAM", "medium", 10,
            "Open-redirect parameter in the URL",
            "The link carries a redirect target (url= / next= / "
            "redirect=). Attackers abuse open redirects on real sites "
            "to launder a phishing destination.",
            "Check where the redirect actually lands before logging in.")

    # --- U12: many hyphens / digits in the domain ---------------------
    if host.count("-") >= 3:
        result.add(
            "URL-MANY-HYPHENS", "low", 5,
            f"{host.count('-')} hyphens in the domain",
            "Hyphen-stuffed domains (secure-paypal-login-verify.com) "
            "are a cheap way to stuff brand + urgency words into a host.",
            "Prefer the brand's short, clean domain.")

    if not result.findings:
        result.add(
            "URL-CLEAN", "info", 0,
            "No phishing heuristics triggered",
            "Recognised structure, valid HTTPS, no lookalike, IP, "
            "punycode or subdomain abuse detected.",
            "No action needed — still check the sender before logging in.")

    return result.finalize()
