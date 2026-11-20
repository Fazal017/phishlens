"""Email header + body phishing heuristics (stdlib only).

Parses a raw RFC 5322 message with the stdlib ``email`` package and
checks the authentication results a receiver would see (SPF / DKIM /
DMARC), sender consistency (From vs Reply-To vs display name), urgency
language, link/display-text mismatches, and QR-code phishing
("quishing") wording. No network lookups, no credentials.
"""

import re
from email import policy
from email.parser import BytesParser

from .brands import URGENCY_KEYWORDS, BRAND_ALIASES, is_legitimate_brand_domain
from .scoring import AnalysisResult
from .url_analyzer import analyze_url

LINK_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
DISPLAY_TEXT_RE = re.compile(r">([^<]{4,80})</a>", re.IGNORECASE)


def _auth_result(header_value, mechanism):
    """Extract 'pass' / 'fail' / 'softfail' / 'neutral' for one mechanism
    from an Authentication-Results or Received-SPF header value."""
    if not header_value:
        return None
    m = re.search(rf"{mechanism}\s*=\s*(\w+)", header_value, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _get_body_text(msg):
    """Best-effort plain-text body (plain part preferred, HTML stripped)."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_content()
                except Exception:
                    continue
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    html = part.get_content()
                    return re.sub(r"<[^>]+>", " ", html)
                except Exception:
                    continue
        return ""
    try:
        content = msg.get_content()
    except Exception:
        return ""
    if msg.get_content_type() == "text/html":
        return re.sub(r"<[^>]+>", " ", content)
    return content or ""


def _get_raw_html(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    return part.get_content()
                except Exception:
                    continue
        return ""
    if msg.get_content_type() == "text/html":
        try:
            return msg.get_content()
        except Exception:
            return ""
    return ""


def analyze_email(raw_bytes_or_text, target="<email>"):
    """Score one raw email message. Returns an :class:`AnalysisResult`."""
    if isinstance(raw_bytes_or_text, str):
        raw = raw_bytes_or_text.encode("utf-8", errors="replace")
    else:
        raw = raw_bytes_or_text
    result = AnalysisResult(target=target, kind="email")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # noqa: BLE001 - malformed input is expected
        result.add("EMAIL-PARSE", "high", 25, "Email could not be parsed",
                   f"The message is malformed ({exc}).",
                   "Do not trust a message that cannot be parsed.")
        return result.finalize()

    from_hdr = str(msg.get("From", "") or "")
    reply_to = str(msg.get("Reply-To", "") or "")
    subject = str(msg.get("Subject", "") or "")
    auth_results = str(msg.get("Authentication-Results", "") or "")
    received_spf = str(msg.get("Received-SPF", "") or "")
    body = _get_body_text(msg)
    html = _get_raw_html(msg)
    text_all = f"{subject}\n{body}".lower()

    # --- E01: From address --------------------------------------------
    from_match = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", from_hdr)
    from_domain = from_match.group(0).split("@", 1)[1].lower() if from_match else ""
    display_name = from_hdr.split("<")[0].strip().strip('"')

    # --- E02: Reply-To mismatch ---------------------------------------
    if reply_to and from_domain:
        reply_match = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", reply_to)
        reply_domain = reply_match.group(0).split("@", 1)[1].lower() if reply_match else ""
        if reply_domain and reply_domain != from_domain:
            result.add(
                "EMAIL-REPLYTO-MISMATCH", "high", 25,
                "Reply-To domain differs from From domain",
                f"From is {from_domain} but replies go to {reply_domain}. "
                "Attackers keep a spoofed From and harvest replies (and "
                "credentials) at an address they control.",
                "Reply only to the address shown in From — or better, "
                "contact the organisation through its official site.")

    # --- E03: display-name spoofing ------------------------------------
    dn_lower = display_name.lower()
    for alias, brand in BRAND_ALIASES.items():
        if alias in dn_lower or brand in dn_lower:
            if from_domain and not is_legitimate_brand_domain(from_domain, brand):
                result.add(
                    "EMAIL-DISPLAY-SPOOF", "critical", 40,
                    f"Display name claims '{brand}' but sender is {from_domain}",
                    f"The name shown is '{display_name}' — the brand — "
                    f"but the real sender domain is {from_domain}, which "
                    "the brand does not own. Mail clients show the name "
                    "prominently and hide the address.",
                    "Always expand the sender to see the real address "
                    "before acting on a branded message.")
            break

    # --- E04: SPF / DKIM / DMARC ---------------------------------------
    spf = _auth_result(auth_results, "spf") or _auth_result(received_spf, "spf")
    # Received-SPF often reads "Received-SPF: fail (domain ...)"
    if spf is None and received_spf:
        m = re.search(r"\b(pass|fail|softfail|neutral|none)\b",
                      received_spf, re.IGNORECASE)
        spf = m.group(1).lower() if m else None
    dkim = _auth_result(auth_results, "dkim")
    dmarc = _auth_result(auth_results, "dmarc")

    if spf == "fail":
        result.add(
            "EMAIL-SPF-FAIL", "high", 25,
            "SPF check failed",
            "The sending server is not authorised to send mail for "
            f"{from_domain or 'this domain'} — the address is spoofed.",
            "Treat the message as untrusted; verify via the official site.")
    elif spf == "softfail":
        result.add(
            "EMAIL-SPF-SOFTFAIL", "medium", 12,
            "SPF softfail",
            "The sending server is probably not authorised for this domain.",
            "Be cautious; check the other signals in this report.")
    elif spf in ("neutral", "none"):
        result.add(
            "EMAIL-SPF-NEUTRAL", "low", 5,
            "SPF neutral / none",
            "No conclusive SPF result for the sender domain.",
            "Do not rely on SPF alone for this message.")
    if dkim == "fail":
        result.add(
            "EMAIL-DKIM-FAIL", "high", 20,
            "DKIM signature failed",
            "The message signature does not match — content may have "
            "been altered in transit or was never signed by the domain.",
            "Treat the message as untrusted.")
    if dmarc == "fail":
        result.add(
            "EMAIL-DMARC-FAIL", "high", 20,
            "DMARC check failed",
            "The message fails the domain owner's published DMARC policy.",
            "Treat the message as untrusted.")
    if spf is None and dkim is None and dmarc is None:
        result.add(
            "EMAIL-NO-AUTH", "medium", 10,
            "No SPF / DKIM / DMARC results present",
            "No authentication headers were found, so the sender cannot "
            "be verified at all.",
            "Do not act on links or attachments from unverifiable mail.")

    # --- E05: urgency / pressure language ------------------------------
    urgency_hits = sorted({k for k in URGENCY_KEYWORDS if k in text_all})
    if len(urgency_hits) >= 3:
        result.add(
            "EMAIL-URGENCY", "medium", 15,
            f"Pressure language: {', '.join(urgency_hits)}",
            "Urgency ('act now or your account closes') is the core "
            "social-engineering lever in phishing: it pushes the reader "
            "to click before thinking.",
            "Urgency in an email is a reason to slow down, not speed up. "
            "Verify through the official app or site.")
    elif urgency_hits:
        result.add(
            "EMAIL-URGENCY", "low", 5,
            f"Pressure language: {', '.join(urgency_hits)}",
            "Some urgency wording is present.",
            "Pause and verify through an official channel.")

    # --- E06: links in the body ----------------------------------------
    links = LINK_RE.findall(body + " " + html)
    worst_link_score = 0
    for link in dict.fromkeys(links):
        link_result = analyze_url(link)
        worst_link_score = max(worst_link_score, link_result.score)
        if link_result.score >= 60:
            result.add(
                "EMAIL-BAD-LINK", "critical", 35,
                f"Body contains a high-risk link ({link_result.score}/100)",
                f"Link {link} scores {link_result.score}/100 on the URL "
                f"heuristics ({link_result.risk}).",
                "Do not click it. Navigate to the service yourself.")
            break
    if links and worst_link_score < 60:
        result.add(
            "EMAIL-LINKS-CHECKED", "info", 0,
            f"{len(set(links))} link(s) checked, worst score "
            f"{worst_link_score}/100",
            "No body link scored as high-risk on URL heuristics.",
            "No action needed for the links themselves.")

    # Display-text vs href mismatch (HTML mail): <a href="evil">paypal.com</a>
    if html:
        for href in HREF_RE.findall(html):
            href_host = re.search(r"https?://([^/\"'<>]+)", href)
            for text in DISPLAY_TEXT_RE.findall(html):
                shown = text.strip().lower()
                if shown.startswith(("http", "www.")) and href_host:
                    shown_host = shown.replace("https://", "").replace(
                        "http://", "").split("/")[0].lstrip("www.")
                    real_host = href_host.group(1).lower().lstrip("www.")
                    if shown_host and shown_host != real_host:
                        result.add(
                            "EMAIL-LINK-MISMATCH", "critical", 35,
                            "Link text shows a different destination than the real href",
                            f"The visible text says {shown_host} but the "
                            f"link actually goes to {real_host}.",
                            "Hover / long-press every link and read the "
                            "real destination before clicking.")
                        break
            else:
                continue
            break

    # --- E07: QR-code phishing ("quishing") -----------------------------
    if re.search(r"\bqr\s*code\b", text_all) and re.search(
            r"\b(scan|scan it|scan to|scan the)\b", text_all):
        result.add(
            "EMAIL-QR-PHISHING", "medium", 15,
            "Message pushes the reader to scan a QR code",
            "QR-code phishing ('quishing') is a major 2026 tactic: the "
            "malicious URL hides inside an image, so link scanners and "
            "email filters cannot see it, and the phone opens it in a "
            "browser with fewer warnings.",
            "Never scan a QR code from an unexpected email. Open the "
            "service's app yourself instead.")

    # --- E08: attachment warning ----------------------------------------
    if msg.get_content_type() in ("multipart/mixed",) or re.search(
            r'filename\s*=\s*"[^"]+\.(exe|scr|js|vbs|bat|ps1|zip|iso|img)"',
            raw.decode("utf-8", errors="ignore"), re.IGNORECASE):
        result.add(
            "EMAIL-RISKY-ATTACHMENT", "high", 20,
            "Risky attachment type present",
            "Executable / script / archive attachments are a common "
            "malware delivery route.",
            "Do not open unexpected attachments; verify with the sender "
            "through another channel first.")

    if not result.findings:
        result.add(
            "EMAIL-CLEAN", "info", 0,
            "No phishing heuristics triggered",
            "Sender authentication passed, no display-name spoof, no "
            "urgency pressure and no high-risk links found.",
            "No action needed.")

    return result.finalize()
