"""Business Email Compromise (BEC) detection (PhishLens v2).

Credential phishing steals a password; BEC steals a *payment*.
The attacker impersonates an executive / supplier, hijacks or
fakes a thread, and asks finance to wire money, change bank details
or buy gift cards — urgently, confidentially, and usually for the
first time from that sender. v1 checked headers and urgency in
isolation; v2 builds a *sender behaviour profile* and scores the
combination that defines BEC:

1. First-time sender -- the sender (or the sender->recipient pair)
   has no history in ``samples/bec_history.json``.
2. Reply-chain hijack -- ``In-Reply-To`` / ``References`` do not
   agree, or a ``Re:`` subject arrives with no thread headers at all.
3. Authority + urgency + payment-request -- all three together is
   the BEC signature; any two is a strong warning.
4. Writing-style deviation -- function-word frequency of the body
   vs the sender's historical profile (cosine similarity). A
   hijacked account / impersonator writes differently from the
   real executive, even when the address looks right.
5. Lookalike sender domain -- reuse of the 3-D squatting check.

Stdlib only, no network. History is a local JSON file the user owns.
"""

import json
import math
import re
from collections import Counter
from email import policy
from email.parser import BytesParser
from pathlib import Path

from .brands import BRAND_ALIASES, BRANDS
from .email_analyzer import _get_body_text, analyze_email
from .scoring import AnalysisResult
from .squatting import analyze_squatting_label, closest_brand_3d

FUNCTION_WORDS = [
    "the", "of", "and", "to", "in", "i", "you", "we", "please", "thanks",
    "thank", "hi", "hello", "regards", "best", "will", "can", "could",
    "would", "should", "for", "on", "with", "as", "at", "by", "from",
    "is", "are", "it", "this", "that", "please", "kindly", "urgent",
]

AUTHORITY_WORDS = {
    "ceo", "cfo", "chief executive", "chief financial", "director",
    "managing director", "president", "chairman", "board", "executive",
    "finance director", "head of finance",
}

URGENCY_WORDS = {
    "urgent", "urgently", "immediately", "asap", "today", "before end of day",
    "eod", "confidential", "do not discuss", "keep this between us",
    "discreet", "sensitive", "final notice", "act now",
}

PAYMENT_WORDS = {
    "wire transfer", "wire the", "bank transfer", "bank details",
    "change bank", "new bank account", "updated bank", "invoice",
    "payment", "pay the", "gift card", "gift cards", "amazon gift",
    "itunes gift", "crypto", "bitcoin", "usdt", "transfer the funds",
    "release the payment", "process the payment", "vendor payment",
    "supplier payment", "remittance",
}


def function_word_profile(text):
    """Normalised frequency of function words in *text*."""
    words = re.findall(r"[a-z]+", (text or "").lower())
    total = max(1, len(words))
    counts = Counter(w for w in words if w in FUNCTION_WORDS)
    return {w: counts.get(w, 0) / total for w in FUNCTION_WORDS}


def cosine_similarity(a, b):
    keys = set(a) | set(b)
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def style_deviation(body_text, historical_profile):
    """1 - cosine similarity vs the sender's historical function words.

    0.0 = writes exactly like history; ~0.5+ = a different author.
    Returns (deviation, cosine).
    """
    if not historical_profile:
        return None, None
    current = function_word_profile(body_text)
    hist = historical_profile.get("function_words") or {}
    # Historical profiles may be stored as raw counts; normalise them.
    total = sum(hist.values()) or 1
    hist_norm = {k: v / total for k, v in hist.items()}
    cos = cosine_similarity(current, hist_norm)
    return 1.0 - cos, cos


def load_history(path=None):
    """Load sender history JSON. Returns {sender: profile}."""
    p = Path(path) if path else Path(__file__).resolve().parent.parent / "samples" / "bec_history.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data.get("senders", data) if isinstance(data, dict) else {}


def _sender_domain(from_hdr):
    m = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", from_hdr or "")
    return m.group(0).lower() if m else "", (m.group(0).split("@", 1)[1].lower() if m else "")


def analyze_bec(raw_bytes_or_text, history=None, history_path=None, target="<email>"):
    """Score one raw email for BEC risk. Returns an AnalysisResult."""
    if history is None:
        history = load_history(history_path)
    # Start from the v1 email analysis (auth, spoof, urgency, links).
    base = analyze_email(raw_bytes_or_text, target=target)
    result = AnalysisResult(target=target, kind="bec")
    seen = set()
    for f in base.findings:
        result.add(f.rule_id, f.severity, f.weight, f.title, f.explanation, f.remediation)
        seen.add(f.rule_id)

    if isinstance(raw_bytes_or_text, str):
        raw = raw_bytes_or_text.encode("utf-8", errors="replace")
    else:
        raw = raw_bytes_or_text
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        return result.finalize()

    from_hdr = str(msg.get("From", "") or "")
    to_hdr = str(msg.get("To", "") or "")
    subject = str(msg.get("Subject", "") or "")
    in_reply_to = str(msg.get("In-Reply-To", "") or "").strip()
    references = str(msg.get("References", "") or "")
    body = _get_body_text(msg)
    text_all = f"{subject}\n{body}".lower()
    sender, sender_domain = _sender_domain(from_hdr)
    to_match = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", to_hdr or "")
    recipient = to_match.group(0).lower() if to_match else ""
    profile = history.get(sender) if sender else None

    # --- B01: first-time sender / first-time pair ----------------------
    if sender and profile is None:
        result.add(
            "BEC-FIRST-TIME-SENDER", "high", 30,
            f"First-time sender: {sender} has no history",
            "This sender has never mailed this mailbox before in the "
            "supplied history. BEC almost always arrives from a "
            "first-time (or newly spoofed) sender.",
            "Verify the request through a known channel before paying anything.")
    elif sender and profile and recipient:
        typical = [r.lower() for r in profile.get("typical_recipients", [])]
        if typical and recipient not in typical:
            result.add(
                "BEC-UNUSUAL-RECIPIENT", "medium", 15,
                f"Sender {sender} has never mailed {recipient} before",
                "The sender is known, but not to this recipient — an "
                "impersonator reuses a real name with a new target.",
                "Check with the sender on a known number / channel.")

    # --- B02: reply-chain hijack ---------------------------------------
    is_reply_subject = subject.strip().lower().startswith("re:")
    if is_reply_subject and not in_reply_to and not references:
        result.add(
            "BEC-THREAD-HIJACK", "high", 30,
            "Subject says 'Re:' but there are no thread headers",
            "A genuine reply carries In-Reply-To / References. A "
            "faked 'Re:' subject with no thread headers is a "
            "thread-hijack lure: it borrows trust from a conversation "
            "that never happened.",
            "Search your mailbox for the original thread before acting.")
    elif in_reply_to and references and in_reply_to not in references:
        result.add(
            "BEC-THREAD-HIJACK", "high", 30,
            "In-Reply-To does not appear in References",
            "The reply chain is internally inconsistent — the message "
            "claims to answer a message it does not reference.",
            "Search your mailbox for the original thread before acting.")
    elif in_reply_to:
        # In-Reply-To should point at the same domain as the sender.
        m = re.search(r"@([\w.-]+)", in_reply_to)
        if m and sender_domain and m.group(1).lower() != sender_domain:
            result.add(
                "BEC-THREAD-HIJACK", "high", 30,
                "In-Reply-To points to a different domain than the sender",
                f"In-Reply-To references {m.group(1)} but the sender is "
                f"{sender_domain} — the thread was stitched together.",
                "Search your mailbox for the original thread before acting.")

    # --- B03: authority + urgency + payment (the BEC signature) --------
    authority = sorted({w for w in AUTHORITY_WORDS if w in text_all})
    urgency = sorted({w for w in URGENCY_WORDS if w in text_all})
    payment = sorted({w for w in PAYMENT_WORDS if w in text_all})
    combo = sum(bool(x) for x in (authority, urgency, payment))
    if combo == 3:
        result.add(
            "BEC-AUTH-URGENCY-PAYMENT", "critical", 50,
            "BEC signature: authority + urgency + payment request together",
            f"Authority ({', '.join(authority)}), urgency "
            f"({', '.join(urgency)}) and a payment request "
            f"({', '.join(payment)}) in one message. Each alone is "
            "common; all three together is the classic BEC pattern.",
            "Do not pay. Verify the request by phone on a number you "
            "already have — never a number in this email.")
    elif combo == 2:
        which = [n for n, x in (("authority", authority), ("urgency", urgency),
                                ("payment", payment)) if x]
        result.add(
            "BEC-TWO-SIGNALS", "high", 30,
            f"BEC warning: two of three signals present ({' + '.join(which)})",
            "Two BEC signals in one message is a strong warning even "
            "without the third.",
            "Pause and verify through a known channel before acting.")

    # --- B04: writing-style deviation ----------------------------------
    if profile:
        deviation, cos = style_deviation(body, profile)
        if deviation is not None and deviation > 0.35:
            result.add(
                "BEC-STYLE-DEVIATION", "high", 25,
                f"Writing style deviates from sender's history "
                f"(deviation {deviation:.2f}, cosine {cos:.2f})",
                "Function-word frequency (the, of, and, please, thanks…) "
                "differs sharply from this sender's historical mail. "
                "An impersonator — or a hijacked account used by "
                "someone else — writes differently from the real person.",
                "Compare with a genuine mail from this sender; do not "
                "rely on the name alone.")
    elif sender:
        # No history to compare against is itself covered by B01.
        pass

    # --- B05: lookalike sender domain (3-D squatting) ------------------
    if sender_domain:
        labels = sender_domain.split(".")
        reg_label = labels[-2] if len(labels) >= 2 else sender_domain
        brand, analysis = closest_brand_3d(reg_label)
        if brand and analysis["dimensions"] and not any(
                sender_domain.endswith("." + d) or sender_domain == d
                for d in BRANDS.get(brand, set())):
            # Only flag when the domain is not the brand's own and the
            # sender is *claiming* that brand in the display name.
            if brand in from_hdr.lower():
                result.add(
                    "BEC-LOOKALIKE-SENDER", "critical", 40,
                    f"Sender domain '{sender_domain}' squats '{brand}' "
                    f"({', '.join(analysis['dimensions'])})",
                    "The sender's domain is a lookalike of a brand the "
                    "display name claims — a BEC sender impersonation.",
                    "Check the real sender domain, not the display name.")

    return result.finalize()
