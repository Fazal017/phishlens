"""Brand list and string-similarity helpers for lookalike detection.

Only the Python standard library is used. Brands are stored as
``name -> set of legitimate domains`` so a lookalike check can tell
"close to paypal, but not paypal.com" apart from the real thing.
"""

BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
    "amazon": {"amazon.com", "amazon.co.uk"},
    "apple": {"apple.com", "icloud.com"},
    "binance": {"binance.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "github": {"github.com"},
    "linkedin": {"linkedin.com"},
    "chase": {"chase.com"},
    "bank of america": {"bankofamerica.com"},
    "wells fargo": {"wellsfargo.com"},
    "coinbase": {"coinbase.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "whatsapp": {"whatsapp.com"},
}

# Short forms / squashed names attackers commonly use in domains.
BRAND_ALIASES = {
    "paypal": "paypal",
    "google": "google",
    "microsoft": "microsoft",
    "amazon": "amazon",
    "apple": "apple",
    "binance": "binance",
    "facebook": "facebook",
    "instagram": "instagram",
    "netflix": "netflix",
    "steam": "steam",
    "github": "github",
    "linkedin": "linkedin",
    "chase": "chase",
    "bankofamerica": "bank of america",
    "wellsfargo": "wells fargo",
    "coinbase": "coinbase",
    "adobe": "adobe",
    "dropbox": "dropbox",
    "whatsapp": "whatsapp",
}

# TLDs disproportionately abused for phishing (cheap / free / no-questions
# registration). A legit site *can* use one, so this is a small weight,
# never a verdict on its own.
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "buzz",
    "online", "site", "fun", "icu", "sbs", "quest", "cam", "rest",
    "live", "shop", "work", "zip", "mov", "ru", "su",
}

# "ru" / "su" are in the list above because they appear often in
# credential-phishing kits, but they are also legitimate country TLDs.
# Keep their weight identical to the other suspicious TLDs (small) and
# rely on the other signals for the final score.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
    "tiny.cc", "bit.do", "s.id", "rb.gy",
}

# Words that, in a URL path / query, usually mean "give us credentials".
SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "password", "wallet", "unlock",
    "suspended", "limited", "alert", "security", "authenticate",
    "free", "prize", "winner", "claim", "urgent",
}

URGENCY_KEYWORDS = {
    "urgent", "immediately", "act now", "verify now", "suspended",
    "suspension", "limited time", "expires", "expiring", "final notice",
    "final warning", "account will be closed", "will be closed",
    "confirm within", "within 24 hours", "24 hours", "locked",
    "unauthorized", "unusual activity", "security alert",
}


def levenshtein(a, b):
    """Classic edit distance (insert/delete/substitute = 1)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[-1]


def closest_brand(label):
    """Return (brand, distance) for the brand name closest to *label*.

    ``label`` is one dot-separated label of a domain, lower-cased and
    stripped of digits/hyphens for the comparison (``paypa1`` -> ``paypa``).
    """
    best_brand, best_dist = None, 99
    for alias, brand in BRAND_ALIASES.items():
        d = levenshtein(label, alias)
        if d < best_dist:
            best_brand, best_dist = brand, d
    return best_brand, best_dist


def is_legitimate_brand_domain(domain, brand):
    """True if *domain* is (or is a subdomain of) a real domain of *brand*."""
    domain = domain.lower().strip(".")
    for legit in BRANDS.get(brand, set()):
        if domain == legit or domain.endswith("." + legit):
            return True
    return False


def registered_domain(domain):
    """Best-effort registrable domain: last two labels (``a.b.co.uk`` -> ``b.co.uk``).

    Good enough for a heuristic tool; a full public-suffix list would need
    a third-party dependency, which this project deliberately avoids.
    """
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()
