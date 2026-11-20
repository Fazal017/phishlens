"""Adversarial evasion harness (PhishLens v2).

The point of v2 is not just to score a phish once, but to survive
the attacker *adapting* to the detector. This harness takes a known
phishing URL and generates 10 evasion variants — the tricks a kit
operator actually uses when their first link gets flagged — then
scores every variant with the full v2 scorer and reports how many
still score >= 60 ("caught").

Variants (all synthetic, never fetched):
 1. legit-word padding   -- add official/help/support words to the path
 2. shortener + redirect -- wrap the kit URL behind bit.ly + a redirect param
 3. homoglyph            -- punycode lookalike domain (xn--pypal-4ve.com)
 4. split brand          -- brand across subdomains (paypal.com.verify-account.xyz)
 5. @ decoy              -- brand before '@', kit host after it
 6. hyphen stuffing      -- paypal-secure-login-verify on a cheap TLD
 7. redirect param       -- ?next=<kit url> on a neutral-looking host
 8. http + long path     -- drop TLS, bury the host in a long path
 9. vowel swap           -- paypel.com (sounds identical)
10. keyboard typo        -- paypak.com (k is next to l on QWERTY)

Pass bar: at least 9/10 variants still caught. The report is written
to evasion_report.json so the result is auditable, not asserted.
"""

import json
from pathlib import Path

from .v2 import analyze_v2_url

EVASION_VARIANTS = [
    ("legit-word-padding",
     "https://paypa1.com/login/verify/account?source=official-help-support"),
    ("shortener-redirect",
     "https://bit.ly/paypal-login-verify-secure?redirect=https://paypa1.com/login"),
    ("homoglyph-punycode",
     "https://xn--pypal-4ve.com/login/verify/account"),
    ("split-brand-subdomains",
     "https://www.paypal.com.verify-account.xyz/login"),
    ("at-sign-decoy",
     "https://paypal.com@paypa1.com/login/verify/account"),
    ("hyphen-stuffing",
     "https://paypal-secure-login-verify.top/account/verify"),
    ("redirect-param",
     "https://login-helpdesk.example.org/redirect?next=https://paypa1.com/login"),
    ("http-long-path",
     "http://paypa1.com/login/verify/account/security/update/confirm/1234567890"),
    ("vowel-swap",
     "https://paypel.com/login/verify/account"),
    ("keyboard-typo",
     "https://paypak.com/login/verify/account"),
]


def generate_evasion_variants(base_url=None):
    """Return [(variant_id, url), ...]. ``base_url`` is informational:
    the 10 variants are fixed, deterministic cases built from the
    canonical paypa1.com kit URL, so runs are reproducible."""
    return list(EVASION_VARIANTS)


def run_evasion_harness(base_url=None, output_path=None):
    """Score all 10 variants with the v2 scorer; write evasion_report.json."""
    variants = generate_evasion_variants(base_url)
    cases = []
    caught = 0
    for variant_id, url in variants:
        result = analyze_v2_url(url)
        is_caught = result.score >= 60
        caught += 1 if is_caught else 0
        cases.append({
            "variant": variant_id, "url": url, "score": result.score,
            "risk": result.risk, "caught": is_caught,
            "rules": [f.rule_id for f in result.findings],
        })
    report = {
        "base_url": base_url or "https://paypa1.com/login/verify/account",
        "threshold": 60, "total": len(cases), "caught": caught,
        "pass_rate": caught / len(cases) if cases else 0,
        "passed": caught >= 9,
        "cases": cases,
    }
    if output_path:
        Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
