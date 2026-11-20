# PhishLens — Phishing URL & Email Header Analyzer

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Stdlib only](https://img.shields.io/badge/dependencies-stdlib%20only-green.svg)](requirements.txt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-19%20passing-brightgreen.svg)](tests/test_phishlens.py)

Score a URL or an email for phishing risk (0–100) and find out **why** — no API keys, no network requests, no accounts. PhishLens never fetches the URL it analyses, so checking a suspicious link never requires visiting it.

> **Heuristic only — not a verdict.** A high score means "do not trust this, verify through an official channel". A low score means "nothing in these checks looked wrong", not "this is safe". When in doubt, confirm with [VirusTotal](https://www.virustotal.com/) or the organisation's official app/site.

## What it catches

2026 phishing is rarely a misspelled email from a prince. It is:

| Tactic | How PhishLens catches it |
|---|---|
| **Brand impersonation / subdomain abuse** | `paypal.com.verify-account.xyz` — the brand is in a subdomain of a domain the brand does not own (`URL-BRAND-IN-SUBDOMAIN`) |
| **Typosquatting** | `paypa1.com` — 1 edit from PayPal, with a digit swapped for a letter (`URL-LOOKALIKE-DOMAIN`, Levenshtein distance) |
| **Homoglyph / IDN homograph attacks** | `xn--pypal-4ve.com` — punycode domains using Cyrillic/Greek lookalike letters (`URL-PUNYCODE`, `URL-HOMOGLYPH`) |
| **Bare-IP hosts** | `http://185.220.101.45/...` — no brand domain to check at all (`URL-IP-HOST`) |
| **`@` decoys** | `microsoft.com@evil-login.ru` — the browser goes to the host *after* `@` (`URL-AT-SIGN`, `URL-BRAND-BEFORE-AT`) |
| **URL shorteners hiding the destination** | `bit.ly/paypal-login-verify-secure` — destination invisible to the reader (`URL-SHORTENER`) |
| **QR-code phishing ("quishing")** | "Scan the QR code to verify" — the malicious URL hides inside an image, invisible to link scanners (`EMAIL-QR-PHISHING`) |
| **Display-name spoofing** | From shows "PayPal Support" but the sender domain is not PayPal's (`EMAIL-DISPLAY-SPOOF`) |
| **Reply-To harvesting** | From and Reply-To go to different domains (`EMAIL-REPLYTO-MISMATCH`) |
| **Failed sender authentication** | SPF / DKIM / DMARC `fail` in `Authentication-Results` / `Received-SPF` (`EMAIL-SPF-FAIL`, `EMAIL-DKIM-FAIL`, `EMAIL-DMARC-FAIL`) |
| **Urgency pressure** | "Your account will be suspended in 24 hours — act now" (`EMAIL-URGENCY`) |
| **Link text ≠ real destination** | Visible text says one host, the `href` goes to another (`EMAIL-LINK-MISMATCH`) |

Plus supporting signals: missing HTTPS, suspicious TLDs (`.xyz`, `.top`, `.click`…), excessive subdomains, very long / high-entropy URLs, open-redirect parameters, credential keywords (`login`, `verify`, `secure`, `account`…), and risky attachments.

## Scoring

| Score | Risk | Meaning |
|---|---|---|
| 0–29 | Low | No phishing heuristics triggered |
| 30–59 | Medium | Suspicious — verify through an official channel first |
| 60–79 | High | Likely phishing — do not visit / do not trust |
| 80–100 | Critical | Likely phishing — do not visit / do not trust |

One *critical* impersonation signal (a 1-edit typosquat of a major brand, a punycode homograph, a bare-IP host, a brand abused as someone else's subdomain) is worth 40–50 points. Ordinary signals (plain HTTP, a suspicious TLD, a long URL) are worth 5–15 and can only reach High when they stack up. Every finding carries a rule id, severity, explanation, and a remediation step.

## Install

```bash
git clone https://github.com/<your-username>/phishlens.git
cd phishlens
# No dependencies to install — Python 3.8+ standard library only.
python3 phishlens.py url https://www.google.com/
```

## Usage

### Analyse one URL

```bash
python phishlens.py url https://paypa1.com/login/verify/account
```

Expected output:

```
PhishLens  |  URL  |  https://paypa1.com/login/verify/account
Score:  65/100  [#############-------]  Risk: High
Verdict: Likely phishing — do not visit / do not trust
------------------------------------------------------------------------
[CRITICAL] URL-LOOKALIKE-DOMAIN (+50) — Lookalike domain: 'paypa1' mimics 'paypal' with substituted characters
           'paypa1' only reads as 'paypal' after undoing a character substitution (e.g. 1 for l, 0 for o). The real domain is not the brand's.
           Fix: Type the brand's domain yourself; do not trust a near-miss spelling.
[MEDIUM  ] URL-SUSPICIOUS-KEYWORDS (+15) — Suspicious keywords in URL: account, login, verify
           login / verify / secure / account language in the URL is typical of credential-harvesting pages.
           Fix: Go to the service's official site instead of following a 'verify your account' link.
------------------------------------------------------------------------
```

Exit code is `2` when the score is 60+ (handy in scripts/CI), `0` otherwise. Add `--json` for machine-readable output.

### Analyse an email

```bash
python phishlens.py email --file samples/phishing_email.txt
python phishlens.py email --file samples/legit_email.txt
```

The phishing sample scores **100/100 (Critical)**: display-name spoof (+40), a high-risk link in the body (+35), Reply-To mismatch (+25), SPF/DKIM/DMARC fail (+25/+20/+20), urgency language (+15) and a QR-code push (+15). The legitimate sample scores **0/100 (Low)** — SPF/DKIM/DMARC all pass, sender and Reply-To match, no urgency, no risky links. Pass any raw `.eml` / `.txt` message (export it from your mail client — never forward a live phish to yourself to test it).

### Batch mode — JSON or HTML report

```bash
python phishlens.py batch --file samples/urls.txt --output report.json
python phishlens.py batch --file samples/urls.txt --output report.html
```

Sample results on the bundled `samples/urls.txt` (8 phishing-like, 7 legitimate):

| URL | Score | Risk |
|---|---|---|
| `https://google-support-login.top/account@verify` | 100 | Critical |
| `https://www.paypal.com.verify-account.xyz/login` | 97 | Critical |
| `http://185.220.101.45/secure/paypal/verify` | 93 | Critical |
| `http://paypal-secure-login.xyz/verify/account` | 82 | Critical |
| `https://xn--pypal-4ve.com/login/verify/account` | 80 | Critical |
| `https://microsoft.com@evil-login.ru/update` | 77 | High |
| `https://paypa1.com/login/verify/account` | 65 | High |
| `https://bit.ly/paypal-login-verify-secure` | 65 | High |
| `https://www.paypal.com/signin` | 0 | Low |
| `https://www.google.com/` | 0 | Low |
| `https://www.amazon.com/` | 0 | Low |
| `https://www.binance.com/en` | 0 | Low |
| `https://github.com/` | 0 | Low |
| `https://www.wikipedia.org/` | 0 | Low |
| `https://www.microsoft.com/.../microsoft-outlook` | 5 | Low |

Phishing separates cleanly: **65–100 vs 0–5**. A pre-generated `report.json` / `report.html` from this sample run is included in the repo.

Example JSON (one entry of `report.json`):

```json
{
  "target": "https://paypa1.com/login/verify/account",
  "kind": "url",
  "score": 65,
  "risk": "High",
  "verdict": "Likely phishing — do not visit / do not trust",
  "findings": [
    {
      "rule_id": "URL-LOOKALIKE-DOMAIN",
      "severity": "critical",
      "weight": 50,
      "title": "Lookalike domain: 'paypa1' mimics 'paypal' with substituted characters",
      "explanation": "'paypa1' only reads as 'paypal' after undoing a character substitution (e.g. 1 for l, 0 for o). The real domain is not the brand's.",
      "remediation": "Type the brand's domain yourself; do not trust a near-miss spelling."
    }
  ]
}
```

## Tests

```bash
python3 -m unittest discover -s tests -v
# Ran 19 tests ... OK
```

19 tests, all offline and deterministic: Levenshtein distance, per-rule URL checks (typosquat, IP host, punycode, subdomain abuse, `@` decoy, shortener), email checks (display spoof, SPF fail, Reply-To mismatch, QR phishing), a sample-separation test asserting phishing > 60 and legit < 30 on every bundled URL, and JSON/HTML report round-trips.

## Project layout

```
phishlens/
├── phishlens.py            # CLI: url / email / batch
├── src/
│   ├── brands.py           # brand list, suspicious TLDs/shorteners, Levenshtein
│   ├── url_analyzer.py     # URL heuristics (U01–U12)
│   ├── email_analyzer.py   # email header/body heuristics (E01–E08)
│   ├── scoring.py          # weighted findings -> 0-100 score + risk band
│   └── report.py           # terminal table, JSON, standalone HTML report
├── samples/
│   ├── urls.txt            # 15 URLs: 8 phishing-like, 7 legit
│   ├── phishing_email.txt  # spoofed PayPal mail (SPF/DKIM/DMARC fail, QR push)
│   └── legit_email.txt     # genuine-style PayPal statement mail (all auth pass)
├── tests/test_phishlens.py # 19 unittest tests
├── report.json / report.html   # example batch output on the samples
├── requirements.txt        # stdlib only — nothing to install
└── LICENSE                 # MIT
```

## Limitations

- **Heuristic, not a verdict.** A clever phish on a fresh domain with clean wording can score low; a legitimate marketing mail with urgency language and a shortener can score Medium. Always confirm high-stakes cases with VirusTotal, the organisation's official app, or a phone call to a published number.
- **No live checks.** PhishLens never fetches a URL, so it cannot see the page content, TLS certificate, domain age, or blocklist status. That is a safety choice — add those (via VirusTotal / urlscan.io APIs) if you want a second layer.
- **Brand list is small** (PayPal, Google, Microsoft, Amazon, Apple, Binance, Facebook, Instagram, Netflix, Steam, GitHub, LinkedIn, Chase, Bank of America, Wells Fargo, Coinbase, Adobe, Dropbox, WhatsApp). Add brands in `src/brands.py`.
- **Registrable-domain detection uses the last two labels**, not the full public-suffix list (e.g. `co.uk` edge cases). Good enough for a heuristic; a `tldextract`-style list would need a dependency.
- **`.ru` is treated as a suspicious TLD** because it is heavily abused by phishing kits — it is also a legitimate country TLD, so it only ever contributes a small weight.

## Ethical use

Built for defence: SOC triage, security awareness training, and checking links *before* anyone clicks them. Do not use it to craft more convincing phishing pages, to test whether your own phish evades detection, or to harass anyone. The sample URLs and emails are synthetic examples — do not visit them, and do not send the phishing sample to real people.

## License

MIT — see [LICENSE](LICENSE).
