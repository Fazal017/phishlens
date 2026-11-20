# PhishLens — Phishing URL & Email Header Analyzer

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Stdlib only](https://img.shields.io/badge/dependencies-stdlib%20only-green.svg)](requirements.txt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-46%20passing-brightgreen.svg)](tests/test_phishlens.py)

Score a URL or an email for phishing risk (0–100) and find out **why** — no API keys, no network requests, no accounts. PhishLens never fetches the URL it analyses, so checking a suspicious link never requires visiting it.

## v2.0 — Advanced: PhishLens Adversarial

> **v1 is still here and still works** (`phishlens.py`, 19 tests). v2 is a
> second engine alongside it (`phishlens_v2.py`), built on an original
> idea: *don't score a phish once — score the kit behind it, the
> sender behind it, and whether it survives evasion.*

Most phishing checkers are tutorial-level: one edit-distance check,
one SPF check, done. v2 adds three things no tutorial checker does,
and they are the reason a fresh kit domain or a BEC mail is caught
here when a single-axis scorer misses it:

### 1. Three-dimensional brand squatting (`src/squatting.py`)

Every candidate label is scored on **three independent axes**, and
only needs to be close on one:

- **(a) Edit distance — Damerau-Levenshtein** (transposition costs 1,
  plain Levenshtein counts it as 2). `paypall` and `paypla` are 1 edit away.
- **(b) Phonetic similarity — Soundex + vowel-swap normalisation.**
  `paypel` / `paypol` sound identical to `paypal` (Soundex P140) even
  though the spelling differs.
- **(c) Keyboard-adjacency distance — QWERTY-neighbour weighted edit
  distance.** An adjacent-key substitution costs 0.5, a random one
  costs 1.0. `paypak` (k sits next to l) is keyboard-distance 0.5;
  `paypaz` is 1.0.

The same four lookalikes are caught *differently* — that is the point:

| Domain | Damerau | Keyboard | Phonetic | Caught as |
|---|---|---|---|---|
| `paypa1.com` | 0 (1→l) | 0.0 | Soundex P140, match | `SQ-PHONETIC` |
| `paypal-secure-login.xyz` | 6 | 6.0 | no | `SQ-EMBEDDED-BRAND` — brand intact, domain not the brand's |
| `paypaI.com` (capital I for l) | 1 | 0.5 | no | `SQ-EDIT-1` + keyboard |
| `paypall.com` | 1 | 1.0 | Soundex P140, match | `SQ-EDIT-1` + phonetic + keyboard |

Legitimate `paypal.com` scores 0 on the squatting findings — every
layer checks "is this actually the brand's own domain?" first.

### 2. Phishing-kit fingerprinting (`src/kit.py`)

A kit is a reusable template: the same login page, path pattern and
redirect chain, reused across hundreds of domains. v2 fingerprints
the **kit**, so a fresh domain running a known kit is caught on
structure alone:

- **URL-structure templates** — credential-harvest, Microsoft 365,
  payment/invoice, crypto seed-phrase, document-share kits.
- **Kit signature** — SHA-256 of the *normalised* path pattern
  (digits / hex / random segments replaced by `{id}`), so
  `paypa1.com/login/verify/account` and
  `paypal-secure-login.xyz/login/verify/account` share signature
  `21caf8f57004`.
- **Redirect-chain simulation** — a supplied chain map is followed
  hop by hop, offline; shortener → impersonation → kit is itself a
  fingerprint. v2 also **unwraps redirect targets** hidden in
  `?next=` / `?url=` params and scores the destination too.
- **Form analysis** — a supplied HTML snippet/title is checked for a
  password field naming a brand the domain does not own
  (`KIT-FORM-BRAND-MISMATCH`, +45), plus a favicon/domain mismatch
  heuristic.

```bash
python phishlens_v2.py kit https://paypa1.com/login/verify/account
# 95/100 Critical — v1 lookalike (+50) + KIT-CRED-HARVEST (+30) + keywords (+15)
python phishlens_v2.py kit --file samples/kit_urls.txt
# 11/12 kit URLs score >= 60 (the one miss is a brand-less crypto-seed
# kit at 52/100 Medium — see Limitations)
```

### 3. Business Email Compromise detection (`src/bec.py`)

Credential phishing steals a password; BEC steals a *payment*.
v2 builds a sender behaviour profile from `samples/bec_history.json`
and scores the combination that defines BEC:

- **First-time sender** — sender (or sender→recipient pair) has no history.
- **Reply-chain hijack** — `Re:` subject with no thread headers, or
  `In-Reply-To` not in `References`, or pointing at another domain.
- **Authority + urgency + payment together** — each alone is common;
  all three is the BEC signature (+50).
- **Writing-style deviation** — function-word frequency (the, of,
  and, please, thanks…) vs the sender's historical profile, as
  cosine similarity. A hijacked / impersonated author writes
  differently even when the address looks right.
- **Lookalike sender domain** — the 3-D squatting check, applied to
  the sender.

```bash
python phishlens_v2.py bec --file samples/bec_phishing.txt
# 100/100 Critical — first-time sender + thread hijack + authority/urgency/payment
python phishlens_v2.py bec --file samples/bec_legit_thread.txt
# 0/100 Low — known sender, consistent thread, matching style
```

### 4. Adversarial evasion harness (`src/evasion.py`)

The harness generates **10 evasion variants** of a phishing URL —
legit-word padding, shortener+redirect, homoglyph, split brand
across subdomains, `@` decoy, hyphen stuffing, redirect param,
HTTP + long path, vowel swap, keyboard typo — and scores each with
the full v2 scorer. Pass bar: **≥ 9/10 still caught (≥ 60)**.

```bash
python phishlens_v2.py evade --output evasion_report.json
```

| Variant | Score | Caught |
|---|---|---|
| legit-word-padding | 100 | yes |
| shortener-redirect | 100 | yes |
| homoglyph-punycode | 100 | yes |
| split-brand-subdomains | 100 | yes |
| @-sign-decoy | 100 | yes |
| hyphen-stuffing | 100 | yes |
| redirect-param (unwrapped) | 100 | yes |
| http-long-path | 100 | yes |
| vowel-swap (`paypel`) | 100 | yes |
| keyboard-typo (`paypak`) | 100 | yes |

**Evasion result (verified): 10/10 caught, pass rate 100%.**
Full per-variant report in [`evasion_report.json`](evasion_report.json).

## v2 tests

```bash
python3 -m unittest discover -s tests -v
# Ran 46 tests ... OK  (19 v1 + 22 v2 + 5 evasion)
```

27 new tests: phonetic / keyboard / Damerau squatting, kit template +
signature + form mismatch, BEC first-time sender / payment+urgency /
style deviation, v2 legit-vs-phishing separation, and the evasion
harness (10 variants generated, ≥ 9/10 caught, report JSON written).

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
# Ran 46 tests ... OK
```

46 tests, all offline and deterministic: 19 v1 tests (Levenshtein,
per-rule URL checks, email checks, sample separation, report
round-trips) + 22 v2 tests (3-D squatting, kit fingerprinting, BEC,
v2 separation) + 5 evasion-harness tests.

## Project layout

```
phishlens/
├── phishlens.py            # v1 CLI: url / email / batch (unchanged)
├── phishlens_v2.py         # v2 CLI: kit / bec / evade
├── src/
│   ├── brands.py           # brand list, suspicious TLDs/shorteners, Levenshtein
│   ├── url_analyzer.py     # URL heuristics (U01–U12)
│   ├── email_analyzer.py   # email header/body heuristics (E01–E08)
│   ├── scoring.py          # weighted findings -> 0-100 score + risk band
│   ├── report.py           # terminal table, JSON, standalone HTML report
│   ├── squatting.py        # v2: 3-D squatting (Damerau, phonetic, keyboard)
│   ├── kit.py              # v2: kit templates, signature, redirect chain, form
│   ├── bec.py              # v2: BEC (first-time sender, thread hijack, style)
│   ├── evasion.py          # v2: 10-variant evasion harness
│   └── v2.py               # v2: combined scorer + redirect-target unwrapping
├── samples/
│   ├── urls.txt            # 15 URLs: 8 phishing-like, 7 legit
│   ├── phishing_email.txt  # spoofed PayPal mail (SPF/DKIM/DMARC fail, QR push)
│   ├── legit_email.txt     # genuine-style PayPal statement mail (all auth pass)
│   ├── kit_urls.txt        # 12 kit-style URLs
│   ├── bec_phishing.txt    # BEC: fake CEO, urgent wire transfer, hijacked thread
│   ├── bec_legit_thread.txt# genuine CEO thread (known sender, matching style)
│   ├── bec_history.json    # sender behaviour profiles for BEC
│   └── evasion_cases.json  # the 10 evasion variants
├── tests/
│   ├── test_phishlens.py   # 19 v1 tests
│   ├── test_v2.py          # 22 v2 tests
│   └── test_evasion.py     # 5 evasion-harness tests
├── evasion_report.json     # v2 evasion harness output (10/10 caught)
├── report.json / report.html   # example batch output on the samples
├── requirements.txt        # stdlib only — nothing to install
└── LICENSE                 # MIT
```

## Limitations

- **Heuristic, not a verdict.** A clever phish on a fresh domain with clean wording can score low; a legitimate marketing mail with urgency language and a shortener can score Medium. Always confirm high-stakes cases with VirusTotal, the organisation's official app, or a phone call to a published number.
- **v2 kit honesty:** 11/12 kit samples score ≥ 60. The miss is a brand-less crypto-seed kit (`metamask-restore-wallet.top/import/restore`, 52/100 Medium) — with no brand to squat and no v1 impersonation signal, only the kit template fires. Evasion scores are all 100 because the layers stack and cap at 100; the informative number is the 10/10 catch rate, not the score itself.
- **No live checks.** PhishLens never fetches a URL, so it cannot see the page content, TLS certificate, domain age, or blocklist status. That is a safety choice — add those (via VirusTotal / urlscan.io APIs) if you want a second layer.
- **Brand list is small** (PayPal, Google, Microsoft, Amazon, Apple, Binance, Facebook, Instagram, Netflix, Steam, GitHub, LinkedIn, Chase, Bank of America, Wells Fargo, Coinbase, Adobe, Dropbox, WhatsApp). Add brands in `src/brands.py`.
- **Registrable-domain detection uses the last two labels**, not the full public-suffix list (e.g. `co.uk` edge cases). Good enough for a heuristic; a `tldextract`-style list would need a dependency.
- **`.ru` is treated as a suspicious TLD** because it is heavily abused by phishing kits — it is also a legitimate country TLD, so it only ever contributes a small weight.

## Ethical use

Built for defence: SOC triage, security awareness training, and checking links *before* anyone clicks them. Do not use it to craft more convincing phishing pages, to test whether your own phish evades detection, or to harass anyone. The sample URLs and emails are synthetic examples — do not visit them, and do not send the phishing sample to real people.

## License

MIT — see [LICENSE](LICENSE).
