"""Tests for PhishLens — run with:  python -m unittest discover -s tests -v

All tests are offline and deterministic: no network, no API keys.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.brands import levenshtein  # noqa: E402
from src.email_analyzer import analyze_email  # noqa: E402
from src.report import render_html, results_to_json  # noqa: E402
from src.url_analyzer import analyze_url, shannon_entropy  # noqa: E402


def sample(name):
    return (ROOT / "samples" / name).read_bytes()


class TestLevenshtein(unittest.TestCase):
    def test_identical_is_zero(self):
        self.assertEqual(levenshtein("paypal", "paypal"), 0)

    def test_one_edit_typosquat(self):
        self.assertEqual(levenshtein("paypa1", "paypal"), 1)
        self.assertEqual(levenshtein("paypa", "paypal"), 1)


class TestUrlAnalyzer(unittest.TestCase):
    def test_legit_paypal_scores_low(self):
        r = analyze_url("https://www.paypal.com/signin")
        self.assertLess(r.score, 30)
        self.assertEqual(r.risk, "Low")

    def test_legit_google_scores_low(self):
        self.assertLess(analyze_url("https://www.google.com/").score, 30)

    def test_typosquat_scores_high(self):
        r = analyze_url("https://paypa1.com/login/verify/account")
        self.assertGreaterEqual(r.score, 60)
        self.assertIn("URL-LOOKALIKE-DOMAIN",
                      [f.rule_id for f in r.findings])

    def test_ip_host_scores_high(self):
        r = analyze_url("http://185.220.101.45/secure/paypal/verify")
        self.assertGreaterEqual(r.score, 60)
        self.assertIn("URL-IP-HOST", [f.rule_id for f in r.findings])

    def test_punycode_scores_high(self):
        r = analyze_url("https://xn--pypal-4ve.com/login/verify/account")
        self.assertGreaterEqual(r.score, 60)
        self.assertIn("URL-PUNYCODE", [f.rule_id for f in r.findings])

    def test_brand_in_subdomain_scores_high(self):
        r = analyze_url("https://www.paypal.com.verify-account.xyz/login")
        self.assertGreaterEqual(r.score, 60)
        self.assertIn("URL-BRAND-IN-SUBDOMAIN",
                      [f.rule_id for f in r.findings])

    def test_at_sign_decoy_scores_high(self):
        r = analyze_url("https://microsoft.com@evil-login.ru/update")
        self.assertGreaterEqual(r.score, 60)
        self.assertIn("URL-BRAND-BEFORE-AT",
                      [f.rule_id for f in r.findings])

    def test_shortener_with_brand_path_scores_high(self):
        r = analyze_url("https://bit.ly/paypal-login-verify-secure")
        self.assertGreaterEqual(r.score, 60)

    def test_http_is_flagged_but_not_high_alone(self):
        # http alone (+10) must not push a clean domain into High.
        r = analyze_url("http://www.wikipedia.org/")
        self.assertLess(r.score, 30)

    def test_entropy_helper(self):
        self.assertGreater(shannon_entropy("a1b2c3d4e5f6g7h8"),
                           shannon_entropy("aaaaaaaa"))
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_every_finding_has_explanation_and_fix(self):
        r = analyze_url("https://paypa1.com/login/verify/account")
        for f in r.findings:
            self.assertTrue(f.explanation.strip())
            self.assertTrue(f.remediation.strip())
            self.assertIn(f.severity,
                          ("info", "low", "medium", "high", "critical"))


class TestSampleSeparation(unittest.TestCase):
    """The bundled samples must separate cleanly: phishing > 60, legit < 30."""

    def test_sample_urls_separate(self):
        lines = [ln.strip() for ln in
                 (ROOT / "samples" / "urls.txt").read_text().splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
        self.assertEqual(len(lines), 15)
        phishing, legit = lines[:8], lines[8:]
        for u in phishing:
            with self.subTest(url=u):
                self.assertGreater(analyze_url(u).score, 60, u)
        for u in legit:
            with self.subTest(url=u):
                self.assertLess(analyze_url(u).score, 30, u)


class TestEmailAnalyzer(unittest.TestCase):
    def test_phishing_email_scores_high(self):
        r = analyze_email(sample("phishing_email.txt"),
                          target="phishing_email.txt")
        self.assertGreaterEqual(r.score, 60)
        rule_ids = [f.rule_id for f in r.findings]
        self.assertIn("EMAIL-DISPLAY-SPOOF", rule_ids)
        self.assertIn("EMAIL-SPF-FAIL", rule_ids)
        self.assertIn("EMAIL-REPLYTO-MISMATCH", rule_ids)

    def test_legit_email_scores_low(self):
        r = analyze_email(sample("legit_email.txt"), target="legit_email.txt")
        self.assertLess(r.score, 30)

    def test_qr_phishing_note_is_raised(self):
        r = analyze_email(sample("phishing_email.txt"),
                          target="phishing_email.txt")
        self.assertIn("EMAIL-QR-PHISHING", [f.rule_id for f in r.findings])


class TestReport(unittest.TestCase):
    def test_json_round_trip(self):
        r = analyze_url("https://paypa1.com/login/verify/account")
        data = results_to_json([r])[0]
        self.assertEqual(json.loads(json.dumps(data))["score"], r.score)
        self.assertEqual(data["risk"], r.risk)

    def test_html_report_contains_target_and_score(self):
        r = analyze_url("https://paypa1.com/login/verify/account")
        html_out = render_html([r])
        self.assertIn("paypa1.com", html_out)
        self.assertIn(str(r.score), html_out)


if __name__ == "__main__":
    unittest.main()
