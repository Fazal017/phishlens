"""Tests for PhishLens v2 — run with: python -m unittest discover -s tests -v
All offline and deterministic.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.bec import analyze_bec, function_word_profile, style_deviation  # noqa: E402
from src.evasion import generate_evasion_variants, run_evasion_harness  # noqa: E402
from src.kit import analyze_kit, fingerprint_kit, kit_signature, normalise_path_pattern  # noqa: E402
from src.squatting import (  # noqa: E402
    analyze_squatting_label, damerau_levenshtein, is_keyboard_neighbour,
    keyboard_distance, phonetic_match, soundex, squat_findings,
)
from src.v2 import analyze_v2_url  # noqa: E402


def sample(name):
    return (ROOT / "samples" / name).read_bytes()


HISTORY = {
    "sarah.chen@acmecorp.com": {
        "function_words": {"the": 0.16, "please": 0.06, "thanks": 0.03,
                           "will": 0.04, "and": 0.07, "for": 0.05,
                           "to": 0.06, "of": 0.05},
        "typical_recipients": ["finance@acmecorp.com"],
    }
}


class TestSquatting3D(unittest.TestCase):
    def test_damerau_transposition_is_one(self):
        # Plain Levenshtein counts a transposition as 2; Damerau counts 1.
        self.assertEqual(damerau_levenshtein("paypla", "paypal"), 1)
        self.assertEqual(damerau_levenshtein("paypall", "paypal"), 1)

    def test_paypa1_caught_by_phonetic_dimension(self):
        a = analyze_squatting_label("paypa1", "paypal")
        self.assertIn("phonetic", a["dimensions"])
        self.assertEqual(a["damerau_distance"], 0)  # 1 maps back to l

    def test_paypaI_caught_by_edit_dimension(self):
        a = analyze_squatting_label("paypaI", "paypal")
        self.assertEqual(a["damerau_distance"], 1)
        self.assertIn("edit-1", a["dimensions"])

    def test_paypall_caught_on_multiple_dimensions(self):
        a = analyze_squatting_label("paypall", "paypal")
        self.assertIn("edit-1", a["dimensions"])
        self.assertIn("phonetic", a["dimensions"])

    def test_paypal_secure_caught_as_embedded_not_typosquat(self):
        findings = squat_findings("paypal-secure-login.xyz")
        ids = [f[0] for f in findings]
        self.assertIn("SQ-EMBEDDED-BRAND", ids)
        self.assertNotIn("SQ-EDIT-1", ids)

    def test_phonetic_vowel_swap(self):
        self.assertTrue(phonetic_match("paypel", "paypal"))
        self.assertTrue(phonetic_match("paypol", "paypal"))
        self.assertEqual(soundex("paypal"), soundex("paypel"))

    def test_keyboard_neighbour(self):
        self.assertTrue(is_keyboard_neighbour("k", "l"))
        self.assertFalse(is_keyboard_neighbour("k", "z"))
        # paypak: k next to l, so keyboard distance is 0.5, not 1.0
        self.assertEqual(keyboard_distance("paypak", "paypal"), 0.5)
        self.assertEqual(keyboard_distance("paypaz", "paypal"), 1.0)

    def test_legit_paypal_no_squatting_findings(self):
        self.assertEqual(squat_findings("www.paypal.com"), [])


class TestKitFingerprint(unittest.TestCase):
    def test_kit_template_matches_credential_harvest(self):
        fp = fingerprint_kit("https://paypa1.com/login/verify/account")
        self.assertEqual(fp["template"], "KIT-CRED-HARVEST")

    def test_kit_signature_same_kit_different_domain(self):
        # Same path pattern on two domains -> same signature.
        self.assertEqual(
            kit_signature("https://paypa1.com/login/verify/account"),
            kit_signature("https://paypal-secure-login.xyz/login/verify/account"))
        self.assertNotEqual(
            kit_signature("https://paypa1.com/login/verify/account"),
            kit_signature("https://paypa1.com/payment/invoice"))

    def test_normalise_path_pattern_masks_ids(self):
        self.assertEqual(
            normalise_path_pattern("https://x.example/login/9f3a2b7c/verify"),
            "/login/{id}/verify")

    def test_kit_form_brand_mismatch(self):
        r = analyze_kit(
            "https://paypa1.com/login",
            page_title="PayPal - Sign in",
            html_snippet='<form><input type="password" name="password"></form>')
        self.assertIn("KIT-FORM-BRAND-MISMATCH", [f.rule_id for f in r.findings])
        self.assertGreaterEqual(r.score, 60)

    def test_kit_urls_score_high(self):
        lines = [ln.strip() for ln in (ROOT / "samples" / "kit_urls.txt")
                 .read_text().splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
        self.assertEqual(len(lines), 12)
        high = sum(1 for u in lines if analyze_kit(u).score >= 60)
        self.assertGreaterEqual(high, 10, f"only {high}/12 kit URLs >= 60")


class TestBEC(unittest.TestCase):
    def test_bec_phishing_scores_critical(self):
        r = analyze_bec(sample("bec_phishing.txt"), history=HISTORY,
                        target="bec_phishing.txt")
        ids = [f.rule_id for f in r.findings]
        self.assertGreaterEqual(r.score, 60)
        self.assertIn("BEC-FIRST-TIME-SENDER", ids)
        self.assertIn("BEC-THREAD-HIJACK", ids)
        self.assertIn("BEC-AUTH-URGENCY-PAYMENT", ids)

    def test_bec_legit_thread_scores_low(self):
        r = analyze_bec(sample("bec_legit_thread.txt"), history=HISTORY,
                        target="bec_legit_thread.txt")
        self.assertLess(r.score, 30, [f.rule_id for f in r.findings])

    def test_bec_first_time_sender_alone(self):
        # A first-time sender with no other BEC signals is flagged, not critical.
        mail = ("From: New Vendor <vendor@new-supplier.example>\n"
                "To: finance@acmecorp.com\nSubject: Hello\n\n"
                "Hi, please find our catalogue attached. Thanks.")
        r = analyze_bec(mail, history=HISTORY)
        self.assertIn("BEC-FIRST-TIME-SENDER", [f.rule_id for f in r.findings])

    def test_bec_payment_plus_urgency(self):
        mail = ("From: Sarah Chen <sarah.chen@acmecorp.com>\n"
                "To: finance@acmecorp.com\nSubject: Payment today\n\n"
                "Please process the payment urgently today, wire transfer "
                "before end of day. Thanks.")
        r = analyze_bec(mail, history=HISTORY)
        self.assertIn("BEC-TWO-SIGNALS", [f.rule_id for f in r.findings])

    def test_style_deviation_known_sender_different_author(self):
        # Same sender, completely different writing style.
        dev, cos = style_deviation(
            "SEND MONEY NOW URGENT WIRE TRANSFER CONFIDENTIAL CEO",
            HISTORY["sarah.chen@acmecorp.com"])
        self.assertGreater(dev, 0.35)
        self.assertLess(cos, 0.65)

    def test_style_deviation_legit_style_is_low(self):
        body = ("Hi team, please review the Q3 budget summary and the "
                "updated figures for the quarter. I will share the details "
                "in the meeting and we can discuss the plan. Thanks for "
                "the work on the budget and please let me know.")
        dev, cos = style_deviation(body, HISTORY["sarah.chen@acmecorp.com"])
        self.assertLess(dev, 0.35)

    def test_function_word_profile_sums(self):
        prof = function_word_profile("the the please thanks the")
        self.assertAlmostEqual(prof["the"], 0.6)
        self.assertAlmostEqual(prof["please"], 0.2)


class TestV2Combined(unittest.TestCase):
    def test_v2_legit_stays_low(self):
        self.assertLess(analyze_v2_url("https://www.paypal.com/signin").score, 30)
        self.assertLess(analyze_v2_url("https://www.google.com/").score, 30)

    def test_v2_phishing_stays_high(self):
        for url in ("https://paypa1.com/login/verify/account",
                    "https://paypel.com/login/verify/account",
                    "https://paypak.com/login/verify/account"):
            with self.subTest(url=url):
                self.assertGreaterEqual(analyze_v2_url(url).score, 60, url)


if __name__ == "__main__":
    unittest.main()
