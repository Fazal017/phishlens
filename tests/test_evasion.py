"""Tests for the PhishLens v2 evasion harness.
Run with: python -m unittest discover -s tests -v
All offline and deterministic.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.evasion import EVASION_VARIANTS, generate_evasion_variants, run_evasion_harness  # noqa: E402
from src.v2 import analyze_v2_url  # noqa: E402


class TestEvasionHarness(unittest.TestCase):
    def test_ten_variants_generated(self):
        variants = generate_evasion_variants()
        self.assertEqual(len(variants), 10)
        ids = [v[0] for v in variants]
        self.assertEqual(len(set(ids)), 10)
        for want in ("legit-word-padding", "shortener-redirect",
                     "homoglyph-punycode", "split-brand-subdomains",
                     "at-sign-decoy", "hyphen-stuffing", "redirect-param",
                     "http-long-path", "vowel-swap", "keyboard-typo"):
            self.assertIn(want, ids)

    def test_at_least_nine_of_ten_caught(self):
        report = run_evasion_harness()
        self.assertGreaterEqual(report["caught"], 9,
                                [(c["variant"], c["score"]) for c in report["cases"]])
        self.assertTrue(report["passed"])

    def test_each_variant_individually(self):
        for variant_id, url in generate_evasion_variants():
            with self.subTest(variant=variant_id):
                score = analyze_v2_url(url).score
                # The harness bar is 9/10, so record which (if any) miss.
                self.assertGreaterEqual(score, 60, f"{variant_id}: {url} scored {score}")

    def test_evasion_report_json_written(self):
        out = ROOT / "evasion_report.json"
        report = run_evasion_harness(output_path=str(out))
        self.assertTrue(out.is_file())
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["total"], 10)
        self.assertEqual(data["caught"], report["caught"])
        self.assertIn("cases", data)
        self.assertEqual(len(data["cases"]), 10)
        for case in data["cases"]:
            self.assertIn("variant", case)
            self.assertIn("score", case)
            self.assertIn("caught", case)
            self.assertIn("rules", case)

    def test_evasion_cases_sample_matches_harness(self):
        data = json.loads((ROOT / "samples" / "evasion_cases.json").read_text())
        self.assertEqual(len(data["variants"]), 10)
        harness_ids = {v[0] for v in generate_evasion_variants()}
        sample_ids = {v["id"] for v in data["variants"]}
        self.assertEqual(harness_ids, sample_ids)


if __name__ == "__main__":
    unittest.main()
