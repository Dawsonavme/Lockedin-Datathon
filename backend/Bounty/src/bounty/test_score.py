"""Tests for the bounty scoring. Run from the project root:

    python -m unittest discover -s src/bounty -p "test_*.py"
"""
import sys
import unittest
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import load_rules, score  # noqa: E402

# Small, round weights so expected values are easy to work out by hand
RULES = {
    "round_to": 1,
    "severity": {"base": 50, "per_impact_point": 25},
    "urgency": {
        "epss_weight": 1.0,
        "exploitability_weight": 0.0,
        "exploit_code": {"metasploit": 0.5},
        "kev_multiplier": 2.0,
        "ransomware_multiplier": 1.5,
    },
    "difficulty": {
        "scope_changed": 0.5,
        "per_log10_products": 0.0,
        "max_log10_products": 3,
        "fix_type": {"upgrade": 0.0, "config": 0.0, "code_change": 1.0, "unclear": 0.0},
        "fix_type_missing": 0.25,
    },
    "rarity": {"cwe_rarity_weight": 0.0, "abstraction": {"variant": 2.0}},
}


def row(**overrides):
    """One feature row with everything neutral: severity 100, all factors 1."""
    base = {
        "cvss3_impact_score": 2.0, "cvss3_exploitability_score": 0.0, "epss": 0.0,
        "in_kev": 0, "ransomware": 0, "exploitdb": 0, "metasploit": 0, "nuclei": 0,
        "poc_github": 0, "scope": "UNCHANGED", "n_affected_cpes": 0,
        "cwe_rarity": 0.0, "cwe_abstraction": "base",
        "fix_p_upgrade": 1.0, "fix_p_config": 0.0, "fix_p_code_change": 0.0, "fix_p_unclear": 0.0,
    }
    base.update(overrides)
    return base


def points(*rows):
    return score(pd.DataFrame(list(rows)), RULES)["points"].tolist()


class ScoreTests(unittest.TestCase):
    def test_neutral_row_scores_severity_only(self):
        self.assertEqual(points(row()), [100])

    def test_factors_multiply(self):
        # urgency (1 + 0.5 metasploit) x 2 KEV = 3; difficulty 1.5; rarity 2 -> 100 x 3 x 1.5 x 2
        hot = row(metasploit=1, in_kev=1, scope="CHANGED", cwe_abstraction="variant")
        self.assertEqual(points(hot), [900])

    def test_epss_uses_square_root(self):
        self.assertEqual(points(row(epss=0.25)), [150])

    def test_ransomware_multiplies_urgency(self):
        self.assertEqual(points(row(ransomware=1)), [150])

    def test_granite_fix_type_is_probability_weighted(self):
        unsure = row(fix_p_upgrade=0.5, fix_p_code_change=0.5)
        self.assertEqual(points(unsure), [150])

    def test_unlabelled_rows_use_missing_default(self):
        unlabelled = row(fix_p_upgrade=None, fix_p_config=None, fix_p_code_change=None, fix_p_unclear=None)
        self.assertEqual(points(unlabelled), [125])

    def test_no_granite_columns_uses_missing_default(self):
        df = pd.DataFrame([row()]).drop(columns=[c for c in row() if c.startswith("fix_p_")])
        self.assertEqual(score(df, RULES)["points"].tolist(), [125])

    def test_granite_impact_fills_missing_cvss(self):
        out = score(pd.DataFrame([row(cvss3_impact_score=None, impact_est=4.0)]), RULES)
        self.assertEqual(out["points"].tolist(), [150])
        self.assertEqual(out["impact_source"].tolist(), ["granite"])

    def test_nvd_impact_wins_over_granite(self):
        out = score(pd.DataFrame([row(impact_est=6.0)]), RULES)
        self.assertEqual(out["points"].tolist(), [100])
        self.assertEqual(out["impact_source"].tolist(), ["nvd"])

    def test_no_impact_anywhere_gives_blank_points(self):
        out = score(pd.DataFrame([row(cvss3_impact_score=None)]), RULES)
        self.assertTrue(pd.isna(out["points"].iloc[0]))

    def test_points_round_to_step(self):
        rules = {**RULES, "round_to": 5}
        out = score(pd.DataFrame([row(cvss3_impact_score=2.1)]), rules)  # 102.5
        self.assertEqual(out["points"].iloc[0] % 5, 0)

    def test_missing_column_is_rejected(self):
        with self.assertRaises(KeyError):
            score(pd.DataFrame([row()]).drop(columns=["epss"]), RULES)

    def test_shipped_rules_load_and_score(self):
        out = score(pd.DataFrame([row()]), load_rules())
        self.assertGreater(out["points"].iloc[0], 0)


if __name__ == "__main__":
    unittest.main()
