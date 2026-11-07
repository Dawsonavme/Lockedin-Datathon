"""Tests for the bounty scoring. Run from the project root:

    python -m unittest discover -s src/bounty -p "test_*.py"
"""
import sys
import unittest
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import score  # noqa: E402

RULES = [
    {"name": "in_kev", "field": "in_kev", "op": "==", "value": 1, "points": 50},
    {"name": "epss_high", "field": "epss", "op": ">=", "value": 0.5, "points": 20},
]


class ScoreTests(unittest.TestCase):
    def test_points_add_up(self):
        df = pd.DataFrame({"in_kev": [1, 0, 1], "epss": [0.6, 0.6, 0.1]})
        out = score(df, RULES)
        self.assertEqual(out["points"].tolist(), [70, 20, 50])

    def test_reasons_list_the_rules_that_matched(self):
        df = pd.DataFrame({"in_kev": [1, 0], "epss": [0.6, 0.1]})
        out = score(df, RULES)
        self.assertEqual(out["reasons"].tolist(), ["in_kev;epss_high", ""])

    def test_missing_values_never_match(self):
        df = pd.DataFrame({"in_kev": [1], "epss": [float("nan")]})
        out = score(df, RULES)
        self.assertEqual(out["points"].tolist(), [50])

    def test_cap_limits_points(self):
        df = pd.DataFrame({"in_kev": [1], "epss": [0.9]})
        out = score(df, RULES, cap=60)
        self.assertEqual(out["points"].tolist(), [60])

    def test_unknown_operator_is_rejected(self):
        bad = [{"name": "x", "field": "in_kev", "op": "~~", "value": 1, "points": 1}]
        with self.assertRaises(ValueError):
            score(pd.DataFrame({"in_kev": [1]}), bad)

    def test_missing_column_is_rejected(self):
        bad = [{"name": "x", "field": "nope", "op": "==", "value": 1, "points": 1}]
        with self.assertRaises(KeyError):
            score(pd.DataFrame({"in_kev": [1]}), bad)

    def test_negative_points_are_rejected(self):
        bad = [{"name": "x", "field": "in_kev", "op": "==", "value": 1, "points": -5}]
        with self.assertRaises(ValueError):
            score(pd.DataFrame({"in_kev": [1]}), bad)


if __name__ == "__main__":
    unittest.main()
