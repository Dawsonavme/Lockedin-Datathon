"""Score each CVE-month row with the bounty rules in rules.json.

Each rule adds its points when its condition holds. Rules are data, so you can
change the values without touching this code. The points for each row are capped
at max_points_per_row if the config sets one.

Output: assets/data/parsed/bounty_scores.csv
Usage:  python src/bounty/score.py
"""
import json
import operator
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
FEATURES = Path("F:/LockedIn/assets/data/parsed/cve_monthly_features.parquet")
OUT = Path("F:/LockedIn/assets/data/parsed/bounty_scores.csv")

OPS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}


def load_rules(path=HERE / "rules.json"):
    """Return (rules, cap) from the JSON config. cap is None if not set."""
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    return config["rules"], config.get("max_points_per_row")


def score(features, rules, cap=None):
    """Return a DataFrame with 'points' and 'reasons' for each row of features."""
    if not rules:
        raise ValueError("no rules given")

    points = pd.Series(0, index=features.index, dtype="int64")
    hits = {}
    for rule in rules:
        name = rule["name"]
        field, op, value, pts = rule["field"], rule["op"], rule["value"], rule["points"]
        if op not in OPS:
            raise ValueError(f"{name}: unknown operator {op!r}")
        if field not in features.columns:
            raise KeyError(f"{name}: no column {field!r}")
        if pts < 0:
            raise ValueError(f"{name}: points must be 0 or more")
        # Blank values (NaN) never match, so missing data scores zero for that rule
        hit = OPS[op](features[field], value).astype(bool)
        hits[name] = hit
        points = points + hit.astype("int64") * pts

    if cap is not None:
        points = points.clip(upper=cap)

    hit_frame = pd.DataFrame(hits, index=features.index)
    reasons = hit_frame.apply(
        lambda row: ";".join(name for name, hit in row.items() if hit), axis=1
    )
    return pd.DataFrame({"points": points, "reasons": reasons}, index=features.index)


def main():
    features = pd.read_parquet(FEATURES)
    rules, cap = load_rules()
    scored = score(features, rules, cap)
    out = pd.concat([features[["cve_id", "month"]], scored], axis=1)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT, index=False)
    print(f"Scored {len(out):,} CVE-month rows -> {OUT}")
    print(out["points"].describe().to_string())


if __name__ == "__main__":
    main()
