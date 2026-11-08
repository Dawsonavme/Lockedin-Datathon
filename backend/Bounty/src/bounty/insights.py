"""Summarise the bounty board for the insights page.

Reads the scores (score.py), the monthly features (build_features.py) and Granite's
accuracy check (granite/check_accuracy.py) and writes one small JSON file that the
API serves at /insights.

Output: assets/data/parsed/insights.json
Usage:  python src/bounty/insights.py
"""
import json
from pathlib import Path

import pandas as pd

PARSED = Path(__file__).resolve().parents[2] / "assets" / "data" / "parsed"
OUT = PARSED / "insights.json"
BIN = 50  # points per histogram bar
TOP_BIN = 800  # everything above goes in the last bar


def points_histogram(points):
    capped = points.clip(upper=TOP_BIN) // BIN * BIN
    counts = capped.value_counts().sort_index()
    return [{"from": int(start), "to": None if start >= TOP_BIN else int(start + BIN), "count": int(n)}
            for start, n in counts.items()]


def by_group(board, column):
    total = board["points"].sum()
    groups = board.groupby(column)["points"]
    return [
        {"key": key, "count": int(group.size), "median_points": int(group.median()),
         "share_of_points": round(group.sum() / total, 3)}
        for key, group in sorted(groups, key=lambda kv: -kv[1].sum())
    ]


def accuracy():
    path = PARSED / "granite_accuracy.csv"
    if not path.exists():
        return None
    check = pd.read_csv(path)
    nist_mean = check["nist_impact"].mean()
    answers = check.groupby("damage").agg(count=("cve_id", "size"), nist_impact=("nist_impact", "mean"),
                                          granite_impact=("granite_impact", "mean"))
    return {
        "sample": len(check),
        "granite_error": round((check["granite_impact"] - check["nist_impact"]).abs().mean(), 2),
        "guess_error": round((nist_mean - check["nist_impact"]).abs().mean(), 2),
        # Does a worse Granite answer line up with a worse real score?
        "by_answer": [{"answer": k, "count": int(r["count"]), "nist_impact": round(r["nist_impact"], 2),
                       "granite_impact": round(r["granite_impact"], 2)}
                      for k, r in answers.sort_values("nist_impact", ascending=False).iterrows()],
    }


def main():
    scores = pd.read_csv(PARSED / "bounty_scores.csv")
    month = scores["month"].max()
    board = scores[(scores["month"] == month) & scores["points"].notna()]
    features = pd.read_parquet(PARSED / "cve_monthly_features.parquet", columns=["month", "cve_id", "in_kev"])
    features = features[features["month"].astype(str).str.startswith(month[:7])]
    board = board.merge(features[["cve_id", "in_kev"]], on="cve_id", how="left")
    board["in_kev"] = board["in_kev"].fillna(False).astype(bool)
    unscored = int((scores["month"] == month).sum() - len(board))

    insights = {
        "month": month[:7],
        "bounties": len(board),
        "median_points": int(board["points"].median()),
        "top_points": int(board["points"].max()),
        "granite_labelled": int(board["fix_type"].notna().sum()),
        "granite_scored": int((board["impact_source"] == "granite").sum()),
        "still_unscored": unscored,
        "histogram": points_histogram(board["points"]),
        # Granite's labels, over the CVEs it has labelled so far
        "categories": by_group(board.dropna(subset=["category"]), "category"),
        "fix_types": by_group(board.dropna(subset=["fix_type"]), "fix_type"),
        "kev": {
            "count": int(board["in_kev"].sum()),
            "median_points": int(board.loc[board["in_kev"], "points"].median()),
            "other_median_points": int(board.loc[~board["in_kev"], "points"].median()),
            "share_of_points": round(board.loc[board["in_kev"], "points"].sum() / board["points"].sum(), 3),
        },
        # How strongly each factor moves the final points (correlation, 0 = not at all)
        "factor_influence": {
            factor: round(board["points"].corr(board[factor]), 2)
            for factor in ["severity", "urgency", "difficulty", "rarity"]
        },
        "accuracy": accuracy(),
    }
    OUT.write_text(json.dumps(insights, indent=2))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
