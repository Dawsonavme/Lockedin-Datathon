"""Check how well Granite's damage answer estimates CVSS 3 impact.

For CVEs that NIST has scored, ask Granite the same damage question label_cves.py asks
for unscored ones, turn the answer into an impact estimate the same way, and save it
next to NIST's real impact score. insights.py summarises the result.

Output: assets/data/parsed/granite_accuracy.csv
Usage:  python src/granite/check_accuracy.py [--sample 500]
"""
import argparse
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

from label_cves import DAMAGE_IMPACT, DAMAGE_OPTIONS, DAMAGE_QUESTION, DATA, bounty_board
from decision import decide

OUT = DATA / "parsed" / "granite_accuracy.csv"


def estimate(row):
    probs = decide(row.description, DAMAGE_QUESTION, DAMAGE_OPTIONS)
    return {
        "cve_id": row.cve_id,
        "nist_impact": row.cvss3_impact_score,
        "damage": max(probs, key=probs.get),
        "granite_impact": round(sum(p * DAMAGE_IMPACT[k] for k, p in probs.items()), 2),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sample", type=int, default=500, help="how many scored CVEs to check")
    parser.add_argument("--workers", type=int, default=32)
    args = parser.parse_args()

    scored = bounty_board("2025-12").dropna(subset=["cvss3_impact_score"])
    sample = scored.sample(args.sample, random_state=2026)  # not the seed the mapping was fitted on
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(estimate, sample.itertuples(index=False)))
    result = pd.DataFrame(rows)
    result.to_csv(OUT, index=False)

    error = (result["granite_impact"] - result["nist_impact"]).abs().mean()
    baseline = (scored["cvss3_impact_score"].mean() - result["nist_impact"]).abs().mean()
    print(f"Wrote {OUT}: Granite off by {error:.2f} on average, always guessing the mean: {baseline:.2f}")


if __name__ == "__main__":
    main()
