"""Label CVE descriptions with Granite for the bounty point system.

For each CVE on the bounty board (the CVEs in one month of exploit signals), Granite
reads the NIST description and answers:
  fix      how it gets fixed -> feeds the Difficulty factor
  category what kind of weakness it is -> shown on the card, used for events
  damage   what an attacker can do -> estimates impact when NIST has no CVSS 3 score
           (only asked for those CVEs)

CVEs are labelled hottest first (KEV, then EPSS), and results are appended as they
finish, so the run can be stopped and restarted without losing work.

Output: assets/data/parsed/granite_labels.csv
Usage:  python src/granite/label_cves.py [--month 2025-12] [--limit 1000]
"""
import argparse
import csv
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

from decision import MODEL, decide

DATA = Path(__file__).resolve().parents[2] / "assets" / "data"
OUT = DATA / "parsed" / "granite_labels.csv"
WORKERS = 16
CHUNK = 256

FIX_QUESTION = "How would a defender most likely fix this vulnerability?"
FIX_OPTIONS = {
    "upgrade": "Upgrade to a fixed version or install a vendor patch",
    "code_change": "Change the source code, no fixed version is mentioned",
    "config": "Change a setting or apply a workaround",
    "unclear": "The description does not say",
}

CATEGORY_QUESTION = "Which category best describes this vulnerability?"
CATEGORY_OPTIONS = {
    "injection": "Injection (SQL, command, script or XSS)",
    "memory": "Memory safety (buffer overflow, use after free)",
    "access": "Authentication or access control",
    "other": "Something else",
}

DAMAGE_QUESTION = "What is the worst an attacker can do with this vulnerability?"
DAMAGE_OPTIONS = {
    "control": "Take full control or run their own code",
    "data": "Read or change sensitive data",
    "outage": "Crash the product or make it unavailable",
    "minor": "Something minor, such as leak a little information",
}
# CVSS 3 impact sub-score for each answer, used as a stand-in for the missing score.
# Fitted on 400 board CVEs that NIST has scored; on 200 held-out ones the estimate is
# off by 0.94 on average (always guessing the mean: 1.34), with no overall bias.
DAMAGE_IMPACT = {"control": 5.25, "data": 3.72, "outage": 3.54, "minor": 2.13}

COLUMNS = (
    ["cve_id", "fix_type"] + [f"fix_p_{k}" for k in FIX_OPTIONS]
    + ["category"] + [f"category_p_{k}" for k in CATEGORY_OPTIONS]
    + ["damage"] + [f"damage_p_{k}" for k in DAMAGE_OPTIONS]
    + ["impact_est", "model"]
)


def label(row):
    """Ask Granite the questions for one CVE and return one output row."""
    out = {"cve_id": row.cve_id, "model": MODEL}
    for name, question, options in [
        ("fix", FIX_QUESTION, FIX_OPTIONS),
        ("category", CATEGORY_QUESTION, CATEGORY_OPTIONS),
    ]:
        probs = decide(row.description, question, options)
        column = "fix_type" if name == "fix" else "category"
        out[column] = max(probs, key=probs.get)
        out.update({f"{name}_p_{k}": round(p, 4) for k, p in probs.items()})

    if pd.isna(row.cvss3_impact_score):
        probs = decide(row.description, DAMAGE_QUESTION, DAMAGE_OPTIONS)
        out["damage"] = max(probs, key=probs.get)
        out.update({f"damage_p_{k}": round(p, 4) for k, p in probs.items()})
        # Expected impact over the answers, so an unsure model lands in between
        out["impact_est"] = round(sum(p * DAMAGE_IMPACT[k] for k, p in probs.items()), 2)
    return out


def bounty_board(month):
    """CVEs with signals in the given month, hottest first, with their descriptions."""
    signals = pd.read_csv(DATA / "exploit_signals_2025.csv", usecols=["month", "cve_id", "epss", "in_kev"])
    signals = signals[signals["month"] == month]
    if signals.empty:
        raise SystemExit(f"no exploit signals for month {month}")
    vulns = pd.read_csv(
        DATA / "vulnerabilities.csv",
        usecols=["cve_id", "description", "cvss3_impact_score"],
        low_memory=False,
    )
    vulns["cvss3_impact_score"] = pd.to_numeric(vulns["cvss3_impact_score"], errors="coerce")
    board = signals.merge(vulns, on="cve_id", how="inner").dropna(subset=["description"])
    return board.sort_values(["in_kev", "epss"], ascending=False, na_position="last")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--month", default="2025-12", help="signals month that defines the board (YYYY-MM)")
    parser.add_argument("--limit", type=int, help="label at most this many new CVEs")
    parser.add_argument("--workers", type=int, default=WORKERS, help="requests to send at once")
    args = parser.parse_args()

    board = bounty_board(args.month)
    done = set(pd.read_csv(OUT, usecols=["cve_id"])["cve_id"]) if OUT.exists() else set()
    todo = board[~board["cve_id"].isin(done)]
    if args.limit:
        todo = todo.head(args.limit)
    print(f"{len(board):,} CVEs on the {args.month} board, {len(done):,} already labelled, {len(todo):,} to do")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    new_file = not OUT.exists()
    with open(OUT, "a", newline="", encoding="utf-8") as f, ThreadPoolExecutor(max_workers=args.workers) as pool:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        if new_file:
            writer.writeheader()
        for start in range(0, len(todo), CHUNK):
            chunk = todo.iloc[start:start + CHUNK]
            writer.writerows(pool.map(label, chunk.itertuples(index=False)))
            f.flush()
            print(f"  {min(start + CHUNK, len(todo)):,} / {len(todo):,}")

    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
