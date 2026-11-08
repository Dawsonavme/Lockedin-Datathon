"""Parse the LockedIn CVE data into one CSV with a fixed set of columns.

Output: assets/data/parsed/cve_parsed.csv, one row per CVE, with columns:
  cve_id                       CVE identifier
  cwe_id                       CWE ID(s), separated by ';'
  abstraction                  abstraction of each CWE in cwe_id, in the same order,
                               separated by ';' (blank for categories)
  cvss3_exploitability_score   CVSS 3 exploitability sub-score
  cvss3_impact_score           CVSS 3 impact sub-score

Usage: python src/parse_all.py
"""
from pathlib import Path

import pandas as pd

DATA = Path("F:/LockedIn/assets/data")
OUT = DATA / "parsed" / "cve_parsed.csv"


def split_list(value):
    """Split a ';'-separated field such as cwe_ids into a list. Blank -> []."""
    if pd.isna(value):
        return []
    return [part.strip() for part in str(value).split(";") if part.strip()]


# 1. CVE table: only the columns we need
vulns = pd.read_csv(
    DATA / "vulnerabilities.csv",
    usecols=["cve_id", "cwe_ids", "cvss3_exploitability_score", "cvss3_impact_score"],
    low_memory=False,
)
assert vulns["cve_id"].is_unique, "vulnerabilities.csv has duplicate cve_id values"

for col in ["cvss3_exploitability_score", "cvss3_impact_score"]:
    vulns[col] = pd.to_numeric(vulns[col], errors="coerce")

# 2. CWE abstractions, looked up for each CWE on each CVE
weakness = pd.read_csv(DATA / "weakness_types.csv", usecols=["cwe_id", "abstraction"])
weakness["abstraction"] = weakness["abstraction"].str.strip().str.lower()
abstraction_map = dict(zip(weakness["cwe_id"], weakness["abstraction"].fillna("")))

cwe_lists = vulns["cwe_ids"].apply(split_list)
vulns["abstraction"] = cwe_lists.apply(
    lambda cwes: ";".join(abstraction_map.get(c, "") for c in cwes)
)

# 3. Rename to the names used in the notes and write one file
out = vulns.rename(columns={"cwe_ids": "cwe_id"})[
    ["cve_id", "cwe_id", "abstraction", "cvss3_exploitability_score", "cvss3_impact_score"]
]

OUT.parent.mkdir(parents=True, exist_ok=True)
out.to_csv(OUT, index=False)
print(f"Wrote {len(out):,} rows x {out.shape[1]} columns to {OUT}")
