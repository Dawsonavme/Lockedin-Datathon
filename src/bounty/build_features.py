"""Build one feature row per CVE per month of 2025 exploit signals.

Each row is a CVE as of one monthly snapshot, so a bounty score built from it only
uses information that existed at that month (no later exploitation data).

Output: assets/data/parsed/cve_monthly_features.parquet
Usage:  python src/bounty/build_features.py
"""
from pathlib import Path

import pandas as pd

DATA = Path("F:/LockedIn/assets/data")
OUT = DATA / "parsed" / "cve_monthly_features.parquet"

# Monthly signals: one row per CVE per month
signals = pd.read_csv(DATA / "exploit_signals_2025.csv")
signals["month"] = pd.to_datetime(signals["month"], format="%Y-%m")
assert not signals.duplicated(["cve_id", "month"]).any(), "duplicate cve_id/month rows"

# Static CVE facts from the NVD table
vulns = pd.read_csv(
    DATA / "vulnerabilities.csv",
    usecols=[
        "cve_id",
        "published",
        "cvss3_score",
        "cvss3_severity",
        "attack_vector",
        "privileges_required",
        "user_interaction",
        "cwe_ids",
    ],
    parse_dates=["published"],
    low_memory=False,
)
assert vulns["cve_id"].is_unique, "vulnerabilities.csv has duplicate cve_id values"
vulns["cvss3_score"] = pd.to_numeric(vulns["cvss3_score"], errors="coerce")

features = signals.merge(vulns, on="cve_id", how="left")

OUT.parent.mkdir(parents=True, exist_ok=True)
features.to_parquet(OUT, index=False)
print(f"Wrote {len(features):,} rows x {features.shape[1]} columns to {OUT}")
