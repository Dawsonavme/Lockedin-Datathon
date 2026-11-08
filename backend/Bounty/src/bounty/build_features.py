"""Build one feature row per CVE per month of 2025 exploit signals.

Each row is a CVE as of one monthly snapshot, so a bounty score built from it only
uses information that existed at that month (no later exploitation data).

Output: assets/data/parsed/cve_monthly_features.parquet
Usage:  python src/bounty/build_features.py
"""
from pathlib import Path

import pandas as pd

DATA = Path(__file__).resolve().parents[2] / "assets" / "data"
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
        "cvss3_impact_score",
        "cvss3_exploitability_score",
        "attack_vector",
        "privileges_required",
        "user_interaction",
        "scope",
        "cwe_ids",
        "n_affected_cpes",
    ],
    parse_dates=["published"],
    low_memory=False,
)
assert vulns["cve_id"].is_unique, "vulnerabilities.csv has duplicate cve_id values"
for col in ["cvss3_score", "cvss3_impact_score", "cvss3_exploitability_score", "n_affected_cpes"]:
    vulns[col] = pd.to_numeric(vulns[col], errors="coerce")

# Rarity: the first CWE of each CVE, and how rare that CWE is across all CVEs.
# cwe_rarity is 1 for the rarest CWE and close to 0 for the most common one.
vulns["primary_cwe"] = vulns["cwe_ids"].str.split(";").str[0].str.strip()
cwe_counts = vulns["primary_cwe"].value_counts()
rarity = 1 - cwe_counts.rank(method="max", ascending=True, pct=True) + 1 / len(cwe_counts)
vulns["cwe_rarity"] = vulns["primary_cwe"].map(rarity)

weakness = pd.read_csv(DATA / "weakness_types.csv", usecols=["cwe_id", "name", "abstraction"])
weakness["abstraction"] = weakness["abstraction"].str.strip().str.lower().fillna("category")
vulns = vulns.merge(
    weakness.rename(columns={"cwe_id": "primary_cwe", "name": "cwe_name", "abstraction": "cwe_abstraction"}),
    on="primary_cwe",
    how="left",
)

# Ransomware use from CISA's KEV list
kev = pd.read_csv(DATA / "known_exploited.csv", usecols=["cve_id", "known_ransomware_use"])
vulns["ransomware"] = vulns["cve_id"].isin(kev.loc[kev["known_ransomware_use"] == "Known", "cve_id"]).astype(int)

features = signals.merge(vulns, on="cve_id", how="left")

OUT.parent.mkdir(parents=True, exist_ok=True)
features.to_parquet(OUT, index=False)
print(f"Wrote {len(features):,} rows x {features.shape[1]} columns to {OUT}")
