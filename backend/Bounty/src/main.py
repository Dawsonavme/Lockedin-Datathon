import pandas as pd

DATA = "F:/LockedIn/assets/data"

def split_list(s):
    """Split a ';'-separated field like cwe_ids into a clean list. Blank -> []."""
    if pd.isna(s):
        return []
    return [x.strip() for x in str(s).split(";") if x.strip()]

# Known exploited vulnerabilities (CISA KEV), one row per CVE
known_exp = pd.read_csv(f"{DATA}/known_exploited.csv", parse_dates=["date_added", "due_date"])
known_exp["cwe_list"] = known_exp["cwe_ids"].apply(split_list)

# Exploit signals for 2025, one row per CVE per month
exp_signals_25 = pd.read_csv(f"{DATA}/exploit_signals_2025.csv")
exp_signals_25["month"] = pd.to_datetime(exp_signals_25["month"], format="%Y-%m")
exp_signals_25["year"] = exp_signals_25["month"].dt.year  # file is all 2025, so this is just 2025

# CWE list; abstraction is blank for categories, so keep those as NaN
weakness_types = pd.read_csv(f"{DATA}/weakness_types.csv")
weakness_types["abstraction"] = weakness_types["abstraction"].str.strip().str.lower()

# Full NVD table (about 238 MB, so loading takes a while)
vulnerabilities = pd.read_csv(
    f"{DATA}/vulnerabilities.csv",
    parse_dates=["published", "last_modified"],
    low_memory=False,
)
for col in ["cvss3_exploitability_score", "cvss3_impact_score"]:
    vulnerabilities[col] = pd.to_numeric(vulnerabilities[col], errors="coerce")
vulnerabilities["cwe_list"] = vulnerabilities["cwe_ids"].apply(split_list)
vulnerabilities["in_kev"] = vulnerabilities["cve_id"].isin(known_exp["cve_id"])

# One row per CVE-weakness pair, with the weakness name and abstraction attached
cve_weakness = (
    vulnerabilities[["cve_id", "cwe_list"]]
    .explode("cwe_list")
    .rename(columns={"cwe_list": "cwe_id"})
    .merge(weakness_types[["cwe_id", "name", "abstraction"]], on="cwe_id", how="left")
)

print(known_exp.head(5).to_string())
print(vulnerabilities[["cve_id", "cvss3_exploitability_score", "cvss3_impact_score", "in_kev"]].head())
print(cve_weakness.head())

