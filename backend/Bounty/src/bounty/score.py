"""Give each CVE-month row a bounty: points = severity x urgency x difficulty x rarity.

  severity    how bad it is: CVSS 3 impact, or Granite's estimate when NIST has none
  urgency     how likely it is to be attacked now: EPSS, exploitability, public
              exploit code, KEV and ransomware use
  difficulty  how hard it is to fix: scope, how many products it hits, and
              Granite's read of how it gets fixed
  rarity      how unusual the weakness is: CWE frequency and abstraction

Weights live in rules.json, so you can tune them without touching this code.
Granite labels come from src/granite/label_cves.py; CVEs it has not labelled yet
fall back to the defaults in rules.json.

Output: assets/data/parsed/bounty_scores.csv
Usage:  python src/bounty/score.py
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
PARSED = HERE.parents[1] / "assets" / "data" / "parsed"
FEATURES = PARSED / "cve_monthly_features.parquet"
LABELS = PARSED / "granite_labels.csv"
OUT = PARSED / "bounty_scores.csv"

REQUIRED = [
    "cvss3_impact_score", "cvss3_exploitability_score", "epss", "in_kev", "ransomware",
    "exploitdb", "metasploit", "nuclei", "poc_github", "scope", "n_affected_cpes",
    "cwe_rarity", "cwe_abstraction",
]


def load_rules(path=HERE / "rules.json"):
    """Return the weights config as a dict."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _num(features, col):
    return pd.to_numeric(features[col], errors="coerce").fillna(0)


def score(features, rules):
    """Return a DataFrame with points and the four factors for each row of features.

    Optional Granite columns: impact_est, fix_p_<type> for each type in rules.
    Rows with no impact score from NIST or Granite get blank points.
    """
    missing = [col for col in REQUIRED if col not in features.columns]
    if missing:
        raise KeyError(f"missing columns: {missing}")

    # Severity
    sev = rules["severity"]
    nvd_impact = pd.to_numeric(features["cvss3_impact_score"], errors="coerce")
    granite_impact = (pd.to_numeric(features["impact_est"], errors="coerce")
                      if "impact_est" in features.columns else pd.Series(np.nan, index=features.index))
    impact = nvd_impact.fillna(granite_impact)
    impact_source = np.where(nvd_impact.notna(), "nvd", np.where(granite_impact.notna(), "granite", ""))
    severity = sev["base"] + sev["per_impact_point"] * impact

    # Urgency
    urg = rules["urgency"]
    urgency = (
        1
        + urg["epss_weight"] * np.sqrt(_num(features, "epss").clip(0, 1))
        + urg["exploitability_weight"] * _num(features, "cvss3_exploitability_score") / 3.9
    )
    for col, weight in urg["exploit_code"].items():
        urgency += weight * _num(features, col)
    urgency *= np.where(_num(features, "in_kev") == 1, urg["kev_multiplier"], 1)
    urgency *= np.where(_num(features, "ransomware") == 1, urg["ransomware_multiplier"], 1)

    # Difficulty: Granite's fix type is weighted by its probabilities
    dif = rules["difficulty"]
    breadth = np.log10(_num(features, "n_affected_cpes") + 1).clip(upper=dif["max_log10_products"])
    fix_cols = {kind: f"fix_p_{kind}" for kind in dif["fix_type"]}
    if all(col in features.columns for col in fix_cols.values()):
        fix_bonus = sum(
            dif["fix_type"][kind] * pd.to_numeric(features[col], errors="coerce")
            for kind, col in fix_cols.items()
        ).where(features[fix_cols["upgrade"]].notna(), dif["fix_type_missing"])
    else:
        fix_bonus = pd.Series(dif["fix_type_missing"], index=features.index)
    difficulty = 1 + dif["scope_changed"] * (features["scope"] == "CHANGED") + dif["per_log10_products"] * breadth + fix_bonus

    # Rarity
    rar = rules["rarity"]
    rarity = (1 + rar["cwe_rarity_weight"] * _num(features, "cwe_rarity")) * (
        features["cwe_abstraction"].map(rar["abstraction"]).fillna(1.0)
    )

    raw = severity * urgency * difficulty * rarity
    step = rules.get("round_to", 1)
    points = (raw / step).round() * step

    return pd.DataFrame({
        "points": points.astype("Int64"),
        "severity": severity.round(1),
        "urgency": pd.Series(urgency, index=features.index).round(3),
        "difficulty": pd.Series(difficulty, index=features.index).round(3),
        "rarity": rarity.round(3),
        "impact_source": impact_source,
    }, index=features.index)


def main():
    features = pd.read_parquet(FEATURES)
    if LABELS.exists():
        labels = pd.read_csv(LABELS).drop(columns=["model"])
        features = features.merge(labels, on="cve_id", how="left")
        print(f"Using Granite labels for {features['fix_type'].notna().sum():,} of {len(features):,} rows")
    else:
        print(f"No {LABELS.name} yet, so Granite factors use the rules.json defaults")

    scored = score(features, load_rules())
    keep = ["cve_id", "month"] + [c for c in ["fix_type", "category"] if c in features.columns]
    out = pd.concat([features[keep], scored], axis=1)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT, index=False)
    print(f"Scored {len(out):,} CVE-month rows -> {OUT}")
    print(out["points"].describe(percentiles=[.25, .5, .75, .9, .99]).to_string())
    print(out["impact_source"].value_counts().to_string())


if __name__ == "__main__":
    main()
