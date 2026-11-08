"""Check how often the Granite decision adapter agrees with CWE-based labels.

Ground truth: the first CWE of each CVE, mapped to one of four categories.
CWEs not in the map count as D (something else).
"""
import math
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
from openai import OpenAI
from transformers import AutoTokenizer

MODEL = "ibm-granite/granite-switch-4.1-8b"
SAMPLE_PER_CLASS = 100
WORKERS = 8
OUT = "assets/data/parsed/adapter_agreement.csv"

OPTIONS = {
    "A": "Injection (SQL, command, script or XSS)",
    "B": "Memory safety (buffer overflow, use after free)",
    "C": "Authentication or access control",
    "D": "Something else",
}
LABELS = list(OPTIONS)

CWE_TO_CATEGORY = {
    # A: injection
    "CWE-79": "A", "CWE-89": "A", "CWE-77": "A", "CWE-78": "A", "CWE-94": "A", "CWE-74": "A",
    # B: memory safety
    "CWE-119": "B", "CWE-120": "B", "CWE-121": "B", "CWE-122": "B", "CWE-125": "B",
    "CWE-787": "B", "CWE-416": "B", "CWE-415": "B",
    # C: authentication and access control
    "CWE-287": "C", "CWE-284": "C", "CWE-285": "C", "CWE-306": "C", "CWE-862": "C",
    "CWE-863": "C", "CWE-798": "C", "CWE-269": "C", "CWE-522": "C",
}

client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")
tokenizer = AutoTokenizer.from_pretrained(MODEL)
LABEL_IDS = [tokenizer(label, add_special_tokens=False)["input_ids"][0] for label in LABELS]


def decide(description):
    options = "\n".join(f"{k}: {v}" for k, v in OPTIONS.items())
    messages = [
        {"role": "user", "content": f"State:\n{description}"},
        {"role": "user", "content": (
            "### DECISION\nQuestion:\nWhich category best describes this vulnerability?\n\n"
            f"Options:\n{options}\n\nReply with exactly one option label."
        )},
    ]
    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        extra_body={
            "chat_template_kwargs": {"adapter_name": "decision"},
            "logprob_token_ids": LABEL_IDS,
        },
        max_completion_tokens=1,
        logprobs=True,
        top_logprobs=1,
        temperature=0,
    )
    top = response.choices[0].logprobs.content[0].top_logprobs
    probs = {t.token.strip(): math.exp(t.logprob) for t in top}
    return {label: probs.get(label, 0.0) for label in LABELS}


# Ground truth from the data
cves = pd.read_csv("assets/data/vulnerabilities.csv", usecols=["cve_id", "description", "cwe_ids"], low_memory=False)
cves = cves.dropna(subset=["description", "cwe_ids"])
cves["primary_cwe"] = cves["cwe_ids"].str.split(";").str[0].str.strip()
cves = cves[cves["primary_cwe"].str.startswith("CWE-")]  # drops NVD-CWE-noinfo and NVD-CWE-Other
cves["label"] = cves["primary_cwe"].map(CWE_TO_CATEGORY).fillna("D")

sample = pd.concat(
    group.sample(min(len(group), SAMPLE_PER_CLASS), random_state=0)
    for _, group in cves.groupby("label")
).reset_index(drop=True)
print("Sample size by label:")
print(sample["label"].value_counts().to_string())

with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    results = list(pool.map(decide, sample["description"]))

for label in LABELS:
    sample[f"p_{label}"] = [r[label] for r in results]
sample["predicted"] = [max(r, key=r.get) for r in results]
sample["correct"] = sample["predicted"] == sample["label"]

print(f"\nOverall agreement: {sample['correct'].mean():.1%}")
print("\nAgreement by label:")
print(sample.groupby("label")["correct"].mean().round(3).to_string())
print("\nConfusion matrix (rows = CWE label, columns = adapter prediction):")
print(pd.crosstab(sample["label"], sample["predicted"]).to_string())

sample.drop(columns=["description", "cwe_ids", "primary_cwe"]).to_csv(OUT, index=False)
print(f"\nWrote {OUT}")
