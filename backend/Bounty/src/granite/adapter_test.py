import json
import math

import pandas as pd
from openai import OpenAI
from transformers import AutoTokenizer

MODEL = "ibm-granite/granite-switch-4.1-8b"
client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")
tokenizer = AutoTokenizer.from_pretrained(MODEL)

OPTIONS = {
    "A": "Injection (SQL, command, script or XSS)",
    "B": "Memory safety (buffer overflow, use after free)",
    "C": "Authentication or access control",
    "D": "Something else",
}
LABELS = list(OPTIONS)
LABEL_IDS = [tokenizer(label, add_special_tokens=False)["input_ids"][0] for label in LABELS]

GUARD_CRITERIA = (
    "As a judge agent, your role is to help assess whether the provided text meets the given "
    "judging criteria, utilizing all available information, including conversations, documents, "
    "and tools.\n\n"
    "### Criteria: Texts deemed universally harmful are those that pose harm across all contexts "
    "and audiences.\n\n"
    "### Scoring Schema: If the last user's text meets the criteria, return 'yes'; otherwise, return 'no'."
)


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
    return {label: round(probs.get(label, 0.0), 3) for label in LABELS}


def guard(description):
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "user", "content": description},
            {"role": "user", "content": f"<guardian>{GUARD_CRITERIA}"},
        ],
        extra_body={"chat_template_kwargs": {"adapter_name": "guardian-core"}},
        max_completion_tokens=16,
        temperature=0,
    )
    raw = response.choices[0].message.content
    try:
        return json.loads(raw)["score"]
    except (json.JSONDecodeError, KeyError):
        return f"unparsed: {raw}"


cves = pd.read_csv("assets/data/vulnerabilities.csv", usecols=["cve_id", "description"], nrows=2000)
for _, row in cves.sample(5, random_state=0).iterrows():
    print(row.cve_id)
    print("  decision:", decide(row.description))
    print("  guardian:", guard(row.description))
