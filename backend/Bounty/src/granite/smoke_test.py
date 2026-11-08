import pandas as pd
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")
MODEL = "ibm-granite/granite-switch-4.1-8b"

# 1. Plain chat to confirm the server works
reply = client.chat.completions.create(
    model=MODEL,
    messages=[{"role": "user", "content": "In one sentence, what is CWE-79?"}],
    max_completion_tokens=80,
    temperature=0,
)
print(reply.choices[0].message.content)

# 2. Summarise a few real CVE descriptions
cves = pd.read_csv("assets/data/vulnerabilities.csv", usecols=["cve_id", "description"], nrows=5)
for _, row in cves.iterrows():
    reply = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Summarise in under 15 words:\n{row.description}"}],
        max_completion_tokens=40,
        temperature=0,
    )
    print(row.cve_id, "->", reply.choices[0].message.content)
