"""Ask Granite multiple-choice questions about a CVE with the decision adapter.

The adapter answers with one option label. We read the probability of every label
from the logprobs, so callers get a full distribution instead of a single guess.
Needs the vLLM server from smoke_test.py running on localhost:8000.
"""
import math

from openai import OpenAI
from transformers import AutoTokenizer

MODEL = "ibm-granite/granite-switch-4.1-8b"
LABELS = ["A", "B", "C", "D"]

client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")
tokenizer = AutoTokenizer.from_pretrained(MODEL)
LABEL_IDS = [tokenizer(label, add_special_tokens=False)["input_ids"][0] for label in LABELS]


def decide(state, question, options):
    """Return {option_key: probability} for one question.

    options maps a short key (used in our output columns) to the text the model sees,
    in label order A, B, C, D. Probabilities are renormalised to sum to 1.
    """
    if len(options) != len(LABELS):
        raise ValueError(f"need exactly {len(LABELS)} options, got {len(options)}")
    keys = list(options)
    option_text = "\n".join(f"{label}: {options[key]}" for label, key in zip(LABELS, keys))
    messages = [
        {"role": "user", "content": f"State:\n{state}"},
        {"role": "user", "content": (
            f"### DECISION\nQuestion:\n{question}\n\n"
            f"Options:\n{option_text}\n\nReply with exactly one option label."
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
    raw = [probs.get(label, 0.0) for label in LABELS]
    total = sum(raw) or 1.0
    return {key: p / total for key, p in zip(keys, raw)}
