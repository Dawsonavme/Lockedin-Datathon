"""Plain-language CVE explanations written by Granite.

Granite reads the NIST description and answers in three labelled lines (what's broken,
who's affected, how to fix). The first answer is saved on the CVE, so each CVE costs
one Granite call and later visits load instantly, even if the Granite server is down.
Needs the vLLM server from backend/Bounty (GRANITE_URL, default localhost:8000).
"""
import json
import os
import urllib.request

GRANITE_URL = os.environ.get('GRANITE_URL', 'http://localhost:8000/v1')
MODEL = 'ibm-granite/granite-switch-4.1-8b'
TIMEOUT = 60  # seconds; a typical answer takes 5-10


class GraniteUnavailable(Exception):
    pass


def prompt(cve):
    name = f' ({cve.Name})' if cve.Name else ''
    return (
        f'{cve.Cve_Id}{name}\nWeakness: {cve.Cwe_Name or "unknown"}\nNIST description:\n{cve.Description}\n\n'
        'Explain this vulnerability to a developer who is new to security. Answer in exactly three lines, '
        'each under 40 words, starting with these labels:\n'
        "What's broken: ...\nWho's affected: ...\nHow to fix: ...\n"
        "Only use facts from the description. If it does not say how to fix it, say to check the vendor's advisory."
    )


def ask_granite(cve):
    """Granite's three-line explanation of one CVE, as plain text."""
    body = {
        'model': MODEL,
        'messages': [{'role': 'user', 'content': prompt(cve)}],
        'max_tokens': 250,
        'temperature': 0,
    }
    request = urllib.request.Request(
        f'{GRANITE_URL}/chat/completions', json.dumps(body).encode(), {'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            answer = json.load(response)
    except (OSError, ValueError) as e:  # connection refused, timeout, bad JSON
        raise GraniteUnavailable(str(e)) from e
    return answer['choices'][0]['message']['content'].strip()


def explanation(cve):
    """The saved explanation, asking Granite for one the first time."""
    if not cve.Explanation:
        cve.Explanation = ask_granite(cve)
        cve.save(update_fields=['Explanation'])
    return cve.Explanation
