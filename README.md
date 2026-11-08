# CVE Catcher

A bounty board that turns patching real security vulnerabilities into a game, powered by IBM Granite.

Every CVE on the board is a bounty worth points. Hunters accept a bounty, get the fix applied on the systems they look after, and mark it fixed to climb the leaderboard. IBM Granite reads the CVE descriptions to fill in what the data is missing.

## The question

With hundreds of thousands of known vulnerabilities, which ones should defenders fix first, and can we motivate people to fix them?

## What we did

**A point value for every CVE.** Points are four factors multiplied together, rounded to the nearest 5:

> Points = Severity × Urgency × Difficulty × Rarity

| Factor | Question it answers | Comes from | Range |
| --- | --- | --- | --- |
| Severity (base points) | How bad is an attack? | CVSS 3 impact (50 + 25 × impact), or Granite's estimate when NIST has none | 50 to 200 |
| Urgency | Will it be attacked soon? | EPSS exploit probability, exploitability, public exploit code; ×1.5 on CISA's Known Exploited list, ×1.25 more for ransomware | ×1.0 to ×6.5 |
| Difficulty | How much work is the fix? | Scope, number of affected products, and Granite's fix type | ×1.0 to ×2.3 |
| Rarity | How unusual is the weakness? | How rare its CWE weakness type is | ×1.0 to ×1.45 |

All weights live in [`rules.json`](backend/Bounty/src/bounty/rules.json).

**IBM Granite** (`ibm-granite/granite-switch-4.1-8b`, served with vLLM on our own GPUs) does three jobs:

1. **Fills in severity.** When NIST has no CVSS score, Granite reads the description and answers "what is the worst an attacker can do?" (take control, read or change data, crash it, something minor). The answer becomes an impact estimate.
2. **Labels each CVE** with how it gets fixed (upgrade, code change, config change, unclear) and its weakness type (injection, memory safety, access control, other). The fix type feeds Difficulty; the category drives the filters and the weekly challenge themes.
3. **Explains it in plain words.** On any bounty page, "Explain this CVE" returns what's broken, who's affected and how to fix it. Answers are saved, so each CVE costs one Granite call.

The labels use Granite's decision adapter: we ask a multiple-choice question and read the probability of every option from the logprobs, so an unsure answer lands in between instead of guessing.

**The game.** A Django API and SvelteKit website with the bounty board (search, filters, sorting), a daily challenge (×1.5), a themed weekly challenge (×1.25), sponsors who add points to bounties, a leaderboard, and an Insights page with the findings below.

## What we found

All numbers are from the December 2025 board (305,346 bounties).

- **24% of CVEs had no NIST severity score**, so they would have been worth nothing. Granite's estimates put **72,742** of them on the board.
- **Granite's estimates hold up.** On 500 CVEs that NIST *had* scored, Granite's impact estimate was off by **1.11** on average (0 to 6 scale), versus **1.38** for always guessing the average: about 20% better. Its answers rank in the right order: CVEs it says let an attacker "take full control" have the highest real NIST impact (4.69), and "something minor" the lowest (3.23).
- **Exploited CVEs pay about 3× more:** a median of 955 points for the 1,479 CVEs on CISA's Known Exploited list, versus 290 for the rest.
- **Urgency and severity drive the score** (correlation with points 0.72 and 0.63), then rarity (0.25) and difficulty (0.13).
- The top bounty is **Log4Shell (CVE-2021-44228) at 2,520 points.**

## How it fits together

```
Datathon data ──► build_features.py ──► Granite labels ──► score.py ──► load_bounties ──► Django API + database ◄──► Website
                                        (label_cves.py)                                         │
                                                                                                └──► Granite explains (live)
```

| Folder | What's in it |
| --- | --- |
| [`backend/Bounty/src/bounty`](backend/Bounty/src/bounty) | Feature building, scoring, insights |
| [`backend/Bounty/src/granite`](backend/Bounty/src/granite) | Granite labelling and the accuracy check |
| [`backend/api`](backend/api) | Django API, game logic, challenges, explanations |
| [`frontend/cve-catcher-frontend`](frontend/cve-catcher-frontend) | SvelteKit website |

## Running it

`backend/api/database.db` is in Git LFS and already holds the full board and the saved Granite explanations, so `git lfs install` before cloning and the app runs without rebuilding anything.

**1. Granite** (needs a GPU; we used 2× NVIDIA A16 with vLLM 0.26):

```bash
python -m vllm.entrypoints.openai.api_server --model ibm-granite/granite-switch-4.1-8b \
  --host 127.0.0.1 --port 8000 --tensor-parallel-size 2 --max-model-len 4096 --gpu-memory-utilization 0.82
```

Without Granite the site still works; only the Explain button shows "Granite isn't available".

**2. API** (Python 3.12):

```bash
cd backend/api
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 127.0.0.1:8001
```

**3. Website** (Node 22+):

```bash
cd frontend/cve-catcher-frontend
npm install
npm run dev -- --port 5173
```

Open http://localhost:5173. The website calls the API at `/api`, which the dev server forwards to port 8001.

**Rebuilding the board from the raw data** (optional; needs `vllm pandas pyarrow openai transformers`):

```bash
cd backend/Bounty
python src/bounty/build_features.py
python src/granite/label_cves.py --limit 1000      # Granite labels, resumable
python src/bounty/score.py
python src/granite/check_accuracy.py              # Granite vs NIST on 500 scored CVEs
python src/bounty/insights.py
cd ../api && python manage.py load_bounties && python manage.py explain_bounties
```

## Limits and next steps

- "Mark as fixed" is on the honor system. Next: hunters submit a link to their patch, Granite checks it fits the CVE, and a sponsor approves.
- The board covers one month of the datathon dataset. Next: pull new CVEs from NIST's feed and label each with Granite as it arrives.
- Points are fixed for the month. Next: bounties that rise as a CVE's exploit probability climbs.
- Granite only rephrases NIST's description, so it can repeat its mistakes; the original text is always shown beside the explanation.
