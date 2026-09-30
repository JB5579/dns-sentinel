# DNS Sentinel

**Shadow-mode DNS log triage, built on a Jev-format decision switch.**

Every DNS query on your network gets four typed decisions — `category` (choice),
`suspicion` (score 1–10), `privacy` (noul), `recommend` (log-only / flag-review /
suggest-block) — and every decision lands in an append-only SQLite log with its full
confidence distribution.

**It never blocks anything.** Shadow mode is the product: the tool proposes, a human
approves. (This build doesn't even wire the action path — enforcement is out of scope
until the shadow gate says the switch has earned it.)

## Why

Routers and DNS resolvers already log everything your network asks. Nobody triages it.
This tool answers three questions about each query — *what is it, how suspicious is it,
may it leave the house* — at a median cost measured in hundredths of a cent per thousand
queries, locally, with no cloud dependency if you want none.

## Quick start

```bash
# 1. Shakedown the pipeline with the bundled sample (no model needed)
python3 dns_sentinel.py --logs sample.log --format generic --db sample.db

# 2. Re-read the report any time
python3 dns_sentinel.py --db sample.db --report

# 3. Point it at real logs (Pi-hole example)
python3 dns_sentinel.py --logs "/var/log/pihole.log*" --format pi-hole --db dns.db
```

Formats: `pi-hole`, `adguard` (JSON-lines), `bind`, `generic` (`<ts> <client> <domain>`).

## Engines

| adapter | what | when to use |
|---|---|---|
| `heuristic` | transparent label heuristics, engine-tagged | pipeline shakedown only — its rows are marked `engine='heuristic'` and never count as shadow evidence |
| `laya` | local open-source 420M System-1 runtime (Apache-2.0) | fully local, free, private; wire your port in `run_laya()` |
| `api` | any Jev-compatible HTTP endpoint | when you have a key; set `DNS_SENTINEL_API` + `DNS_SENTINEL_KEY` |

Auto mode: API key present → API; else local; errors **fail safe** — a failed decision
escalates to the human queue, never silently passes.

## The shadow gate (the whole point)

Run in shadow for a representative period, then compare against ground truth:

- the consensus baseline blocklists already on your resolver (the report prints per-engine
  agreement: blocklist-hit rows should be flagged, clean rows should pass), and
- a hand-labeled golden set: export `flag-review` rows, label them yourself, count agreement.

Target: **≥90% agreement** before anyone even discusses letting the switch act.
Synthetic data never counts as evidence. The golden set you accrue is the training set
for the next stage (distill the switch into a small local student).

## Files

- `dns_sentinel.py` — parser, adapters, policy gate, SQLite decision log, report
- `request-template.json` — the switch: four questions with per-option criteria (the rubric IS the product)
- `sample.log` — mixed fixture: normal / infra / telemetry / ads / DGA / lookalike / private

## Honest notes

- **The demo heuristic misses quiet lookalikes by design** — `bankofamerica-login-verify.com`
  sails through it. That's not a bug, it's the sales pitch: transparent heuristics catch
  the loud stuff; a model switch catches the rest. Run it with a real engine and diff.
- Author-reported datapoints that motivated this: median Jev decision ≈ 300 ms, median
  $0.000068/decision. MEASURED on the author's own i3-2350M (2011, 4 threads) with the
  official `laya` package and this 4-question switch: ~5–9 min cold start, **~26–30 s per
  decision warm** — the public ~630 ms figure (i5-5200U) does NOT transfer to this box or
  question shape. Plan sampled/golden-set runs, not full-log passes. Measure your own
  hardware; trust the report, not the hype.
- MEASURED QUALITY, zero-shot: the checkpoint is calibration-inverted on domain strings
  (`www.google.com` → suggest-block at P=0.86; a DGA-style name scored 2.1 of 9). Expect
  the ≥90% shadow gate to FAIL without fine-tuning — that is the point of the golden set,
  and of this tool's human gate. Raw scores are preserved (`suspicion_dist.raw_score`);
  the discrete mapping is provisional nearest-level.
- The `laya` adapter targets the official package (NandhaKishorM/laya, Apache-2.0):
  `python3 -m venv .venv && .venv/bin/pip install torch --index-url
  https://download.pytorch.org/whl/cpu && .venv/bin/pip install laya`, then run
  `.venv/bin/python dns_sentinel.py --adapter laya ...`. (The CPU torch wheel matters:
  the default Linux wheel drags in CUDA, ~10× the disk.)
- This is week-one software. The taxonomy is a starting point; edit
  `request-template.json` and the criteria are versioned in your git history, where rubrics belong.
