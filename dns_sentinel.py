#!/usr/bin/env python3
"""
DNS Sentinel — shadow-mode DNS log triage switch (Phase 0 artifact).

Reads DNS query logs from the household network (Pi-hole / AdGuard / BIND / generic
syslog), classifies each query through a Jev-format decision switch (4 questions:
category, suspicion, privacy, recommend), and writes every decision to an append-only
SQLite log with full confidence distributions. SHADOW MODE: this tool never blocks,
reroutes, or enforces anything. It is a student driver with the instructor seated.
Human approval is the only path to action, and this build doesn't even wire the action.

Runtime adapters (pick with --adapter, default: auto):
  api    POSTs the switch request to a Jev-compatible HTTP endpoint.
         Env: DNS_SENTINEL_API (base URL), DNS_SENTINEL_KEY (bearer).
  laya   Local open-source 420M System-1 runtime (Apache-2.0). Tries `import laya`;
         if the installed package differs, wire it inside run_laya() — one function,
         clearly marked.
  heuristic  No model: transparent label heuristics, LABELED engine='heuristic' in the
         log so its rows can never be mistaken for model output. For pipeline shakedown
         only — heuristic rows never count as shadow evidence.

Usage:
  python3 dns_sentinel.py --logs "/var/log/pihole.log*" --format pi-hole
  python3 dns_sentinel.py --logs sample.log --format generic --db dns.db
  python3 dns_sentinel.py --db dns.db --report
"""

import argparse
import glob
import hashlib
import json
import math
import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.join(HERE, "request-template.json")

# Consensus ad/telemetry blocklist substrings — the BASELINE the shadow run is graded
# against. Deliberately small and uncontroversial; this is the "existing blocklist."
BASELINE_LISTS = [
    "doubleclick.net", "googlesyndication.com", "google-analytics.com",
    "googletagmanager.com", "adsrvr.org", "scorecardresearch.com", "hotjar.com",
    "crashlytics.com", "app-measurement.com", "telemetry.microsoft.com",
    "sentry.io", "graph.facebook.com",
]

CATEGORIES = ["infrastructure", "normal-usage", "telemetry", "advertising", "suspicious"]
RECOMMENDATIONS = ["log-only", "flag-review", "suggest-block"]

# ---------------------------------------------------------------- log parsing

def parse_line(line, fmt):
    """Return dict(query=..., client=..., ts=...) or None. Three formats, honestly named."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if fmt == "pi-hole":
        # Pi-hole pihole.log: "Sep 24 03:14:07 dnsmasq[123]: query[A] x.com from 192.168.1.5"
        if " query[" in line and " from " in line:
            try:
                head, rest = line.split("dnsmasq", 1)
                body = rest.split(":", 1)[1].strip()          # "query[A] dom from client"
                spec = body.split("query", 1)[1].strip()      # "[A] dom from client"
                qtype, dom_client = spec.lstrip("[").split("]", 1)  # "A", "dom from client"
                domain, client = dom_client.strip().split(" from ", 1)
                ts = " ".join(head.split()[:3])
                return {"query": domain.strip(), "client": client.strip(),
                        "ts": ts, "qtype": qtype}
            except (ValueError, IndexError):
                return None
        return None
    if fmt == "adguard":
        # AdGuard Home query log JSON lines
        try:
            j = json.loads(line)
            return {"query": j.get("domain", ""), "client": j.get("client", ""),
                    "ts": str(j.get("time", "")), "qtype": j.get("type", "")}
        except json.JSONDecodeError:
            return None
    if fmt == "bind":
        # BIND query log: "24-Sep-2026 03:14:07.123 queries: client@0x7f 192.168.1.5#54321 (x.com): query: x.com IN A +"
        if " query: " in line:
            try:
                dom = line.split(" query: ", 1)[1].split()[0]
                client = ""
                if "client@" in line:
                    seg = line.split("client@", 1)[1]
                    client = seg.split("#", 1)[0].split()[-1]
                ts = " ".join(line.split()[:2])
                return {"query": dom.rstrip("."), "client": client, "ts": ts, "qtype": ""}
            except (ValueError, IndexError):
                return None
        return None
    # generic: "ISO8601 client query" or just "query" per line
    parts = line.split()
    if not parts:
        return None
    if len(parts) >= 3:
        return {"query": parts[-1], "client": parts[-2], "ts": " ".join(parts[:-2]), "qtype": ""}
    return {"query": parts[-1], "client": "", "ts": "", "qtype": ""}

def collect_logs(patterns, fmt, limit):
    rows = []
    for pat in patterns:
        for path in glob.glob(pat) if any(c in pat for c in "*?[") else [pat]:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        r = parse_line(line, fmt)
                        if r and r["query"]:
                            rows.append(r)
                            if limit and len(rows) >= limit:
                                return rows
            except OSError as e:
                print(f"warn: cannot read {path}: {e}", file=sys.stderr)
    return rows

# ---------------------------------------------------------------- state build

def parent_domain(domain):
    parts = domain.rstrip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()

def label_entropy(domain):
    """Transparent, boring entropy-ish score for the DEMO adapter only."""
    label = domain.split(".")[0]
    if not label:
        return 0.0
    vowels = sum(c in "aeiou" for c in label)
    distinct = len(set(label))
    return round((distinct / len(label)) * 0.5 + (1 - vowels / len(label)) * 0.5, 3)

def baseline_flags(domain):
    d = domain.lower()
    return sorted({b for b in BASELINE_LISTS if b in d or d.endswith("." + b) or d == b})

def build_state(q, repeat_counts):
    dom = q["query"].rstrip(".")
    hits = baseline_flags(dom)
    return {
        "timestamp": q.get("ts") or datetime.now(timezone.utc).isoformat(),
        "client": q.get("client", ""),
        "query": dom.lower(),
        "query_type": q.get("qtype", ""),
        "parent_domain": parent_domain(dom),
        "blocklist_hits": hits,
        "repeat_count_24h": repeat_counts.get(dom.lower(), 1),
    }

# ---------------------------------------------------------------- adapters

def load_template():
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        return json.load(f)

def run_api(state, template, api_base, api_key):
    """POST to a Jev-compatible endpoint. Returns (answers, engine_tag).
    Defensive parsing: the happy-path response shape is documented but our own
    live validation died on a 402, so treat any unexpected shape as a failure and
    fail SAFE (escalate) rather than guess."""
    req = {"state": state, "questions": template["questions"]}
    body = json.dumps(req).encode()
    r = urllib.request.Request(
        api_base.rstrip("/") + "/decisions", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            payload = json.loads(resp.read().decode())
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"}, "api-error"
    answers = {}
    raw = payload.get("answers", payload.get("decisions", payload))
    for qname in template["questions"]:
        a = raw.get(qname, {}) if isinstance(raw, dict) else {}
        val = a.get("value", a.get("choice", a.get("score", a.get("answer"))))
        dist = a.get("probabilities", a.get("distribution", a.get("confidence")))
        if val is None:
            return {"_error": f"missing answer for {qname}"}, "api-parse-error"
        answers[qname] = {"value": val, "distribution": dist}
    return answers, "api"

def map_score_answer(spec, ans):
    """Score semantics (confirmed vs TypeSafe SDK response shape + the ZazenCodes
    walkthrough, Sept 25): the returned score is a 0-INDEXED position into the
    ordered options, and the response carries a `legend` dict mapping the index
    to the label text. Raw values can be continuous (calibrated soft score).
    Map by nearest index, resolve the label via legend when present, preserve raw."""
    raw = float(ans.get("score", 0.0))
    opts = list(spec.get("options", []))
    legend = ans.get("legend") or {}
    if opts:
        idx = max(0, min(len(opts) - 1, int(round(raw))))
        return {"value": opts[idx], "raw_score": raw, "index": idx,
                "label": legend.get(str(idx)),
                "probabilities": ans.get("probabilities")}
    return {"value": raw, "raw_score": raw, "index": None,
            "label": None, "probabilities": ans.get("probabilities")}

def run_laya(state, template):
    """Local Laya runtime via the official `laya` package (NandhaKishorM/laya,
    Apache-2.0; pip install laya, Python 3.10+; CPU path documented, laya[onnx]
    optional). Router API: router.predict(state, questions) -> {"answers":
    {qname: {"choice"/"score"/"noul": ...}}}. The Router is created once and
    reused — checkpoint preload is the expensive part (MEASURED ~5-9 min cold on this
    box; keep ONE process alive for a whole run), each call after
    is one forward pass (MEASURED ~26-30 s/decision warm on the i3-2350M; the public
    ~630 ms i5-5200U datapoint does NOT transfer). Per-row calls keep this simple; predict()
    also accepts a LIST of states if you need throughput later.
    The state is flattened to one readable line: the model is an encoder, not
    a chat model — feed it text, keep the structured original in the DB."""
    try:
        from laya import Router
    except ImportError:
        return {"_error": "laya not installed — create a venv, pip install laya "
                          "(see README Engines table)"}, "laya-missing"
    try:
        router = run_laya._router
    except AttributeError:
        router = run_laya._router = Router()
    try:
        flat = "; ".join(f"{k}={state[k]}" for k in sorted(state))
        result = router.predict(flat, template["questions"])
        answers = {}
        for qname, spec in template["questions"].items():
            ans = result["answers"][qname]
            if spec["type"] == "noul":
                p = float(ans.get("noul", ans.get("probability", 0.0)))
                value = "yes" if p >= 0.5 else "no"   # yes == private (template criteria)
                dist = {"P(yes)": round(p, 4)}
            elif spec["type"] == "score":
                # 0-indexed into options; legend resolves the label. See
                # map_score_answer() — unit-tested, not model-dependent.
                m = map_score_answer(spec, ans)
                value = m["value"]
                dist = {"raw_score": m["raw_score"], "index": m["index"],
                        "label": m["label"], "probabilities": m["probabilities"]}
            else:
                value = ans.get("choice", ans.get("value"))
                dist = ans.get("probabilities", ans.get("distribution"))
            if value is None:
                return {"_error": f"no value returned for {qname}"}, "laya-parse-error"
            answers[qname] = {"value": value, "distribution": dist}
        return answers, "laya"
    except Exception as e:  # never let one bad row kill the batch
        return {"_error": f"{type(e).__name__}: {e}"}, "laya-error"

def run_heuristic(state):
    """Demo-only. Engine-tagged so its rows are identifiable and excludable."""
    dom = state["query"]
    hits = state["blocklist_hits"]
    ent = label_entropy(dom)
    if any(k in dom for k in ("telemetry", "crash", "metrics", "analytics")) and not hits:
        cat, sus = "telemetry", 3
    elif hits and ent > 0.55:
        cat, sus = "suspicious", 7
    elif hits:
        cat, sus = "advertising", 5
    elif ent > 0.7 and (len(dom) > 24 or state["repeat_count_24h"] > 3
                        or dom.endswith((".xyz", ".top", ".live", ".click"))):
        cat, sus = "suspicious", 7
    elif any(k in dom for k in ("cdn", "gstatic", "cloudfront", "akamai", "apple.com",
                                "microsoft.com", "google.com", "ntppool")):
        cat, sus = "infrastructure", 1
    else:
        cat, sus = "normal-usage", 3
    if sus >= 9:
        rec = "suggest-block"
    elif sus >= 7:
        rec = "flag-review"
    else:
        rec = "log-only"
    return {
        "category": {"value": cat, "distribution": None},
        "suspicion": {"value": sus, "distribution": None},
        "privacy": {"value": "not-private", "distribution": None},
        "recommend": {"value": rec, "distribution": None},
    }, "heuristic"

# ---------------------------------------------------------------- policy + store

def apply_policy(answers):
    """The gate: model recommendation IN, final recommendation OUT. A human (or a
    future approval workflow) may approve/suppress/override — nothing bypasses it."""
    rec = str(answers.get("recommend", {}).get("value", ""))
    if rec not in RECOMMENDATIONS:
        rec = "flag-review"  # fail safe: unknown output -> human queue
    sus = answers.get("suspicion", {}).get("value")
    try:
        sus = int(sus)
    except (TypeError, ValueError):
        sus = None
    if sus is not None and sus >= 9 and rec == "log-only":
        rec = "flag-review"  # policy floor: never auto-ignore a 9
    return rec

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_utc TEXT NOT NULL,
  log_ts TEXT,
  client TEXT,
  query TEXT NOT NULL,
  query_type TEXT,
  parent_domain TEXT,
  blocklist_hits TEXT,
  repeat_count_24h INTEGER,
  engine TEXT NOT NULL,
  category TEXT, category_dist TEXT,
  suspicion INTEGER, suspicion_dist TEXT,
  privacy TEXT, privacy_dist TEXT,
  recommend_model TEXT,
  recommend_final TEXT,
  state_json TEXT NOT NULL,
  decision_hash TEXT NOT NULL,
  human_action TEXT DEFAULT 'none',
  UNIQUE(decision_hash)
);
CREATE INDEX IF NOT EXISTS idx_dec_query ON decisions(query);
CREATE INDEX IF NOT EXISTS idx_dec_engine ON decisions(engine);
"""

def row_hash(state):
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()

def open_db(path):
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    return con

def insert_decision(con, state, answers, engine, final_rec):
    dist = lambda k: json.dumps(answers.get(k, {}).get("distribution"))
    try:
        sus_val = int(answers.get("suspicion", {}).get("value"))
    except (TypeError, ValueError):
        sus_val = None
    con.execute(
        "INSERT OR IGNORE INTO decisions (ts_utc, log_ts, client, query, query_type,"
        " parent_domain, blocklist_hits, repeat_count_24h, engine, category,"
        " category_dist, suspicion, suspicion_dist, privacy, privacy_dist,"
        " recommend_model, recommend_final, state_json, decision_hash)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), state.get("timestamp"),
         state.get("client"), state["query"], state.get("query_type"),
         state.get("parent_domain"), json.dumps(state.get("blocklist_hits")),
         state.get("repeat_count_24h"), engine,
         str(answers.get("category", {}).get("value")), dist("category"),
         sus_val, dist("suspicion"),
         str(answers.get("privacy", {}).get("value")), dist("privacy"),
         str(answers.get("recommend", {}).get("value")), final_rec,
         json.dumps(state, sort_keys=True), row_hash(state)))

# ---------------------------------------------------------------- report

def report(con):
    c = con.cursor()
    n = c.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
    print(f"\n=== DNS Sentinel shadow report ===")
    print(f"decisions logged: {n}")
    if not n:
        return
    print("\nby engine:")
    for eng, k in c.execute("SELECT engine, COUNT(*) FROM decisions GROUP BY engine"):
        print(f"  {eng:14s} {k}")
    print("\nmodel recommendation (final, post-gate):")
    for r, k in c.execute("SELECT recommend_final, COUNT(*) FROM decisions GROUP BY 1 ORDER BY 2 DESC"):
        print(f"  {r:14s} {k}")
    print("\ncategory mix:")
    for cat, k in c.execute("SELECT category, COUNT(*) FROM decisions GROUP BY 1 ORDER BY 2 DESC"):
        print(f"  {str(cat):14s} {k}")
    flagged = c.execute(
        "SELECT query, recommend_final, suspicion, engine FROM decisions"
        " WHERE recommend_final != 'log-only' ORDER BY suspicion DESC LIMIT 15").fetchall()
    print(f"\nhuman review queue (top {len(flagged)}):")
    for q, r, s, e in flagged:
        print(f"  [{r:13s}] sus={s} ({e}) {q}")
    # Shadow agreement: engine suggestions vs consensus baseline, per engine.
    print("\nshadow agreement vs baseline blocklists (by engine):")
    for eng, in c.execute("SELECT DISTINCT engine FROM decisions"):
        hit_n, hit_ok = c.execute(
            "SELECT COUNT(*), SUM(recommend_final IN ('flag-review','suggest-block'))"
            " FROM decisions WHERE engine=? AND blocklist_hits != '[]'", (eng,)).fetchone()
        clean_n, clean_ok = c.execute(
            "SELECT COUNT(*), SUM(recommend_final='log-only')"
            " FROM decisions WHERE engine=? AND blocklist_hits='[]'", (eng,)).fetchone()
        if hit_n:
            print(f"  {eng:14s} blocklist-hit rows flagged: {hit_ok}/{hit_n}"
                  f"  | clean rows passed: {clean_ok}/{clean_n}")
    print("\nnext: export the flag-review rows, label them, and grow the golden set.")

# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="DNS Sentinel — shadow-mode DNS triage switch")
    ap.add_argument("--logs", nargs="*", default=[], help="log paths/globs")
    ap.add_argument("--format", default="generic",
                    choices=["pi-hole", "adguard", "bind", "generic"])
    ap.add_argument("--db", default=os.path.join(HERE, "dns_sentinel.db"))
    ap.add_argument("--adapter", default="auto", choices=["auto", "api", "laya", "heuristic"])
    ap.add_argument("--limit", type=int, default=0, help="max queries to process")
    ap.add_argument("--report", action="store_true", help="print report and exit")
    args = ap.parse_args()

    con = open_db(args.db)
    if args.report:
        report(con)
        return

    queries = collect_logs(args.logs, args.format, args.limit)
    if not queries:
        print("no queries parsed — check --logs/--format (see docstring)")
        return
    repeats = {}
    for q in queries:
        d = q["query"].rstrip(".").lower()
        repeats[d] = repeats.get(d, 0) + 1

    template = load_template()
    api_base = os.environ.get("DNS_SENTINEL_API", "")
    api_key = os.environ.get("DNS_SENTINEL_KEY", "")

    laya_missing_noticed = False

    def pick(q):
        nonlocal laya_missing_noticed
        state = build_state(q, repeats)
        use_api = args.adapter == "api" or (args.adapter == "auto" and api_base and api_key)
        use_laya = args.adapter == "laya" or (args.adapter == "auto" and not use_api)
        if use_api:
            a, eng = run_api(state, template, api_base, api_key)
            if "_error" in a:
                # Fail safe: a failed decision goes to the human queue as-is.
                # Its model answers are UNKNOWN — never substitute a guess.
                print(f"warn: api {q['query']}: {a['_error']} -> escalated to human queue",
                      file=sys.stderr)
                a = {"recommend": {"value": "flag-review", "distribution": None}}
                eng = f"error:{eng}"
            return state, a, eng
        if use_laya:
            a, eng = run_laya(state, template)
            if "_error" in a:
                if eng == "laya-missing" and args.adapter == "auto":
                    # Dev convenience only: no engine configured -> transparent
                    # shakedown, engine-tagged so it can't count as evidence.
                    if not laya_missing_noticed:
                        print("notice: laya not installed and no API configured — "
                              "running engine='heuristic' shakedown (these rows "
                              "don't count as shadow evidence)", file=sys.stderr)
                        laya_missing_noticed = True
                    a, eng = run_heuristic(state)
                else:
                    print(f"warn: laya {q['query']}: {a['_error']} -> escalated to human queue",
                          file=sys.stderr)
                    a = {"recommend": {"value": "flag-review", "distribution": None}}
                    eng = f"error:{eng}"
            return state, a, eng
        a, eng = run_heuristic(state)
        return state, a, eng

    n_ins = 0
    for q in queries:
        state, answers, engine = pick(q)
        final = apply_policy(answers)
        insert_decision(con, state, answers, engine, final)
        n_ins += 1
    con.commit()
    print(f"processed {n_ins} queries -> {args.db} (shadow mode: nothing was blocked)")
    report(con)

if __name__ == "__main__":
    main()
