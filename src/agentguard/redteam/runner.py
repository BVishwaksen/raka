from __future__ import annotations

import statistics
import time
from typing import Optional

from .attacker_agent import mutate
from .attacks.corpus import ATTACKS, CORPUS_VERSION, render
from .benign_traffic import BENIGN
from .canaries import Fixtures
from .judge import is_refusal, judge


def _pct(values, p):
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def run_suite(target, fixtures: Fixtures, label: str, attacker: Optional[str] = None,
              victim: Optional[str] = None, categories: Optional[list] = None,
              mutations: Optional[list] = None, known_tools: Optional[set] = None,
              benign: bool = True) -> dict:
    pids = list(fixtures.principals)
    attacker = attacker or pids[0]
    victim = victim or pids[1]
    attacks = [a for a in ATTACKS if not categories or a.category in categories]
    if mutations:
        attacks += [m for a in attacks if len(a.turns) == 1 and a.repeat == 1 and a.category != "resource_abuse"
                    for m in mutate(a, mutations)]
    out = {"label": label, "corpus_version": CORPUS_VERSION, "ts": time.time(), "attacks": [], "benign": []}
    latencies = []
    for a in attacks:
        principal = None if a.attacker == "anonymous" else attacker
        sess = target.new_session(principal)
        results = []
        for _ in range(a.repeat):
            for turn in render(a, fixtures, attacker, victim):
                r = target.send(turn, sess)
                results.append(r)
                latencies.append(r.latency_ms)
        j = judge(a, results, fixtures, attacker, known_tools)
        out["attacks"].append({"id": a.id, "category": a.category, "success": j.success, "evidence": j.evidence,
                               "blocked": any(is_refusal(r) for r in results)})
    if benign:
        for b in BENIGN:
            principal = attacker if b["needs_auth"] else None
            sess = target.new_session(principal)
            own = (fixtures.principals.get(attacker, {}).get("owned") or ["ORD-000101"])[0]
            refused = False
            for t in b["turns"]:
                r = target.send(t.replace("{own_order}", own), sess)
                latencies.append(r.latency_ms)
                refused = refused or is_refusal(r) or bool(r.error)
            out["benign"].append({"id": b["id"], "kind": b["kind"], "refused": refused})
    out["latency"] = {"p50": _pct(latencies, 50), "p95": _pct(latencies, 95),
                      "mean": statistics.fmean(latencies) if latencies else None}
    return out
