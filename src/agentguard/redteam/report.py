from __future__ import annotations

from collections import defaultdict


def _asr(run: dict) -> dict:
    by = defaultdict(lambda: [0, 0])
    for a in run["attacks"]:
        by[a["category"]][1] += 1
        by[a["category"]][0] += int(a["success"])
    return by


def _fp(run: dict):
    b = run.get("benign", [])
    return None if not b else sum(x["refused"] for x in b) / len(b)


def _fmt(v, unit=""):
    return "n/a" if v is None else (f"{v:.1f}{unit}" if isinstance(v, float) else f"{v}{unit}")


def _pct_fmt(v):
    return "n/a" if v is None else f"{v * 100:.1f}%"


def build_report(off: dict, on: dict) -> str:
    a_off, a_on = _asr(off), _asr(on)
    lines = [f"# Agent Security Layer scoreboard", "",
             f"Corpus version: {on.get('corpus_version')}. Layer off = `{off['label']}`, layer on = `{on['label']}`.", "",
             "## Attack success rate by category", "", "| Category | Layer off | Layer on |", "|---|---|---|"]
    for cat in sorted(set(a_off) | set(a_on)):
        f = lambda d: f"{d[cat][0]}/{d[cat][1]}" if cat in d else "n/a"
        lines.append(f"| {cat} | {f(a_off)} | {f(a_on)} |")
    tot = lambda d: (sum(v[0] for v in d.values()), sum(v[1] for v in d.values()))
    (so, to), (sn, tn) = tot(a_off), tot(a_on)
    lines += [f"| **total** | {so}/{to} | {sn}/{tn} |", ""]
    leaks = lambda r: sum(1 for a in r["attacks"] if a["category"] == "cross_principal" and a["success"])
    lines += ["## Headline metrics", "", "| Metric | Layer off | Layer on |", "|---|---|---|",
              f"| Cross-principal leaks | {leaks(off)} | {leaks(on)} |",
              f"| False-positive rate (benign refused) | {_pct_fmt(_fp(off))} | {_pct_fmt(_fp(on))} |",
              f"| Latency p50 (ms) | {_fmt(off['latency']['p50'])} | {_fmt(on['latency']['p50'])} |",
              f"| Latency p95 (ms) | {_fmt(off['latency']['p95'])} | {_fmt(on['latency']['p95'])} |", ""]
    if off["latency"]["p95"] is not None and on["latency"]["p95"] is not None:
        lines += [f"Added end-to-end latency p95: {on['latency']['p95'] - off['latency']['p95']:.1f} ms "
                  "(includes network and model variance; see docs/benchmarks.md).", ""]
    misses = [a for a in on["attacks"] if a["success"]]
    lines += ["## Known misses (layer on)", ""]
    lines += [f"- `{a['id']}` ({a['category']}): {a['evidence']}" for a in misses] or ["- none in this corpus run"]
    lines += ["", "> This scoreboard measures a fixed corpus. Passing it is not a guarantee of safety; "
              "see docs/limits.md.", ""]
    return "\n".join(lines)
