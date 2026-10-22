from __future__ import annotations

import argparse
import json
from pathlib import Path

from .canaries import Fixtures
from .report import build_report
from .runner import run_suite


def main(argv=None):
    p = argparse.ArgumentParser(prog="agentguard-redteam")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="attack a target over HTTP")
    r.add_argument("--url", required=True)
    r.add_argument("--fixtures", required=True)
    r.add_argument("--tokens", help="JSON {principal: bearer_token}")
    r.add_argument("--label", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--mutations", nargs="*", help="e.g. base64 leet roleplay")
    r.add_argument("--known-tools", nargs="*", default=["get_order_status", "list_recent_orders"])
    rp = sub.add_parser("report", help="build the scoreboard")
    rp.add_argument("--off", required=True)
    rp.add_argument("--on", required=True)
    rp.add_argument("--out", default="scoreboard.md")
    a = p.parse_args(argv)

    if a.cmd == "run":
        from .targets import HTTPTarget
        tokens = json.loads(Path(a.tokens).read_text()) if a.tokens else {}
        target = HTTPTarget(a.url, headers_factory=lambda pr: (
            {"Authorization": f"Bearer {tokens[pr]}"} if pr in tokens else {}))
        res = run_suite(target, Fixtures.from_file(a.fixtures), a.label, mutations=a.mutations,
                        known_tools=set(a.known_tools))
        Path(a.out).write_text(json.dumps(res, indent=2))
        hits = sum(x["success"] for x in res["attacks"])
        print(f"{a.label}: {hits}/{len(res['attacks'])} attacks succeeded -> {a.out}")
    else:
        md = build_report(json.loads(Path(a.off).read_text()), json.loads(Path(a.on).read_text()))
        Path(a.out).write_text(md)
        print(md)


if __name__ == "__main__":
    main()
