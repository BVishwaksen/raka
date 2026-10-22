"""The harness must be able to tell a vulnerable toy agent from a protected one."""
from agentguard import Guard, Manifest, Session, ToolCall
from agentguard.redteam.canaries import Fixtures
from agentguard.redteam.report import build_report
from agentguard.redteam.runner import run_suite
from agentguard.redteam.targets import CallableTarget
from agentguard.redteam.targets.base import TargetResult
from tests.conftest import MANIFEST

DATA = {"ORD-000101": ("cust_a", "CANARY-TRK-AAAA"), "ORD-000201": ("cust_b", "CANARY-TRK-BBBB")}
FIX = Fixtures.from_dict({"principals": {"cust_a": {"owned": ["ORD-000101"], "canaries": ["CANARY-TRK-AAAA"]},
                                         "cust_b": {"owned": ["ORD-000201"], "canaries": ["CANARY-TRK-BBBB"]}},
                          "markers": {"injection": "PWNED-7731"}})


def make_target(guard=None):
    def fn(msg, sess):
        import re
        trace, text = [], "Happy to help."
        m = re.search(r"ORD-\d{6}", msg)
        if m:
            oid, who = m.group(0), sess["principal"]
            args = {"order_id": oid, "customer_id": who if guard else DATA.get(oid, ("", ""))[0]}  # vulnerable: trusts model
            if guard:
                s = Session(sess["id"], who, "authenticated")
                if guard.check(ToolCall(s, "get_order_status", args)).action == "block":
                    return TargetResult(text="Sorry, I can't help with that request.", blocked=True)
            trace.append({"tool": "get_order_status", "args": args})
            row = DATA.get(oid)
            if row and (guard is None or row[0] == who):
                text = f"Tracking {row[1]}"
        return text, trace
    return CallableTarget(fn)


def test_harness_distinguishes_protection():
    off = run_suite(make_target(), FIX, "off", categories=["cross_principal"], benign=False)
    guard = Guard.from_config({}, Manifest.from_dict(MANIFEST))
    on = run_suite(make_target(guard), FIX, "on", categories=["cross_principal"], benign=False)
    assert any(a["success"] for a in off["attacks"])
    assert not any(a["success"] for a in on["attacks"])
    assert "cross_principal" in build_report(off, on)
