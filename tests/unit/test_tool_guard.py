import pytest
from hypothesis import given, strategies as st
from agentguard import Session, ToolCall


def call(session, tool="get_order_status", prov="user_request", **args):
    return ToolCall(session, tool, args, prov)


def test_allows_valid_call(make_guard, alice):
    v = make_guard().check(call(alice, order_id="ORD-000123", customer_id="cust_1"))
    assert v.action == "allow"


def test_unknown_tool_blocked(make_guard, alice):
    assert make_guard().check(call(alice, tool="drop_db")).rule_id == "TOOL_NOT_IN_MANIFEST"


def test_anonymous_blocked(make_guard, anon):
    assert make_guard().check(call(anon, order_id="ORD-000123", customer_id="x")).rule_id == "AUTH_REQUIRED"


def test_trusted_param_mismatch(make_guard, alice):
    v = make_guard().check(call(alice, order_id="ORD-000123", customer_id="cust_2"))
    assert (v.action, v.rule_id) == ("block", "TRUSTED_PARAM_MISMATCH")


def test_trusted_param_missing(make_guard, alice):
    assert make_guard().check(call(alice, order_id="ORD-000123")).rule_id == "TRUSTED_PARAM_MISSING"


@pytest.mark.parametrize("bad", ["ORD-1", "ORD-000123' OR 1=1", "../x", "ORD-000123\n"])
def test_invalid_order_id(make_guard, alice, bad):
    assert make_guard().check(call(alice, order_id=bad, customer_id="cust_1")).rule_id == "ARG_INVALID"


def test_untrusted_provenance_blocked(make_guard, alice):
    v = make_guard().check(call(alice, prov="retrieved_content", order_id="ORD-000123", customer_id="cust_1"))
    assert v.rule_id == "UNTRUSTED_PROVENANCE" and v.blocked


def test_permissive_flags_untrusted_provenance(make_guard, alice):
    g = make_guard({"profile": "permissive"})
    v = g.check(call(alice, prov="retrieved_content", order_id="ORD-000123", customer_id="cust_1"))
    assert v.action == "flag"


def test_domain_allowlist_and_approval(make_guard, alice):
    g = make_guard()
    assert g.check(call(alice, tool="send_email", to="x@evil.test")).rule_id == "DOMAIN_NOT_ALLOWED"
    v = g.check(call(alice, tool="send_email", to="bob@example.com"))
    assert v.rule_id == "APPROVAL_REQUIRED" and v.modified_payload == {"approval": "confirm"}


def test_session_budget(make_guard, alice):
    g = make_guard({"limits": {"max_tool_calls_per_session": 2}})
    for i in range(2):
        assert g.check(call(alice, order_id=f"ORD-00000{i}", customer_id="cust_1")).action == "allow"
    assert g.check(call(alice, order_id="ORD-000009", customer_id="cust_1")).rule_id == "RATE_LIMIT_SESSION"


def test_per_minute_override(make_guard, alice):
    g = make_guard({"overrides": {"tools": {"get_order_status": {"max_calls_per_minute": 1}}}})
    assert g.check(call(alice, order_id="ORD-000001", customer_id="cust_1")).action == "allow"
    assert g.check(call(alice, order_id="ORD-000002", customer_id="cust_1")).rule_id == "RATE_LIMIT_TOOL"


def test_loop_flag(make_guard, alice):
    g = make_guard()
    verdicts = [g.check(call(alice, order_id="ORD-000001", customer_id="cust_1")) for _ in range(3)]
    assert verdicts[-1].rule_id == "LOOP_DETECTED"


@given(st.text(max_size=40))
def test_never_allows_foreign_principal(text):
    from agentguard import Guard, Manifest, Session
    from tests.conftest import MANIFEST
    g = Guard.from_config({}, manifest=Manifest.from_dict(MANIFEST))
    s = Session("p", principal_id="cust_1", auth_level="authenticated")
    if text != "cust_1":
        v = g.check(ToolCall(s, "get_order_status", {"order_id": "ORD-000001", "customer_id": text}))
        assert v.action == "block"
