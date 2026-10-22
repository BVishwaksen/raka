import json
from agentguard import Guard, Manifest, JsonlSink, ToolCall
from tests.conftest import MANIFEST


def test_event_fields_and_jsonl(tmp_path, alice):
    path = tmp_path / "a.jsonl"
    g = Guard.from_config({}, Manifest.from_dict(MANIFEST), [JsonlSink(path)])
    g.check(ToolCall(alice, "get_order_status", {"order_id": "ORD-000001", "customer_id": "cust_2"}))
    e = json.loads(path.read_text().splitlines()[0])
    for k in ("ts", "session", "principal", "checkpoint", "subject", "verdict", "mode", "rule_id",
              "reason", "latency_ms", "layer_version", "policy_version"):
        assert k in e
    assert e["rule_id"] == "TRUSTED_PARAM_MISMATCH"


def test_hashed_identifiers(sink, alice):
    g = Guard.from_config({"audit": {"hash_identifiers": True, "salt": "s"}}, Manifest.from_dict(MANIFEST), [sink])
    g.check(ToolCall(alice, "get_order_status", {"order_id": "ORD-000001", "customer_id": "cust_1"}))
    assert sink.events[0]["principal"].startswith("h_") and "cust_1" not in json.dumps(sink.events[0])


def test_mode_off_and_failure_modes(make_guard, alice, sink):
    g = make_guard({"modes": {"tool_guard": "off"}})
    assert g.check(ToolCall(alice, "anything", {})).mode == "off" and not sink.events
    g2 = make_guard()
    g2._tool.check = lambda c: 1 / 0
    assert g2.check(ToolCall(alice, "get_order_status", {})).action == "block"   # fail closed
    g2._input.check = lambda c: 1 / 0
    from agentguard import UserInput
    assert g2.check(UserInput(alice, "hi")).action != "block"                      # shadow/fail open


def test_broken_sink_does_not_break_host(alice):
    class Bad:
        def write(self, e): raise RuntimeError("disk full")
    g = Guard.from_config({}, Manifest.from_dict(MANIFEST), [Bad()])
    assert g.check(ToolCall(alice, "get_order_status", {"order_id": "ORD-000001", "customer_id": "cust_1"})).action == "allow"
