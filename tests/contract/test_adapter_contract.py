"""Contract tests any adapter can reuse: it must translate agent objects into correct layer events.

To reuse: copy `check_adapter_contract` and call it with your adapter factory.
"""
from agentguard import Guard, Manifest
from tests.conftest import MANIFEST


def check_adapter_contract(guard: Guard):
    from agentguard import Session, ToolCall
    s = Session("c1", principal_id="cust_1", auth_level="authenticated")
    assert guard.check(ToolCall(s, "get_order_status", {"order_id": "ORD-000001", "customer_id": "cust_1"})).action == "allow"
    assert guard.check(ToolCall(s, "get_order_status", {"order_id": "ORD-000001", "customer_id": "cust_9"})).action == "block"
    assert guard.check(ToolCall(Session("c2"), "get_order_status", {"order_id": "ORD-000001", "customer_id": ""})).action == "block"


def test_reference_contract():
    check_adapter_contract(Guard.from_config({}, Manifest.from_dict(MANIFEST)))
