import pytest
from agentguard import Guard, Manifest, MemorySink, Session

MANIFEST = {"tools": {
    "get_order_status": {"requires_auth": True, "trusted_params": ["customer_id"],
                         "validated_params": {"order_id": r"^ORD-[0-9]{6}$"}, "max_rows": 5},
    "send_email": {"requires_auth": True, "allowed_domains": ["example.com"], "approval": "confirm",
                   "side_effects": True},
}}


@pytest.fixture
def sink():
    return MemorySink()


@pytest.fixture
def make_guard(sink):
    def _make(cfg=None, manifest=MANIFEST):
        return Guard.from_config(cfg or {}, manifest=Manifest.from_dict(manifest), sinks=[sink])
    return _make


@pytest.fixture
def alice():
    return Session("s1", principal_id="cust_1", auth_level="authenticated")


@pytest.fixture
def anon():
    return Session("s2")
