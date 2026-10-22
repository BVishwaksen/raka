import pytest
from agentguard.policy.engine import load_policy


def test_profiles_load():
    assert load_policy({"profile": "strict"}).get("context", "quarantine_score") == 1
    assert load_policy({"profile": "permissive"}).get("provenance", "untrusted_action") == "flag"


def test_override_wins():
    assert load_policy({"limits": {"max_input_chars": 5}}).get("limits", "max_input_chars") == 5


def test_unknown_profile_and_future_schema():
    with pytest.raises(ValueError):
        load_policy({"profile": "nope"})
    with pytest.raises(ValueError):
        load_policy({"version": 99})
