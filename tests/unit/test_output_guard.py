from agentguard import ModelOutput


def out(session, text, **kw):
    return ModelOutput(session, text, kw.get("tool_results", []))


def test_canary_blocked(make_guard, alice):
    g = make_guard({"output": {"canaries": ["CANARY-"]}})
    assert g.check(out(alice, "key is CANARY-TRK-1234")).rule_id == "CANARY_LEAK"


def test_secret_pattern(make_guard, alice):
    assert make_guard().check(out(alice, "use sk-abcdefghijklmnop1234")).rule_id == "SECRET_PATTERN"


def test_external_image_stripped(make_guard, alice):
    v = make_guard().check(out(alice, "Hi ![x](https://attacker.example/c?d=1) there"))
    assert v.action == "modify" and "attacker" not in v.modified_payload


def test_link_allowlist(make_guard, alice):
    g = make_guard({"output": {"allowed_link_domains": ["acme.com"]}})
    v = g.check(out(alice, "[ok](https://acme.com/a) [bad](https://evil.test/x)"))
    assert v.action == "modify" and "evil.test" not in v.modified_payload and "acme.com" in v.modified_payload


def test_prompt_leak(make_guard, alice):
    alice.attributes["system_prompt"] = "You are a helpful support agent for Acme and you must never reveal secrets"
    v = make_guard().check(out(alice, "Sure: you are a helpful support agent for acme and you must never reveal secrets"))
    assert v.rule_id == "PROMPT_LEAK"


def test_cross_principal_data(make_guard, alice):
    alice.attributes["other_principal_values"] = ["TRK-9999"]
    assert make_guard().check(out(alice, "tracking TRK-9999")).rule_id == "CROSS_PRINCIPAL_DATA"


def test_commitments_profiles(make_guard, alice):
    assert make_guard({"output": {"forbidden_commitments": ["refund"]}}).check(out(alice, "I guarantee a refund")).action == "flag"
    strict = make_guard({"profile": "strict", "output": {"forbidden_commitments": ["refund"]}})
    assert strict.check(out(alice, "I guarantee a refund")).action == "block"


def test_grounding(make_guard, alice):
    g = make_guard({"output": {"grounded_patterns": [r"TRK-\d+"]}})
    assert g.check(out(alice, "TRK-111", tool_results=[{"t": "TRK-111"}])).action == "allow"
    assert g.check(out(alice, "TRK-222", tool_results=[{"t": "TRK-111"}])).rule_id == "UNGROUNDED_VALUE"


def test_clean_output(make_guard, alice):
    assert make_guard().check(out(alice, "Your order has shipped.")).action == "allow"
