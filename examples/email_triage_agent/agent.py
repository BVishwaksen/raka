"""Second example: email triage with an allowlisted send_email tool that needs confirmation."""
from agentguard import Guard, Manifest, Session, ToolCall

manifest = Manifest.from_dict({"tools": {
    "send_email": {"requires_auth": True, "allowed_domains": ["example.com"], "approval": "confirm",
                   "side_effects": True},
    "read_inbox": {"requires_auth": True, "trusted_params": ["mailbox"], "max_rows": 20}}})
guard = Guard.from_config({"profile": "strict"}, manifest=manifest)
s = Session("e1", principal_id="alice", auth_level="authenticated")

for call in [
    ToolCall(s, "send_email", {"to": "bob@example.com"}, "user_request"),      # -> flag APPROVAL_REQUIRED
    ToolCall(s, "send_email", {"to": "evil@attacker.test"}, "user_request"),   # -> block DOMAIN_NOT_ALLOWED
    ToolCall(s, "read_inbox", {"mailbox": "alice"}, "retrieved_content"),     # -> block UNTRUSTED_PROVENANCE
    ToolCall(s, "read_inbox", {"mailbox": "bob"}, "user_request"),            # -> block TRUSTED_PARAM_MISMATCH
]:
    v = guard.check(call)
    print(call.tool, call.args, "->", v.action, v.rule_id)
