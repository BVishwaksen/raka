"""Plain-Python tool-calling loop wrapped with agentguard. Run: python examples/plain_loop_agent/agent.py"""
from agentguard import Guard, Manifest, MemorySink, Session
from agentguard.adapters.plain_loop import GuardBlocked, guard_input, guard_output, guarded_tool

MANIFEST = Manifest.from_dict({"tools": {
    "lookup_note": {"requires_auth": True, "trusted_params": ["user_id"],
                    "validated_params": {"note_id": r"^N-\d{4}$"}, "max_rows": 3}}})
NOTES = {"N-0001": ("u1", "buy milk"), "N-0002": ("u2", "secret plan")}
sink = MemorySink()
guard = Guard.from_config({"profile": "balanced"}, manifest=MANIFEST, sinks=[sink])
session = Session("s1", principal_id="u1", auth_level="authenticated")


@guarded_tool(guard, lambda: session)
def lookup_note(user_id, note_id):
    owner, text = NOTES[note_id]
    return text if owner == user_id else None


def fake_model(text):  # stands in for an LLM deciding which tool to call
    return {"tool": "lookup_note", "args": {"note_id": text.split()[-1]}}


def run(user_text):
    user_text = guard_input(guard, session, user_text)
    call = fake_model(user_text)
    try:
        result = lookup_note(user_id=session.principal_id, **call["args"])  # identity bound by code
    except GuardBlocked as e:
        return f"blocked: {e}"
    return guard_output(guard, session, f"Your note says: {result}", [result])


if __name__ == "__main__":
    print(run("read note N-0001"))
    print(run("read note N-0002"))      # owner filter in the tool returns None
    print(run("read note ../../etc"))   # fails manifest validation -> blocked
    print([(e["rule_id"], e["verdict"]) for e in sink.events])
