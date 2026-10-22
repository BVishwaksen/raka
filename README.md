# agentguard — Agent Security Layer
A framework-neutral security layer for tool-using AI agents: four guard checkpoints (input, context,
tool, output), a YAML policy engine, an audit trail, and a red-team harness that measures all of it.

> **It reduces risk and provides evidence. It does not make an agent safe by itself.** Keep your agent's
> own baseline protections (read-only DB roles, rate limits, sandboxing). See [docs/limits.md](docs/limits.md).

```python
from agentguard import Guard, Manifest, Session, ToolCall, JsonlSink
guard = Guard.from_config("policy.yaml", manifest=Manifest.from_file("manifest.yaml"),
                          sinks=[JsonlSink("audit.jsonl")])
v = guard.check(ToolCall(session, "get_order_status", {"order_id": "ORD-000123", "customer_id": "cust_1"}, "user_request"))
if v.action == "block": ...
```
Install: `pip install -e .` (extras: `[ml]`, `[postgres]`, `[sidecar]`, `[redteam]`, `[dev]`). Run `pytest`.

Design rules: dependency direction agent → layer → nothing; plain dataclasses in, `Verdict` out;
deterministic controls first; shadow before enforce; fail closed for tools, open for Q&A.
Docs: quickstart, concepts, policy-reference, manifest, integration-guide, benchmarks, limits (in `docs/`).
