# Quickstart (wrap a plain agent in ~30 minutes)
1. `pip install -e .[dev]`
2. Describe your tools in a manifest ([manifest.md](manifest.md)).
3. Create `policy.yaml` (`profile: balanced`). Input guard starts in `shadow`.
4. Write one adapter file mapping your objects to `UserInput`, `RetrievedContext`, `ToolCall`, `ModelOutput`.
5. Run in shadow, read `audit.jsonl`, then enforce per checkpoint.
Working example: `python examples/plain_loop_agent/agent.py`.
