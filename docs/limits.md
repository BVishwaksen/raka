# What this layer does not catch
- Novel or purely semantic attacks: input/context heuristics are signals with known evasions (paraphrase, other languages, multi-step).
- It cannot know who owns a record: ownership must be enforced by the host (scoped queries, row-level security).
- It does not sandbox tools, restrict network egress, or limit spend.
- Multi-turn slow-burn analysis and cross-agent trust are not implemented in v0.1.
- Session replay through a new policy is not implemented yet (audit events do not carry payloads).
- Rate/loop state is in-process; multi-process hosts need a shared store.
The layer reduces risk and provides evidence; it does not make an agent safe by itself.
