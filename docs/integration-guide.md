# Integration guide
Checklist: one adapter file; generate a manifest; start in shadow; review audit events; enforce per checkpoint;
keep your baseline protections. Map: user message → `UserInput`; retrieved chunks → `RetrievedContext`;
before executing a tool → `ToolCall(provenance=...)`; before replying → `ModelOutput`.
Run the contract test (`tests/contract/test_adapter_contract.py`) against your adapter. Reference adapter: the
Customer Support Agent's `app/security_adapter.py`.
