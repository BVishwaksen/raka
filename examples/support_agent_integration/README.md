# Support agent integration
The reference integration lives in the support agent repo (`app/security_adapter.py`, the only file
that imports `agentguard`). It builds a manifest from `tools.yaml`, maps the agent's four hooks to
`guard.check(...)`, and runs the shared contract tests (`tests/contract/test_adapter_contract.py`).
