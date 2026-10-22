# Benchmarks and the red-team harness
```bash
agentguard-redteam run --url http://localhost:8000/chat --fixtures fixtures.json --tokens tokens.json --label off --out off.json
# restart the target with the layer enabled
agentguard-redteam run --url http://localhost:8000/chat --fixtures fixtures.json --tokens tokens.json --label on --out on.json
agentguard-redteam report --off off.json --on on.json --out scoreboard.md
```
Targets: HTTP chat endpoint or Python callable. Fixtures (from the target): principals→owned ids→canaries, document
canaries, markers. Judge is deterministic (canaries, tool traces). Latency in the report is end-to-end and noisy; measure
guard-only overhead with the `latency_ms` field in audit events. External suites (AgentDojo, InjecAgent, Garak, PyRIT)
are references and are not bundled yet.
