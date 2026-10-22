# Policy reference (schema version 1)
```yaml
version: 1
profile: balanced            # strict | balanced | permissive (merged under your overrides)
modes: {input_guard: shadow, context_guard: enforce, tool_guard: enforce, output_guard: enforce}  # off|shadow|enforce
failure: {tool_guard: closed, input_guard: open, context_guard: open, output_guard: open}
limits: {max_tool_calls_per_session: 20, max_input_chars: 8000, max_inputs_per_minute: 30, loop_threshold: 3}
input: {block_score: 0.8, redact_pii: false}
context: {quarantine_score: 2}
provenance: {untrusted_action: block}      # block | flag
approval: {confirm_side_effects: false}
output: {block_external_images: true, allowed_link_domains: [], canaries: ["CANARY-"], secret_patterns: true,
         forbidden_commitments: ["refund"], commitment_action: flag, grounded_patterns: []}
audit: {hash_identifiers: false, salt: ""}
overrides: {tools: {get_order_status: {max_calls_per_minute: 6, approval: auto, enabled: true, failure: closed}}}
```
Rule ids: TOOL_NOT_IN_MANIFEST, TOOL_DISABLED, AUTH_REQUIRED, TRUSTED_PARAM_MISSING/MISMATCH, ARG_MISSING/INVALID,
DOMAIN_NOT_ALLOWED, ROW_LIMIT_EXCEEDED, UNTRUSTED_PROVENANCE, RATE_LIMIT_SESSION/TOOL, APPROVAL_REQUIRED,
LOOP_DETECTED, CANARY_LEAK, SECRET_PATTERN, PROMPT_LEAK, CROSS_PRINCIPAL_DATA, EXTERNAL_IMAGE, EXTERNAL_LINK,
FORBIDDEN_COMMITMENT, UNGROUNDED_VALUE, CONTEXT_QUARANTINE, CONTEXT_SANITIZED, INJECTION_SUSPECTED, INJECTION_SIGNAL,
INPUT_TOO_LARGE, INPUT_RATE_LIMIT, PII_REDACTED, CHECK_ERROR.
