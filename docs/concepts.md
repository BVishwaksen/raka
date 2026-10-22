# Concepts
**Checkpoints.** Input guard (user text; shadow first), Context guard (retrieved chunks; quarantine, strip invisible
characters, never obey), Tool guard (deterministic: manifest, auth, trusted params, validated args, domain allowlists,
limits, provenance, approval, loop flag), Output guard (canaries, secret patterns, prompt fragments, risky links/images,
forbidden commitments, ungrounded values, other principals' data).
**Verdicts.** `allow | block | flag | modify`; `modify` carries `modified_payload` (sanitized text or chunk list).
In `shadow` mode the caller always receives `allow` (mode=`shadow`), while the audit records what would have happened.
**Provenance.** A tool call that follows only from retrieved or tool-returned content is blocked/flagged by policy.
**Approval.** `confirm`/`human_only` return `flag` with `rule_id=APPROVAL_REQUIRED`; the host pauses and asks.
**Fail modes.** Tool guard fails closed on internal errors; others fail open with logging (overridable).
