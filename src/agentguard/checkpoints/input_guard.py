"""Input guard: heuristic signals on user text. Ships in shadow mode until FP rate is known."""
from __future__ import annotations

from ..api import UserInput, Verdict
from ..detectors import heuristics as h


class InputGuard:
    def __init__(self, policy, state, classifier=None):
        self.policy, self.state, self.classifier = policy, state, classifier

    def check(self, inp: UserInput) -> Verdict:
        text = inp.text or ""
        limits = self.policy.get("limits", default={})
        if len(text) > limits.get("max_input_chars", 8000):
            return Verdict("block", "input exceeds maximum size", "INPUT_TOO_LARGE", 1.0)
        if self.state.input_minute_count(inp.session.id) > limits.get("max_inputs_per_minute", 30):
            return Verdict("block", "too many messages per minute", "INPUT_RATE_LIMIT", 1.0)

        score, findings = 0.0, []
        for rid, w in h.find_injection(text):
            score += w
            findings.append(rid)
        if h.has_invisible(text):
            score += 0.3
            findings.append("INVISIBLE_CHARS")
        if h.has_mixed_script(text):
            score += 0.4
            findings.append("MIXED_SCRIPT")
        for decoded in h.decode_base64_blobs(text):
            score += 0.3
            findings.append("ENCODED_BLOB")
            if h.find_injection(decoded):
                score += 0.6
                findings.append("ENCODED_INJECTION")
        if self.classifier is not None:
            score = max(score, float(self.classifier(text)))
        score = round(min(score, 2.0), 3)

        if self.policy.get("input", "redact_pii", default=False):
            red, kinds = h.redact_pii(text)
            if kinds and score < self.policy.get("input", "block_score", default=0.8):
                return Verdict("modify", "redacted PII: " + ", ".join(kinds), "PII_REDACTED", score,
                               modified_payload=red)
        if score >= self.policy.get("input", "block_score", default=0.8):
            return Verdict("block", "injection-like input: " + ", ".join(findings), "INJECTION_SUSPECTED", score)
        if score > 0:
            return Verdict("flag", "weak injection signals: " + ", ".join(findings), "INJECTION_SIGNAL", score)
        return Verdict("allow", "", "INPUT_OK", 0.0)
