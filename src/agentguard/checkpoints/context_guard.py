"""Context guard: retrieved chunks are untrusted data. Quarantine, strip, never obey."""
from __future__ import annotations

from ..api import RetrievedContext, Verdict
from ..detectors import heuristics as h


def scan_text(text: str):
    """Return (score, findings). Weight 2 = clearly instruction-like; 1 = hidden/obfuscated."""
    findings, score = set(), 0.0
    for rid, _w in h.find_injection(text):
        findings.add(rid)
        score += 2
    if h.has_invisible(text):
        findings.add("INVISIBLE_CHARS")
        score += 1
    for m in h.HTML_COMMENT_RE.finditer(text):
        if len(m.group(1).strip()) > 20:
            findings.add("HIDDEN_HTML_COMMENT")
            score += 1
            break
    for decoded in h.decode_base64_blobs(text):
        findings.add("ENCODED_BLOB")
        score += 1
        if h.find_injection(decoded):
            findings.add("ENCODED_INSTRUCTIONS")
            score += 2
    return score, findings


class ContextGuard:
    def __init__(self, policy):
        self.policy = policy

    def check(self, ctx: RetrievedContext) -> Verdict:
        limit = self.policy.get("context", "quarantine_score", default=2)
        kept, quarantined, sanitized, max_score, all_findings = [], 0, 0, 0.0, set()
        for chunk in ctx.chunks:
            c = dict(chunk) if isinstance(chunk, dict) else {"text": str(chunk)}
            score, findings = scan_text(c.get("text", ""))
            max_score = max(max_score, score)
            all_findings |= findings
            if score >= limit:
                quarantined += 1
                continue
            if "INVISIBLE_CHARS" in findings:
                c["text"] = h.strip_invisible(c["text"])
                sanitized += 1
            kept.append(c)
        if not quarantined and not sanitized:
            return Verdict("allow", "", "CONTEXT_OK", 0.0)
        rule = "CONTEXT_QUARANTINE" if quarantined else "CONTEXT_SANITIZED"
        reason = f"quarantined {quarantined}, sanitized {sanitized} chunk(s): " + ", ".join(sorted(all_findings))
        return Verdict("modify", reason, rule, max_score, modified_payload=kept)
