"""Output guard: stop leaks and risky rendering before the reply leaves the host."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ..api import ModelOutput, Verdict

SECRET_RES = [
    ("API_KEY", re.compile(r"\b(sk|pk|rk)[-_][A-Za-z0-9_\-]{16,}\b")),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
]
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*<?https?://[^)]*\)", re.I)
HTML_IMG_RE = re.compile(r"<img\b[^>]*>", re.I)
MD_LINK_RE = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)", re.I)


def _norm_words(text: str) -> list:
    return re.findall(r"[a-z0-9']+", text.lower())


class OutputGuard:
    def __init__(self, policy):
        self.policy = policy

    def check(self, out: ModelOutput) -> Verdict:
        cfg = self.policy.get("output", default={})
        text = out.text or ""
        attrs = out.session.attributes or {}

        canaries = list(cfg.get("canaries") or []) + list(attrs.get("canaries") or [])
        for c in canaries:
            if c and c in text:
                return Verdict("block", "reply contains a canary token", "CANARY_LEAK")
        if cfg.get("secret_patterns", True):
            for name, rx in SECRET_RES:
                if rx.search(text):
                    return Verdict("block", f"reply matches secret pattern {name}", "SECRET_PATTERN")
        prompt = attrs.get("system_prompt")
        if prompt:
            pw, tw = _norm_words(prompt), " ".join(_norm_words(text))
            n = 8
            for i in range(0, max(0, len(pw) - n + 1)):
                if " ".join(pw[i:i + n]) in tw:
                    return Verdict("block", "reply contains a system-prompt fragment", "PROMPT_LEAK")
        for v in attrs.get("other_principal_values") or []:
            if v and v in text:
                return Verdict("block", "reply contains data owned by another principal", "CROSS_PRINCIPAL_DATA")

        flags: list[Verdict] = []
        new_text = text
        if cfg.get("block_external_images", True):
            stripped = HTML_IMG_RE.sub("", MD_IMAGE_RE.sub("", new_text))
            if stripped != new_text:
                new_text = stripped
                flags.append(Verdict("modify", "removed external image(s)", "EXTERNAL_IMAGE"))
        allowed = [d.lower() for d in (cfg.get("allowed_link_domains") or [])]
        if allowed:
            def repl(m):
                host = (urlparse(m.group(2)).hostname or "").lower()
                ok = any(host == a or host.endswith("." + a) for a in allowed)
                return m.group(0) if ok else m.group(1)
            stripped = MD_LINK_RE.sub(repl, new_text)
            if stripped != new_text:
                new_text = stripped
                flags.append(Verdict("modify", "removed link(s) to non-allowlisted domains", "EXTERNAL_LINK"))

        low = text.lower()
        for phrase in cfg.get("forbidden_commitments") or []:
            if phrase.lower() in low:
                action = cfg.get("commitment_action", "flag")
                return Verdict(action, f"reply contains forbidden commitment {phrase!r}", "FORBIDDEN_COMMITMENT")

        grounded = cfg.get("grounded_patterns") or []
        if grounded:
            known = json.dumps(out.tool_results, default=str) + " " + str(attrs.get("known_text", ""))
            for pat in grounded:
                for m in re.finditer(pat, text):
                    if m.group(0) not in known:
                        return Verdict("flag", "reply quotes a value absent from tool results", "UNGROUNDED_VALUE")

        if any(f.action == "modify" for f in flags):
            return Verdict("modify", "; ".join(f.reason for f in flags), flags[0].rule_id,
                           modified_payload=new_text)
        return Verdict("allow", "", "OUTPUT_OK")
