"""Cheap, deterministic text heuristics. Signals, not proof: see docs/limits.md."""
from __future__ import annotations

import base64
import re
import unicodedata

INVISIBLE_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")

# (rule_id, regex, weight). Weight 2 ~ "clearly instruction-like" for context scanning.
INJECTION_PATTERNS = [
    ("OVERRIDE_INSTRUCTIONS", re.compile(
        r"(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|system|original)\s+"
        r"(instructions?|rules?|prompts?|messages?|guidelines?)", re.I), 0.6),
    ("REVEAL_PROMPT", re.compile(
        r"(reveal|show|print|repeat|output|leak)\s+(me\s+)?(your\s+|the\s+)?(system\s+|hidden\s+|initial\s+)?(prompt|instructions)", re.I), 0.6),
    ("ROLE_REASSIGN", re.compile(r"\byou\s+are\s+now\s+(a|an|the|in)\b|\bnew\s+instructions?\s*:", re.I), 0.5),
    ("FAKE_SYSTEM_TAG", re.compile(r"<\s*/?\s*(system|assistant)\s*>|\[/?INST\]|\bSYSTEM\s*:", re.I), 0.5),
    ("CONCEAL_FROM_USER", re.compile(r"(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show)\s+(this\s+to\s+)?the\s+user", re.I), 0.6),
    ("TOOL_DIRECTIVE", re.compile(r"\b(call|use|invoke|run|execute)\s+(the\s+)?[\w\-]+\s+(tool|function)\b", re.I), 0.4),
    ("EXFIL_DIRECTIVE", re.compile(r"\b(send|post|forward|email|upload)\b.{0,60}\b(to|at)\b\s+(https?://|\S+@\S+)", re.I), 0.6),
    ("JAILBREAK_PERSONA", re.compile(r"\b(DAN|developer\s+mode|jailbreak(ed)?|do\s+anything\s+now)\b", re.I), 0.5),
    ("ROLEPLAY_FRAMING", re.compile(r"\b(pretend|act|roleplay|role-play)\s+(to\s+be\s+|as\s+(if\s+)?)", re.I), 0.3),
    ("IMPERSONATE_ADMIN", re.compile(r"\bi\s+am\s+(the\s+)?(admin|administrator|developer|your\s+(creator|owner))\b", re.I), 0.4),
]
B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
PHONE_RE = re.compile(r"(?<!\w)(\+?\d{1,3}[ .-]?)?(\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\w)")


def find_injection(text: str) -> list:
    return [(rid, w) for rid, rx, w in INJECTION_PATTERNS if rx.search(text)]


def has_invisible(text: str) -> bool:
    return bool(INVISIBLE_RE.search(text))


def strip_invisible(text: str) -> str:
    return INVISIBLE_RE.sub("", text)


def has_mixed_script(text: str) -> bool:
    """Latin mixed with Cyrillic/Greek inside one word: classic confusable trick."""
    for word in re.findall(r"\w+", text):
        scripts = set()
        for ch in word:
            if ch.isalpha():
                name = unicodedata.name(ch, "")
                for s in ("LATIN", "CYRILLIC", "GREEK"):
                    if name.startswith(s):
                        scripts.add(s)
        if "LATIN" in scripts and len(scripts) > 1:
            return True
    return False


def decode_base64_blobs(text: str) -> list:
    out = []
    for m in B64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except Exception:
            continue
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.9:
            out.append(decoded)
    return out


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def redact_pii(text: str):
    kinds = []

    def card(m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            kinds.append("card")
            return "[REDACTED_CARD]"
        return m.group(0)

    text = CARD_RE.sub(card, text)
    if EMAIL_RE.search(text):
        kinds.append("email")
        text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    if PHONE_RE.search(text):
        kinds.append("phone")
        text = PHONE_RE.sub("[REDACTED_PHONE]", text)
    return text, kinds
