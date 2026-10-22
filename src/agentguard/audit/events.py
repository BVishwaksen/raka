from __future__ import annotations

from datetime import datetime, timezone

AUDIT_SCHEMA_VERSION = 1


def make_event(*, session, principal, checkpoint, subject, verdict, latency_ms, policy_version,
               error=None, note=None) -> dict:
    from .. import __version__
    evt = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "session": session, "principal": principal, "checkpoint": checkpoint, "subject": subject,
        "verdict": verdict.action, "mode": verdict.mode, "rule_id": verdict.rule_id,
        "reason": verdict.reason, "score": verdict.score, "latency_ms": round(latency_ms, 3),
        "layer_version": __version__, "policy_version": policy_version,
        "audit_schema": AUDIT_SCHEMA_VERSION,
    }
    if error:
        evt["error"] = error
    if note:
        evt["note"] = note
    return evt
