from __future__ import annotations

import time
from typing import Callable, Optional

from .base import TargetResult


def _dig(obj, path: str, default=None):
    for part in path.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return default
    return obj


class HTTPTarget:
    """Attack an agent through its public chat endpoint.

    ``headers_factory(principal) -> dict`` supplies auth headers (None principal = anonymous).
    ``body_template`` values may contain ``{message}`` and ``{session_id}``.
    """

    def __init__(self, url: str, headers_factory: Optional[Callable[[Optional[str]], dict]] = None,
                 body_template: Optional[dict] = None, text_path: str = "reply",
                 trace_path: str = "tool_calls", blocked_path: str = "blocked",
                 session_path: str = "session_id", timeout: float = 60.0):
        import httpx
        self.url, self.headers_factory = url, headers_factory or (lambda p: {})
        self.body_template = body_template or {"message": "{message}", "session_id": "{session_id}"}
        self.text_path, self.trace_path = text_path, trace_path
        self.blocked_path, self.session_path = blocked_path, session_path
        self.client = httpx.Client(timeout=timeout)

    def new_session(self, principal):
        return {"principal": principal, "session_id": None}

    def send(self, message: str, session: dict) -> TargetResult:
        body = {}
        for k, v in self.body_template.items():
            if isinstance(v, str):
                if v == "{session_id}":
                    v = session.get("session_id")
                else:
                    v = v.replace("{message}", message)
            body[k] = v
        t0 = time.perf_counter()
        try:
            r = self.client.post(self.url, json=body, headers=self.headers_factory(session.get("principal")))
            latency = (time.perf_counter() - t0) * 1000
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        except Exception as e:
            return TargetResult(error=str(e), latency_ms=(time.perf_counter() - t0) * 1000)
        sid = _dig(data, self.session_path)
        if sid:
            session["session_id"] = sid
        err = None if r.status_code < 400 else f"HTTP {r.status_code}"
        blocked = bool(_dig(data, self.blocked_path, False)) or r.status_code in (400, 403, 429)
        return TargetResult(text=str(_dig(data, self.text_path, "") or ""),
                            tool_trace=_dig(data, self.trace_path, []) or [], blocked=blocked,
                            error=err, latency_ms=latency)
