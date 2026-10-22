from __future__ import annotations

import time

from .base import TargetResult


class CallableTarget:
    """Wrap ``fn(message, session) -> str | (str, trace) | TargetResult``."""

    def __init__(self, fn):
        self.fn = fn
        self._n = 0

    def new_session(self, principal):
        self._n += 1
        return {"principal": principal, "id": f"rt_{self._n}"}

    def send(self, message, session):
        t0 = time.perf_counter()
        try:
            out = self.fn(message, session)
        except Exception as e:
            return TargetResult(error=str(e), latency_ms=(time.perf_counter() - t0) * 1000)
        lat = (time.perf_counter() - t0) * 1000
        if isinstance(out, TargetResult):
            out.latency_ms = out.latency_ms or lat
            return out
        text, trace = out if isinstance(out, tuple) else (out, [])
        return TargetResult(text=text, tool_trace=trace, latency_ms=lat)
