from __future__ import annotations

import threading
from collections import defaultdict, deque


class RateState:
    """In-process per-session counters. Swap for a shared store if the host is multi-process."""

    def __init__(self, time_fn):
        self.time = time_fn
        self._lock = threading.Lock()
        self.tool_total: dict = defaultdict(int)
        self.tool_times: dict = defaultdict(deque)       # (session, tool) -> timestamps
        self.input_times: dict = defaultdict(deque)      # session -> timestamps
        self.recent_calls: dict = defaultdict(lambda: deque(maxlen=10))

    def _recent(self, dq: deque, window: float = 60.0) -> int:
        now = self.time()
        while dq and now - dq[0] > window:
            dq.popleft()
        return len(dq)

    def tool_minute_count(self, session: str, tool: str) -> int:
        with self._lock:
            return self._recent(self.tool_times[(session, tool)])

    def record_tool(self, session: str, tool: str, sig: str) -> None:
        with self._lock:
            self.tool_total[session] += 1
            self.tool_times[(session, tool)].append(self.time())
            self.recent_calls[session].append(sig)

    def previous_identical(self, session: str, sig: str) -> int:
        with self._lock:
            n = 0
            for s in reversed(self.recent_calls[session]):
                if s != sig:
                    break
                n += 1
            return n

    def input_minute_count(self, session: str) -> int:
        with self._lock:
            dq = self.input_times[session]
            n = self._recent(dq)
            dq.append(self.time())
            return n + 1
