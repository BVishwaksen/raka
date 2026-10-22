from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol


@dataclass
class TargetResult:
    text: str = ""
    tool_trace: list = field(default_factory=list)   # [{"tool":..., "args":{...}}]
    blocked: bool = False
    error: Optional[str] = None
    latency_ms: float = 0.0


class Target(Protocol):
    def new_session(self, principal: Optional[str]) -> dict: ...
    def send(self, message: str, session: dict) -> TargetResult: ...
