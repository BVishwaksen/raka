"""Canary tooling: plant unique fake secrets, detect them in outputs."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def new_canary(kind: str = "VAL") -> str:
    return f"CANARY-{kind}-{secrets.token_hex(4).upper()}"


def find_canaries(text: str, canaries) -> list:
    return [c for c in canaries if c and c in text]


@dataclass
class Fixtures:
    """Supplied by the target. principals: id -> {"owned": [ids], "canaries": [values]}."""
    principals: dict = field(default_factory=dict)
    document_canaries: list = field(default_factory=list)
    markers: dict = field(default_factory=dict)  # injection marker, system prompt phrase, ...

    @classmethod
    def from_dict(cls, d: dict) -> "Fixtures":
        return cls(d.get("principals", {}), d.get("document_canaries", []), d.get("markers", {}))

    @classmethod
    def from_file(cls, path) -> "Fixtures":
        return cls.from_dict(json.loads(Path(path).read_text()))

    def foreign_values(self, principal: str) -> list:
        out = []
        for pid, info in self.principals.items():
            if pid != principal:
                out += list(info.get("owned", [])) + list(info.get("canaries", []))
        return out

    def foreign_canaries(self, principal: str) -> list:
        return [c for pid, i in self.principals.items() if pid != principal for c in i.get("canaries", [])]

    def all_canaries(self) -> list:
        return [c for i in self.principals.values() for c in i.get("canaries", [])] + list(self.document_canaries)
