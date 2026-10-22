"""Policy = configuration. Plain-Python evaluation; an external engine can sit behind this later."""
from __future__ import annotations

import copy
import warnings
from pathlib import Path
from typing import Any, Optional, Union

import yaml

SUPPORTED_SCHEMA = 1
PROFILES_DIR = Path(__file__).parent / "profiles"
CHECKPOINTS = ("input_guard", "context_guard", "tool_guard", "output_guard")

DEFAULTS: dict = {
    "version": 1,
    "profile": "balanced",
    "modes": {"input_guard": "shadow", "context_guard": "enforce", "tool_guard": "enforce",
              "output_guard": "enforce"},
    "failure": {"tool_guard": "closed", "input_guard": "open", "context_guard": "open",
                "output_guard": "open"},
    "limits": {"max_tool_calls_per_session": 20, "max_input_chars": 8000, "max_inputs_per_minute": 30,
               "loop_threshold": 3},
    "input": {"block_score": 0.8, "redact_pii": False},
    "context": {"quarantine_score": 2},
    "provenance": {"untrusted_action": "block"},
    "approval": {"confirm_side_effects": False},
    "output": {"block_external_images": True, "allowed_link_domains": [], "canaries": [],
               "secret_patterns": True, "forbidden_commitments": [], "commitment_action": "flag",
               "grounded_patterns": []},
    "audit": {"hash_identifiers": False, "salt": ""},
    "overrides": {"tools": {}},
}


def deep_merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Policy:
    def __init__(self, data: dict):
        self.data = data

    @property
    def version(self) -> int:
        return int(self.data.get("version", 1))

    @property
    def profile(self) -> str:
        return self.data.get("profile", "balanced")

    def get(self, *path: str, default: Any = None) -> Any:
        cur: Any = self.data
        for p in path:
            if not isinstance(cur, dict) or p not in cur:
                return default
            cur = cur[p]
        return cur

    def mode(self, checkpoint: str) -> str:
        m = self.get("modes", checkpoint, default="enforce")
        if m not in ("off", "shadow", "enforce"):
            raise ValueError(f"invalid mode {m!r} for {checkpoint}")
        return m

    def failure(self, checkpoint: str, tool: Optional[str] = None) -> str:
        if tool:
            o = self.tool_override(tool).get("failure")
            if o:
                return o
        return self.get("failure", checkpoint, default="closed")

    def tool_override(self, tool: str) -> dict:
        return self.get("overrides", "tools", tool, default={}) or {}


def load_policy(src: Union[None, str, Path, dict, Policy] = None) -> Policy:
    if isinstance(src, Policy):
        return src
    if src is None:
        raw: dict = {}
    elif isinstance(src, dict):
        raw = src
    else:
        raw = yaml.safe_load(Path(src).read_text()) or {}
    version = int(raw.get("version", 1))
    if version > SUPPORTED_SCHEMA:
        raise ValueError(f"policy schema version {version} is newer than supported ({SUPPORTED_SCHEMA})")
    profile = raw.get("profile", DEFAULTS["profile"])
    pfile = PROFILES_DIR / f"{profile}.yaml"
    if not pfile.exists():
        raise ValueError(f"unknown profile {profile!r}")
    profile_data = yaml.safe_load(pfile.read_text()) or {}
    data = deep_merge(deep_merge(DEFAULTS, profile_data), raw)
    data["profile"] = profile
    return Policy(data)
