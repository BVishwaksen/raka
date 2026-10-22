"""Public API of the Agent Security Layer.

This module is the contract: events (plain dataclasses), Verdict, Manifest and Guard.
Dependency direction: agent -> layer -> nothing. Nothing in here imports agent code.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Optional, Sequence, Union

import yaml

API_VERSION = "1"
Action = Literal["allow", "block", "flag", "modify"]
VALID_APPROVAL = ("auto", "confirm", "human_only")

log = logging.getLogger("agentguard")


# --------------------------------------------------------------------------- events
@dataclass
class Session:
    id: str
    principal_id: Optional[str] = None
    auth_level: str = "anonymous"  # "anonymous" or anything else = authenticated
    attributes: dict = field(default_factory=dict)

    @property
    def authenticated(self) -> bool:
        return self.auth_level != "anonymous" and bool(self.principal_id)


@dataclass
class UserInput:
    session: Session
    text: str


@dataclass
class RetrievedContext:
    session: Session
    chunks: list  # each chunk: str or dict with "text" + origin metadata
    source: str = ""


@dataclass
class ToolCall:
    session: Session
    tool: str
    args: dict
    provenance: str = "user_request"  # user_request | retrieved_content | tool_output | ...


@dataclass
class ModelOutput:
    session: Session
    text: str
    tool_results: list = field(default_factory=list)


Event = Union[UserInput, RetrievedContext, ToolCall, ModelOutput]


@dataclass
class Verdict:
    action: Action = "allow"
    reason: str = ""
    rule_id: str = ""
    score: Optional[float] = None
    modified_payload: Any = None
    mode: Literal["enforce", "shadow", "off"] = "enforce"

    @property
    def blocked(self) -> bool:
        return self.action == "block"


# ------------------------------------------------------------------------- manifest
@dataclass
class ToolSpec:
    name: str
    requires_auth: bool = True
    trusted_params: list = field(default_factory=list)
    validated_params: dict = field(default_factory=dict)
    max_rows: Optional[int] = None
    approval: str = "auto"
    allowed_domains: list = field(default_factory=list)
    enabled: bool = True
    side_effects: bool = False
    max_calls_per_minute: Optional[int] = None


@dataclass
class Manifest:
    """Neutral description of an agent's tools. How the layer stays generic."""

    tools: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Manifest":
        data = data.get("tools", data) if isinstance(data, dict) else {}
        tools: dict[str, ToolSpec] = {}
        for name, raw in data.items():
            raw = dict(raw or {})
            unknown = set(raw) - set(ToolSpec.__dataclass_fields__) - {"name"}
            if unknown:
                raise ValueError(f"manifest tool {name!r}: unknown keys {sorted(unknown)}")
            raw.pop("name", None)
            spec = ToolSpec(name=name, **raw)
            if spec.approval not in VALID_APPROVAL:
                raise ValueError(f"manifest tool {name!r}: approval must be one of {VALID_APPROVAL}")
            for p, pat in spec.validated_params.items():
                try:
                    re.compile(pat)
                except re.error as e:
                    raise ValueError(f"manifest tool {name!r}: bad pattern for {p!r}: {e}") from e
            tools[name] = spec
        return cls(tools=tools)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "Manifest":
        return cls.from_dict(yaml.safe_load(Path(path).read_text()) or {})


# ---------------------------------------------------------------------------- guard
class Guard:
    """Entry point. ``guard.check(event)`` returns a Verdict and writes one audit event."""

    def __init__(self, policy, manifest: Optional[Manifest] = None, sinks: Sequence = (),
                 classifier: Optional[Callable[[str], float]] = None,
                 time_fn: Callable[[], float] = time.time):
        from .checkpoints import ContextGuard, InputGuard, OutputGuard, ToolGuard
        from .checkpoints._state import RateState

        self.policy = policy
        self.manifest = manifest or Manifest()
        self.sinks = list(sinks)
        self._state = RateState(time_fn)
        self._input = InputGuard(policy, self._state, classifier)
        self._context = ContextGuard(policy)
        self._tool = ToolGuard(policy, self.manifest, self._state)
        self._output = OutputGuard(policy)

    @classmethod
    def from_config(cls, config=None, manifest: Optional[Manifest] = None, sinks: Sequence = (),
                    classifier=None) -> "Guard":
        from .policy.engine import load_policy
        return cls(load_policy(config), manifest, sinks, classifier)

    # -- dispatch ----------------------------------------------------------------
    def check(self, event: Event) -> Verdict:
        if isinstance(event, UserInput):
            cp, subject, fn = "input_guard", "user_input", self._input.check
        elif isinstance(event, RetrievedContext):
            cp, subject, fn = "context_guard", event.source or "retrieved_context", self._context.check
        elif isinstance(event, ToolCall):
            cp, subject, fn = "tool_guard", event.tool, self._tool.check
        elif isinstance(event, ModelOutput):
            cp, subject, fn = "output_guard", "model_output", self._output.check
        else:
            raise TypeError(f"unsupported event type: {type(event).__name__}")

        mode = self.policy.mode(cp)
        if mode == "off":
            return Verdict("allow", "checkpoint disabled", "MODE_OFF", mode="off")

        t0 = time.perf_counter()
        error = None
        try:
            verdict = fn(event)
        except Exception as exc:  # fail mode decides
            log.exception("checkpoint %s failed", cp)
            error = f"{type(exc).__name__}: {exc}"
            tool = event.tool if isinstance(event, ToolCall) else None
            if self.policy.failure(cp, tool) == "closed":
                verdict = Verdict("block", "checkpoint error (fail closed)", "CHECK_ERROR")
            else:
                verdict = Verdict("flag", "checkpoint error (fail open)", "CHECK_ERROR_FAIL_OPEN")
        verdict.mode = mode
        latency = (time.perf_counter() - t0) * 1000
        self._audit(cp, subject, event.session, verdict, latency, error)

        if mode == "shadow" and verdict.action != "allow":
            return Verdict("allow", f"shadow: would {verdict.action}: {verdict.reason}",
                           verdict.rule_id, verdict.score, None, "shadow")
        return verdict

    def scan_document(self, text: str, source: str = "") -> Verdict:
        """Ingestion-time scan: quarantine instead of re-checking on every query."""
        from .checkpoints.context_guard import scan_text
        score, findings = scan_text(text)
        limit = self.policy.get("context", "quarantine_score", default=2)
        if score >= limit:
            v = Verdict("block", "document quarantined: " + ", ".join(sorted(findings)),
                        "DOC_QUARANTINE", float(score))
        elif findings:
            v = Verdict("flag", "document has minor findings: " + ", ".join(sorted(findings)),
                        "DOC_SUSPICIOUS", float(score))
        else:
            v = Verdict("allow", "", "DOC_OK", 0.0)
        self._audit("context_guard", source or "document", Session("ingest"), v, 0.0, None, extra="ingestion")
        return v

    # -- audit -------------------------------------------------------------------
    def _ident(self, value: Optional[str]) -> Optional[str]:
        if value and self.policy.get("audit", "hash_identifiers", default=False):
            salt = str(self.policy.get("audit", "salt", default=""))
            return "h_" + hashlib.sha256((salt + value).encode()).hexdigest()[:12]
        return value

    def _audit(self, cp, subject, session, verdict, latency, error, extra=None):
        from .audit.events import make_event
        evt = make_event(
            session=self._ident(session.id), principal=self._ident(session.principal_id),
            checkpoint=cp, subject=subject, verdict=verdict, latency_ms=latency,
            policy_version=self.policy.version, error=error, note=extra,
        )
        for sink in self.sinks:
            try:
                sink.write(evt)
            except Exception:  # audit failures must never break the host
                log.exception("audit sink %r failed", sink)
