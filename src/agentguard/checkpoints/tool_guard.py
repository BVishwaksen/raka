"""Tool guard: deterministic per-call checks. The layer's strongest control."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ..api import ToolCall, Verdict

UNTRUSTED_PROVENANCE = {"retrieved_content", "tool_output", "untrusted", "retrieved"}
ROW_KEYS = ("limit", "max_rows", "top", "n_rows", "page_size")


def _block(rule: str, reason: str) -> Verdict:
    return Verdict("block", reason, rule)


def _domains(value: str) -> list:
    out = []
    for part in re.split(r"[,\s;]+", value):
        if part.startswith(("http://", "https://")):
            host = urlparse(part).hostname
            if host:
                out.append(host.lower())
        elif "@" in part:
            out.append(part.rsplit("@", 1)[1].strip(">").lower())
    return out


class ToolGuard:
    def __init__(self, policy, manifest, state):
        self.policy, self.manifest, self.state = policy, manifest, state

    def check(self, call: ToolCall) -> Verdict:
        s = call.session
        spec = self.manifest.tools.get(call.tool)
        if spec is None:
            return _block("TOOL_NOT_IN_MANIFEST", f"tool {call.tool!r} is not declared in the manifest")
        override = self.policy.tool_override(call.tool)
        if not spec.enabled or override.get("enabled") is False:
            return _block("TOOL_DISABLED", f"tool {call.tool!r} is disabled")
        if spec.requires_auth and not s.authenticated:
            return _block("AUTH_REQUIRED", "tool requires an authenticated session")

        args = call.args or {}
        for p in spec.trusted_params:  # must equal the session's trusted value, never model-supplied
            if p not in args:
                return _block("TRUSTED_PARAM_MISSING", f"trusted parameter {p!r} was not bound by the host")
            if str(args[p]) != str(s.principal_id):
                return _block("TRUSTED_PARAM_MISMATCH", f"{p} differs from session principal")
        for p, pattern in spec.validated_params.items():
            if p not in args:
                return _block("ARG_MISSING", f"required argument {p!r} is missing")
            v = args[p]
            if isinstance(v, (dict, list)) or not re.fullmatch(pattern, str(v)):
                return _block("ARG_INVALID", f"argument {p!r} does not match the declared pattern")
        allowed = [d.lower() for d in spec.allowed_domains]
        if allowed:
            for k, v in args.items():
                vals = v if isinstance(v, list) else [v]
                for item in vals:
                    if isinstance(item, str):
                        for dom in _domains(item):
                            if not any(dom == a or dom.endswith("." + a) for a in allowed):
                                return _block("DOMAIN_NOT_ALLOWED", f"argument {k!r} targets a non-allowlisted domain")
        if spec.max_rows is not None:
            for k in ROW_KEYS:
                if isinstance(args.get(k), int) and args[k] > spec.max_rows:
                    return _block("ROW_LIMIT_EXCEEDED", f"{k} exceeds manifest max_rows")

        flags: list[Verdict] = []
        if call.provenance in UNTRUSTED_PROVENANCE:
            action = self.policy.get("provenance", "untrusted_action", default="block")
            v = Verdict(action, "call followed only from retrieved/tool-returned content", "UNTRUSTED_PROVENANCE")
            if action == "block":
                return v
            flags.append(v)

        # limits
        max_total = self.policy.get("limits", "max_tool_calls_per_session")
        if max_total is not None and self.state.tool_total[s.id] >= max_total:
            return _block("RATE_LIMIT_SESSION", "per-session tool call budget exhausted")
        per_min = override.get("max_calls_per_minute", spec.max_calls_per_minute)
        if per_min is not None and self.state.tool_minute_count(s.id, call.tool) >= per_min:
            return _block("RATE_LIMIT_TOOL", "per-minute call limit for this tool exceeded")

        # approval
        level = override.get("approval", spec.approval)
        if level == "auto" and spec.side_effects and self.policy.get("approval", "confirm_side_effects", default=False):
            level = "confirm"
        approved = call.tool in (s.attributes.get("approved_tools") or [])
        if level != "auto" and not (approved and level == "confirm"):
            v = Verdict("flag", f"approval required ({level})", "APPROVAL_REQUIRED",
                        modified_payload={"approval": level})
            self._record(call)
            return v

        # anomaly: tight loops
        sig = call.tool + json.dumps(args, sort_keys=True, default=str)
        threshold = int(self.policy.get("limits", "loop_threshold", default=3))
        if self.state.previous_identical(s.id, sig) >= threshold - 1:
            flags.append(Verdict("flag", "identical call repeated (possible loop)", "LOOP_DETECTED"))
        self._record(call)
        if flags:
            return flags[0]
        return Verdict("allow", "", "TOOL_OK")

    def _record(self, call: ToolCall) -> None:
        sig = call.tool + json.dumps(call.args or {}, sort_keys=True, default=str)
        self.state.record_tool(call.session.id, call.tool, sig)
