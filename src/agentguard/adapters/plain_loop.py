"""Thin helpers for wrapping a plain Python tool-calling loop."""
from __future__ import annotations

import functools
from typing import Callable

from ..api import Guard, ModelOutput, Session, ToolCall, UserInput


class GuardBlocked(Exception):
    def __init__(self, verdict):
        super().__init__(f"{verdict.rule_id}: {verdict.reason}")
        self.verdict = verdict


def guarded_tool(guard: Guard, get_session: Callable[[], Session], name: str = None,
                 provenance: Callable[[], str] = lambda: "user_request"):
    """Decorator: run the tool guard before the function executes (keyword args are the tool args)."""
    def deco(fn):
        tool_name = name or fn.__name__

        @functools.wraps(fn)
        def wrapper(**kwargs):
            v = guard.check(ToolCall(get_session(), tool_name, kwargs, provenance()))
            if v.action == "block" or v.rule_id == "APPROVAL_REQUIRED":
                raise GuardBlocked(v)
            return fn(**kwargs)
        return wrapper
    return deco


def guard_input(guard: Guard, session: Session, text: str) -> str:
    v = guard.check(UserInput(session, text))
    if v.action == "block":
        raise GuardBlocked(v)
    return v.modified_payload if v.action == "modify" and isinstance(v.modified_payload, str) else text


def guard_output(guard: Guard, session: Session, text: str, tool_results=None) -> str:
    v = guard.check(ModelOutput(session, text, tool_results or []))
    if v.action == "block":
        raise GuardBlocked(v)
    return v.modified_payload if v.action == "modify" and isinstance(v.modified_payload, str) else text
