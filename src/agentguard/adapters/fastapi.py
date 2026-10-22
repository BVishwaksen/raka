"""FastAPI helper (extra: agentguard[sidecar]). Raises HTTP 400 when the input guard blocks."""
from __future__ import annotations

from ..api import Guard, Session, UserInput


def input_dependency(guard: Guard, session_factory):
    """Usage: ``Depends(input_dependency(guard, lambda req: Session(...)))`` on a route with a ``text`` query."""
    from fastapi import HTTPException, Request  # type: ignore

    async def dep(request: Request, text: str) -> str:
        v = guard.check(UserInput(session_factory(request), text))
        if v.action == "block":
            raise HTTPException(status_code=400, detail="request blocked by security policy")
        return v.modified_payload if v.action == "modify" else text

    return dep
