"""Test helper: a ``Kit`` whose tool calls go to an in-test router (no network).

The seller-flow tests drive the REAL flows (``do_sell`` / ``do_inbox`` /
``do_deliver`` / ``run_serve_job``) against scripted tool results, so what is
proven is the kit's own behaviour — signing only self-built bytes, refusing
before signing, deriving idempotency keys — not a re-implementation of it.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import lhub

Router = Callable[[str, dict[str, Any]], dict[str, Any]]


def use_kit(monkeypatch: pytest.MonkeyPatch, kit: lhub.Kit) -> None:
    """Make every ``Kit.from_env()`` (the CLI and the MCP tools) return ``kit``."""

    def from_env(base_url: str | None = None) -> lhub.Kit:
        return kit

    monkeypatch.setattr(lhub.Kit, "from_env", staticmethod(from_env))


class RouterKit(lhub.Kit):
    """A Kit with the MCP transport replaced by a per-test router function."""

    def __init__(self, home: Path, router: Router) -> None:
        super().__init__("http://localhost:19999", home)
        self.router = router
        self.tool_calls: list[tuple[str, dict[str, Any]]] = []
        self.with_session_flags: list[bool] = []
        self.ensure_session_calls = 0

    def ensure_session(self) -> None:
        self.ensure_session_calls += 1
        self.ensure_key()
        self._session_token = "test-session-token"

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        with_session: bool = True,
        _recover: int = 2,
    ) -> dict[str, Any]:
        self.tool_calls.append((name, arguments))
        self.with_session_flags.append(with_session)
        return self.router(name, arguments)

    def calls_to(self, name: str) -> list[dict[str, Any]]:
        return [arguments for tool, arguments in self.tool_calls if tool == name]
