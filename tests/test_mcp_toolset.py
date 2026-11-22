"""The `lhub.py mcp` stdio server toolset — budget is NEVER exposed (sec N-12) — and each
tool's title and MCP annotations (add-claude-code-plugin design D-1; the `owner_link` row
is add-owner-confirm-link design D-11's)."""

from __future__ import annotations

import asyncio
import importlib.metadata
import inspect
import re
from pathlib import Path
from typing import Any

import pytest

import lhub

KIT_README = Path(__file__).resolve().parents[1] / "README.md"

EXPECTED_TOOLS = {
    # Buyer tools (add-agent-front-door D-11).
    "find_services",
    "hire",
    "get_result",
    "accept",
    "dispute",
    "balance",
    # The owner approval link (add-owner-confirm-link D-11, kit 0.3.3).
    "owner_link",
    # Seller tools (add-agent-seller-door task 4.6).
    "sell",
    "my_listings",
    "inbox",
    "deliver",
}

# The add-claude-code-plugin design D-1 table, copied here independently of
# lhub.MCP_TOOL_ANNOTATIONS so a change on either side fails:
# (title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint).
D1_TABLE: dict[str, tuple[str, bool, bool, bool, bool]] = {
    "find_services": ("Find services", True, False, True, False),
    "balance": ("Get balance", False, False, True, False),
    "my_listings": ("List my listings", False, False, True, False),
    "get_result": ("Get result", False, True, True, False),
    "hire": ("Hire a service", False, True, False, True),
    "accept": ("Accept delivery", False, True, True, True),
    "dispute": ("Dispute deal", False, True, True, True),
    "sell": ("Create listing", False, False, False, False),
    # Not idempotent (D-1 item 5): a repeat countersigns proposals that arrived since.
    "inbox": ("Check seller inbox", False, True, False, True),
    "deliver": ("Deliver result", False, False, True, True),
    # add-owner-confirm-link D-11 (the bridge's D-3 readings): every hint false. Not
    # idempotent: a repeat replaces the deal's link. Not destructive: it moves no money.
    "owner_link": ("Request owner confirmation link", False, False, False, False),
}
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
# The MCP protocol default of an absent hint: what a client reads, so an
# "effective" value maps a missing hint to this.
HINT_DEFAULTS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}


def test_registry_is_exactly_the_eleven_kit_tools() -> None:
    functions = lhub.mcp_tool_functions()
    assert set(functions) == EXPECTED_TOOLS
    assert set(lhub.MCP_TOOL_NAMES) == EXPECTED_TOOLS
    assert len(lhub.MCP_TOOL_NAMES) == len(EXPECTED_TOOLS) == 11


def test_kit_readme_names_exactly_the_registry() -> None:
    # The served /kit/README.md says which tools `lhub.py mcp` exposes; a tool added
    # to the registry (owner_link, kit 0.3.3) must appear there too, and nothing else.
    text = " ".join(KIT_README.read_text(encoding="utf-8").split())
    _head, found, rest = text.partition("exposing exactly: ")
    assert found, "the kit README no longer states the tools `lhub.py mcp` exposes"
    listed = re.findall(r"`([^`]+)`", rest.partition(".")[0])
    assert sorted(listed) == sorted(lhub.MCP_TOOL_NAMES)


def test_registry_never_mentions_budget() -> None:
    handler_names = set()
    for name, fn in lhub.mcp_tool_functions().items():
        assert "budget" not in name.lower()
        handler_names.add(fn.__name__)
    # And no registered handler routes to the budget command.
    assert "cmd_budget_set" not in handler_names
    assert not any("budget" in handler for handler in handler_names)


def test_mcp_server_exposes_exactly_the_registry() -> None:
    """Build the real MCP server and list its tools (needs the `mcp` extra).

    list_tools() is synchronous in mcp 2.x and a coroutine in 1.x — both are
    handled so the assertion holds on whichever major is installed.
    """
    pytest.importorskip("mcp")
    server = lhub.build_mcp_server()
    tools = server.list_tools()
    if inspect.iscoroutine(tools):
        tools = asyncio.run(tools)
    names = {tool.name for tool in tools}
    assert names == EXPECTED_TOOLS
    assert not any("budget" in name.lower() for name in names)


# ---------------------------------------------------------------------------
# Titles and annotations (add-claude-code-plugin D-1).
# ---------------------------------------------------------------------------


def test_every_tool_has_exactly_one_annotation_row() -> None:
    assert set(lhub.MCP_TOOL_ANNOTATIONS) == set(lhub.MCP_TOOL_NAMES) == set(D1_TABLE)


def _mcp_major() -> int:
    pytest.importorskip("mcp")
    return int(importlib.metadata.version("mcp").split(".")[0])


async def _listed_tools(server: Any, major: int) -> list[dict[str, Any]]:
    """tools/list through a real in-process client, each tool in wire form (camelCase)."""
    if major >= 2:
        from mcp.client.client import Client

        async with Client(server) as client:
            listed: Any = await client.list_tools()
    else:
        # mcp 1.x. A 2.x-typed mypy cannot see this 1.x helper; the branch only
        # runs on a 1.x install (the `uv run --with 'mcp<2'` leg).
        from mcp.shared.memory import (  # type: ignore[attr-defined]
            create_connected_server_and_client_session,
        )

        async with create_connected_server_and_client_session(server._mcp_server) as session:
            listed = await session.list_tools()
    return [tool.model_dump(by_alias=True, mode="json", exclude_none=True) for tool in listed.tools]


def test_tools_carry_the_d1_title_and_annotations_on_the_wire() -> None:
    major = _mcp_major()
    server = lhub.build_mcp_server()
    accepted = inspect.signature(server.add_tool).parameters
    tools = {tool["name"]: tool for tool in asyncio.run(_listed_tools(server, major))}
    assert set(tools) == EXPECTED_TOOLS
    if major < 2 and "annotations" not in accepted:
        # An old 1.x: registered without annotations (D-1), still served.
        assert all("annotations" not in tool for tool in tools.values())
        return
    assert major < 2 or {"title", "annotations"} <= set(accepted)  # 2.x always has both
    for name, (title, *hints) in D1_TABLE.items():
        wire = tools[name]
        annotations = wire["annotations"]
        effective = [annotations.get(hint, HINT_DEFAULTS[hint]) for hint in HINTS]
        assert effective == hints, name
        # Stronger than effective: every hint is explicit, none left to a default.
        assert set(HINTS) <= set(annotations), name
        assert annotations["title"] == title, name
        if "title" in accepted:
            assert wire["title"] == title, name
        # Annotations change no description (the tool's own docstring).
        assert wire["description"] == lhub.mcp_tool_functions()[name].__doc__, name


def test_an_add_tool_without_the_keywords_gets_no_metadata() -> None:
    # The mcp 1.2-era FastMCP.add_tool(fn, name=None, description=None): the
    # kit registers without title/annotations instead of failing (D-1).
    def add_tool(fn: Any, name: str | None = None, description: str | None = None) -> None:
        raise AssertionError("introspected, never called")

    for name in lhub.MCP_TOOL_NAMES:
        assert lhub._mcp_tool_metadata(add_tool, name) == {}


def test_an_annotations_only_add_tool_carries_the_title_inside() -> None:
    # A 1.x whose add_tool takes annotations= but not title= (mcp 1.9.x): the
    # title still reaches clients, as annotations.title. An mcp too old to
    # model ToolAnnotations at all (before 1.9) gets no metadata, not an error.
    types = pytest.importorskip("mcp.types")

    def add_tool(
        fn: Any, name: str | None = None, description: str | None = None, annotations: Any = None
    ) -> None:
        raise AssertionError("introspected, never called")

    metadata = lhub._mcp_tool_metadata(add_tool, "inbox")
    if not hasattr(types, "ToolAnnotations"):
        assert metadata == {}
        return
    assert set(metadata) == {"annotations"}
    assert metadata["annotations"].model_dump(by_alias=True, exclude_none=True) == {
        "title": "Check seller inbox",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    }


def test_parse_sse_extracts_jsonrpc_messages() -> None:
    raw = (
        b"event: message\r\n"
        b'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\r\n'
        b"\r\n"
        b"event: message\n"
        b'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n'
        b"\n"
        b": a comment line\n\n"
    )
    messages = lhub.parse_sse(raw)
    assert {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}} in messages
    assert any(m.get("method") == "notifications/progress" for m in messages)


def test_parse_sse_joins_multiline_data() -> None:
    raw = b'data: {"a":\ndata:  1}\n\n'
    assert lhub.parse_sse(raw) == [{"a": 1}]
