"""The `lhub.py mcp` stdio server toolset — budget is NEVER exposed (sec N-12)."""

from __future__ import annotations

import asyncio
import inspect

import pytest

import lhub

EXPECTED_TOOLS = {
    # Buyer tools (add-agent-front-door D-11).
    "find_services",
    "hire",
    "get_result",
    "accept",
    "dispute",
    "balance",
    # Seller tools (add-agent-seller-door task 4.6).
    "sell",
    "my_listings",
    "inbox",
    "deliver",
}


def test_registry_is_exactly_the_ten_kit_tools() -> None:
    functions = lhub.mcp_tool_functions()
    assert set(functions) == EXPECTED_TOOLS
    assert set(lhub.MCP_TOOL_NAMES) == EXPECTED_TOOLS


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
