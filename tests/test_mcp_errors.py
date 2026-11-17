"""Kit failures reach an MCP caller as the CLI's failure JSON (D-4, orchestrator ruling 2026-11-16).

mcp 2.x treats any tool exception other than its ``ToolError`` as a crash and keeps the
text server-side, so an MCP caller of ``lhub.py mcp`` saw only "Error executing tool
<name>". ``build_mcp_server`` now re-raises a ``KitError`` as the SDK's ``ToolError``
whose message is exactly the JSON object the CLI prints for that failure, built by the
same ``failure_payload`` helper ``main`` uses. Pinned through the REAL server and an
in-process client of whichever mcp major is installed (run the 1.x leg with
``uv run --with 'mcp<2' pytest tests/test_mcp_errors.py``):

  * a plain KitError (the ``deliver`` input-root refusal) and a retryable refusal arrive
    as the CLI JSON — byte-for-byte what ``main`` prints for the same failure;
  * a ``hire`` that fails after its deal opened carries ``deal_id``/``stage``/``next_step``,
    and a ``KitFailure`` (hire timeout) carries its payload, as on the CLI;
  * any other exception keeps the SDK's own handling (control).
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import logging
from pathlib import Path
from typing import Any

import pytest
from routerkit import RouterKit
from test_hire_failure import DEAL_ID, LISTING_ID, FlowWorld, outage

import lhub

pytest.importorskip("mcp")
MCP_MAJOR = int(importlib.metadata.version("mcp").split(".")[0])


async def _call(name: str, arguments: dict[str, Any]) -> tuple[bool, str]:
    server = lhub.build_mcp_server()
    if MCP_MAJOR >= 2:
        from mcp.client.client import Client

        async with Client(server) as client:
            result: Any = await client.call_tool(name, arguments)
            is_error = result.is_error
    else:
        # mcp 1.x. A 2.x-typed mypy cannot see this 1.x helper; the branch only
        # runs on a 1.x install (the `uv run --with 'mcp<2'` leg).
        from mcp.shared.memory import (  # type: ignore[attr-defined]
            create_connected_server_and_client_session,
        )

        async with create_connected_server_and_client_session(server._mcp_server) as session:
            result = await session.call_tool(name, arguments)
            is_error = result.isError
    text = "".join(str(getattr(item, "text", "")) for item in result.content)
    return bool(is_error), text


def call_tool(name: str, arguments: dict[str, Any]) -> tuple[bool, str]:
    """Call one tool on the real kit MCP server; return (is_error, the caller's text)."""
    logging.disable(logging.CRITICAL)  # the SDK logs tool failures server-side
    try:
        return asyncio.run(_call(name, arguments))
    finally:
        logging.disable(logging.NOTSET)


def tool_error_text(tool: str, cli_stdout: str) -> str:
    """What the caller must see: the SDK's prefix, then the CLI's JSON (no newline)."""
    return f"Error executing tool {tool}: {cli_stdout.removesuffix(chr(10))}"


def use_kit(monkeypatch: pytest.MonkeyPatch, kit: lhub.Kit) -> None:
    def from_env(base_url: str | None = None) -> lhub.Kit:
        return kit

    monkeypatch.setattr(lhub.Kit, "from_env", staticmethod(from_env))


@pytest.fixture
def input_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = (tmp_path / "inputs").resolve()
    root.mkdir()
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", root)
    return root


def test_plain_kit_error_reaches_the_caller_as_the_cli_json(input_root: Path) -> None:
    # The repro: pre-fix, 2.x callers saw exactly "Error executing tool deliver".
    with pytest.raises(lhub.KitError) as refused:
        lhub.resolve_input_path("/etc/hosts", input_root)
    is_error, text = call_tool("deliver", {"deal_id": DEAL_ID, "file_path": "/etc/hosts"})
    assert is_error
    assert text == tool_error_text("deliver", lhub.json_text({"error": str(refused.value)}))
    payload = json.loads(text.removeprefix("Error executing tool deliver: "))
    assert payload == {"error": str(refused.value)}
    assert str(input_root) not in text  # operator-local context stays off the LLM surface


def test_retryable_refusal_matches_the_cli_byte_for_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise outage(name)

    kit = RouterKit(tmp_path / "home", route)
    kit.ensure_key()
    use_kit(monkeypatch, kit)
    assert lhub.main(["balance"]) == 1
    cli_stdout = capsys.readouterr().out

    is_error, text = call_tool("balance", {})
    assert is_error
    assert text == tool_error_text("balance", cli_stdout)
    payload = json.loads(text.removeprefix("Error executing tool balance: "))
    assert list(payload) == ["error", "code", "retryable"]
    assert payload["code"] == "upstream_unavailable"
    assert payload["retryable"] is True


def test_post_open_hire_failure_carries_the_deal_like_the_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    input_root: Path,
) -> None:
    world = FlowWorld(tmp_path)
    world.failures["propose_agreement"] = outage("propose_agreement")
    use_kit(monkeypatch, world.kit)
    (input_root / "input.txt").write_bytes(world.input_path.read_bytes())

    argv = ["hire", "--listing", LISTING_ID, "--input", str(world.input_path)]
    assert lhub.main([*argv, "--max-price", "1.00"]) == 1
    cli_stdout = capsys.readouterr().out

    is_error, text = call_tool(
        "hire", {"listing_id": LISTING_ID, "input_path": "input.txt", "max_price": "1.00"}
    )
    assert is_error
    assert text == tool_error_text("hire", cli_stdout)
    payload = json.loads(text.removeprefix("Error executing tool hire: "))
    assert payload["deal_id"] == DEAL_ID
    assert payload["stage"] == lhub.HIRE_STAGE_OPENED
    assert f"python lhub.py status --deal {DEAL_ID}" in payload["next_step"]
    assert list(payload)[:3] == ["error", "code", "retryable"]


def test_kit_failure_payload_reaches_the_caller_like_the_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    input_root: Path,
) -> None:
    # A KitFailure (the countersign wait timed out) prints its deal view plus
    # `error` on the CLI; the MCP caller gets the same object.
    world = FlowWorld(tmp_path)
    use_kit(monkeypatch, world.kit)
    (input_root / "input.txt").write_bytes(world.input_path.read_bytes())

    argv = ["hire", "--listing", LISTING_ID, "--input", str(world.input_path)]
    assert lhub.main([*argv, "--max-price", "1.00", "--timeout", "0"]) == 1
    cli_stdout = capsys.readouterr().out

    is_error, text = call_tool(
        "hire",
        {
            "listing_id": LISTING_ID,
            "input_path": "input.txt",
            "max_price": "1.00",
            "timeout_seconds": 0,
        },
    )
    assert is_error
    assert text == tool_error_text("hire", cli_stdout)
    payload = json.loads(text.removeprefix("Error executing tool hire: "))
    assert payload["deal_id"] == DEAL_ID
    assert payload["stage"] == lhub.HIRE_STAGE_PROPOSED
    assert payload["error"].startswith("timed out after 0s")


def test_other_exceptions_keep_the_sdk_handling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Control: only KitError is converted. A crash keeps the SDK's own text —
    # on 2.x the generic one, with nothing of the exception's text.
    detail = "internal detail /private/secret/path"

    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError(detail)

    kit = RouterKit(tmp_path / "home", route)
    kit.ensure_key()
    use_kit(monkeypatch, kit)
    is_error, text = call_tool("balance", {})
    assert is_error
    if MCP_MAJOR >= 2:
        assert text == "Error executing tool balance"
        assert "secret" not in text
    else:
        # 1.x's own (unchanged) handling of any exception: prefix + its text.
        assert text == f"Error executing tool balance: {detail}"
    assert "{" not in text  # never the CLI JSON
