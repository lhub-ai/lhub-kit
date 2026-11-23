"""The default marketplace (fix-kit-default-url D-1, D-2, D-6; spec agent-kit
"Default Marketplace").

Each check runs the kit's real code down to ``Kit._http_post``, which a scripted
bridge replaces, so what is proven is where the kit's requests actually go, not
a restatement of the resolution order. No socket is opened: the transport is
stubbed, and the conftest's socket guard refuses any non-loopback connect anyway.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import lhub

PUBLIC = "https://lhub.ai"
FLAG_URL = "https://flag.invalid"
ENV_URL = "https://env.invalid"
JSON_HEADERS = {"Content-Type": "application/json"}
SEARCH_RESULT: dict[str, Any] = {
    "total": 1,
    "results": [{"listing": {"id": "00000000-0000-4000-8000-000000000001"}}],
}
TOOL_PAYLOADS: dict[str, dict[str, Any]] = {
    "search_services": SEARCH_RESULT,
    "auth_challenge": {"nonce": "nonce-1", "audience": lhub.HANDSHAKE_AUDIENCE},
    "auth_complete": {"session_token": "session-1", "expires_at": "2099-01-01T00:00:00Z"},
    "register_agent": {"agent_did": "did:key:zRegistered", "replayed": False},
    "get_balance": {"available": {"amount": 10_000_000, "unit": "LHUB-DEV"}},
}
INIT_CALLS = [
    "initialize",
    "notifications/initialized",
    "auth_challenge",
    "auth_complete",
    "register_agent",
    "get_balance",
]
# The D-6 table (--url and LHUB_URL both set; only LHUB_URL; neither), the
# --url-only row that completes it, and the empty values: an empty --url or
# LHUB_URL counts as unset (spec agent-kit "Default Marketplace").
PRECEDENCE = [
    pytest.param(FLAG_URL, ENV_URL, FLAG_URL, id="both-set-url-flag-wins"),
    pytest.param(None, ENV_URL, ENV_URL, id="only-LHUB_URL"),
    pytest.param(None, None, PUBLIC, id="neither-default"),
    pytest.param(FLAG_URL, None, FLAG_URL, id="only-url-flag"),
    pytest.param("", None, PUBLIC, id="empty-url-flag-is-unset"),
    pytest.param(None, "", PUBLIC, id="empty-LHUB_URL-is-unset"),
    pytest.param("", "", PUBLIC, id="both-empty-default"),
    pytest.param("", ENV_URL, ENV_URL, id="empty-url-flag-falls-to-LHUB_URL"),
    pytest.param(FLAG_URL, "", FLAG_URL, id="url-flag-over-empty-LHUB_URL"),
]


class ScriptedBridge:
    """An MCP bridge behind ``Kit._http_post`` that records every request."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str]]] = []

    @property
    def urls(self) -> set[str]:
        return {url for url, _name, _headers in self.requests}

    @property
    def calls(self) -> list[str]:
        return [name for _url, name, _headers in self.requests]

    def post(
        self, url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        message = json.loads(body)
        method = str(message.get("method"))
        name = str(message["params"]["name"]) if method == "tools/call" else method
        self.requests.append((url, name, dict(headers)))
        result: dict[str, Any]
        if method == "initialize":
            result = {"protocolVersion": lhub.MCP_PROTOCOL_VERSION, "capabilities": {}}
            return 200, {**JSON_HEADERS, lhub.MCP_SESSION_HEADER: "sid-1"}, reply(message, result)
        if method == "notifications/initialized":
            return 202, {}, b""
        payload = TOOL_PAYLOADS[name]
        result = {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "structuredContent": payload,
            "isError": False,
        }
        return 200, JSON_HEADERS, reply(message, result)


def reply(message: dict[str, Any], result: dict[str, Any]) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()


@pytest.fixture
def bridge(monkeypatch: pytest.MonkeyPatch) -> ScriptedBridge:
    """Replace the transport of every Kit, including those the CLI builds itself."""
    scripted = ScriptedBridge()

    def post(
        _kit: lhub.Kit, url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        return scripted.post(url, body, headers)

    monkeypatch.setattr(lhub.Kit, "_http_post", post)
    return scripted


def set_env_url(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv(lhub.ENV_BASE_URL, raising=False)
    else:
        monkeypatch.setenv(lhub.ENV_BASE_URL, value)


# --- Scenario: No configuration reaches the public marketplace ----------------


def test_the_default_is_the_public_sandbox() -> None:
    assert lhub.DEFAULT_BASE_URL == PUBLIC
    assert lhub.ENV_BASE_URL == "LHUB_URL"


def test_from_env_with_nothing_set_is_the_public_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    set_env_url(monkeypatch, None)
    assert lhub.Kit.from_env().base_url == PUBLIC


def test_find_with_nothing_set_sends_to_the_public_sandbox(
    monkeypatch: pytest.MonkeyPatch, bridge: ScriptedBridge, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env_url(monkeypatch, None)
    home = lhub.kit_home_from_env()
    assert list(home.iterdir()) == []  # a fresh home: no key, no session
    assert lhub.main(["find", "--category", "digital_services/code/review"]) == 0
    assert json.loads(capsys.readouterr().out) == SEARCH_RESULT
    assert bridge.urls == {PUBLIC + lhub.MCP_PATH}
    assert bridge.calls == ["initialize", "notifications/initialized", "search_services"]
    # Anonymous: no key was minted and no session token was sent.
    assert not (home / "agent.pem").exists()
    assert all(lhub.LHUB_SESSION_HEADER not in headers for _u, _n, headers in bridge.requests)


def test_the_url_help_names_the_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("COLUMNS", "200")  # one line per option, so the text is not wrapped
    with pytest.raises(SystemExit) as exited:
        lhub.main(["init", "--help"])
    assert exited.value.code == 0
    assert "marketplace base URL (default $LHUB_URL or https://lhub.ai)" in capsys.readouterr().out


# --- Scenario: An explicit marketplace wins -----------------------------------


@pytest.mark.parametrize(("flag", "env", "expected"), PRECEDENCE)
def test_precedence_through_from_env(
    monkeypatch: pytest.MonkeyPatch, flag: str | None, env: str | None, expected: str
) -> None:
    set_env_url(monkeypatch, env)
    assert lhub.Kit.from_env(flag).base_url == expected


@pytest.mark.parametrize(("flag", "env", "expected"), PRECEDENCE)
def test_precedence_through_the_cli_parsed_url(
    monkeypatch: pytest.MonkeyPatch,
    bridge: ScriptedBridge,
    capsys: pytest.CaptureFixture[str],
    flag: str | None,
    env: str | None,
    expected: str,
) -> None:
    set_env_url(monkeypatch, env)
    argv = ["find"] if flag is None else ["find", "--url", flag]
    assert lhub.build_parser().parse_args(argv).url == flag  # what cmd_find hands from_env
    assert lhub.main(argv) == 0
    assert json.loads(capsys.readouterr().out) == SEARCH_RESULT
    assert bridge.urls == {expected + lhub.MCP_PATH}


# --- Scenario: init names the marketplace -------------------------------------


def test_init_names_the_marketplace_it_registered_with(
    monkeypatch: pytest.MonkeyPatch, bridge: ScriptedBridge, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env_url(monkeypatch, None)
    assert lhub.main(["init"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["marketplace"] == PUBLIC
    assert set(out) == {"did", "key_path", "home", "marketplace", "registration", "balance"}
    assert out["registration"] == TOOL_PAYLOADS["register_agent"]
    assert bridge.urls == {PUBLIC + lhub.MCP_PATH}
    assert bridge.calls == INIT_CALLS


@pytest.mark.parametrize("via", ["url-flag", "LHUB_URL"])
@pytest.mark.parametrize(
    ("credentialed", "shown", "userinfo_parts"),
    [
        pytest.param(
            "https://alice:s3cret@bridge.invalid",
            "https://bridge.invalid",
            ("alice", "s3cret"),
            id="user-pass",
        ),
        pytest.param(
            "https://alice:s%33cret@bridge.invalid:8443/",
            "https://bridge.invalid:8443",
            ("alice", "s%33cret", "s3cret"),
            id="percent-encoded-port-slash",
        ),
    ],
)
def test_init_marketplace_carries_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
    bridge: ScriptedBridge,
    capsys: pytest.CaptureFixture[str],
    via: str,
    credentialed: str,
    shown: str,
    userinfo_parts: tuple[str, ...],
) -> None:
    if via == "url-flag":
        set_env_url(monkeypatch, None)
        argv = ["init", "--url", credentialed]
    else:
        set_env_url(monkeypatch, credentialed)
        argv = ["init"]
    assert lhub.main(argv) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["marketplace"] == shown
    for secret in userinfo_parts:
        assert secret not in captured.out
        assert secret not in captured.err
    # The redaction is for display only: the requests still went to the URL given.
    assert bridge.urls == {credentialed.rstrip("/") + lhub.MCP_PATH}
    assert bridge.calls == INIT_CALLS
