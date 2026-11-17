"""R-AFD-3 recovery paths (sdd N3), driven against a scripted in-process bridge.

Two loss modes, both recovered transparently inside ``Kit.call_tool``:

  * the MCP TRANSPORT session dies (bridge restart → HTTP 404 "session not
    found") → re-initialize, retry;
  * the LHUB APPLICATION session dies (auth-required tool error) →
    re-handshake (challenge → sign → complete → register), retry.

Plus the retry bound: a server that keeps failing exhausts the recovery
budget and surfaces a KitError instead of looping.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import lhub

AUTH_REQUIRED_TEXT = (
    "mcp: authentication required — complete the auth_challenge/auth_complete handshake"
    " and pass the session token in the X-LHUB-Session header"
)
JSON_HEADERS = {"Content-Type": "application/json"}


class FakeBridge:
    """A scripted MCP bridge behind Kit._http_post.

    Transport sessions: only ids issued by THIS instance's ``initialize`` are
    valid — a pre-seeded foreign id behaves like a post-restart stale session.
    Application sessions: ``auth_complete`` mints tokens into ``valid_tokens``.
    """

    def __init__(self, *, require_token: bool = False) -> None:
        self.require_token = require_token
        self.kill_transport = False  # True → every tools/call 404s
        self.reject_business_token = False  # True → business tools always auth-required
        self.valid_sids: set[str] = set()
        self.valid_tokens: set[str] = set()
        self.rpc_methods: list[str] = []
        self.tool_calls: list[str] = []
        self.business_headers: list[dict[str, str]] = []
        self._sid_counter = 0
        self._token_counter = 0

    def post(
        self, url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        message = json.loads(body)
        method = str(message.get("method"))
        self.rpc_methods.append(method)

        if method == "initialize":
            self._sid_counter += 1
            sid = f"sid-{self._sid_counter}"
            self.valid_sids.add(sid)
            return (
                200,
                {**JSON_HEADERS, "Mcp-Session-Id": sid},
                self._result(message, {"protocolVersion": "2025-06-18", "capabilities": {}}),
            )
        if method == "notifications/initialized":
            return 202, {}, b""
        if method != "tools/call":
            return 400, {}, b"unexpected method"

        if self.kill_transport or headers.get("Mcp-Session-Id") not in self.valid_sids:
            return 404, {}, b"session not found"

        name = str(message["params"]["name"])
        self.tool_calls.append(name)

        if name == "auth_challenge":
            return (
                200,
                JSON_HEADERS,
                self._tool_ok(message, {"nonce": "nonce-1", "audience": lhub.HANDSHAKE_AUDIENCE}),
            )
        if name == "auth_complete":
            self._token_counter += 1
            token = f"tok-{self._token_counter}"
            self.valid_tokens.add(token)
            return (
                200,
                JSON_HEADERS,
                self._tool_ok(
                    message,
                    {
                        "session_token": token,
                        "header": "X-LHUB-Session",
                        "expires_at": "2027-01-01T00:00:00Z",
                    },
                ),
            )
        if name == "register_agent":
            return (
                200,
                JSON_HEADERS,
                self._tool_ok(
                    message,
                    {"agent_did": "did:fake", "registration_kind": "self", "replayed": False},
                ),
            )

        # Business tool.
        self.business_headers.append(dict(headers))
        token_ok = headers.get("X-LHUB-Session") in self.valid_tokens
        if self.reject_business_token or (self.require_token and not token_ok):
            return 200, JSON_HEADERS, self._tool_err(message, AUTH_REQUIRED_TEXT)
        return 200, JSON_HEADERS, self._tool_ok(message, {"ok": True})

    @staticmethod
    def _result(message: dict[str, Any], result: dict[str, Any]) -> bytes:
        return json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()

    @classmethod
    def _tool_ok(cls, message: dict[str, Any], payload: dict[str, Any]) -> bytes:
        return cls._result(
            message,
            {
                "content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload,
                "isError": False,
            },
        )

    @classmethod
    def _tool_err(cls, message: dict[str, Any], text: str) -> bytes:
        return cls._result(message, {"content": [{"type": "text", "text": text}], "isError": True})


def make_kit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bridge: FakeBridge) -> lhub.Kit:
    kit = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    monkeypatch.setattr(kit, "_http_post", bridge.post)
    return kit


def test_transport_session_lost_reinitializes_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = FakeBridge()
    kit = make_kit(tmp_path, monkeypatch, bridge)
    kit._mcp_session_id = "stale-from-before-the-restart"

    payload = kit.call_tool("ping", {}, with_session=False)

    assert payload == {"ok": True}
    # One failed call, a full re-initialize, then the successful retry.
    assert bridge.rpc_methods == [
        "tools/call",
        "initialize",
        "notifications/initialized",
        "tools/call",
    ]


def test_auth_required_rehandshakes_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = FakeBridge(require_token=True)
    kit = make_kit(tmp_path, monkeypatch, bridge)
    kit._mcp_session_id = "seeded-sid"
    bridge.valid_sids.add("seeded-sid")
    kit._session_token = "dead-token-from-before-the-restart"

    payload = kit.call_tool("ping", {})

    assert payload == {"ok": True}
    # Failed business call → full handshake (challenge, complete, register) → retry.
    assert bridge.tool_calls == [
        "ping",
        "auth_challenge",
        "auth_complete",
        "register_agent",
        "ping",
    ]
    # The retry carried the freshly minted token.
    assert bridge.business_headers[-1].get("X-LHUB-Session") == "tok-1"
    # The recovered session was persisted for the next process.
    saved = json.loads((tmp_path / "home" / "session.json").read_text())
    assert saved["session_token"] == "tok-1"


def test_transport_recovery_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bridge = FakeBridge()
    bridge.kill_transport = True
    kit = make_kit(tmp_path, monkeypatch, bridge)
    kit._mcp_session_id = "whatever"

    with pytest.raises(lhub.KitError, match="kept dying"):
        kit.call_tool("ping", {}, with_session=False)

    # 3 attempts, 2 re-initializations — then give up (no infinite loop).
    assert bridge.rpc_methods.count("tools/call") == 3
    assert bridge.rpc_methods.count("initialize") == 2


def test_auth_recovery_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bridge = FakeBridge(require_token=True)
    bridge.reject_business_token = True  # even fresh tokens are rejected
    kit = make_kit(tmp_path, monkeypatch, bridge)
    kit._mcp_session_id = "seeded-sid"
    bridge.valid_sids.add("seeded-sid")

    with pytest.raises(lhub.KitError, match="authentication required"):
        kit.call_tool("ping", {})

    # 3 attempts, 2 full handshakes — then surface the error.
    assert bridge.tool_calls.count("ping") == 3
    assert bridge.tool_calls.count("auth_complete") == 2


def test_handshake_refuses_unexpected_audience(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The kit signs only the pinned handshake audience (same class as D-5 step 2)."""
    bridge = FakeBridge()

    def other_audience_post(
        url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        message = json.loads(body)
        if message.get("method") == "tools/call" and message["params"]["name"] == "auth_challenge":
            payload = {"nonce": "n", "audience": "some-other-audience"}
            return 200, JSON_HEADERS, FakeBridge._tool_ok(message, payload)
        return bridge.post(url, body, headers)

    kit = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    monkeypatch.setattr(kit, "_http_post", other_audience_post)

    with pytest.raises(lhub.KitRefusal, match="audience"):
        kit.handshake()
    assert "auth_complete" not in bridge.tool_calls


# ---------------------------------------------------------------------------
# Transport-failure classification (serve backoff): network-level failures are
# KitTransportError — the retryable class `serve` backs off on — while tool
# refusals and malformed non-5xx responses stay plain KitError (loop-ending).
# ---------------------------------------------------------------------------


def test_network_failures_are_transport_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import http.client
    import urllib.error
    import urllib.request

    kit = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    failures: list[BaseException] = [
        urllib.error.URLError(ConnectionRefusedError(61, "Connection refused")),
        TimeoutError("timed out"),
        http.client.RemoteDisconnected("Remote end closed connection"),
        ConnectionResetError(54, "Connection reset by peer"),
    ]
    for failure in failures:

        def refuse(*_args: Any, **_kwargs: Any) -> Any:
            raise failure  # noqa: B023 - read immediately, loop body runs to completion

        monkeypatch.setattr(urllib.request, "urlopen", refuse)
        with pytest.raises(lhub.KitTransportError):
            kit._http_post("http://127.0.0.1:9/mcp/v1", b"{}", {})


def test_rpc_5xx_is_transport_error_but_non_5xx_is_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    # A proxy mid-restart: 502 with an HTML body and no JSON-RPC response.
    monkeypatch.setattr(
        kit, "_http_post", lambda url, body, headers: (502, JSON_HEADERS, b"<html>bad gateway")
    )
    with pytest.raises(lhub.KitTransportError):
        kit._rpc_response("tools/call", {"name": "get_inbox", "arguments": {}}, with_session=False)
    # A non-5xx malformed answer is a contract problem, not an outage.
    monkeypatch.setattr(
        kit, "_http_post", lambda url, body, headers: (200, JSON_HEADERS, b"not json")
    )
    with pytest.raises(lhub.KitError) as excinfo:
        kit._rpc_response("tools/call", {"name": "get_inbox", "arguments": {}}, with_session=False)
    assert not isinstance(excinfo.value, lhub.KitTransportError)


def test_exhausted_session_recovery_is_transport_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A flapping bridge (sessions keep dying past the recovery budget) is a
    # transport-class failure, so `serve` backs off instead of dying.
    bridge = FakeBridge()
    bridge.kill_transport = True
    kit = make_kit(tmp_path, monkeypatch, bridge)
    kit._mcp_session_id = "whatever"
    with pytest.raises(lhub.KitTransportError, match="kept dying"):
        kit.call_tool("ping", {}, with_session=False)
