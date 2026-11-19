"""Every request the kit sends carries ``User-Agent: lhub-kit/<KIT_VERSION>``.

The defect (add-house-agent-static-fulfilment task 6.6): kit 0.3.1 set its
User-Agent only on the MCP path. The registration envelope
(``POST /v1/agents/register``) and mandate intake (``POST /v1/mandates/intent``)
went out with urllib's default ``Python-urllib/3.x``, which the Cloudflare edge
in front of lhub.ai refuses (HTTP 403, ``error code: 1010``). Both are
``budget set``'s calls, so no kit user could set a budget there. Registration
over MCP (``init``) carried the kit's User-Agent and was not affected.

These tests drive the REAL ``Kit._http_post`` (no monkeypatched transport)
against a loopback stub bridge that records each request's headers. The stub
answers 201 to registration and mandate intake, and plays a minimal MCP server
(initialize, the initialized notification, tools/call). The structural test pins
``Kit._http_post`` as the kit's only urllib call site, so a request path added
later cannot skip the header.
"""

from __future__ import annotations

import ast
import json
import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, NamedTuple, cast

import pytest

import lhub

KIT_FILE = Path(__file__).resolve().parents[1] / "lhub.py"
# Built from KIT_VERSION, not from lhub.USER_AGENT, so the wire tests below fail on
# the header actually sent, even on a kit that has no USER_AGENT constant.
EXPECTED_UA = f"lhub-kit/{lhub.KIT_VERSION}"
STUB_SESSION = "stub-mcp-session"
MANDATE_ID = "stub-mandate-1"


class Captured(NamedTuple):
    """One request the stub received."""

    method: str
    path: str
    user_agents: list[str]  # every User-Agent header line, so a duplicate shows
    headers: dict[str, str]  # lower-cased names
    body: bytes

    @property
    def rpc_method(self) -> str:
        """The JSON-RPC method of an MCP request ("" for any other body)."""
        try:
            message = json.loads(self.body)
        except ValueError:
            return ""
        method = message.get("method") if isinstance(message, dict) else None
        return method if isinstance(method, str) else ""


class _StubServer(ThreadingHTTPServer):
    captured: list[Captured]


class _StubHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        """Quiet: the default handler logs every request to stderr."""

    def _reply(self, status: int, payload: bytes, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        request = Captured(
            method="POST",
            path=self.path,
            user_agents=list(self.headers.get_all("User-Agent") or []),
            headers={name.lower(): value for name, value in self.headers.items()},
            body=body,
        )
        cast(_StubServer, self.server).captured.append(request)
        if self.path == "/v1/agents/register":
            self._reply(201, b'{"registered":true}')
        elif self.path == "/v1/mandates/intent":
            self._reply(201, json.dumps({"id": MANDATE_ID}).encode())
        elif self.path == lhub.MCP_PATH:
            self._reply_mcp(json.loads(body))
        else:
            self._reply(200, b"{}")

    def _reply_rpc(
        self, message: dict[str, Any], result: dict[str, Any], extra: dict[str, str] | None = None
    ) -> None:
        reply = {"jsonrpc": "2.0", "id": message["id"], "result": result}
        self._reply(200, json.dumps(reply).encode(), extra)

    def _reply_mcp(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        if method == "initialize":
            self._reply_rpc(
                message,
                {"protocolVersion": lhub.MCP_PROTOCOL_VERSION},
                {lhub.MCP_SESSION_HEADER: STUB_SESSION},
            )
        elif method == "notifications/initialized":
            self._reply(202, b"")
        elif method == "tools/call":
            self._reply_rpc(message, {"structuredContent": {"stub": "ok"}})
        else:
            self._reply(400, b"{}")


class Stub(NamedTuple):
    base_url: str
    captured: list[Captured]

    def to(self, path: str) -> list[Captured]:
        return [request for request in self.captured if request.path == path]


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> Iterator[Stub]:
    """A loopback stub bridge on an ephemeral port, recording every request."""
    # The kit uses urllib's default opener, which honours proxy settings: keep any
    # *_proxy variable from routing these loopback requests elsewhere, and let the
    # opener be rebuilt under that environment.
    for name in ("http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)
    monkeypatch.setenv("no_proxy", "*")
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setattr(urllib.request, "_opener", None)

    server = _StubServer(("127.0.0.1", 0), _StubHandler)
    server.captured = []
    # A short poll interval keeps shutdown() (it waits one poll) out of the timings.
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    try:
        yield Stub(f"http://127.0.0.1:{server.server_address[1]}", server.captured)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _kit(stub: Stub, tmp_path: Path) -> lhub.Kit:
    return lhub.Kit(stub.base_url, tmp_path / "kit-home")


def _assert_kit_ua(request: Captured) -> None:
    label = f"{request.method} {request.path} {request.rpc_method}".rstrip()
    assert request.user_agents == [EXPECTED_UA], (
        f"{label}: User-Agent {request.user_agents!r}, want exactly [{EXPECTED_UA!r}]"
    )


# --- the three surfaces ------------------------------------------------------


def test_registration_sends_the_kit_user_agent(stub: Stub, tmp_path: Path) -> None:
    kit = _kit(stub, tmp_path)
    assert kit.register_envelope() == 201

    (request,) = stub.to("/v1/agents/register")
    _assert_kit_ua(request)
    # The header is the only addition: the body on the wire is exactly the bytes the
    # kit signed, and the signed-envelope headers arrive unchanged.
    assert request.headers["x-lhub-register-did"] == kit.did
    lhub.verify_jws_es256_canonical(
        did=kit.did,
        jws=request.headers["x-lhub-register-signature"],
        expected_canonical=request.body,
    )


def test_mandate_intake_sends_the_kit_user_agent(stub: Stub, tmp_path: Path) -> None:
    kit = _kit(stub, tmp_path)
    claims = {
        "exp": 1_800_000_000,
        "price_ceiling": {"amount": 50_000, "unit": lhub.SETTLEMENT_UNIT},
        "total_budget": {"amount": 9_000_000, "unit": lhub.SETTLEMENT_UNIT},
    }
    assert kit.submit_intent_mandate(claims) == MANDATE_ID

    (request,) = stub.to("/v1/mandates/intent")
    _assert_kit_ua(request)
    assert request.headers["x-lhub-mandate-did"] == kit.did
    lhub.verify_jws_es256_canonical(
        did=kit.did,
        jws=request.headers["x-lhub-mandate-signature"],
        expected_canonical=request.body,
    )


def test_mcp_call_sends_the_kit_user_agent_on_every_request(stub: Stub, tmp_path: Path) -> None:
    kit = _kit(stub, tmp_path)
    assert kit.call_tool("list_categories", {}, with_session=False) == {"stub": "ok"}

    requests = stub.to(lhub.MCP_PATH)
    assert [r.rpc_method for r in requests] == [
        "initialize",
        "notifications/initialized",
        "tools/call",
    ]
    for request in requests:
        _assert_kit_ua(request)


def test_every_request_of_a_session_carries_the_kit_user_agent(stub: Stub, tmp_path: Path) -> None:
    """All three surfaces from one kit, counted: no request may go out without it."""
    kit = _kit(stub, tmp_path)
    kit.register_envelope()
    kit.submit_intent_mandate({"exp": 1_800_000_000})
    kit.call_tool("list_categories", {}, with_session=False)

    # What was measured: five requests on three paths, every one of them checked.
    assert [(r.path, r.rpc_method) for r in stub.captured] == [
        ("/v1/agents/register", ""),
        ("/v1/mandates/intent", ""),
        (lhub.MCP_PATH, "initialize"),
        (lhub.MCP_PATH, "notifications/initialized"),
        (lhub.MCP_PATH, "tools/call"),
    ]
    for request in stub.captured:
        _assert_kit_ua(request)


# --- a caller cannot omit, blank or replace it ---------------------------------


@pytest.mark.parametrize(
    "caller_headers",
    [
        pytest.param({}, id="none"),
        pytest.param({"User-Agent": "someone-else/1.0"}, id="replace"),
        pytest.param({"User-Agent": ""}, id="blank"),
        pytest.param({"user-agent": ""}, id="blank-lowercase"),
        pytest.param({"USER-AGENT": "Python-urllib/3.12"}, id="urllib-default-uppercase"),
        pytest.param({"User-agent": "other/1", "user-agent": "other/2"}, id="two-spellings"),
    ],
)
def test_http_post_overrides_any_caller_user_agent(
    stub: Stub, tmp_path: Path, caller_headers: dict[str, str]
) -> None:
    kit = _kit(stub, tmp_path)
    headers = {"Content-Type": "application/json", "X-Stub-Probe": "kept", **caller_headers}
    status, _headers, _raw = kit._http_post(stub.base_url + "/probe", b'{"a":1}', headers)
    assert status == 200

    (request,) = stub.to("/probe")
    _assert_kit_ua(request)
    assert request.body == b'{"a":1}'
    assert request.headers["x-stub-probe"] == "kept"
    assert request.headers["content-type"] == "application/json"


def test_user_agent_constant_names_the_kit_version() -> None:
    assert lhub.USER_AGENT == EXPECTED_UA


# --- structural: _http_post is the only way out ----------------------------------

# Modules whose use means talking to the network. Their exception classes may be
# named anywhere (catching is not sending); everything else is confined.
_NETWORK_MODULES = ("urllib.request", "http.client")
_OTHER_HTTP_STACKS = frozenset(
    {"socket", "ssl", "requests", "httpx", "urllib3", "aiohttp", "http.server"}
)
_SENDER = "Kit._http_post"


def _dotted(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def network_uses(source: str) -> list[tuple[str, int, str]]:
    """Every use of a network module in ``source``: (enclosing scope, line, name).

    An aliased or from-import of a network module, or an import of another HTTP
    stack, is reported with the scope ``<import>``: it would let a call escape
    the dotted-name check.
    """
    uses: list[tuple[str, int, str]] = []

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                visit(child, (*scope, child.name))
                continue
            if isinstance(child, ast.Import):
                for alias in child.names:
                    if alias.name in _OTHER_HTTP_STACKS or (
                        alias.name in _NETWORK_MODULES and alias.asname is not None
                    ):
                        uses.append(("<import>", child.lineno, alias.name))
                continue
            if isinstance(child, ast.ImportFrom):
                module = child.module or ""
                names = {alias.name for alias in child.names}
                if (
                    module in _NETWORK_MODULES
                    or module in _OTHER_HTTP_STACKS
                    or (module == "urllib" and "request" in names)
                    or (module == "http" and names & {"client", "server"})
                ):
                    uses.append(("<import>", child.lineno, f"from {module}"))
                continue
            if isinstance(child, ast.Attribute):
                dotted = _dotted(child)
                if dotted is not None and dotted.startswith(
                    tuple(m + "." for m in _NETWORK_MODULES)
                ):
                    if not dotted.endswith(("Error", "Exception")):
                        uses.append((".".join(scope), child.lineno, dotted))
                    continue
            visit(child, scope)

    visit(ast.parse(source), ())
    return uses


def test_http_post_is_the_kits_only_network_call_site() -> None:
    uses = network_uses(KIT_FILE.read_text(encoding="utf-8"))
    # Not vacuous: the sender itself is found.
    assert {name for _scope, _line, name in uses} >= {
        "urllib.request.Request",
        "urllib.request.urlopen",
    }
    escaped = [use for use in uses if use[0] != _SENDER]
    assert escaped == [], f"network use outside {_SENDER} (it would skip the User-Agent): {escaped}"


_SECOND_URLOPEN = """\
import urllib.request
class Kit:
    def _http_post(self):
        return urllib.request.urlopen('x')
    def fetch(self):
        return urllib.request.urlopen(urllib.request.Request('y'))
"""

_RAW_CONNECTION = """\
import http.client
def get():
    return http.client.HTTPSConnection('h')
"""


@pytest.mark.parametrize(
    ("source", "found"),
    [
        pytest.param(
            _SECOND_URLOPEN,
            [
                ("Kit.fetch", 6, "urllib.request.urlopen"),
                ("Kit.fetch", 6, "urllib.request.Request"),
            ],
            id="second-urlopen",
        ),
        pytest.param(
            _RAW_CONNECTION, [("get", 3, "http.client.HTTPSConnection")], id="raw-connection"
        ),
        pytest.param(
            "from urllib.request import urlopen\n",
            [("<import>", 1, "from urllib.request")],
            id="from-import",
        ),
        pytest.param(
            "from urllib import request\n", [("<import>", 1, "from urllib")], id="module-from"
        ),
        pytest.param(
            "import urllib.request as r\n", [("<import>", 1, "urllib.request")], id="alias"
        ),
        pytest.param("import socket\n", [("<import>", 1, "socket")], id="socket"),
    ],
)
def test_the_call_site_check_catches_an_escape(
    source: str, found: list[tuple[str, int, str]]
) -> None:
    """Positive control: the structural check reports each kind of escape."""
    escaped = [use for use in network_uses(source) if use[0] != _SENDER]
    assert escaped == found
