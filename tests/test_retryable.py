"""harden-public-sandbox task 3.2 — the kit's half of the retryable error class, plus
per-process-unique request ids, the `budget set --days` ceiling and the bounded HTTP read.

The retryable class (design D-4 / D-4a): a retryable refusal is an ``isError`` tool
result whose ``_meta["ai.lhub/error"]`` is ``{"code": <code>, "retryable": true}`` and
whose text begins ``<code>:``. These tests pin, against the bridge's exact wire shape:

  * detection — the marker, the text-prefix fallback, and the closed code set;
  * the D-4 Open Question for the kit: ``_meta`` IS visible on the kit's raw JSON-RPC
    path (JSON and SSE bodies alike), because the kit decodes the result object itself;
  * ``serve`` backs off on ``upstream_unavailable`` and ``rate_limited`` like a transport
    error — capped, never a hot loop — and a rate-limited ``register_agent`` escalates
    to a longer cap (the identity window lasts up to a day);
  * ``inbox`` and ``deliver`` surface the code; a plain refusal is unchanged.
"""

from __future__ import annotations

import base64
import email.message
import io
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from routerkit import RouterKit
from test_inbox_flow import DEAL_ID, SellerWorld

import lhub

KIT_DIR = Path(__file__).resolve().parents[1]
JSON_HEADERS = {"Content-Type": "application/json"}
SSE_HEADERS = {"Content-Type": "text/event-stream"}

# The bridge's wire forms (services/protocol-bridge/internal/mcp/errors.go
# retryableToolError: the marker in `_meta`, the text `<code>: <fixed text>
# (correlationId=…)`, the structured content left as the tool's zero output).
MARKER_UPSTREAM = {"ai.lhub/error": {"code": "upstream_unavailable", "retryable": True}}
MARKER_RATE = {"ai.lhub/error": {"code": "rate_limited", "retryable": True}}
UPSTREAM_TEXT = "upstream_unavailable: temporarily unavailable; retry later (correlationId=0a1b)"
RATE_TEXT = "rate_limited: rate limited; retry later (correlationId=2c3d)"
STATE_TEXT = (
    "the deal operation could not be completed in the deal's current state (correlationId=4e5f)"
)
AUTH_REQUIRED_TEXT = (
    "mcp: authentication required — complete the auth_challenge/auth_complete handshake"
    " and pass the session token in the X-LHUB-Session header"
)


def tool_error_result(text: str, *, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"deal_id": "", "state": ""},  # the tool's zero output
        "isError": True,
    }
    if meta is not None:
        result["_meta"] = meta
    return result


def rpc_body(rpc_id: Any, result: dict[str, Any], *, sse: bool) -> bytes:
    message = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "result": result})
    if sse:
        return f"event: message\ndata: {message}\n\n".encode()
    return message.encode()


def tool_ok_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "structuredContent": payload,
        "isError": False,
    }


def retryable(code: str, tool: str = "get_inbox") -> lhub.KitRetryableError:
    text = UPSTREAM_TEXT if code == lhub.CODE_UPSTREAM_UNAVAILABLE else RATE_TEXT
    return lhub.KitRetryableError(f"{tool}: {text}", code=code, tool=tool)


# ---------------------------------------------------------------------------
# Detection: the `_meta` marker, the text-prefix fallback, the closed code set.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (tool_error_result(UPSTREAM_TEXT, meta=MARKER_UPSTREAM), "upstream_unavailable"),
        (tool_error_result(RATE_TEXT, meta=MARKER_RATE), "rate_limited"),
        # Fallback: no `_meta` (a proxy or build that drops it) — the text prefix.
        (tool_error_result(UPSTREAM_TEXT), "upstream_unavailable"),
        (tool_error_result(RATE_TEXT), "rate_limited"),
        # The marker is authoritative even when the text does not lead with the code.
        (
            tool_error_result("temporarily unavailable", meta=MARKER_UPSTREAM),
            "upstream_unavailable",
        ),
        # An unusable marker falls back to the text.
        (tool_error_result(RATE_TEXT, meta={"ai.lhub/error": "rate_limited"}), "rate_limited"),
        (
            tool_error_result(RATE_TEXT, meta={"ai.lhub/error": {"code": "rate_limited"}}),
            "rate_limited",
        ),
    ],
    ids=[
        "meta-upstream",
        "meta-rate",
        "text-upstream",
        "text-rate",
        "meta-wins-over-text",
        "non-object-marker-text-fallback",
        "marker-without-retryable-text-fallback",
    ],
)
def test_retryable_results_are_detected(result: dict[str, Any], expected: str) -> None:
    assert lhub.retryable_code(result) == expected


@pytest.mark.parametrize(
    "result",
    [
        tool_error_result(STATE_TEXT),
        tool_error_result(AUTH_REQUIRED_TEXT),
        # Unknown codes are not retryable, marker or text (a closed set).
        tool_error_result(
            "maintenance: back soon",
            meta={"ai.lhub/error": {"code": "maintenance", "retryable": True}},
        ),
        # `retryable` must be exactly true.
        tool_error_result(
            "temporarily unavailable",
            meta={"ai.lhub/error": {"code": "upstream_unavailable", "retryable": "true"}},
        ),
        # The code must LEAD the text, followed by ':' — not merely appear in it.
        tool_error_result("search failed: rate_limited: nope"),
        tool_error_result("rate_limited without a colon"),
        # The handshake's own coarse refusal is deliberately unmarked (D-2).
        tool_error_result("mcp: rate limit exceeded; please retry later (correlationId=77)"),
    ],
    ids=[
        "state-refusal",
        "auth-required",
        "unknown-code",
        "retryable-not-true",
        "code-not-leading",
        "no-colon",
        "handshake-coarse-refusal",
    ],
)
def test_other_results_are_not_retryable(result: dict[str, Any]) -> None:
    assert lhub.retryable_code(result) is None


def test_retryable_error_is_beside_not_under_transport_error() -> None:
    # D-4: "KitTransportError callers are unchanged" — scripts/canary and
    # scripts/metrics/supply.sh catch KitTransportError FIRST and route a
    # `rate_limited` KitError to a one-window wait, so the new class must not
    # be swallowed by their transport branch.
    exc = retryable(lhub.CODE_RATE_LIMITED)
    assert isinstance(exc, lhub.KitError)
    assert not isinstance(exc, lhub.KitTransportError)
    # Their substring checks keep working on the message.
    assert "rate_limited" in str(exc)


# ---------------------------------------------------------------------------
# The D-4 Open Question (kit side): `_meta` is visible on the raw client path.
# ---------------------------------------------------------------------------


def raw_kit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: dict[str, Any], *, sse: bool
) -> lhub.Kit:
    kit = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    kit._mcp_session_id = "sid-1"

    def post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        message = json.loads(body)
        return 200, SSE_HEADERS if sse else JSON_HEADERS, rpc_body(message["id"], result, sse=sse)

    monkeypatch.setattr(kit, "_http_post", post)
    return kit


@pytest.mark.parametrize("sse", [False, True], ids=["json-body", "sse-body"])
def test_raw_path_sees_the_meta_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sse: bool
) -> None:
    # The marker alone decides (the text here does NOT lead with the code), so
    # this passes only if `_meta` survives the kit's own decode path.
    result = tool_error_result("temporarily unavailable (correlationId=9)", meta=MARKER_UPSTREAM)
    kit = raw_kit(tmp_path, monkeypatch, result, sse=sse)
    with pytest.raises(lhub.KitRetryableError) as excinfo:
        kit.call_tool("get_deal", {"deal_id": DEAL_ID}, with_session=False)
    assert excinfo.value.code == "upstream_unavailable"
    assert excinfo.value.tool == "get_deal"
    assert str(excinfo.value).startswith("get_deal: temporarily unavailable (correlationId=9)")


@pytest.mark.parametrize("sse", [False, True], ids=["json-body", "sse-body"])
def test_raw_path_text_fallback_without_meta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sse: bool
) -> None:
    kit = raw_kit(tmp_path, monkeypatch, tool_error_result(RATE_TEXT), sse=sse)
    with pytest.raises(lhub.KitRetryableError) as excinfo:
        kit.call_tool("start_negotiation", {}, with_session=False)
    assert excinfo.value.code == "rate_limited"
    # The `<tool>: <code>:` form is kept, so substring checks downstream still match.
    assert str(excinfo.value).startswith(f"start_negotiation: {RATE_TEXT}")


def test_raw_path_plain_refusal_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit = raw_kit(tmp_path, monkeypatch, tool_error_result(STATE_TEXT), sse=True)
    with pytest.raises(lhub.KitError) as excinfo:
        kit.call_tool("agree_deal", {}, with_session=False)
    assert not isinstance(excinfo.value, lhub.KitRetryableError)
    assert str(excinfo.value) == f"agree_deal: {STATE_TEXT}"  # byte-for-byte as before


# ---------------------------------------------------------------------------
# serve: a retryable refusal backs off like a transport error (capped, never hot).
# ---------------------------------------------------------------------------


class StopLoop(Exception):
    """Raised by the patched sleep to end the (otherwise infinite) loop under test."""


def patch_sleep(monkeypatch: pytest.MonkeyPatch, *, stop_after: int) -> list[float]:
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) >= stop_after:
            raise StopLoop

    monkeypatch.setattr(time, "sleep", fake_sleep)
    return sleeps


class RefusingInboxWorld:
    """get_inbox raises a retryable refusal ``failures`` times, then answers."""

    def __init__(
        self, tmp_path: Path, *, failures: int, code: str, tool: str = "get_inbox"
    ) -> None:
        self.remaining = failures
        self.code = code
        self.tool = tool
        self.polls = 0
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()

    def route(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name != "get_inbox":
            raise AssertionError(f"unexpected tool {name}")
        self.polls += 1
        if self.remaining > 0:
            self.remaining -= 1
            raise retryable(self.code, self.tool)
        return {"items": [], "polled_at": "now", "poll_hint_seconds": 30}


def test_serve_survives_upstream_unavailable_and_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Spec "Seller loop survives a downstream outage": backs off and retries
    # rather than exiting (pre-3.2 the loop ended on the first tool refusal).
    world = RefusingInboxWorld(tmp_path, failures=2, code=lhub.CODE_UPSTREAM_UNAVAILABLE)
    sleeps = patch_sleep(monkeypatch, stop_after=3)
    with pytest.raises(StopLoop):
        lhub.run_serve_loop(world.kit, argv_base=None, interval_seconds=30.0, once=False)
    assert sleeps == [30.0, 60.0, 30.0]  # the transport schedule, then the plain interval
    assert world.polls == 3
    captured = capsys.readouterr()
    assert captured.err.count("[upstream_unavailable]") == 2
    assert json.loads(captured.out)["round"] == 3  # the loop resumed and emitted


def test_serve_rate_limited_backoff_is_capped_and_never_hot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = RefusingInboxWorld(tmp_path, failures=50, code=lhub.CODE_RATE_LIMITED)
    sleeps = patch_sleep(monkeypatch, stop_after=8)
    with pytest.raises(StopLoop):
        lhub.run_serve_loop(world.kit, argv_base=None, interval_seconds=30.0, once=False)
    assert sleeps == [30.0, 60.0, 120.0, 240.0, 300.0, 300.0, 300.0, 300.0]
    assert min(sleeps) >= 30.0  # never below the poll interval
    assert max(sleeps) == float(lhub.SERVE_BACKOFF_CAP_SECONDS)
    assert world.polls == 8  # exactly one call per round: no inner retry loop


def test_serve_identity_rate_limit_escalates_past_the_transport_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A rate-limited register_agent (the re-handshake re-registers) can last up
    # to a day (R-HPS-5), so the wait keeps doubling past 5 min to a 1 h cap.
    world = RefusingInboxWorld(
        tmp_path, failures=50, code=lhub.CODE_RATE_LIMITED, tool="register_agent"
    )
    sleeps = patch_sleep(monkeypatch, stop_after=10)
    with pytest.raises(StopLoop):
        lhub.run_serve_loop(world.kit, argv_base=None, interval_seconds=30.0, once=False)
    assert sleeps == [30.0, 60.0, 120.0, 240.0, 480.0, 960.0, 1920.0, 3600.0, 3600.0, 3600.0]
    assert max(sleeps) == float(lhub.SERVE_IDENTITY_BACKOFF_CAP_SECONDS)
    assert capsys.readouterr().err.count("[rate_limited]") == 10


def test_serve_once_raises_on_a_retryable_refusal(tmp_path: Path) -> None:
    world = RefusingInboxWorld(tmp_path, failures=1, code=lhub.CODE_UPSTREAM_UNAVAILABLE)
    with pytest.raises(lhub.KitRetryableError):
        lhub.run_serve_loop(world.kit, argv_base=None, interval_seconds=1.0, once=True)
    assert world.polls == 1


def test_serve_still_ends_on_a_plain_refusal(tmp_path: Path) -> None:
    def refuse(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise lhub.KitError(f"get_inbox: {STATE_TEXT}")

    kit = RouterKit(tmp_path / "home", refuse)
    kit.ensure_key()
    with pytest.raises(lhub.KitError) as excinfo:
        lhub.run_serve_loop(kit, argv_base=None, interval_seconds=1.0, once=False)
    assert not isinstance(excinfo.value, (lhub.KitTransportError, lhub.KitRetryableError))


class IdentityLimitedBridge:
    """A wire-level bridge: business tools need a minted token; register_agent is
    refused `rate_limited` (the identity window exhausted). ``reject_tokens``
    makes every business call answer auth-required, forcing a re-handshake
    (and a re-registration) every round."""

    def __init__(self, *, reject_tokens: bool = False) -> None:
        self.reject_tokens = reject_tokens
        self.tokens: set[str] = set()
        self.tool_calls: list[str] = []

    def post(
        self, url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        message = json.loads(body)
        if message.get("method") != "tools/call":
            raise AssertionError(f"unexpected method {message.get('method')}")
        name = str(message["params"]["name"])
        self.tool_calls.append(name)
        if name == "auth_challenge":
            payload = {"nonce": "n-1", "audience": lhub.HANDSHAKE_AUDIENCE}
            return 200, SSE_HEADERS, rpc_body(message["id"], tool_ok_result(payload), sse=True)
        if name == "auth_complete":
            token = f"tok-{len(self.tokens) + 1}"
            self.tokens.add(token)
            payload = {"session_token": token, "expires_at": "2099-01-01T00:00:00Z"}
            return 200, SSE_HEADERS, rpc_body(message["id"], tool_ok_result(payload), sse=True)
        if name == "register_agent":
            refusal = tool_error_result(RATE_TEXT, meta=MARKER_RATE)
            return 200, SSE_HEADERS, rpc_body(message["id"], refusal, sse=True)
        if name == "get_inbox":
            if self.reject_tokens or headers.get(lhub.LHUB_SESSION_HEADER) not in self.tokens:
                refusal = tool_error_result(AUTH_REQUIRED_TEXT + " (correlationId=aa)")
                return 200, SSE_HEADERS, rpc_body(message["id"], refusal, sse=True)
            inbox = {"items": [], "polled_at": "now", "poll_hint_seconds": 30}
            return 200, SSE_HEADERS, rpc_body(message["id"], tool_ok_result(inbox), sse=True)
        raise AssertionError(f"unexpected tool {name}")


def identity_kit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bridge: IdentityLimitedBridge
) -> lhub.Kit:
    kit = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    kit.ensure_key()
    kit._mcp_session_id = "sid-1"
    kit._session_token = "stale-token-from-before-the-bridge-restart"
    monkeypatch.setattr(kit, "_http_post", bridge.post)
    return kit


def test_serve_rehandshake_refused_registration_recovers_next_round(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The realistic R-HPS-5 case, through the REAL call_tool/handshake path: a
    # registered seller's session died (bridge restart) and its re-registration
    # is refused `rate_limited`. The handshake already minted a session, so the
    # next round polls with it — one backoff wait, no repeated registration.
    bridge = IdentityLimitedBridge()
    kit = identity_kit(tmp_path, monkeypatch, bridge)
    sleeps = patch_sleep(monkeypatch, stop_after=2)
    with pytest.raises(StopLoop):
        lhub.run_serve_loop(kit, argv_base=None, interval_seconds=30.0, once=False)
    assert bridge.tool_calls == [
        "get_inbox",  # stale token -> auth required
        "auth_challenge",
        "auth_complete",
        "register_agent",  # refused rate_limited (identity window)
        "get_inbox",  # next round, the minted session: served
    ]
    assert sleeps == [30.0, 30.0]  # one backoff wait, then the plain interval
    err = capsys.readouterr().err
    assert "registration is rate-limited" in err
    assert "up to a day" in err


def test_serve_repeated_identity_refusals_escalate_one_registration_per_round(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = IdentityLimitedBridge(reject_tokens=True)
    kit = identity_kit(tmp_path, monkeypatch, bridge)
    sleeps = patch_sleep(monkeypatch, stop_after=9)
    with pytest.raises(StopLoop):
        lhub.run_serve_loop(kit, argv_base=None, interval_seconds=30.0, once=False)
    assert sleeps == [30.0, 60.0, 120.0, 240.0, 480.0, 960.0, 1920.0, 3600.0, 3600.0]
    # Exactly one registration attempt per round — the waits are the only retry.
    assert bridge.tool_calls.count("register_agent") == 9
    assert bridge.tool_calls.count("get_inbox") == 9


def test_init_surfaces_a_rate_limited_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bridge = IdentityLimitedBridge()
    kit = identity_kit(tmp_path, monkeypatch, bridge)
    kit._session_token = None
    patch_from_env(monkeypatch, kit)
    assert lhub.main(["init"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["code"] == "rate_limited"
    assert out["retryable"] is True
    assert out["error"].startswith(f"register_agent: {RATE_TEXT}")
    assert "up to a day" in out["error"]
    assert bridge.tool_calls.count("register_agent") == 1


# ---------------------------------------------------------------------------
# inbox / deliver surface the code; a plain refusal is unchanged.
# ---------------------------------------------------------------------------


def patch_from_env(monkeypatch: pytest.MonkeyPatch, kit: lhub.Kit) -> None:
    def from_env(base_url: str | None = None) -> lhub.Kit:
        return kit

    monkeypatch.setattr(lhub.Kit, "from_env", staticmethod(from_env))


@pytest.fixture
def buyer_key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(0xB0BB1E5, ec.SECP256R1())


def test_inbox_reports_the_code_and_memorizes_no_refusal(
    tmp_path: Path, buyer_key: ec.EllipticCurvePrivateKey
) -> None:
    buyer_did = lhub.did_key_from_public_key(buyer_key.public_key())
    world = SellerWorld(tmp_path, buyer_key, buyer_did)
    route = world.route
    outage = {"on": True}

    def flaky(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "agree_deal" and outage["on"]:
            raise retryable(lhub.CODE_UPSTREAM_UNAVAILABLE, "agree_deal")
        return route(name, arguments)

    world.kit.router = flaky
    first = lhub.do_inbox(world.kit)
    (action,) = first["actions"]
    assert action["action"] == "error"
    assert action["code"] == "upstream_unavailable"
    assert action["retryable"] is True
    # An outage is not a refusal: nothing is memorized against the proposal
    # sha, so the next poll countersigns once the marketplace is back.
    assert world.kit.refusal_reason(DEAL_ID, world.proposal_sha) is None
    outage["on"] = False
    second = lhub.do_inbox(world.kit)
    assert second["actions"][0]["action"] == "countersigned"
    assert len(world.agreed) == 1


def test_inbox_cli_surfaces_the_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = RefusingInboxWorld(tmp_path, failures=1, code=lhub.CODE_RATE_LIMITED)
    patch_from_env(monkeypatch, world.kit)
    assert lhub.main(["inbox"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out == {
        "error": f"get_inbox: {RATE_TEXT}",
        "code": "rate_limited",
        "retryable": True,
    }


def test_deliver_cli_surfaces_the_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise retryable(lhub.CODE_UPSTREAM_UNAVAILABLE, name)

    kit = RouterKit(tmp_path / "home", route)
    kit.ensure_key()
    patch_from_env(monkeypatch, kit)
    deliverable = tmp_path / "out.md"
    deliverable.write_bytes(b"# done\n")
    assert lhub.main(["deliver", DEAL_ID, str(deliverable)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["code"] == "upstream_unavailable"
    assert out["retryable"] is True
    assert out["error"].startswith(f"upload_deal_file: {UPSTREAM_TEXT}")


def test_plain_refusal_output_carries_no_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise lhub.KitError(f"{name}: {STATE_TEXT}")

    kit = RouterKit(tmp_path / "home", route)
    kit.ensure_key()
    patch_from_env(monkeypatch, kit)
    deliverable = tmp_path / "out.md"
    deliverable.write_bytes(b"# done\n")
    assert lhub.main(["deliver", DEAL_ID, str(deliverable)]) == 1
    assert json.loads(capsys.readouterr().out) == {"error": f"upload_deal_file: {STATE_TEXT}"}


def test_serve_job_deliver_outage_is_recorded_with_its_code(tmp_path: Path) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "upload_deal_file":
            data = base64.b64decode(arguments["content_b64"])
            return {"sha256": lhub.sha256_ref(data).removeprefix("sha256:"), "size": len(data)}
        if name == "submit_proof":
            raise retryable(lhub.CODE_UPSTREAM_UNAVAILABLE, "submit_proof")
        raise AssertionError(f"unexpected tool {name}")

    kit = RouterKit(tmp_path / "home", route)
    kit.ensure_key()
    job_dir = kit.job_dir(DEAL_ID)
    (job_dir / "input").write_bytes(b"payload\n")
    item = {"deal_id": DEAL_ID, "listing_content_hash": "ab" * 32, "todo": "fulfil"}
    out = lhub.run_serve_job(kit, item, [sys.executable, "-c", "print('ok')"])
    assert out["action"] == "deliver_failed"
    assert out["code"] == "upstream_unavailable"
    assert out["retryable"] is True
    failed = json.loads((job_dir / "failed.json").read_text())
    assert failed["status"] == "deliver_failed"
    assert failed["code"] == "upstream_unavailable"
    assert failed["retryable"] is True


# ---------------------------------------------------------------------------
# Request ids: unique within an MCP session across processes (task 3.2).
# ---------------------------------------------------------------------------

ID_FORM = re.compile(r"[0-9a-f]{16}-[1-9][0-9]*")


def test_request_ids_are_unique_bounded_strings(tmp_path: Path) -> None:
    kit = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    ids = [kit._next_id() for _ in range(2000)]
    assert len(set(ids)) == len(ids)
    for rpc_id in ids:
        assert isinstance(rpc_id, str)  # never a number: the bridge decodes those as int64
        assert ID_FORM.fullmatch(rpc_id)
        assert len(rpc_id.encode()) <= 128  # the bridge refuses longer call ids


def test_two_kits_on_one_home_draw_different_prefixes(tmp_path: Path) -> None:
    first = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    second = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    assert first._next_id().split("-")[0] != second._next_id().split("-")[0]


CHILD = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
import lhub

kit = lhub.Kit(sys.argv[2], Path(sys.argv[3]))
sent = []

def post(url, body, headers):
    msg = json.loads(body)
    sent.append({"sid": headers.get(lhub.MCP_SESSION_HEADER), "id": msg.get("id")})
    result = {"content": [{"type": "text", "text": "{}"}], "structuredContent": {}, "isError": False}
    reply = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
    return 200, {"Content-Type": "application/json"}, json.dumps(reply).encode()

kit._http_post = post
for _ in range(int(sys.argv[4])):
    kit.call_tool("get_balance", {})
print(json.dumps(sent))
"""


def test_request_ids_unique_across_two_processes_sharing_a_session(tmp_path: Path) -> None:
    # Pre-3.2 every process counted from 1 on the persisted MCP session, so two
    # processes sent the same ids on one session — MCP's no-reuse rule broken,
    # and the bridge's duplicate-in-flight-id 400 (D-3) when they overlapped.
    base_url = "http://127.0.0.1:9"
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    (home / "session.json").write_text(
        json.dumps(
            {
                "base_url": base_url,
                "did": "did:key:zSharedSessionOwner",
                "mcp_session_id": "sid-shared",
                "protocol_version": lhub.MCP_PROTOCOL_VERSION,
                "session_token": "tok-shared",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        )
    )
    calls = 25
    procs = [
        subprocess.Popen(
            [sys.executable, "-I", "-c", CHILD, str(KIT_DIR), base_url, str(home), str(calls)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    sent: list[list[dict[str, Any]]] = []
    for proc in procs:
        out, err = proc.communicate(timeout=60)
        assert proc.returncode == 0, err
        sent.append(json.loads(out))

    first, second = ({str(call["id"]) for call in batch} for batch in sent)
    # Both processes really shared ONE persisted MCP session…
    assert {call["sid"] for batch in sent for call in batch} == {"sid-shared"}
    # …each used fresh ids, and no id was used by both.
    assert len(first) == len(second) == calls
    assert first.isdisjoint(second)
    for batch in sent:
        for call in batch:
            assert isinstance(call["id"], str)
            assert len(call["id"].encode()) <= 128


# ---------------------------------------------------------------------------
# budget set --days: capped at 399 (escrow's 400-day mandate horizon, task 1.7d).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("days", [1, 7, 398, 399])
def test_budget_days_within_the_horizon_are_accepted(days: int) -> None:
    lhub.validate_budget_days(days)


@pytest.mark.parametrize("days", [0, -1, 400, 401, 10_000])
def test_budget_days_outside_the_horizon_are_refused(days: int) -> None:
    with pytest.raises(lhub.KitError, match="between 1 and 399"):
        lhub.validate_budget_days(days)


def budget_argv(days: int) -> list[str]:
    return [
        "budget",
        "set",
        "--per-task",
        "1.00",
        "--total",
        "5.00",
        "--days",
        str(days),
        "--i-am-the-owner",
        "--url",
        "http://127.0.0.1:9",
    ]


def test_budget_cli_refuses_400_days_before_anything_is_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("LHUB_KIT_HOME", str(home))

    def never(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("nothing may be signed or sent for a refused --days")

    monkeypatch.setattr(lhub.Kit, "register_envelope", never)
    monkeypatch.setattr(lhub.Kit, "submit_intent_mandate", never)
    assert lhub.main(budget_argv(400)) == 1
    assert "between 1 and 399" in json.loads(capsys.readouterr().out)["error"]
    assert not (home / "agent.pem").exists()
    assert not (home / "audit.log").exists()


def test_budget_cli_accepts_399_days(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("LHUB_KIT_HOME", str(home))
    now = 1_800_000_000
    monkeypatch.setattr(time, "time", lambda: float(now))
    submitted: list[dict[str, Any]] = []

    def register(self: lhub.Kit) -> int:
        return 201

    def submit(self: lhub.Kit, claims: dict[str, Any]) -> str:
        submitted.append(dict(claims))
        return "mandate-399"

    monkeypatch.setattr(lhub.Kit, "register_envelope", register)
    monkeypatch.setattr(lhub.Kit, "submit_intent_mandate", submit)
    assert lhub.main(budget_argv(399)) == 0
    (claims,) = submitted
    assert claims["exp"] == now + 399 * 86400
    # One full day inside escrow's 400-day horizon.
    assert (now + 400 * 86400) - claims["exp"] == 86400
    out = json.loads(capsys.readouterr().out)
    assert out["mandate_id"] == "mandate-399"
    assert out["exp_unix"] == claims["exp"]


# ---------------------------------------------------------------------------
# The bounded HTTP read (task 3.2; the read was unbounded).
# ---------------------------------------------------------------------------


class FakeResponse:
    """A urlopen() response: status, headers, a recorded bounded read()."""

    def __init__(self, body: bytes, *, declared: int | None = None, status: int = 200) -> None:
        self.status = status
        self.headers = email.message.Message()
        self.headers["Content-Type"] = "application/json"
        if declared is not None:
            self.headers["Content-Length"] = str(declared)
        self._body = body
        self.reads: list[int] = []

    def read(self, amount: int = -1) -> bytes:
        self.reads.append(amount)
        return self._body if amount < 0 else self._body[:amount]

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


@pytest.fixture
def small_cap(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(lhub, "MAX_RESPONSE_BYTES", 1024)
    return 1024


def post_with(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: Any) -> bytes:
    def urlopen(*_args: Any, **_kwargs: Any) -> Any:
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    kit = lhub.Kit("http://127.0.0.1:9", tmp_path / "home")
    _status, _headers, body = kit._http_post("http://127.0.0.1:9/mcp/v1", b"{}", {})
    return body


def test_declared_oversize_response_is_refused_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, small_cap: int
) -> None:
    response = FakeResponse(b"x" * 10, declared=small_cap + 1)
    with pytest.raises(lhub.KitError, match="larger than the kit's 1024-byte cap") as excinfo:
        post_with(monkeypatch, tmp_path, response)
    assert not isinstance(excinfo.value, lhub.KitTransportError)  # waiting will not help
    assert response.reads == []  # refused on the header, before any body byte


def test_undeclared_oversize_response_reads_at_most_cap_plus_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, small_cap: int
) -> None:
    response = FakeResponse(b"x" * (50 * small_cap))  # chunked/streamed: no length
    with pytest.raises(lhub.KitError, match="1024-byte cap"):
        post_with(monkeypatch, tmp_path, response)
    assert response.reads == [small_cap + 1]


def test_response_at_the_cap_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, small_cap: int
) -> None:
    body = b"y" * small_cap
    assert post_with(monkeypatch, tmp_path, FakeResponse(body, declared=small_cap)) == body
    assert post_with(monkeypatch, tmp_path, FakeResponse(body)) == body


def test_oversize_error_response_is_refused_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, small_cap: int
) -> None:
    headers = email.message.Message()
    error = urllib.error.HTTPError(
        "http://127.0.0.1:9/mcp/v1", 502, "bad gateway", headers, io.BytesIO(b"z" * 4096)
    )
    with pytest.raises(lhub.KitError, match="1024-byte cap"):
        post_with(monkeypatch, tmp_path, error)


def go_sdk_wire(structured: dict[str, Any]) -> bytes:
    """A go-sdk typed tool's POST answer: structured output AND the same JSON as text."""
    text = json.dumps(structured, ensure_ascii=False, separators=(",", ":"))
    result = {"content": [{"type": "text", "text": text}], "structuredContent": structured}
    message = {"jsonrpc": "2.0", "id": "0123456789abcdef-1", "result": result}
    body = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    return f"event: message\ndata: {body}\n\n".encode()


def test_the_cap_clears_the_largest_legitimate_responses() -> None:
    # A deliverable download at the 160 KiB deal-file cap.
    download = go_sdk_wire(
        {
            "deal_id": DEAL_ID,
            "kind": "deliverable",
            "sha256": "ab" * 32,
            "size": lhub.DELIVERABLE_CAP_BYTES,
            "uploaded_by": "did:key:z" + "a" * 48,
            "created_at": "2026-11-16T00:00:00Z",
            "content_b64": base64.b64encode(b"\xff" * lhub.DELIVERABLE_CAP_BYTES).decode(),
        }
    )

    # A 100-hit search page (discovery's maximum) of schema-maximal generic-task
    # listings whose free text is 4-byte UTF-8 (maxLength counts characters).
    def fence(text: str) -> str:
        return f"{lhub.FENCE_OPEN}{text}{lhub.FENCE_CLOSE}"

    wide = "\U0001f600"
    blob = " ".join(
        [wide * 500, *(["text/" + "p" * 75] * 8), wide * 500, "text/" + "m" * 75, "168"]
        + [wide * 1000] * 3
    )
    hit = {
        "listing": {
            "id": "7a1d2f30-1111-4222-8333-944444444444",
            "provider_did": "did:key:z" + "b" * 48,
            "category_id": "digital_services/text/summarization",
            "category_path": "digital_services/text/summarization",
            "tier": 0,
            "unit": "document",
            "price_min": 100000,
            "price_max": 100000,
            "pricing_model": "per_unit",
            "turnaround_seconds": 604800,
            "reputation_score": 0.5,
            "reputation_bucket": "new",
            "completed_count": 0,
            "dispute_rate": 0.0,
            "kyc_status": "none",
            "supported_protocols": ["mcp"],
            "is_house_agent": False,
            "extension_blob": fence(blob),
            "text_summary": fence(wide * 280),
            "score": 0.5,
            "score_breakdown": {"relevance": 0.1, "reputation": 0.1, "price": 0.1},
        },
        "unit": lhub.SETTLEMENT_UNIT,
        "decimals": lhub.UNIT_DECIMALS,
        "price_min_display": "0.10 LHUB-DEV",
        "price_max_display": "0.10 LHUB-DEV",
        "provider_online": True,
        "provider_last_active": "2026-11-16T00:00:00Z",
        "provider_completed": 0,
        "provider_disputes_opened": 0,
    }
    page = go_sdk_wire({"total": 100, "results": [hit] * 100})
    assert len(download) < lhub.MAX_RESPONSE_BYTES
    # The documented 2x margin over the largest legitimate page.
    assert 2 * len(page) <= lhub.MAX_RESPONSE_BYTES
    # Why the bridge's 256 KiB REQUEST cap is not the right yardstick: a
    # legitimate download alone is larger than it.
    assert len(download) > 256 * 1024
