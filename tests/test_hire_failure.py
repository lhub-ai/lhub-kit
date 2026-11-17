"""A failed `hire` names the deal it left behind (harden-public-sandbox task 3.2 fix-pass, arch F1).

`hire` is not resumable and escrow's OpenDeal carries no idempotency key, so running
`hire` again after a part-way failure opens a SECOND deal — and a countersigning seller
plus a standing budget can then agree and fund both. So once the deal exists, the
failure JSON adds ``deal_id``, the ``stage`` reached (``opened`` / ``proposed`` /
``agreed``) and a ``next_step`` to run ``status`` before hiring again. Pinned here,
through the real CLI ``main``:

  * a failure before any deal opened prints exactly what it printed before (byte-exact);
  * ``error`` / ``code`` / ``retryable`` keep their values and lead the JSON;
  * the stage is the last step the kit saw confirmed, at each point a hire can fail;
  * the exception keeps its class, so programmatic callers (the canary) route as before.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pytest
from routerkit import RouterKit

import lhub

DEAL_ID = "d0000000-0000-4000-8000-00000000f001"
LISTING_ID = "7a1d2f30-1111-4222-8333-944444444444"
PROVIDER_DID = "did:key:zProviderExample"
INPUT = b"job input bytes for the failure tests"
REQUEST_ID = lhub.sha256_ref(INPUT)
UPSTREAM_TEXT = "upstream_unavailable: temporarily unavailable; retry later (correlationId=0a1b)"
STATE_TEXT = (
    "the deal operation could not be completed in the deal's current state (correlationId=4e5f)"
)
NEXT_STEP_COMMAND = f"python lhub.py status --deal {DEAL_ID}"


def outage(tool: str) -> lhub.KitRetryableError:
    return lhub.KitRetryableError(
        f"{tool}: {UPSTREAM_TEXT} (a marketplace backing service is temporarily unavailable;"
        " retry later)",
        code=lhub.CODE_UPSTREAM_UNAVAILABLE,
        tool=tool,
    )


def deal(state: str) -> dict[str, Any]:
    return {
        "deal_id": DEAL_ID,
        "state": state,
        "provider_did": PROVIDER_DID,
        "amount": "500000",
        "unit": lhub.SETTLEMENT_UNIT,
    }


class FlowWorld:
    """A scripted bridge for one hire. ``failures`` makes a tool raise; ``reads`` scripts
    successive get_deal answers (the pre-template read first, then the polls)."""

    def __init__(self, tmp_path: Path, *, amount: int = 500_000) -> None:
        self.amount = amount
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()
        self.failures: dict[str, BaseException] = {}
        self.reads: list[dict[str, Any] | BaseException] = []
        self.input_path = tmp_path / "input.txt"
        self.input_path.write_bytes(INPUT)

    def template(self) -> dict[str, Any]:
        content: dict[str, Any] = {
            "version": "1",
            "deal_id": DEAL_ID,
            "request_id": REQUEST_ID,
            "listing_content_hash": "ab" * 32,
            "buyer_did": self.kit.did,
            "provider_did": PROVIDER_DID,
            "amount": self.amount,
            "unit": lhub.SETTLEMENT_UNIT,
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        canonical = lhub.jcs_canonicalize(content)
        return {
            "deal_id": DEAL_ID,
            "content": content,
            "canonical_b64": base64.b64encode(canonical).decode(),
            "sha256": hashlib.sha256(canonical).hexdigest(),
        }

    def route(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        failure = self.failures.get(name)
        if failure is not None:
            raise failure
        if name == "start_negotiation":
            return {"deal_id": DEAL_ID, "state": "NEGOTIATING"}
        if name == "upload_deal_file":
            return {"sha256": REQUEST_ID.removeprefix("sha256:"), "size": len(INPUT)}
        if name == "get_deal":
            reply = self.reads.pop(0) if self.reads else deal("NEGOTIATING")
            if isinstance(reply, BaseException):
                raise reply
            return reply
        if name == "get_agreement_template":
            return self.template()
        if name == "propose_agreement":
            return {"deal_id": DEAL_ID, "state": "NEGOTIATING"}
        raise AssertionError(f"unexpected tool {name}")

    def cli(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        *extra: str,
    ) -> tuple[int, str]:
        kit = self.kit

        def from_env(base_url: str | None = None) -> lhub.Kit:
            return kit

        monkeypatch.setattr(lhub.Kit, "from_env", staticmethod(from_env))
        argv = ["hire", "--listing", LISTING_ID, "--input", str(self.input_path)]
        argv += ["--max-price", "1.00", "--timeout", "5", "--poll", "1", *extra]
        code = lhub.main(argv)
        return code, capsys.readouterr().out


@pytest.fixture(autouse=True)
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Deterministic polling: sleep advances a fake monotonic clock, never waits."""
    now = [1_000.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    monkeypatch.setattr(time, "sleep", sleep)
    return now


def assert_names_the_deal(out: dict[str, Any], stage: str) -> None:
    assert out["deal_id"] == DEAL_ID
    assert out["stage"] == stage
    assert NEXT_STEP_COMMAND in out["next_step"]
    assert "before hiring again" in out["next_step"]


# ---------------------------------------------------------------------------
# Before any deal opened: output unchanged, byte for byte.
# ---------------------------------------------------------------------------


def test_outage_on_open_prints_exactly_what_it_did(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = FlowWorld(tmp_path)
    world.failures["start_negotiation"] = outage("start_negotiation")
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    message = str(world.failures["start_negotiation"])
    assert stdout == (
        "{\n"
        f'  "error": {json.dumps(message)},\n'
        '  "code": "upstream_unavailable",\n'
        '  "retryable": true\n'
        "}\n"
    )


def test_plain_refusal_on_open_prints_exactly_what_it_did(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = FlowWorld(tmp_path)
    message = "start_negotiation: the referenced listing was not found (correlationId=77)"
    world.failures["start_negotiation"] = lhub.KitError(message)
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    assert stdout == "{\n" + f'  "error": {json.dumps(message)}\n' + "}\n"


# ---------------------------------------------------------------------------
# After the deal opened: the deal, the stage reached, and the next step.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failing_tool",
    ["upload_deal_file", "get_agreement_template", "propose_agreement"],
    ids=["outage-on-input-upload", "outage-on-template", "outage-on-propose"],
)
def test_outage_after_open_names_the_deal_at_stage_opened(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failing_tool: str,
) -> None:
    # On propose the proposal may or may not have been stored, so the stage is the
    # last CONFIRMED one ("opened"); `status` tells the two apart.
    world = FlowWorld(tmp_path)
    world.failures[failing_tool] = outage(failing_tool)
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    out = json.loads(stdout)
    # error / code / retryable unchanged, and first.
    assert list(out)[:3] == ["error", "code", "retryable"]
    assert out["error"] == str(world.failures[failing_tool])
    assert out["code"] == "upstream_unavailable"
    assert out["retryable"] is True
    assert_names_the_deal(out, lhub.HIRE_STAGE_OPENED)
    assert set(out) == {"error", "code", "retryable", "deal_id", "stage", "next_step"}


def test_outage_on_the_first_deal_read_names_the_deal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = FlowWorld(tmp_path)
    world.reads = [outage("get_deal")]  # the pre-template provider read
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    assert_names_the_deal(json.loads(stdout), lhub.HIRE_STAGE_OPENED)


def test_outage_after_propose_reports_stage_proposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = FlowWorld(tmp_path)
    world.reads = [deal("NEGOTIATING"), deal("NEGOTIATING"), outage("get_deal")]
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    out = json.loads(stdout)
    assert out["code"] == "upstream_unavailable"
    assert_names_the_deal(out, lhub.HIRE_STAGE_PROPOSED)


def test_outage_after_agreement_reports_stage_agreed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A poll saw DEAL_AGREED (the deal is past negotiation and may be funded),
    # then the marketplace went away: the agent must not hire again.
    world = FlowWorld(tmp_path)
    world.reads = [deal("NEGOTIATING"), deal("DEAL_AGREED"), outage("get_deal")]
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    assert_names_the_deal(json.loads(stdout), lhub.HIRE_STAGE_AGREED)


def test_plain_refusal_after_open_keeps_its_error_and_names_the_deal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The kit refuses to sign a quote above --max-price: the deal stays open
    # (unsigned, until escrow's negotiating TTL), so it is named too. A plain
    # refusal gains no code/retryable.
    world = FlowWorld(tmp_path, amount=2_000_000)  # 2.00 > --max-price 1.00
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    out = json.loads(stdout)
    assert out["error"].startswith("refusing to sign")
    assert "code" not in out
    assert "retryable" not in out
    assert next(iter(out)) == "error"
    assert_names_the_deal(out, lhub.HIRE_STAGE_OPENED)


def test_timeout_payload_adds_only_the_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = FlowWorld(tmp_path)  # every poll answers NEGOTIATING
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    out = json.loads(stdout)
    assert out["error"].startswith("timed out after 5s waiting for the countersign")
    assert out["deal_id"] == DEAL_ID
    assert out["state"] == "NEGOTIATING"
    assert out["stage"] == lhub.HIRE_STAGE_PROPOSED
    # The deal view's own fields are unchanged; only `stage` is new.
    assert set(out) == {
        "deal_id",
        "state",
        "amount",
        "unit",
        "decimals",
        "display",
        "next_step",
        "request_id",
        "stage",
        "error",
    }


def test_dead_deal_payload_adds_the_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = FlowWorld(tmp_path)
    world.reads = [deal("NEGOTIATING"), deal("DEAL_AGREED"), deal("CANCELLED")]
    code, stdout = world.cli(monkeypatch, capsys)
    assert code == 1
    out = json.loads(stdout)
    assert out["error"] == f"deal {DEAL_ID} ended in CANCELLED"
    assert out["stage"] == lhub.HIRE_STAGE_AGREED


def test_success_output_is_unchanged(tmp_path: Path) -> None:
    world = FlowWorld(tmp_path)
    world.reads = [deal("NEGOTIATING"), deal("IN_FULFILLMENT")]
    view = lhub.do_hire(
        world.kit,
        listing_id=LISTING_ID,
        input_bytes=INPUT,
        max_price_minor=1_000_000,
        pinned_provider=None,
        quantity=None,
        timeout_seconds=5,
        poll_seconds=1,
    )
    assert view["state"] == "IN_FULFILLMENT"
    assert "stage" not in view


# ---------------------------------------------------------------------------
# Programmatic callers: the exception keeps its class (the canary routes on it).
# ---------------------------------------------------------------------------


def test_exception_class_is_kept_and_carries_the_deal(tmp_path: Path) -> None:
    world = FlowWorld(tmp_path)
    world.failures["propose_agreement"] = outage("propose_agreement")
    with pytest.raises(lhub.KitRetryableError) as excinfo:
        lhub.do_hire(
            world.kit,
            listing_id=LISTING_ID,
            input_bytes=INPUT,
            max_price_minor=1_000_000,
            pinned_provider=None,
            quantity=None,
            timeout_seconds=5,
            poll_seconds=1,
        )
    assert not isinstance(excinfo.value, lhub.KitFailure)
    assert excinfo.value.context["deal_id"] == DEAL_ID
    assert excinfo.value.context["stage"] == lhub.HIRE_STAGE_OPENED
    # The kit itself never reopens: exactly one deal was opened.
    assert len(world.kit.calls_to("start_negotiation")) == 1


def test_refusal_class_is_kept(tmp_path: Path) -> None:
    world = FlowWorld(tmp_path, amount=2_000_000)
    with pytest.raises(lhub.KitRefusal) as excinfo:
        lhub.do_hire(
            world.kit,
            listing_id=LISTING_ID,
            input_bytes=INPUT,
            max_price_minor=1_000_000,
            pinned_provider=None,
            quantity=None,
            timeout_seconds=5,
            poll_seconds=1,
        )
    assert excinfo.value.context["stage"] == lhub.HIRE_STAGE_OPENED
    assert world.kit.calls_to("propose_agreement") == []  # nothing was signed or sent


def test_context_never_replaces_the_error_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        exc = outage(name)
        exc.context.update({"error": "clobbered", "code": "clobbered", "deal_id": DEAL_ID})
        raise exc

    kit = RouterKit(tmp_path / "home", route)
    kit.ensure_key()

    def from_env(base_url: str | None = None) -> lhub.Kit:
        return kit

    monkeypatch.setattr(lhub.Kit, "from_env", staticmethod(from_env))
    assert lhub.main(["balance"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["error"].startswith("get_balance: upstream_unavailable:")
    assert out["code"] == "upstream_unavailable"
    assert out["deal_id"] == DEAL_ID
