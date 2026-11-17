"""Kit hygiene (seller-door tasks 4.7 / 4.8): quantity default, quote line,
buyer-to-seller hint, find-over-session."""

from __future__ import annotations

import base64
import hashlib
import time
from pathlib import Path
from typing import Any

import pytest
from routerkit import RouterKit

import lhub

DEAL_ID = "d0000000-0000-4000-8000-00000000d001"
LISTING_ID = "7a1d2f30-1111-4222-8333-944444444444"
PROVIDER_DID = "did:key:zProviderExample"
INPUT = b"job input bytes"
REQUEST_ID = lhub.sha256_ref(INPUT)

# The two start_negotiation quantity refusals, VERBATIM from the pinned bridge
# source (D-14: the bridge keeps the word "quantity" in them):
# services/protocol-bridge/internal/mcp/tools.go, classifyStartNegotiationError —
# fmt.Sprintf("quantity must be an integer between 1 and %d", dealamount.MaxQuantityPerDeal)
# with MaxQuantityPerDeal = 100_000 (shared/go/dealamount/dealamount.go), and the
# quantity-not-applicable wording. A bridge rewording is a D-14 orchestrator
# amendment: update these pins consciously, never silently.
BRIDGE_QUANTITY_REQUIRED_MSG = "quantity must be an integer between 1 and 100000"
BRIDGE_QUANTITY_NOT_APPLICABLE_MSG = "quantity is not applicable for this listing's flat pricing"


class HireWorld:
    """Scripted bridge for the full hire flow."""

    def __init__(self, tmp_path: Path, *, per_unit: bool) -> None:
        self.per_unit = per_unit
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()
        self.open_calls: list[dict[str, Any]] = []

    def template(self) -> dict[str, Any]:
        content: dict[str, Any] = {
            "version": "1",
            "deal_id": DEAL_ID,
            "request_id": REQUEST_ID,
            "listing_content_hash": "ab" * 32,
            "buyer_did": self.kit.did,
            "provider_did": PROVIDER_DID,
            "amount": 500_000,
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
        if name == "start_negotiation":
            # Snapshot: do_hire mutates its args dict for the retry.
            self.open_calls.append(dict(arguments))
            if self.per_unit and "quantity" not in arguments:
                # The exact pinned bridge wording (plus the correlation-id
                # suffix the bridge's toolError appends on the wire).
                raise lhub.KitError(
                    f"start_negotiation: {BRIDGE_QUANTITY_REQUIRED_MSG} (correlationId=abc)"
                )
            if not self.per_unit and "quantity" in arguments:
                raise lhub.KitError(
                    f"start_negotiation: {BRIDGE_QUANTITY_NOT_APPLICABLE_MSG} (correlationId=abc)"
                )
            return {"deal_id": DEAL_ID, "state": "NEGOTIATING"}
        if name == "upload_deal_file":
            return {"sha256": REQUEST_ID.removeprefix("sha256:"), "size": len(INPUT)}
        if name == "get_deal":
            return {
                "deal_id": DEAL_ID,
                "state": "IN_FULFILLMENT",
                "provider_did": PROVIDER_DID,
                "amount": "500000",
                "unit": lhub.SETTLEMENT_UNIT,
            }
        if name == "get_agreement_template":
            return self.template()
        if name == "propose_agreement":
            return {"deal_id": DEAL_ID, "state": "NEGOTIATING"}
        raise AssertionError(f"unexpected tool {name}")

    def hire(self, quantity: int | None = None) -> dict[str, Any]:
        return lhub.do_hire(
            self.kit,
            listing_id=LISTING_ID,
            input_bytes=INPUT,
            max_price_minor=1_000_000,
            pinned_provider=None,
            quantity=quantity,
            timeout_seconds=5,
            poll_seconds=0.01,
        )


def test_per_unit_hire_defaults_quantity_to_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    world = HireWorld(tmp_path, per_unit=True)
    out = world.hire(quantity=None)
    assert out["state"] == "IN_FULFILLMENT"
    assert len(world.open_calls) == 2
    assert "quantity" not in world.open_calls[0]
    assert world.open_calls[1]["quantity"] == 1
    assert "R-AFD-16" in capsys.readouterr().err


def test_flat_hire_sends_no_quantity(tmp_path: Path) -> None:
    world = HireWorld(tmp_path, per_unit=False)
    out = world.hire(quantity=None)
    assert out["state"] == "IN_FULFILLMENT"
    assert len(world.open_calls) == 1
    assert "quantity" not in world.open_calls[0]


def test_explicit_quantity_passed_through(tmp_path: Path) -> None:
    world = HireWorld(tmp_path, per_unit=True)
    world.hire(quantity=4)
    assert len(world.open_calls) == 1
    assert world.open_calls[0]["quantity"] == 4


def test_retry_trigger_matches_both_pinned_bridge_messages() -> None:
    # do_hire's R-AFD-16 retry fires on the substring "quantity" (the D-14
    # pin: the bridge keeps that word in its quantity refusals). Both current
    # bridge messages — pinned verbatim above — must carry it, so a bridge
    # rewording that would break the trigger breaks this test first.
    for message in (BRIDGE_QUANTITY_REQUIRED_MSG, BRIDGE_QUANTITY_NOT_APPLICABLE_MSG):
        assert "quantity" in message


def test_quote_reported_before_signing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    world = HireWorld(tmp_path, per_unit=True)
    world.hire(quantity=10)
    err = capsys.readouterr().err
    assert "quote before signing: 0.50 LHUB-DEV" in err
    assert "min_charge" in err  # R-AFD-17: the floor is named in the quote line


def test_accept_hint_on_stderr_and_suppressible(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        assert name == "accept_deal"
        return {"deal_id": DEAL_ID, "state": "RELEASED"}

    kit = RouterKit(tmp_path / "home", route)
    monkeypatch.delenv("LHUB_KIT_QUIET", raising=False)
    out = lhub.do_accept(kit, deal_id=DEAL_ID)
    assert out["state"] == "RELEASED"  # stdout payload unchanged by the hint
    err = capsys.readouterr().err
    assert "sell" in err and "/docs/sell.md" in err

    monkeypatch.setenv("LHUB_KIT_QUIET", "1")
    lhub.do_accept(kit, deal_id=DEAL_ID)
    assert "sell --help" not in capsys.readouterr().err


def test_find_uses_session_when_identity_exists(tmp_path: Path) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        assert name == "search_services"
        return {"results": []}

    kit = RouterKit(tmp_path / "home", route)
    kit.ensure_key()  # an initialised kit
    lhub.do_find(kit, category="", free_text="x", limit=5)
    assert kit.ensure_session_calls == 1
    assert kit.with_session_flags == [True]


def test_find_stays_anonymous_without_identity(tmp_path: Path) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        assert name == "search_services"
        return {"results": []}

    kit = RouterKit(tmp_path / "home", route)
    lhub.do_find(kit, category="c", free_text="", limit=5)
    assert kit.ensure_session_calls == 0
    assert kit.with_session_flags == [False]
    assert not kit.key_path.exists()  # find alone never mints an identity
