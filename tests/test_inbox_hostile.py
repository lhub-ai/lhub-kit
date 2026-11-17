"""Hostile-proposal survival (sec B-1): counterparty bytes never kill the loop.

The security BLOCKER's reproduction: a buyer uploads a v1-shaped
``agreement_proposal`` whose bytes json.loads accepts but a later step
explodes on — a lone-surrogate ``\\ud800`` escape (UnicodeEncodeError inside
``jcs_canonicalize``, BEFORE signature verification) or a deeply nested body
(RecursionError inside ``json.loads``). Neither exception is a ``KitError``,
so pre-fix it escaped ``countersign_item`` → ``do_inbox`` → ``main`` and
``inbox``/``serve`` died on every poll.

Proven here at the FLOW level, per trigger: NO signature is produced, the
poll returns (never raises), the refusal is recorded against the proposal sha
(skipped on the next poll, not re-evaluated), and the OTHER items in the same
poll — a funded fulfil job included — still process. Plus the fail-safe
boundary class: an unexpected exception inside the seller checks is memorized
against the sha; one outside them is reported and retried, never memorized.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from routerkit import RouterKit

import lhub

DEAL_A = "a0000000-0000-4000-8000-00000000000a"  # the hostile countersign deal
DEAL_B = "b0000000-0000-4000-8000-00000000000b"  # the funded fulfil deal
LISTING_ID = "7a1d2f30-1111-4222-8333-944444444444"
LISTING_HASH = "ab" * 32
JOB_INPUT = b"funded job input bytes"
JOB_REQUEST_ID = lhub.sha256_ref(JOB_INPUT)


@pytest.fixture
def buyer_key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(0xB0BB1E5, ec.SECP256R1())


@pytest.fixture
def buyer_did(buyer_key: ec.EllipticCurvePrivateKey) -> str:
    return lhub.did_key_from_public_key(buyer_key.public_key())


class TwoDealWorld:
    """One seller kit; one poll serves a hostile countersign item AND a funded job."""

    def __init__(
        self, tmp_path: Path, buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str
    ) -> None:
        self.buyer_key = buyer_key
        self.buyer_did = buyer_did
        self.agreed: list[dict[str, Any]] = []
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()
        core = {
            "pricing": {
                "model": "flat",
                "currency": lhub.SETTLEMENT_UNIT,
                "amount": "0.50",
                "unit": "job",
            },
            "capability": {"extension_input": {"turnaround_hours": 1}},
        }
        self.kit.store_listing(LISTING_ID, LISTING_HASH, core)
        proposal_request_id = "sha256:" + "cd" * 32
        # Deal A is valid in EVERY respect except the proposal bytes a test
        # plants — so the only thing standing between those bytes and a
        # countersignature is the refusal under test.
        self.deal_a: dict[str, Any] = {
            "deal_id": DEAL_A,
            "state": "NEGOTIATING",
            "amount": "500000",
            "unit": lhub.SETTLEMENT_UNIT,
            "request_id": proposal_request_id,
            "buyer_did": buyer_did,
            "provider_did": self.kit.did,
            "listing_content_hash": LISTING_HASH,
        }
        self.deal_b: dict[str, Any] = {
            "deal_id": DEAL_B,
            "state": "IN_FULFILLMENT",
            "amount": "500000",
            "unit": lhub.SETTLEMENT_UNIT,
            "request_id": JOB_REQUEST_ID,
            "buyer_did": buyer_did,
            "provider_did": self.kit.did,
            "listing_content_hash": LISTING_HASH,
        }
        self.content: dict[str, Any] = {
            "version": "1",
            "deal_id": DEAL_A,
            "request_id": proposal_request_id,
            "listing_content_hash": LISTING_HASH,
            "buyer_did": buyer_did,
            "provider_did": self.kit.did,
            "amount": 500_000,
            "unit": lhub.SETTLEMENT_UNIT,
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self.proposal_bytes = b"{}"
        self.items: list[dict[str, Any]] = [
            {
                "deal_id": DEAL_A,
                "listing_content_hash": LISTING_HASH,
                "state": "NEGOTIATING",
                "todo": "countersign",
                "has_proposal": True,
                "input": {"sha256": "cd" * 32, "size": 3},
            },
            {
                "deal_id": DEAL_B,
                "listing_content_hash": LISTING_HASH,
                "state": "IN_FULFILLMENT",
                "todo": "fulfil",
            },
        ]

    def plant_proposal(self, content: dict[str, Any]) -> None:
        """Plant proposal bytes for deal A (signature irrelevant: refusal is pre-verify)."""
        self.proposal_bytes = json.dumps(
            {"content": content, "signatures": [{"signer": self.buyer_did, "jws": "a.b.c"}]}
        ).encode()

    def plant_signed_proposal(self, content: dict[str, Any]) -> None:
        """Plant a proposal with a VALID buyer signature (passes checks 4-7)."""
        jws = lhub.sign_es256(self.buyer_key, lhub.jcs_canonicalize(content), kid=self.buyer_did)
        self.proposal_bytes = json.dumps(
            {"content": content, "signatures": [{"signer": self.buyer_did, "jws": jws}]}
        ).encode()

    @property
    def proposal_sha(self) -> str:
        return hashlib.sha256(self.proposal_bytes).hexdigest()

    def route(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "get_inbox":
            return {"items": list(self.items), "polled_at": "now", "poll_hint_seconds": 30}
        if name == "get_deal":
            return dict(self.deal_a if arguments["deal_id"] == DEAL_A else self.deal_b)
        if name == "download_deal_file" and arguments.get("kind") == "agreement_proposal":
            return {
                "content_b64": base64.b64encode(self.proposal_bytes).decode(),
                "sha256": self.proposal_sha,
                "size": len(self.proposal_bytes),
            }
        if name == "download_deal_file" and arguments.get("kind") == "job_input":
            return {
                "content_b64": base64.b64encode(JOB_INPUT).decode(),
                "sha256": JOB_REQUEST_ID.removeprefix("sha256:"),
                "size": len(JOB_INPUT),
            }
        if name == "agree_deal":
            self.agreed.append(arguments)
            return {"deal_id": arguments["deal_id"], "state": "DEAL_AGREED"}
        raise AssertionError(f"unexpected tool {name}")


@pytest.fixture
def world(tmp_path: Path, buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str) -> TwoDealWorld:
    return TwoDealWorld(tmp_path, buyer_key, buyer_did)


def assert_hostile_refused_loop_survives(
    world: TwoDealWorld, monkeypatch: pytest.MonkeyPatch, *, reason_match: str
) -> None:
    """The full B-1 acceptance: refuse + record + no signature + rest of poll runs."""
    sign_calls: list[bytes] = []
    real = lhub.sign_es256

    def spy(key: ec.EllipticCurvePrivateKey, payload: bytes, *, kid: str) -> str:
        sign_calls.append(payload)
        return real(key, payload, kid=kid)

    monkeypatch.setattr(lhub, "sign_es256", spy)

    out = lhub.do_inbox(world.kit)  # must RETURN — pre-fix this poll raised
    by_deal = {action["deal_id"]: action for action in out["actions"]}
    assert by_deal[DEAL_A]["action"] == "refused"
    assert reason_match in by_deal[DEAL_A]["reason"]
    # The funded fulfil job in the SAME poll still processed.
    assert by_deal[DEAL_B]["action"] == "input_fetched"
    assert (world.kit.jobs_dir / DEAL_B / "input").read_bytes() == JOB_INPUT
    # No signature was produced anywhere, and nothing was agreed.
    assert sign_calls == []
    assert world.agreed == []
    # The refusal is recorded against the proposal sha…
    assert world.kit.refusal_reason(DEAL_A, world.proposal_sha) is not None
    # …so the next poll skips it (not re-evaluated) and keeps going.
    out2 = lhub.do_inbox(world.kit)
    by_deal2 = {action["deal_id"]: action for action in out2["actions"]}
    assert by_deal2[DEAL_A]["action"] == "skipped"
    assert "previously refused" in by_deal2[DEAL_A]["reason"]
    assert by_deal2[DEAL_B]["action"] == "input_present"
    assert world.agreed == []


def test_lone_surrogate_in_content_field_refused_loop_survives(
    world: TwoDealWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    # json.loads accepts "unit": "\ud800"; pre-fix jcs_canonicalize then raised
    # UnicodeEncodeError (not a KitError) BEFORE signature verification.
    world.plant_proposal(dict(world.content, unit="\ud800"))
    assert_hostile_refused_loop_survives(world, monkeypatch, reason_match="UTF-8")


def test_lone_surrogate_in_content_key_refused_loop_survives(
    world: TwoDealWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = dict(world.content)
    content["\ud800"] = "x"
    world.plant_proposal(content)
    assert_hostile_refused_loop_survives(world, monkeypatch, reason_match="UTF-8")


def test_deeply_nested_proposal_refused_loop_survives(
    world: TwoDealWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pre-fix: RecursionError at json.loads escaped every handler in the chain.
    world.proposal_bytes = b"[" * 40_000 + b"]" * 40_000
    assert_hostile_refused_loop_survives(world, monkeypatch, reason_match="nested too deeply")


def test_fat_hostile_key_set_stores_a_bounded_reason(world: TwoDealWorld) -> None:
    # sec R2 N-1: the key-set-mismatch refusal embeds the extra keys — a
    # counterparty can make that list enormous. The STORED reason and the
    # re-emitted skip reason must stay bounded printable ASCII.
    content = dict(world.content)
    for i in range(200):
        content[f"hostile_key_{i:03d}_" + "A" * 100] = "x"
    world.plant_proposal(content)

    out = lhub.do_inbox(world.kit)
    by_deal = {action["deal_id"]: action for action in out["actions"]}
    assert by_deal[DEAL_A]["action"] == "refused"
    stored = world.kit.refusal_reason(DEAL_A, world.proposal_sha)
    assert stored is not None
    assert len(stored) <= 400
    assert all(0x20 <= ord(ch) < 0x7F for ch in stored)  # printable ASCII only
    # The next poll re-emits a bounded skip reason, not the raw stored text.
    out2 = lhub.do_inbox(world.kit)
    by_deal2 = {action["deal_id"]: action for action in out2["actions"]}
    assert by_deal2[DEAL_A]["action"] == "skipped"
    assert len(by_deal2[DEAL_A]["reason"]) <= 460  # prefix + clipped prior
    assert world.agreed == []


def test_unexpected_check_exception_memorized_against_sha(
    world: TwoDealWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The CLASS, not just the two instances: ANY unexpected exception inside
    # the seller checks is content-derived for those bytes — recorded against
    # the proposal sha like a refusal, no signature, loop alive. The proposal
    # is fully valid (signed), so the patched check is really what fires.
    world.plant_signed_proposal(dict(world.content))

    def boom(**_kwargs: Any) -> None:
        raise RuntimeError("latent check bug")

    with monkeypatch.context() as patched:
        patched.setattr(lhub, "check_price_terms", boom)
        out = lhub.do_inbox(world.kit)
    by_deal = {action["deal_id"]: action for action in out["actions"]}
    assert by_deal[DEAL_A]["action"] == "refused"
    assert "fail-safe" in by_deal[DEAL_A]["reason"]
    assert "RuntimeError" in by_deal[DEAL_A]["reason"]
    assert by_deal[DEAL_B]["action"] == "input_fetched"
    assert world.agreed == []
    # The patch is gone — the checks would now PASS — but the sha is
    # memorized, so the same bytes are skipped, not re-evaluated (and still
    # not signed).
    out2 = lhub.do_inbox(world.kit)
    by_deal2 = {action["deal_id"]: action for action in out2["actions"]}
    assert by_deal2[DEAL_A]["action"] == "skipped"
    assert world.agreed == []


def test_unexpected_item_exception_reported_not_memorized(
    world: TwoDealWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The OUTER fail-safe (do_inbox): a failure not attributable to proposal
    # bytes is reported, the rest of the poll runs, and NOTHING is memorized —
    # the item retries next poll.
    world.plant_proposal(dict(world.content))

    def boom(kit: lhub.Kit, item: Any, *, now_unix: float) -> dict[str, Any]:
        raise RuntimeError("latent item bug")

    with monkeypatch.context() as patched:
        patched.setattr(lhub, "countersign_item", boom)
        out = lhub.do_inbox(world.kit)
    by_deal = {action["deal_id"]: action for action in out["actions"]}
    assert by_deal[DEAL_A]["action"] == "error"
    assert "RuntimeError" in by_deal[DEAL_A]["reason"]
    assert by_deal[DEAL_B]["action"] == "input_fetched"
    assert world.kit.refusal_reason(DEAL_A, world.proposal_sha) is None  # retryable


# ---------------------------------------------------------------------------
# D-14 pinned wrapper key: a get_inbox payload without "items" is a CONTRACT
# error surfaced legibly — never an empty inbox, never a tolerated fallback.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"results": [], "polled_at": "now"},
        {"inbox": [], "polled_at": "now"},
        {"items": "not-a-list"},
        {},
    ],
)
def test_inbox_without_items_list_is_contract_error(
    tmp_path: Path, payload: dict[str, Any]
) -> None:
    kit = RouterKit(tmp_path / "home", lambda name, arguments: dict(payload))
    kit.ensure_key()
    with pytest.raises(lhub.KitError, match="'items'"):
        lhub.do_inbox(kit)


def test_inbox_with_empty_items_list_is_fine(tmp_path: Path) -> None:
    kit = RouterKit(tmp_path / "home", lambda name, arguments: {"items": [], "polled_at": "now"})
    kit.ensure_key()
    out = lhub.do_inbox(kit)
    assert out["items"] == []
    assert out["actions"] == []
