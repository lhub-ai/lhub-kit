"""`inbox` (seller-door D-10): countersign drive-through + funded-input fetch.

Proves at the FLOW level: a passing proposal is countersigned with the derived
idempotency key and a dualsig-shaped two-signature artifact over the kit's OWN
canonical bytes; ANY failed check produces no signature and is never retried
for the same proposal sha; funded inputs are hash-verified before they are
placed (O_EXCL|O_NOFOLLOW) under the jobs dir.
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

DEAL_ID = "d0000000-0000-4000-8000-00000000d001"
LISTING_ID = "7a1d2f30-1111-4222-8333-944444444444"
LISTING_HASH = "ab" * 32
JOB_INPUT = b"the job input bytes"
REQUEST_ID = lhub.sha256_ref(JOB_INPUT)


@pytest.fixture
def buyer_key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(0xB0BB1E5, ec.SECP256R1())


@pytest.fixture
def buyer_did(buyer_key: ec.EllipticCurvePrivateKey) -> str:
    return lhub.did_key_from_public_key(buyer_key.public_key())


class SellerWorld:
    """One seller kit + a scripted bridge for a single deal."""

    def __init__(
        self,
        tmp_path: Path,
        buyer_key: ec.EllipticCurvePrivateKey,
        buyer_did: str,
        *,
        amount: int = 500_000,
    ) -> None:
        self.buyer_key = buyer_key
        self.buyer_did = buyer_did
        self.agreed: list[dict[str, Any]] = []
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()
        core = {
            "pricing": {
                "model": "per_unit",
                "currency": lhub.SETTLEMENT_UNIT,
                "amount": "0.05",
                "unit": "file",
                "min_charge": "0.50",
            },
            "capability": {"extension_input": {"turnaround_hours": 1}},
        }
        self.kit.store_listing(LISTING_ID, LISTING_HASH, core)
        self.deal: dict[str, Any] = {
            "deal_id": DEAL_ID,
            "state": "NEGOTIATING",
            "amount": str(amount),
            "unit": lhub.SETTLEMENT_UNIT,
            "request_id": REQUEST_ID,
            "buyer_did": buyer_did,
            "provider_did": self.kit.did,
            "listing_content_hash": LISTING_HASH,
        }
        self.content: dict[str, Any] = {
            "version": "1",
            "deal_id": DEAL_ID,
            "request_id": REQUEST_ID,
            "listing_content_hash": LISTING_HASH,
            "buyer_did": buyer_did,
            "provider_did": self.kit.did,
            "amount": amount,
            "unit": lhub.SETTLEMENT_UNIT,
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self.proposal_bytes = b""
        self.sign_proposal()
        # D-4a: inbox items carry listing_content_hash, never a listing UUID.
        self.item: dict[str, Any] = {
            "deal_id": DEAL_ID,
            "listing_content_hash": LISTING_HASH,
            "state": "NEGOTIATING",
            "todo": "countersign",
            "has_proposal": True,
            "input": {"sha256": REQUEST_ID.removeprefix("sha256:"), "size": len(JOB_INPUT)},
        }

    def sign_proposal(self, **content_overrides: Any) -> None:
        content = dict(self.content)
        content.update(content_overrides)
        canonical = lhub.jcs_canonicalize(content)
        jws = lhub.sign_es256(self.buyer_key, canonical, kid=self.buyer_did)
        self.proposal_bytes = json.dumps(
            {"content": content, "signatures": [{"signer": self.buyer_did, "jws": jws}]}
        ).encode("utf-8")

    @property
    def proposal_sha(self) -> str:
        return hashlib.sha256(self.proposal_bytes).hexdigest()

    def route(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "get_inbox":
            return {"items": [self.item], "polled_at": "now", "poll_hint_seconds": 30}
        if name == "get_deal":
            return dict(self.deal)
        if name == "download_deal_file" and arguments.get("kind") == "agreement_proposal":
            return {
                "content_b64": base64.b64encode(self.proposal_bytes).decode(),
                "sha256": self.proposal_sha,
                "size": len(self.proposal_bytes),
            }
        if name == "download_deal_file" and arguments.get("kind") == "job_input":
            return {
                "content_b64": base64.b64encode(JOB_INPUT).decode(),
                "sha256": REQUEST_ID.removeprefix("sha256:"),
                "size": len(JOB_INPUT),
            }
        if name == "agree_deal":
            self.agreed.append(arguments)
            return {"deal_id": DEAL_ID, "state": "DEAL_AGREED"}
        raise AssertionError(f"unexpected tool {name}")


@pytest.fixture
def world(tmp_path: Path, buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str) -> SellerWorld:
    return SellerWorld(tmp_path, buyer_key, buyer_did)


def test_happy_path_countersigns_with_derived_key(world: SellerWorld) -> None:
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "countersigned"
    (agree,) = world.agreed
    expected_key = hashlib.sha256((DEAL_ID + world.proposal_sha).encode()).hexdigest()
    assert agree["idempotency_key"] == expected_key

    envelope = json.loads(base64.b64decode(agree["signed_artifact"], validate=True))
    assert set(envelope.keys()) == {"content", "signatures"}
    assert envelope["content"] == world.content
    signers = [sig["signer"] for sig in envelope["signatures"]]
    assert signers == sorted(signers)
    assert set(signers) == {world.buyer_did, world.kit.did}
    # Our countersignature verifies over OUR canonicalization of the content.
    ours = next(s for s in envelope["signatures"] if s["signer"] == world.kit.did)
    lhub.verify_jws_es256_canonical(
        did=world.kit.did,
        jws=ours["jws"],
        expected_canonical=lhub.jcs_canonicalize(world.content),
    )


def test_refusal_signs_nothing_and_is_never_retried(
    world: SellerWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Tamper the deal's amount so content-vs-deal (check 7) refuses.
    world.deal["amount"] = "499999"
    sign_calls: list[bytes] = []
    real = lhub.sign_es256

    def spy(key: ec.EllipticCurvePrivateKey, payload: bytes, *, kid: str) -> str:
        sign_calls.append(payload)
        return real(key, payload, kid=kid)

    monkeypatch.setattr(lhub, "sign_es256", spy)

    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "refused"
    assert "disagrees with the deal record" in action["reason"]
    assert world.agreed == []
    assert sign_calls == []  # NO signature was produced anywhere on the refusal path

    # Same proposal sha on the next poll: skipped, checks not re-run.
    out2 = lhub.do_inbox(world.kit)
    (action2,) = out2["actions"]
    assert action2["action"] == "skipped"
    assert "previously refused" in action2["reason"]
    assert world.agreed == []

    # A FRESH proposal (new sha) is evaluated again — fix the deal and re-sign.
    world.deal["amount"] = "500000"
    world.sign_proposal(issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    monkeypatch.setattr(lhub, "sign_es256", real)
    out3 = lhub.do_inbox(world.kit)
    (action3,) = out3["actions"]
    assert action3["action"] == "countersigned"


def test_wrong_signer_refused(world: SellerWorld) -> None:
    # The signature is valid ES256 — but by a key that is not the deal's buyer.
    stranger = ec.derive_private_key(0x57A9E12, ec.SECP256R1())
    stranger_did = lhub.did_key_from_public_key(stranger.public_key())
    canonical = lhub.jcs_canonicalize(world.content)
    jws = lhub.sign_es256(stranger, canonical, kid=stranger_did)
    world.proposal_bytes = json.dumps(
        {"content": world.content, "signatures": [{"signer": stranger_did, "jws": jws}]}
    ).encode()
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "refused"
    assert "not the deal's buyer" in action["reason"]
    assert world.agreed == []


def test_signature_over_different_bytes_refused(world: SellerWorld) -> None:
    # Signed by the right buyer, but over OTHER content than what is embedded.
    other = dict(world.content, amount=1)
    jws = lhub.sign_es256(world.buyer_key, lhub.jcs_canonicalize(other), kid=world.buyer_did)
    world.proposal_bytes = json.dumps(
        {"content": world.content, "signatures": [{"signer": world.buyer_did, "jws": jws}]}
    ).encode()
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "refused"
    assert "buyer signature invalid" in action["reason"]
    assert world.agreed == []


def test_stale_proposal_refused(world: SellerWorld) -> None:
    stale = time.gmtime(time.time() - lhub.AGREE_MAX_AGE_SECONDS - 60)
    world.sign_proposal(issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", stale))
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "refused"
    assert "stale" in action["reason"]
    assert world.agreed == []


def test_inputless_deal_refused(world: SellerWorld) -> None:
    world.item.pop("input")
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "refused"
    assert "job_input" in action["reason"]
    assert world.agreed == []


def test_unknown_listing_version_refused(world: SellerWorld) -> None:
    # D-4a: ownership matches by content hash. With no stored signed core
    # carrying the deal's pinned hash, the kit never countersigns — even
    # though deal, content and proposal are internally consistent.
    (world.kit.listings_dir / f"{LISTING_ID}.json").unlink()
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "refused"
    assert "no stored signed core" in action["reason"]
    assert world.agreed == []


def test_ownership_matched_by_deal_hash_not_item_fields(world: SellerWorld) -> None:
    # The inbox item's own listing_content_hash copy is advisory: the check
    # resolves ownership from the DEAL record's pinned hash (the platform's
    # value), so a garbled item field alone cannot flip the decision.
    world.item["listing_content_hash"] = "ff" * 32
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "countersigned"


def test_non_negotiating_deal_skipped_without_refusal_record(world: SellerWorld) -> None:
    world.deal["state"] = "DEAL_AGREED"
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "skipped"
    assert world.kit.refusal_reason(DEAL_ID, world.proposal_sha) is None


def test_no_countersign_flag_signs_nothing(world: SellerWorld) -> None:
    out = lhub.do_inbox(world.kit, countersign=False)
    assert out["actions"] == []
    assert world.agreed == []


def test_price_term_violation_refused_at_flow_level(
    tmp_path: Path, buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str
) -> None:
    # Deal and content agree on 0.07 — but the stored listing prices 0.05/unit
    # with min_charge 0.50, so 0.07 is neither a multiple meeting the floor
    # nor the exact floor: refuse.
    world = SellerWorld(tmp_path, buyer_key, buyer_did, amount=70_000)
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "refused"
    assert "min_charge" in action["reason"] or "multiple" in action["reason"]
    assert world.agreed == []


# ---------------------------------------------------------------------------
# Funded-input fetch (todo == fulfil).
# ---------------------------------------------------------------------------


def make_fulfil_world(world: SellerWorld) -> None:
    world.item["todo"] = "fulfil"
    world.item["state"] = "IN_FULFILLMENT"
    world.deal["state"] = "IN_FULFILLMENT"


def test_fulfil_fetches_and_verifies_input(world: SellerWorld) -> None:
    make_fulfil_world(world)
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "input_fetched"
    path = world.kit.jobs_dir / DEAL_ID / "input"
    assert path.read_bytes() == JOB_INPUT

    # Second poll: idempotent, nothing re-downloaded.
    out2 = lhub.do_inbox(world.kit)
    (action2,) = out2["actions"]
    assert action2["action"] == "input_present"


def test_fulfil_refuses_hash_mismatch(world: SellerWorld) -> None:
    make_fulfil_world(world)
    world.deal["request_id"] = "sha256:" + "ee" * 32
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "input_refused"
    assert not (world.kit.jobs_dir / DEAL_ID / "input").exists()


def test_fulfil_refuses_non_uuid_deal_id(world: SellerWorld) -> None:
    make_fulfil_world(world)
    world.item["deal_id"] = "../escape"
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "error"
    assert "not a UUID" in action["reason"]
    assert not (world.kit.jobs_dir / "../escape").exists()


def test_fulfil_refuses_symlinked_input_node(world: SellerWorld, tmp_path: Path) -> None:
    make_fulfil_world(world)
    job_dir = world.kit.job_dir(DEAL_ID)
    outside = tmp_path / "outside"
    outside.write_bytes(b"planted")
    (job_dir / "input").symlink_to(outside)
    out = lhub.do_inbox(world.kit)
    (action,) = out["actions"]
    assert action["action"] == "error"
    assert "symlink" in action["reason"]
    assert outside.read_bytes() == b"planted"  # never written through
