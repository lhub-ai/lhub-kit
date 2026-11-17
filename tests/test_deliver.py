"""`deliver` (seller-door D-10): upload → Tier-0 proof, deterministic keys."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from routerkit import RouterKit

import lhub

DEAL_ID = "d0000000-0000-4000-8000-00000000d001"
DATA = b"# review\nall good\n"


class DeliverWorld:
    def __init__(self, tmp_path: Path) -> None:
        self.uploads: list[dict[str, Any]] = []
        self.proofs: list[dict[str, Any]] = []
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()

    def route(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "upload_deal_file":
            self.uploads.append(arguments)
            data = base64.b64decode(arguments["content_b64"])
            return {
                "deal_id": arguments["deal_id"],
                "kind": arguments["kind"],
                "sha256": lhub.sha256_ref(data).removeprefix("sha256:"),
                "size": len(data),
            }
        if name == "submit_proof":
            self.proofs.append(arguments)
            return {"deal_id": arguments["deal_id"], "state": "PROOF_SUBMITTED"}
        raise AssertionError(f"unexpected tool {name}")


@pytest.fixture
def world(tmp_path: Path) -> DeliverWorld:
    return DeliverWorld(tmp_path)


def test_deliver_uploads_then_submits_tier0_proof(world: DeliverWorld) -> None:
    out = lhub.do_deliver(world.kit, deal_id=DEAL_ID, data=DATA)
    assert out["state"] == "PROOF_SUBMITTED"

    (upload,) = world.uploads
    assert upload["kind"] == "deliverable"
    assert base64.b64decode(upload["content_b64"]) == DATA

    (proof_call,) = world.proofs
    payload = proof_call["proof_payload"]
    assert set(payload.keys()) == {"method", "hash", "jws"}
    assert payload["method"] == "signed-output-hash"
    assert payload["hash"] == lhub.sha256_ref(DATA)

    # The JWS is OUR ES256 over the JCS of {hash, deal_id, issued_at}
    # (the house agent's exact Tier-0 proof shape, signing.py:22-28).
    jws_payload = lhub._b64url_decode(payload["jws"].split(".")[1])
    signed = json.loads(jws_payload)
    assert set(signed.keys()) == {"hash", "deal_id", "issued_at"}
    assert signed["hash"] == payload["hash"]
    assert signed["deal_id"] == DEAL_ID
    assert lhub._ISSUED_AT_FORM.fullmatch(signed["issued_at"]) is not None
    lhub.verify_jws_es256_canonical(
        did=world.kit.did,
        jws=payload["jws"],
        expected_canonical=lhub.jcs_canonicalize(signed),
    )


def test_deliver_idempotency_key_is_deterministic(world: DeliverWorld) -> None:
    lhub.do_deliver(world.kit, deal_id=DEAL_ID, data=DATA)
    lhub.do_deliver(world.kit, deal_id=DEAL_ID, data=DATA)
    keys = [call["idempotency_key"] for call in world.proofs]
    assert keys[0] == keys[1]
    assert keys[0] == f"lhub-kit:proof:{DEAL_ID}:{lhub.sha256_ref(DATA)}"
    # A different deliverable derives a different key.
    lhub.do_deliver(world.kit, deal_id=DEAL_ID, data=b"other bytes")
    assert world.proofs[2]["idempotency_key"] != keys[0]


def test_deliver_refuses_oversize(world: DeliverWorld) -> None:
    with pytest.raises(lhub.KitError, match="160 KiB"):
        lhub.do_deliver(world.kit, deal_id=DEAL_ID, data=b"x" * (lhub.DELIVERABLE_CAP_BYTES + 1))
    assert world.uploads == []
    assert world.proofs == []


def test_deliver_cap_boundary_is_inclusive(world: DeliverWorld) -> None:
    lhub.do_deliver(world.kit, deal_id=DEAL_ID, data=b"x" * lhub.DELIVERABLE_CAP_BYTES)
    assert len(world.proofs) == 1


def test_deliver_refuses_empty(world: DeliverWorld) -> None:
    with pytest.raises(lhub.KitError, match="empty"):
        lhub.do_deliver(world.kit, deal_id=DEAL_ID, data=b"")
    assert world.uploads == []


def test_deliver_refuses_non_uuid_deal(world: DeliverWorld) -> None:
    with pytest.raises(lhub.KitError, match="not a UUID"):
        lhub.do_deliver(world.kit, deal_id="nope", data=DATA)
    assert world.uploads == []


def test_deliver_refuses_upload_hash_disagreement(tmp_path: Path) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "upload_deal_file":
            return {"sha256": "ee" * 32, "size": 1}
        raise AssertionError(name)

    kit = RouterKit(tmp_path / "home", route)
    with pytest.raises(lhub.KitError, match="came back with hash"):
        lhub.do_deliver(kit, deal_id=DEAL_ID, data=DATA)
