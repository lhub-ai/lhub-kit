"""The hire signing gate (D-5 step 2 / spec "Hire Flow").

The kit signs ONLY its own JCS of the validated template content. Every test
here also proves the refusal happens BEFORE any signature exists: the signer
is instrumented, and a refusal with ``calls != 0`` would fail.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import lhub

DEAL_ID = "d0000000-0000-4000-8000-00000000d001"
PROVIDER_DID = "did:key:zProviderExample"
LISTING_HASH = "ab" * 32
REQUEST_ID = "sha256:" + hashlib.sha256(b"job input bytes").hexdigest()
MAX_PRICE = 1_000_000  # 1.00 LHUB-DEV


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(0x1234567890ABCDEF1234567890ABCDEF, ec.SECP256R1())


@pytest.fixture
def own_did(key: ec.EllipticCurvePrivateKey) -> str:
    return lhub.did_key_from_public_key(key.public_key())


@pytest.fixture
def sign_calls(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Instrument the signer; refusal paths must leave this empty."""
    calls: list[bytes] = []
    real = lhub.sign_es256

    def spy(key: ec.EllipticCurvePrivateKey, payload: bytes, *, kid: str) -> str:
        calls.append(payload)
        return real(key, payload, kid=kid)

    monkeypatch.setattr(lhub, "sign_es256", spy)
    return calls


def make_template(own_did: str, **content_overrides: Any) -> dict[str, Any]:
    content: dict[str, Any] = {
        "version": "1",
        "deal_id": DEAL_ID,
        "request_id": REQUEST_ID,
        "listing_content_hash": LISTING_HASH,
        "buyer_did": own_did,
        "provider_did": PROVIDER_DID,
        "amount": 500_000,
        "unit": lhub.SETTLEMENT_UNIT,
        "issued_at": "2026-11-15T12:00:00Z",
    }
    content.update(content_overrides)
    canonical = lhub.jcs_canonicalize(content)
    return {
        "deal_id": DEAL_ID,
        "content": content,
        "canonical_b64": base64.b64encode(canonical).decode("ascii"),
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def sign_it(
    template: dict[str, Any],
    key: ec.EllipticCurvePrivateKey,
    own_did: str,
    **overrides: Any,
) -> tuple[str, bytes]:
    kwargs: dict[str, Any] = {
        "own_did": own_did,
        "deal_id": DEAL_ID,
        "request_id": REQUEST_ID,
        "max_price_minor": MAX_PRICE,
        "deal_provider": PROVIDER_DID,
        "pinned_provider": None,
        "key": key,
    }
    kwargs.update(overrides)
    return lhub.validate_template_and_sign(template, **kwargs)


def test_valid_template_produces_one_signature_artifact(
    key: ec.EllipticCurvePrivateKey, own_did: str
) -> None:
    template = make_template(own_did)
    artifact_b64, canonical = sign_it(template, key, own_did)

    envelope = json.loads(base64.b64decode(artifact_b64, validate=True))
    assert set(envelope.keys()) == {"content", "signatures"}
    assert envelope["content"] == template["content"]
    assert len(envelope["signatures"]) == 1
    sig = envelope["signatures"][0]
    assert sig["signer"] == own_did

    # The JWS payload is the kit's OWN canonical bytes of the content.
    payload_b64 = sig["jws"].split(".")[1]
    payload = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    assert payload == canonical == lhub.jcs_canonicalize(template["content"])

    # The embedded content serialization IS the canonical form (no drift on re-parse).
    assert json.loads(canonical) == template["content"]


def test_canonical_b64_mismatch_refused_unsigned(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    """Spec: server-supplied bytes that disagree with the content are never signed."""
    template = make_template(own_did)
    other = dict(template["content"])
    other["amount"] = 500_001  # one minor unit off — different canonical bytes
    template["canonical_b64"] = base64.b64encode(lhub.jcs_canonicalize(other)).decode("ascii")

    with pytest.raises(lhub.KitRefusal, match=r"refusing to sign.*canonical"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_sha256_mismatch_refused_unsigned(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    template = make_template(own_did)
    template["sha256"] = "0" * 64
    with pytest.raises(lhub.KitRefusal, match=r"refusing to sign.*sha256"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_invalid_canonical_b64_refused_unsigned(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    template = make_template(own_did)
    template["canonical_b64"] = "not-base64!!!"
    with pytest.raises(lhub.KitRefusal, match="refusing to sign"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_wrong_unit_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    """R2 sec N-5: a unit other than LHUB-DEV is refused."""
    template = make_template(own_did, unit="USD")
    with pytest.raises(lhub.KitRefusal, match=r"refusing to sign.*unit"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_over_budget_refused_naming_amount_and_limit(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    """Spec scenario: the refusal names the amount and the limit."""
    template = make_template(own_did, amount=2_000_000)
    with pytest.raises(lhub.KitRefusal) as excinfo:
        sign_it(template, key, own_did)
    message = str(excinfo.value)
    assert "2000000" in message and "2.00 LHUB-DEV" in message
    assert "1000000" in message and "1.00 LHUB-DEV" in message
    assert sign_calls == []


def test_amount_at_max_price_is_signed(key: ec.EllipticCurvePrivateKey, own_did: str) -> None:
    template = make_template(own_did, amount=MAX_PRICE)
    artifact_b64, _ = sign_it(template, key, own_did)
    assert artifact_b64


def test_wrong_request_id_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    template = make_template(own_did, request_id="sha256:" + "c" * 64)
    with pytest.raises(lhub.KitRefusal, match="request_id"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_wrong_buyer_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    template = make_template(own_did, buyer_did="did:key:zSomeoneElse")
    with pytest.raises(lhub.KitRefusal, match="buyer_did"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_provider_mismatch_against_deal_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    template = make_template(own_did, provider_did="did:key:zSwappedProvider")
    with pytest.raises(lhub.KitRefusal, match="provider_did"):
        sign_it(template, key, own_did)  # deal_provider fixture default = PROVIDER_DID
    assert sign_calls == []


def test_pinned_provider_mismatch_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    template = make_template(own_did)
    with pytest.raises(lhub.KitRefusal, match="--provider"):
        sign_it(template, key, own_did, pinned_provider="did:key:zTheOneISawInFind")
    assert sign_calls == []


def test_no_provider_anchor_refused_unsigned(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    """sdd N2: no deal provider AND no --provider pin → fail closed, unsigned."""
    template = make_template(own_did)
    with pytest.raises(lhub.KitRefusal, match="provider anchor"):
        sign_it(template, key, own_did, deal_provider=None, pinned_provider=None)
    assert sign_calls == []


def test_pin_alone_is_a_sufficient_anchor(key: ec.EllipticCurvePrivateKey, own_did: str) -> None:
    """A --provider pin still allows signing when the deal read lacks provider_did."""
    template = make_template(own_did)
    artifact_b64, _ = sign_it(
        template, key, own_did, deal_provider=None, pinned_provider=PROVIDER_DID
    )
    assert artifact_b64


def test_unknown_content_field_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    """Signing fields we did not validate is refused (e.g. a smuggled acceptance object)."""
    template = make_template(own_did, acceptance={"auto": True})
    with pytest.raises(lhub.KitRefusal, match="field set"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_float_amount_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    # Build a valid template first, then swap in the float: the amount TYPE
    # check must fire before any canonicalization of the content is attempted.
    template = make_template(own_did)
    template["content"]["amount"] = 0.5
    with pytest.raises(lhub.KitRefusal, match="integer"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_wrong_deal_id_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    template = make_template(own_did, deal_id="d0000000-0000-4000-8000-00000000beef")
    with pytest.raises(lhub.KitRefusal, match="deal_id"):
        sign_it(template, key, own_did)
    assert sign_calls == []


def test_wrong_version_refused(
    key: ec.EllipticCurvePrivateKey, own_did: str, sign_calls: list[bytes]
) -> None:
    template = make_template(own_did, version="2")
    with pytest.raises(lhub.KitRefusal, match="version"):
        sign_it(template, key, own_did)
    assert sign_calls == []
