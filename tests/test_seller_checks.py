"""The seller countersign checks (seller-door D-10) — the refusal matrix.

Every check refuses on its own failure, with a one-line reason, and the pure
check functions never sign anything (there is no signer in scope at all).
The matrix mirrors the house agent's countersign.py, the reference
implementation these checks were ported from.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import lhub

DEAL_ID = "d0000000-0000-4000-8000-00000000d001"
LISTING_ID = "11111111-2222-4333-8444-555555555555"
LISTING_HASH = "ab" * 32
REQUEST_ID = "sha256:" + "cd" * 32
NOW = time.time()


@pytest.fixture
def seller_key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(0x5E11E12, ec.SECP256R1())


@pytest.fixture
def seller_did(seller_key: ec.EllipticCurvePrivateKey) -> str:
    return lhub.did_key_from_public_key(seller_key.public_key())


@pytest.fixture
def buyer_key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(0xB0BB1E5, ec.SECP256R1())


@pytest.fixture
def buyer_did(buyer_key: ec.EllipticCurvePrivateKey) -> str:
    return lhub.did_key_from_public_key(buyer_key.public_key())


def make_deal(seller_did: str, buyer_did: str, **overrides: Any) -> dict[str, Any]:
    deal: dict[str, Any] = {
        "deal_id": DEAL_ID,
        "state": "NEGOTIATING",
        "request_id": REQUEST_ID,
        "buyer_did": buyer_did,
        "provider_did": seller_did,
        "unit": lhub.SETTLEMENT_UNIT,
        "amount": 500_000,
        "listing_content_hash": LISTING_HASH,
    }
    deal.update(overrides)
    return deal


def make_stored(**pricing_overrides: Any) -> dict[str, Any]:
    pricing: dict[str, Any] = {
        "model": "per_unit",
        "currency": lhub.SETTLEMENT_UNIT,
        "amount": "0.05",
        "unit": "file",
        "min_charge": "0.50",
    }
    pricing.update(pricing_overrides)
    return {
        "listing_id": LISTING_ID,
        "content_hash": LISTING_HASH,
        "core": {"pricing": pricing},
    }


def make_content(seller_did: str, buyer_did: str, **overrides: Any) -> dict[str, Any]:
    content: dict[str, Any] = {
        "version": "1",
        "deal_id": DEAL_ID,
        "request_id": REQUEST_ID,
        "listing_content_hash": LISTING_HASH,
        "buyer_did": buyer_did,
        "provider_did": seller_did,
        "amount": 500_000,
        "unit": lhub.SETTLEMENT_UNIT,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW)),
    }
    content.update(overrides)
    return content


def make_proposal_bytes(
    content: dict[str, Any],
    buyer_key: ec.EllipticCurvePrivateKey,
    buyer_did: str,
    *,
    signer: str | None = None,
    jws: str | None = None,
    signatures: list[dict[str, Any]] | None = None,
    envelope_extra: dict[str, Any] | None = None,
) -> bytes:
    sig = jws or lhub.sign_es256(buyer_key, lhub.jcs_canonicalize(content), kid=buyer_did)
    envelope: dict[str, Any] = {
        "content": content,
        "signatures": (
            signatures if signatures is not None else [{"signer": signer or buyer_did, "jws": sig}]
        ),
    }
    if envelope_extra:
        envelope.update(envelope_extra)
    return json.dumps(envelope).encode("utf-8")


# ---------------------------------------------------------------------------
# Check 4 — the strict envelope parse.
# ---------------------------------------------------------------------------


def test_parse_valid_proposal(buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str) -> None:
    content = make_content("did:key:zSeller", buyer_did)
    parsed = lhub.parse_seller_proposal(make_proposal_bytes(content, buyer_key, buyer_did))
    assert parsed.content == content
    assert parsed.signer == buyer_did
    assert parsed.issued_at_unix == pytest.approx(NOW, abs=1.0)


def test_parse_refuses_non_json() -> None:
    with pytest.raises(lhub.KitRefusal, match="not valid JSON"):
        lhub.parse_seller_proposal(b"\xff\xfenot json")


# --- sec B-1: counterparty bytes must only ever REFUSE, never crash. ---
# json.loads accepts "\ud800"-style escapes (lone surrogates) that later raise
# UnicodeEncodeError — not a KitError — inside jcs_canonicalize, BEFORE any
# signature verification; a deeply nested body raises RecursionError inside
# json.loads itself. Both must surface as KitRefusal.


def test_parse_refuses_lone_surrogate_in_content_value(buyer_did: str) -> None:
    content = make_content("s", buyer_did, unit="\ud800")
    raw = json.dumps(
        {"content": content, "signatures": [{"signer": buyer_did, "jws": "x.y.z"}]}
    ).encode()
    with pytest.raises(lhub.KitRefusal, match="UTF-8"):
        lhub.parse_seller_proposal(raw)


def test_parse_refuses_lone_surrogate_in_content_key(buyer_did: str) -> None:
    content = make_content("s", buyer_did)
    content["\ud800"] = "x"
    raw = json.dumps(
        {"content": content, "signatures": [{"signer": buyer_did, "jws": "x.y.z"}]}
    ).encode()
    with pytest.raises(lhub.KitRefusal, match="UTF-8"):
        lhub.parse_seller_proposal(raw)


def test_parse_refuses_lone_surrogate_in_signer(buyer_did: str) -> None:
    content = make_content("s", buyer_did)
    raw = json.dumps(
        {"content": content, "signatures": [{"signer": "\udfff", "jws": "x.y.z"}]}
    ).encode()
    with pytest.raises(lhub.KitRefusal, match="UTF-8"):
        lhub.parse_seller_proposal(raw)


def test_parse_refuses_deeply_nested_body() -> None:
    deep = b"[" * 40_000 + b"]" * 40_000
    with pytest.raises(lhub.KitRefusal, match="nested too deeply"):
        lhub.parse_seller_proposal(deep)


def test_parse_refuses_envelope_extra_key(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str
) -> None:
    raw = make_proposal_bytes(
        make_content("s", buyer_did), buyer_key, buyer_did, envelope_extra={"extra": 1}
    )
    with pytest.raises(lhub.KitRefusal, match="envelope keys"):
        lhub.parse_seller_proposal(raw)


def test_parse_refuses_unknown_content_key_including_acceptance(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str
) -> None:
    content = make_content("s", buyer_did, acceptance={"any": "thing"})
    with pytest.raises(lhub.KitRefusal, match="field set mismatch"):
        lhub.parse_seller_proposal(make_proposal_bytes(content, buyer_key, buyer_did))


def test_parse_refuses_missing_content_key(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str
) -> None:
    content = make_content("s", buyer_did)
    del content["unit"]
    with pytest.raises(lhub.KitRefusal, match="field set mismatch"):
        lhub.parse_seller_proposal(make_proposal_bytes(content, buyer_key, buyer_did))


@pytest.mark.parametrize("bad_amount", [True, "500000", 1.5, None])
def test_parse_refuses_non_int_amount(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str, bad_amount: Any
) -> None:
    content = make_content("s", buyer_did, amount=bad_amount)
    raw = json.dumps(
        {"content": content, "signatures": [{"signer": buyer_did, "jws": "x.y.z"}]}
    ).encode()
    with pytest.raises(lhub.KitRefusal, match="amount"):
        lhub.parse_seller_proposal(raw)


def test_parse_refuses_amount_over_bound(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str
) -> None:
    content = make_content("s", buyer_did, amount=lhub.MAX_SAFE_INT + 1)
    raw = json.dumps(
        {"content": content, "signatures": [{"signer": buyer_did, "jws": "x.y.z"}]}
    ).encode()
    with pytest.raises(lhub.KitRefusal, match="not in \\[0,"):
        lhub.parse_seller_proposal(raw)


def test_parse_refuses_wrong_version(buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str) -> None:
    content = make_content("s", buyer_did, version="2")
    with pytest.raises(lhub.KitRefusal, match="version"):
        lhub.parse_seller_proposal(make_proposal_bytes(content, buyer_key, buyer_did))


def test_parse_refuses_naive_issued_at(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str
) -> None:
    content = make_content("s", buyer_did, issued_at="2026-11-15T12:00:00")
    with pytest.raises(lhub.KitRefusal, match="issued_at"):
        lhub.parse_seller_proposal(make_proposal_bytes(content, buyer_key, buyer_did))


@pytest.mark.parametrize("count", [0, 2])
def test_parse_refuses_wrong_signature_count(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str, count: int
) -> None:
    sig = {"signer": buyer_did, "jws": "a.b.c"}
    raw = make_proposal_bytes(
        make_content("s", buyer_did), buyer_key, buyer_did, signatures=[sig] * count
    )
    with pytest.raises(lhub.KitRefusal, match="exactly one signature"):
        lhub.parse_seller_proposal(raw)


def test_parse_refuses_signature_object_extra_key(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str
) -> None:
    raw = make_proposal_bytes(
        make_content("s", buyer_did),
        buyer_key,
        buyer_did,
        signatures=[{"signer": buyer_did, "jws": "a.b.c", "extra": "x"}],
    )
    with pytest.raises(lhub.KitRefusal, match="exactly \\{signer, jws\\}"):
        lhub.parse_seller_proposal(raw)


@pytest.mark.parametrize("field", ["signer", "jws"])
def test_parse_refuses_non_string_signature_fields(
    buyer_key: ec.EllipticCurvePrivateKey, buyer_did: str, field: str
) -> None:
    sig: dict[str, Any] = {"signer": buyer_did, "jws": "a.b.c"}
    sig[field] = 7
    raw = make_proposal_bytes(make_content("s", buyer_did), buyer_key, buyer_did, signatures=[sig])
    with pytest.raises(lhub.KitRefusal, match=f"signature.{field}"):
        lhub.parse_seller_proposal(raw)


# ---------------------------------------------------------------------------
# Checks 2 + 3 — the listing is ours and the input is bound.
# ---------------------------------------------------------------------------


def test_binding_passes_on_matching_deal(seller_did: str, buyer_did: str) -> None:
    lhub.check_seller_binding(
        own_did=seller_did,
        deal=make_deal(seller_did, buyer_did),
        stored=make_stored(),
        input_present=True,
    )


def test_binding_refuses_wrong_provider(seller_did: str, buyer_did: str) -> None:
    with pytest.raises(lhub.KitRefusal, match="provider is not this kit's DID"):
        lhub.check_seller_binding(
            own_did=seller_did,
            deal=make_deal("did:key:zSomeoneElse", buyer_did),
            stored=make_stored(),
            input_present=True,
        )


def test_binding_refuses_unknown_listing_version(seller_did: str, buyer_did: str) -> None:
    # D-4a: ownership matches by content hash; no stored core with the deal's
    # pinned hash means "not a listing version this kit sold" — refuse.
    with pytest.raises(lhub.KitRefusal, match="no stored signed core"):
        lhub.check_seller_binding(
            own_did=seller_did,
            deal=make_deal(seller_did, buyer_did),
            stored=None,
            input_present=True,
        )


def test_binding_refuses_content_hash_mismatch(seller_did: str, buyer_did: str) -> None:
    stored = make_stored()
    stored["content_hash"] = "ee" * 32
    with pytest.raises(lhub.KitRefusal, match="listing_content_hash"):
        lhub.check_seller_binding(
            own_did=seller_did,
            deal=make_deal(seller_did, buyer_did),
            stored=stored,
            input_present=True,
        )


def test_binding_refuses_missing_pinned_hash(seller_did: str, buyer_did: str) -> None:
    deal = make_deal(seller_did, buyer_did, listing_content_hash=None)
    with pytest.raises(lhub.KitRefusal, match="no listing_content_hash"):
        lhub.check_seller_binding(
            own_did=seller_did, deal=deal, stored=make_stored(), input_present=True
        )


def test_binding_refuses_non_sha_request_id(seller_did: str, buyer_did: str) -> None:
    deal = make_deal(seller_did, buyer_did, request_id="plain-request-7")
    with pytest.raises(lhub.KitRefusal, match="not sha256-bound"):
        lhub.check_seller_binding(
            own_did=seller_did, deal=deal, stored=make_stored(), input_present=True
        )


def test_binding_refuses_inputless_deal(seller_did: str, buyer_did: str) -> None:
    with pytest.raises(lhub.KitRefusal, match="no job_input"):
        lhub.check_seller_binding(
            own_did=seller_did,
            deal=make_deal(seller_did, buyer_did),
            stored=make_stored(),
            input_present=False,
        )


# ---------------------------------------------------------------------------
# Check 5 — freshness (strict boundaries, mirroring dualsig).
# ---------------------------------------------------------------------------


def test_freshness_accepts_recent() -> None:
    lhub.check_proposal_freshness(NOW - 60, now_unix=NOW)


def test_freshness_refuses_stale() -> None:
    with pytest.raises(lhub.KitRefusal, match="stale"):
        lhub.check_proposal_freshness(NOW - lhub.AGREE_MAX_AGE_SECONDS - 1, now_unix=NOW)


def test_freshness_refuses_future() -> None:
    with pytest.raises(lhub.KitRefusal, match="future"):
        lhub.check_proposal_freshness(NOW + lhub.AGREE_FUTURE_SKEW_SECONDS + 1, now_unix=NOW)


def test_freshness_boundaries_are_inclusive() -> None:
    lhub.check_proposal_freshness(NOW - lhub.AGREE_MAX_AGE_SECONDS, now_unix=NOW)
    lhub.check_proposal_freshness(NOW + lhub.AGREE_FUTURE_SKEW_SECONDS, now_unix=NOW)


# ---------------------------------------------------------------------------
# Check 7 — every content field equals the deal record.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("deal_id", "d0000000-0000-4000-8000-00000000d002"),
        ("request_id", "sha256:" + "ee" * 32),
        ("buyer_did", "did:key:zNotTheBuyer"),
        ("amount", 499_999),
        ("unit", "USD"),
        ("listing_content_hash", "ee" * 32),
    ],
)
def test_content_mismatch_refused_per_field(
    seller_did: str, buyer_did: str, field: str, value: Any
) -> None:
    content = make_content(seller_did, buyer_did)
    content[field] = value
    with pytest.raises(lhub.KitRefusal, match=field):
        lhub.check_content_matches_deal(
            content=content, deal=make_deal(seller_did, buyer_did), own_did=seller_did
        )


def test_content_wrong_provider_refused(seller_did: str, buyer_did: str) -> None:
    content = make_content("did:key:zNotUs", buyer_did)
    with pytest.raises(lhub.KitRefusal, match="provider_did"):
        lhub.check_content_matches_deal(
            content=content, deal=make_deal(seller_did, buyer_did), own_did=seller_did
        )


def test_content_match_passes_and_reports_all_mismatches(seller_did: str, buyer_did: str) -> None:
    deal = make_deal(seller_did, buyer_did)
    lhub.check_content_matches_deal(
        content=make_content(seller_did, buyer_did), deal=deal, own_did=seller_did
    )
    bad = make_content(seller_did, buyer_did, amount=1, unit="USD")
    with pytest.raises(lhub.KitRefusal, match="amount, unit"):
        lhub.check_content_matches_deal(content=bad, deal=deal, own_did=seller_did)


# ---------------------------------------------------------------------------
# Check 8 — price terms from the STORED listing core.
# ---------------------------------------------------------------------------

PER_UNIT = {"model": "per_unit", "currency": "LHUB-DEV", "amount": "0.05", "unit": "file"}


def _pricing(**overrides: Any) -> dict[str, Any]:
    pricing = dict(PER_UNIT)
    pricing.update(overrides)
    return pricing


def test_price_flat_exact_passes() -> None:
    lhub.check_price_terms(
        amount=500_000,
        pricing={"model": "flat", "currency": "LHUB-DEV", "amount": "0.50", "unit": "review"},
        proposal_unit="LHUB-DEV",
    )


def test_price_flat_mismatch_refused() -> None:
    with pytest.raises(lhub.KitRefusal, match="flat amount"):
        lhub.check_price_terms(
            amount=499_999,
            pricing={"model": "flat", "currency": "LHUB-DEV", "amount": "0.50", "unit": "x"},
            proposal_unit="LHUB-DEV",
        )


def test_price_per_unit_multiple_passes() -> None:
    lhub.check_price_terms(amount=150_000, pricing=_pricing(), proposal_unit="LHUB-DEV")


def test_price_per_unit_non_multiple_refused() -> None:
    with pytest.raises(lhub.KitRefusal, match="multiple"):
        lhub.check_price_terms(amount=70_001, pricing=_pricing(), proposal_unit="LHUB-DEV")


def test_price_amount_zero_refused() -> None:
    with pytest.raises(lhub.KitRefusal, match="outside"):
        lhub.check_price_terms(amount=0, pricing=_pricing(), proposal_unit="LHUB-DEV")


def test_price_amount_over_bound_refused() -> None:
    with pytest.raises(lhub.KitRefusal, match="outside"):
        lhub.check_price_terms(
            amount=lhub.MAX_SAFE_INT + 1, pricing=_pricing(), proposal_unit="LHUB-DEV"
        )


def test_price_below_min_charge_refused() -> None:
    with pytest.raises(lhub.KitRefusal, match="below the listing min_charge"):
        lhub.check_price_terms(
            amount=100_000, pricing=_pricing(min_charge="0.50"), proposal_unit="LHUB-DEV"
        )


def test_price_min_charge_floor_exact_passes() -> None:
    # min_charge 0.50 > price 0.07: the floor amount is the ONLY non-multiple
    # amount the bridge can derive (quantity floored to the min charge).
    lhub.check_price_terms(
        amount=500_000,
        pricing=_pricing(amount="0.07", min_charge="0.50"),
        proposal_unit="LHUB-DEV",
    )


def test_price_non_floor_non_multiple_refused_even_with_min_charge() -> None:
    with pytest.raises(lhub.KitRefusal, match="multiple"):
        lhub.check_price_terms(
            amount=510_000,
            pricing=_pricing(amount="0.07", min_charge="0.50"),
            proposal_unit="LHUB-DEV",
        )


def test_price_unit_is_settlement_currency_not_billable_unit() -> None:
    # The proposal unit is compared with pricing.currency, NEVER pricing.unit
    # (arch R2 B-1): a proposal carrying the billable unit must refuse.
    with pytest.raises(lhub.KitRefusal, match="settlement currency"):
        lhub.check_price_terms(amount=50_000, pricing=_pricing(), proposal_unit="file")


def test_price_unknown_model_refused() -> None:
    with pytest.raises(lhub.KitRefusal, match="model"):
        lhub.check_price_terms(
            amount=50_000, pricing=_pricing(model="auction"), proposal_unit="LHUB-DEV"
        )


def test_price_unusable_stored_price_refused() -> None:
    with pytest.raises(lhub.KitRefusal, match="price unusable"):
        lhub.check_price_terms(
            amount=50_000, pricing=_pricing(amount="not-a-number"), proposal_unit="LHUB-DEV"
        )


# ---------------------------------------------------------------------------
# Check 6 — the JWS verifies over OUR OWN canonicalization.
# ---------------------------------------------------------------------------


def test_verify_jws_round_trip(seller_key: ec.EllipticCurvePrivateKey, seller_did: str) -> None:
    payload = lhub.jcs_canonicalize({"a": 1, "b": "two"})
    jws = lhub.sign_es256(seller_key, payload, kid=seller_did)
    lhub.verify_jws_es256_canonical(did=seller_did, jws=jws, expected_canonical=payload)


def test_verify_jws_refuses_payload_mismatch(
    seller_key: ec.EllipticCurvePrivateKey, seller_did: str
) -> None:
    jws = lhub.sign_es256(seller_key, b'{"a":1}', kid=seller_did)
    with pytest.raises(lhub.KitError, match="payload does not equal"):
        lhub.verify_jws_es256_canonical(did=seller_did, jws=jws, expected_canonical=b'{"a":2}')


def test_verify_jws_refuses_wrong_key(
    seller_key: ec.EllipticCurvePrivateKey,
    buyer_key: ec.EllipticCurvePrivateKey,
    buyer_did: str,
) -> None:
    payload = b'{"a":1}'
    jws = lhub.sign_es256(seller_key, payload, kid="did:key:zWhoever")
    with pytest.raises(lhub.KitError, match="does not verify"):
        lhub.verify_jws_es256_canonical(did=buyer_did, jws=jws, expected_canonical=payload)


def test_verify_jws_refuses_non_compact_form(seller_did: str) -> None:
    with pytest.raises(lhub.KitError, match="three-segment"):
        lhub.verify_jws_es256_canonical(did=seller_did, jws="a.b", expected_canonical=b"x")


def test_verify_jws_refuses_non_b64url_segment(seller_did: str) -> None:
    with pytest.raises(lhub.KitError, match="non-alphabet"):
        lhub.verify_jws_es256_canonical(did=seller_did, jws="a+b.c.d", expected_canonical=b"x")


def test_verify_jws_refuses_crit_header(
    seller_key: ec.EllipticCurvePrivateKey, seller_did: str
) -> None:
    payload = b'{"a":1}'
    good = lhub.sign_es256(seller_key, payload, kid=seller_did)
    _header, rest = good.split(".", 1)
    import base64 as b64
    import json as js

    evil_header = (
        b64.urlsafe_b64encode(
            js.dumps({"alg": "ES256", "crit": ["exp"]}, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(lhub.KitError, match="crit"):
        lhub.verify_jws_es256_canonical(
            did=seller_did, jws=f"{evil_header}.{rest}", expected_canonical=payload
        )


def test_verify_jws_refuses_non_es256_alg(
    seller_key: ec.EllipticCurvePrivateKey, seller_did: str
) -> None:
    payload = b'{"a":1}'
    good = lhub.sign_es256(seller_key, payload, kid=seller_did)
    _header, rest = good.split(".", 1)
    import base64 as b64
    import json as js

    none_header = (
        b64.urlsafe_b64encode(js.dumps({"alg": "none"}, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(lhub.KitError, match="alg is not ES256"):
        lhub.verify_jws_es256_canonical(
            did=seller_did, jws=f"{none_header}.{rest}", expected_canonical=payload
        )


# ---------------------------------------------------------------------------
# Deal-record normalization fails closed.
# ---------------------------------------------------------------------------


def test_normalize_requires_every_field(seller_did: str, buyer_did: str) -> None:
    full = {
        "deal_id": DEAL_ID,
        "state": "NEGOTIATING",
        "request_id": REQUEST_ID,
        "buyer_did": buyer_did,
        "provider_did": seller_did,
        "unit": "LHUB-DEV",
        "amount": "500000",
        "listing_content_hash": LISTING_HASH,
    }
    record = lhub.normalize_deal_record(full)
    assert record["amount"] == 500_000
    for field in ("deal_id", "state", "request_id", "buyer_did", "provider_did", "unit"):
        broken = dict(full)
        del broken[field]
        with pytest.raises(lhub.KitRefusal, match=field):
            lhub.normalize_deal_record(broken)


def test_normalize_missing_hash_maps_to_none(seller_did: str, buyer_did: str) -> None:
    payload = {
        "deal_id": DEAL_ID,
        "state": "NEGOTIATING",
        "request_id": REQUEST_ID,
        "buyer_did": buyer_did,
        "provider_did": seller_did,
        "unit": "LHUB-DEV",
        "amount": 1,
    }
    assert lhub.normalize_deal_record(payload)["listing_content_hash"] is None


def test_normalize_refuses_non_integer_amount(seller_did: str, buyer_did: str) -> None:
    payload = {
        "deal_id": DEAL_ID,
        "state": "NEGOTIATING",
        "request_id": REQUEST_ID,
        "buyer_did": buyer_did,
        "provider_did": seller_did,
        "unit": "LHUB-DEV",
        "amount": "12.5",
    }
    with pytest.raises(lhub.KitRefusal, match="integer amount"):
        lhub.normalize_deal_record(payload)
