"""did:key derivation (known-answer) and ES256 compact JWS round-trip.

The did:key known answer was derived with the house agent's independent
implementation (``services/house-agent/.../signing.py``) at authoring time —
two implementations agreeing on the encoding is the cross-check. The structure
test re-decodes the base58 body and verifies the multicodec prefix and the
compressed point against ``cryptography``'s own public numbers.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import lhub

# A fixed, test-only P-256 scalar (sha256("lhub-kit-test-key-1") reduced mod n-1, +1).
TEST_SCALAR = 0x1E98C082CCA674AD934042D44EF9DA846B885BDD3F50D23678702849755548E0
# Derived with the house agent's _did_key_from_public_key over the same scalar.
EXPECTED_DID = "did:key:zDnaeb2d1JGm84ESTKckrtJMdGuVmb2QZY5hZVpq7mpcjdH8s"
EXPECTED_COMPRESSED_HEX = "029d7589bba7b2cb71ee3460ff56e4207c5f4ffe430b0e235158c7ae95b11cb0e8"

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(text: str) -> bytes:
    num = 0
    for ch in text:
        num = num * 58 + _B58_ALPHABET.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + raw


def _test_key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(TEST_SCALAR, ec.SECP256R1())


def test_did_key_known_answer() -> None:
    key = _test_key()
    assert lhub.did_key_from_public_key(key.public_key()) == EXPECTED_DID


def test_did_key_structure_round_trip() -> None:
    """Decode the did:key body: multicodec 0x1200 varint + the SEC1 compressed point."""
    key = _test_key()
    did = lhub.did_key_from_public_key(key.public_key())
    assert did.startswith("did:key:z")
    body = _b58decode(did[len("did:key:z") :])
    assert body[:2] == bytes((0x80, 0x24))  # p256-pub multicodec, varint-encoded
    point = body[2:]
    assert len(point) == 33
    assert point.hex() == EXPECTED_COMPRESSED_HEX
    numbers = key.public_key().public_numbers()
    expected_prefix = 0x02 if numbers.y % 2 == 0 else 0x03
    assert point[0] == expected_prefix
    assert point[1:] == numbers.x.to_bytes(32, "big")


def test_jws_sign_verify_round_trip() -> None:
    """The kit's compact JWS verifies with cryptography over the exact payload bytes."""
    key = _test_key()
    did = lhub.did_key_from_public_key(key.public_key())
    payload = lhub.jcs_canonicalize({"aud": lhub.HANDSHAKE_AUDIENCE, "did": did, "nonce": "n-42"})

    jws = lhub.sign_es256(key, payload, kid=did)
    header_b64, payload_b64, sig_b64 = jws.split(".")

    def unb64(segment: str) -> bytes:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))

    header = json.loads(unb64(header_b64))
    assert header == {"alg": "ES256", "kid": did, "typ": "JWT"}

    # The JWS payload is EXACTLY the canonical bytes (no re-encoding).
    assert unb64(payload_b64) == payload

    # The signature is the fixed-width JOSE R||S form over header.payload.
    sig = unb64(sig_b64)
    assert len(sig) == 64
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    key.public_key().verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))


def test_jws_tamper_fails_verification() -> None:
    key = _test_key()
    did = lhub.did_key_from_public_key(key.public_key())
    payload = lhub.jcs_canonicalize({"v": "original"})
    jws = lhub.sign_es256(key, payload, kid=did)
    header_b64, _payload_b64, sig_b64 = jws.split(".")

    tampered_payload = lhub.jcs_canonicalize({"v": "tampered"})
    tampered_b64 = base64.urlsafe_b64encode(tampered_payload).rstrip(b"=").decode("ascii")

    sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    signing_input = f"{header_b64}.{tampered_b64}".encode("ascii")

    import pytest
    from cryptography.exceptions import InvalidSignature

    with pytest.raises(InvalidSignature):
        key.public_key().verify(
            encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256())
        )
