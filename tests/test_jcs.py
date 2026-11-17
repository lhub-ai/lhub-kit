"""JCS (RFC 8785) — the frozen cross-language vector plus edge-case pins.

The vector under ``shared/go/dealartifact/testdata/vector-v1`` is the repo's
FROZEN canonicalisation contract (hand-authored, never regenerated from an
implementation). The kit's in-file JCS must reproduce it byte-for-byte
(task 4.1 / D-11). The edge cases below are pinned against the ``rfc8785``
reference implementation's output (the library the house agent uses), captured
at authoring time — a second, independent implementation agreeing on the bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import lhub

VECTOR_DIR = Path(__file__).resolve().parent / "vector-v1"  # vendored from the LHUB monorepo (shared/go/dealartifact/testdata/vector-v1)


def test_jcs_vector_v1_bytes_and_hash() -> None:
    """The kit's JCS reproduces the frozen vector exactly (bytes + SHA-256)."""
    input_obj = json.loads((VECTOR_DIR / "input.json").read_text(encoding="utf-8"))
    expected_canonical = (VECTOR_DIR / "canonical").read_bytes()
    expected_hash = (VECTOR_DIR / "content_hash").read_text(encoding="utf-8").strip()

    got = lhub.jcs_canonicalize(input_obj)

    assert got == expected_canonical
    assert hashlib.sha256(got).hexdigest() == expected_hash


@pytest.mark.parametrize(
    ("obj", "expected"),
    [
        # Key sorting.
        ({"b": 2, "a": 1}, b'{"a":1,"b":2}'),
        # Non-ASCII keys sort by UTF-16 code units and emit as raw UTF-8.
        (
            {"€": "euro", "e": "plain", "é": "acute"},
            b'{"e":"plain","\xc3\xa9":"acute","\xe2\x82\xac":"euro"}',
        ),
        # Two-char escapes + \u00xx for other control chars; quotes/backslash.
        (
            {"ctl": "line\nbreak\ttab\x01end", "quote": 'say "hi" \\ done'},
            b'{"ctl":"line\\nbreak\\ttab\\u0001end","quote":"say \\"hi\\" \\\\ done"}',
        ),
        # Nested containers, booleans, null.
        (
            {"nested": {"z": [1, "two", {"k": 3}], "a": True, "m": None}},
            b'{"nested":{"a":true,"m":null,"z":[1,"two",{"k":3}]}}',
        ),
        # An astral-plane key encodes as a surrogate pair in UTF-16, so it
        # sorts AFTER "zzz" (0x007A... < 0xD800...).
        (
            {"\U00010000": "astral-key", "zzz": "last"},
            b'{"zzz":"last","\xf0\x90\x80\x80":"astral-key"}',
        ),
        # Integers up to 2^53-1 serialize without a decimal point.
        (
            {"amount": 100000, "big": 9007199254740991},
            b'{"amount":100000,"big":9007199254740991}',
        ),
    ],
)
def test_jcs_edge_cases_match_rfc8785_reference(obj: dict[str, Any], expected: bytes) -> None:
    assert lhub.jcs_canonicalize(obj) == expected


def test_jcs_refuses_floats() -> None:
    """Money is integer minor units; a float in a signed payload fails closed."""
    with pytest.raises(lhub.KitError, match="float"):
        lhub.jcs_canonicalize({"amount": 1.5})


def test_jcs_refuses_unsafe_integers() -> None:
    with pytest.raises(lhub.KitError, match="safe range"):
        lhub.jcs_canonicalize({"amount": 2**53})


def test_jcs_refuses_non_string_keys() -> None:
    with pytest.raises(lhub.KitError, match="keys"):
        lhub.jcs_canonicalize({1: "x"})


def test_handshake_payload_signs_aud_not_audience() -> None:
    """OQ-1: the challenge RESPONSE field is `audience`; the SIGNED payload uses `aud`."""
    payload = {"aud": lhub.HANDSHAKE_AUDIENCE, "did": "did:key:zTest", "nonce": "n-1"}
    canonical = lhub.jcs_canonicalize(payload)
    assert canonical == b'{"aud":"lhub-mcp-session-handshake","did":"did:key:zTest","nonce":"n-1"}'
    assert b"audience" not in canonical
