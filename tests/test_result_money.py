"""Deliverable verification (D-4), money parsing/formatting, and fence handling."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any, cast

import pytest

import lhub


class FakeKit:
    """A minimal stand-in for Kit: canned get_deal / download_deal_file payloads."""

    def __init__(self, deal: dict[str, Any], file_meta: dict[str, Any]) -> None:
        self._deal = deal
        self._file = file_meta
        self.calls: list[str] = []

    def ensure_session(self) -> None:
        self.calls.append("ensure_session")

    def call_tool(
        self, name: str, arguments: dict[str, Any], *, with_session: bool = True, _recover: int = 2
    ) -> dict[str, Any]:
        self.calls.append(name)
        if name == "get_deal":
            return self._deal
        if name == "download_deal_file":
            return self._file
        raise AssertionError(f"unexpected tool {name}")


def _fence(value: str) -> str:
    return f"{lhub.FENCE_OPEN}\n{value}\n{lhub.FENCE_CLOSE}"


def _deal_with_proof(proof_hash: str, *, fenced: bool = False) -> dict[str, Any]:
    hash_field = proof_hash
    method_field = "signed-output-hash"
    if fenced:
        hash_field = _fence(proof_hash)
        method_field = _fence(method_field)
    return {
        "deal_id": "d-1",
        "state": "PROOF_SUBMITTED",
        "amount": "500000",
        "unit": "LHUB-DEV",
        "proof": {"method": method_field, "hash": hash_field, "jws": "x.y.z"},
    }


def test_verify_deliverable_match_and_mismatch() -> None:
    data = b"the deliverable bytes"
    good = "sha256:" + hashlib.sha256(data).hexdigest()
    ok, actual = lhub.verify_deliverable(good, data)
    assert ok and actual == good

    ok, actual = lhub.verify_deliverable("sha256:" + "0" * 64, data)
    assert not ok
    assert actual == good


def test_do_result_happy_path_writes_file(tmp_path: Path) -> None:
    data = b"reviewed: looks good"
    proof_hash = "sha256:" + hashlib.sha256(data).hexdigest()
    kit = FakeKit(
        _deal_with_proof(proof_hash, fenced=True),  # fenced proof fields are unwrapped
        {"kind": "deliverable", "content_b64": base64.b64encode(data).decode("ascii")},
    )
    out = tmp_path / "review.md"

    result = lhub.do_result(
        cast(lhub.Kit, kit), deal_id="d-1", out_path=out, timeout_seconds=5, poll_seconds=0.01
    )

    assert result["delivered"] is True
    assert result["sha256"] == proof_hash
    assert out.read_bytes() == data
    assert "accept" in result["next_step"]
    # sec S4-1: provider-authored proof fields are passed through AS RECEIVED
    # (fence intact); only the hash was unfenced, for the comparison.
    assert result["proof_method"] == _fence("signed-output-hash")
    assert result["proof_method"].startswith(lhub.FENCE_OPEN)


def test_do_result_mismatch_reports_and_names_dispute(tmp_path: Path) -> None:
    """Spec scenario: tampered deliverable — mismatch reported, no accept, dispute named."""
    good = b"what the provider hashed"
    evil = b"what actually arrived"
    proof_hash = "sha256:" + hashlib.sha256(good).hexdigest()
    kit = FakeKit(
        _deal_with_proof(proof_hash),
        {"kind": "deliverable", "content_b64": base64.b64encode(evil).decode("ascii")},
    )
    out = tmp_path / "review.md"

    with pytest.raises(lhub.KitFailure) as excinfo:
        lhub.do_result(
            cast(lhub.Kit, kit), deal_id="d-1", out_path=out, timeout_seconds=5, poll_seconds=0.01
        )

    failure = excinfo.value
    assert "mismatch" in str(failure)
    assert failure.payload["delivered"] is False
    assert failure.payload["expected_sha256"] == proof_hash
    assert failure.payload["actual_sha256"] == "sha256:" + hashlib.sha256(evil).hexdigest()
    assert "dispute" in failure.payload["next_step"]
    assert not out.exists()  # a mismatching deliverable is never written to --out
    assert "accept_deal" not in kit.calls  # and never accepted


def test_do_result_refuses_malformed_proof_hash(tmp_path: Path) -> None:
    deal = _deal_with_proof("sha256:" + "0" * 64)
    deal["proof"]["hash"] = "md5:abcdef"
    kit = FakeKit(deal, {})
    with pytest.raises(lhub.KitError, match="sha256"):
        lhub.do_result(
            cast(lhub.Kit, kit),
            deal_id="d-1",
            out_path=tmp_path / "x",
            timeout_seconds=5,
            poll_seconds=0.01,
        )


@pytest.mark.parametrize(
    ("text", "minor"),
    [
        ("1.00", 1_000_000),
        ("0.5", 500_000),
        ("0.50", 500_000),
        ("10", 10_000_000),
        ("0.123456", 123_456),
        ("5.000000", 5_000_000),
        ("  2.25 ", 2_250_000),
    ],
)
def test_parse_amount_minor_exact(text: str, minor: int) -> None:
    assert lhub.parse_amount_minor(text) == minor


@pytest.mark.parametrize(
    "bad", ["", "-1.00", "1.2345678", "1e3", "1,00", ".5", "1.", "NaN", "0x10"]
)
def test_parse_amount_minor_refuses(bad: str) -> None:
    with pytest.raises(lhub.KitError, match="invalid amount"):
        lhub.parse_amount_minor(bad)


@pytest.mark.parametrize(
    ("minor", "display"),
    [
        (500_000, "0.50 LHUB-DEV"),
        (1_000_000, "1.00 LHUB-DEV"),
        (10_000_000, "10.00 LHUB-DEV"),
        (123_456, "0.123456 LHUB-DEV"),
        (0, "0.00 LHUB-DEV"),
    ],
)
def test_format_display(minor: int, display: str) -> None:
    assert lhub.format_display(minor) == display


def test_unfence_round_trip() -> None:
    assert lhub.unfence(f"{lhub.FENCE_OPEN}\nsha256:ab\n{lhub.FENCE_CLOSE}") == "sha256:ab"
    assert lhub.unfence("plain value") == "plain value"
    # Only a complete fence is stripped; a lone marker is left as data.
    assert lhub.unfence(lhub.FENCE_OPEN + " not closed") == lhub.FENCE_OPEN + " not closed"


def test_sha256_ref_form() -> None:
    ref = lhub.sha256_ref(b"input")
    assert ref == "sha256:" + hashlib.sha256(b"input").hexdigest()
    assert len(ref) == len("sha256:") + 64
