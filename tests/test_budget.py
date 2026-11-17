"""The budget owner gate (D-12) and the grant cap (sec N-12)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import lhub

KIT_FILE = Path(__file__).resolve().parents[1] / "lhub.py"


def test_budget_noninteractive_without_owner_flag_creates_nothing(tmp_path: Path) -> None:
    """R2 sdd N-7: no terminal + no --i-am-the-owner → exit non-zero, nothing created.

    Runs the real CLI as a child process with stdin NOT a tty. The marketplace
    URL points at a closed local port — but the gate must refuse before any
    key creation, signing, or network call, so nothing is ever contacted.
    """
    home = tmp_path / "home"
    env = dict(os.environ)
    env["LHUB_KIT_HOME"] = str(home)
    env["LHUB_URL"] = "http://127.0.0.1:9"  # discard port; must never be reached

    proc = subprocess.run(
        [
            sys.executable,
            str(KIT_FILE),
            "budget",
            "set",
            "--per-task",
            "1.00",
            "--total",
            "5.00",
            "--days",
            "7",
        ],
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )

    assert proc.returncode != 0
    payload = json.loads(proc.stdout)
    assert "--i-am-the-owner" in payload["error"]
    assert "owner" in payload["error"]
    # Nothing was created: no home dir contents, no key, no audit line.
    assert not (home / "audit.log").exists()
    assert not (home / "agent.pem").exists()
    # The owner notice went to stderr (human channel), not stdout (machine channel).
    assert "OWNER AUTHORIZATION NOTICE" in proc.stderr


def test_budget_total_capped_at_grant() -> None:
    with pytest.raises(lhub.KitError, match="--allow-over-grant"):
        lhub.validate_budget_totals(lhub.SANDBOX_GRANT_MINOR + 1, allow_over_grant=False)


def test_budget_total_at_grant_allowed() -> None:
    lhub.validate_budget_totals(lhub.SANDBOX_GRANT_MINOR, allow_over_grant=False)


def test_budget_total_over_grant_with_flag_allowed() -> None:
    lhub.validate_budget_totals(lhub.SANDBOX_GRANT_MINOR * 2, allow_over_grant=True)


def test_grant_constant_is_ten_units() -> None:
    """The cap matches the once-per-DID sandbox grant: 10.000000 LHUB-DEV."""
    assert lhub.SANDBOX_GRANT_MINOR == 10_000_000
    assert lhub.format_display(lhub.SANDBOX_GRANT_MINOR) == "10.00 LHUB-DEV"


def test_mandate_claims_shape() -> None:
    """D-12: claims are exactly {exp, price_ceiling{amount,unit}, total_budget{amount,unit}}.

    No categories, no counterparty_reputation_floor — their presence makes the
    escrow evaluator refuse coverage (bypass_eval fail-closed).
    """
    claims = {
        "exp": 1_800_000_000,
        "price_ceiling": {"amount": 1_000_000, "unit": lhub.SETTLEMENT_UNIT},
        "total_budget": {"amount": 5_000_000, "unit": lhub.SETTLEMENT_UNIT},
    }
    canonical = lhub.jcs_canonicalize(claims)
    assert canonical == (
        b'{"exp":1800000000,'
        b'"price_ceiling":{"amount":1000000,"unit":"LHUB-DEV"},'
        b'"total_budget":{"amount":5000000,"unit":"LHUB-DEV"}}'
    )
    assert b"categories" not in canonical
    assert b"counterparty_reputation_floor" not in canonical


def test_intake_envelope_canonical_shape() -> None:
    """The mandate intake body is JCS of exactly {owner_did, mandate_jws, nonce}."""
    envelope = {"owner_did": "did:key:zOwner", "mandate_jws": "a.b.c", "nonce": "n-1"}
    assert lhub.jcs_canonicalize(envelope) == (
        b'{"mandate_jws":"a.b.c","nonce":"n-1","owner_did":"did:key:zOwner"}'
    )
