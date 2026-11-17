"""Refusal memory bounds + atomic writes (sec N-1).

A counterparty can mint unlimited fresh proposal shas, so the memory is
capped per deal and overall (oldest evicted first — an evicted sha simply
re-evaluates to the same refusal and signs nothing), and every write goes
through tmp + os.replace so a reader never sees a torn file. Concurrent kit
processes are last-writer-wins by design (documented: a lost entry only
costs a re-refusal).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import lhub

DEAL_A = "a0000000-0000-4000-8000-00000000000a"
DEAL_B = "b0000000-0000-4000-8000-00000000000b"
DEAL_C = "c0000000-0000-4000-8000-00000000000c"


def sha(i: int) -> str:
    return f"{i:064x}"


@pytest.fixture
def kit(tmp_path: Path) -> lhub.Kit:
    return lhub.Kit("http://localhost:19999", tmp_path / "home")


def test_per_deal_cap_evicts_oldest_keeps_newest(kit: lhub.Kit) -> None:
    extra = 5
    total = lhub.REFUSAL_MEMORY_MAX_PER_DEAL + extra
    for i in range(total):
        kit.record_refusal(DEAL_A, sha(i), f"reason-{i}")
    stored = json.loads(kit._refusals_path.read_text())
    assert len(stored) == lhub.REFUSAL_MEMORY_MAX_PER_DEAL
    # The newest record always survives; the overflowed oldest are gone and
    # would simply be re-evaluated (and re-refused) on their next appearance.
    assert kit.refusal_reason(DEAL_A, sha(total - 1)) == f"reason-{total - 1}"
    evicted = sum(1 for i in range(total) if kit.refusal_reason(DEAL_A, sha(i)) is None)
    assert evicted == extra


def test_per_deal_cap_does_not_evict_other_deals(kit: lhub.Kit) -> None:
    kit.record_refusal(DEAL_B, sha(0), "other-deal")
    for i in range(lhub.REFUSAL_MEMORY_MAX_PER_DEAL + 3):
        kit.record_refusal(DEAL_A, sha(i), "flood")
    assert kit.refusal_reason(DEAL_B, sha(0)) == "other-deal"


def test_overall_cap_bounds_the_file(kit: lhub.Kit, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lhub, "REFUSAL_MEMORY_MAX_TOTAL", 10)
    for deal in (DEAL_A, DEAL_B, DEAL_C):
        for i in range(5):
            kit.record_refusal(deal, sha(i), "r")
    stored = json.loads(kit._refusals_path.read_text())
    assert len(stored) == 10
    # The newest record survives the overall eviction too.
    assert kit.refusal_reason(DEAL_C, sha(4)) == "r"


def test_rerecording_same_sha_does_not_grow(kit: lhub.Kit) -> None:
    for _ in range(5):
        kit.record_refusal(DEAL_A, sha(1), "same")
    stored = json.loads(kit._refusals_path.read_text())
    assert len(stored) == 1


def test_write_is_atomic_replace_with_no_tmp_residue(kit: lhub.Kit) -> None:
    for i in range(20):
        kit.record_refusal(DEAL_A, sha(i), "r")
    home = kit._refusals_path.parent
    assert [p.name for p in home.glob("refusals.json.tmp-*")] == []
    # The visible file is always a complete JSON document, owner-only.
    assert isinstance(json.loads(kit._refusals_path.read_text()), dict)
    assert kit._refusals_path.stat().st_mode & 0o777 == 0o600


def test_stored_reason_is_clipped_to_printable_ascii(kit: lhub.Kit) -> None:
    # sec R2 N-1: refusal messages can embed counterparty-sized text (hostile
    # key lists, repr'd values) — the stored reason is clipped at the
    # record_refusal entry point to bounded printable ASCII.
    hostile = "refused: " + "K" * 10_000 + "\x1b[2J\né\ud800"
    kit.record_refusal(DEAL_A, sha(0), hostile)
    stored = kit.refusal_reason(DEAL_A, sha(0))
    assert stored is not None
    assert len(stored) <= 400
    assert all(0x20 <= ord(ch) < 0x7F for ch in stored)  # printable ASCII only
    assert stored.startswith("refused: KKK")


def test_failed_tmp_write_leaves_prior_file_intact(
    kit: lhub.Kit, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit.record_refusal(DEAL_A, sha(0), "kept")

    def refuse_replace(src: str | Path, dst: str | Path) -> None:
        raise OSError("disk says no")

    with monkeypatch.context() as patched:
        # lhub's `os` IS this module object, so patching it here patches the
        # kit's own os.replace call.
        patched.setattr(os, "replace", refuse_replace)
        with pytest.raises(OSError):
            kit.record_refusal(DEAL_A, sha(1), "lost")
    # The prior file is untouched and no tmp residue remains.
    assert kit.refusal_reason(DEAL_A, sha(0)) == "kept"
    assert [p.name for p in kit._refusals_path.parent.glob("refusals.json.tmp-*")] == []
