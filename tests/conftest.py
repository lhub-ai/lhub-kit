"""Test bootstrap: make the single-file kit importable as ``lhub``, and keep every
test away from the operator's own kit home."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

KIT_DIR = Path(__file__).resolve().parents[1]
if str(KIT_DIR) not in sys.path:
    sys.path.insert(0, str(KIT_DIR))


@pytest.fixture(autouse=True)
def _isolated_kit_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point ``$LHUB_KIT_HOME`` at a fresh temp directory for every test.

    The MCP file tools consult the kit home on every call (add-claude-code-plugin
    D-1 item 5), and an unpatched ``Kit.from_env()`` would create a real key
    there: no test may touch the operator's own ``~/.lhub-kit``, not even its
    path. A test that needs another home sets its own (``monkeypatch.setenv``
    overrides this one).
    """
    monkeypatch.setenv("LHUB_KIT_HOME", str(tmp_path_factory.mktemp("kit-home")))
