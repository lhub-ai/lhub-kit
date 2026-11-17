"""Test bootstrap: make the single-file kit importable as ``lhub``."""

from __future__ import annotations

import sys
from pathlib import Path

KIT_DIR = Path(__file__).resolve().parents[1]
if str(KIT_DIR) not in sys.path:
    sys.path.insert(0, str(KIT_DIR))
