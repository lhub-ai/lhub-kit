"""Local-environment checks from the Slice-4 fix-pass (sec S4-2…S4-5)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import lhub

# ----- sec S4-2: the MCP hire tool reads inputs only under a configured root -----


def test_input_path_inside_root_allowed(tmp_path: Path) -> None:
    target = tmp_path / "job.py"
    target.write_text("print('hi')\n")
    resolved = lhub.resolve_input_path("job.py", tmp_path)
    assert resolved == target.resolve()


def test_input_path_absolute_inside_root_allowed(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "job.py"
    target.parent.mkdir()
    target.write_text("x\n")
    assert lhub.resolve_input_path(str(target), tmp_path) == target.resolve()


def test_input_path_outside_root_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("x\n")
    with pytest.raises(lhub.KitError, match="outside the server's input root"):
        lhub.resolve_input_path(str(outside), root)
    with pytest.raises(lhub.KitError, match="outside the server's input root") as refused:
        lhub.resolve_input_path("../elsewhere.txt", root)
    # The text can reach an LLM through `lhub.py mcp`: it never names the
    # absolute root (operator-local; printed on stderr at server start).
    assert str(root.resolve()) not in str(refused.value)


def test_input_path_symlink_leaving_root_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("x\n")
    link = root / "looks-local.txt"
    link.symlink_to(outside)
    with pytest.raises(lhub.KitError, match="outside the server's input root") as refused:
        lhub.resolve_input_path("looks-local.txt", root)
    assert str(outside.resolve()) not in str(refused.value)  # nor the symlink's target


def test_input_root_env_is_honoured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    monkeypatch.setenv(lhub.ENV_INPUT_ROOT, str(root))
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", None)
    assert lhub._input_root() == root.resolve()


# ----- sec S4-3: warn on plain http to a non-loopback host -----


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "127.1.2.3", "[::1]"])
def test_no_warning_for_loopback_http(
    host: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lhub.Kit(f"http://{host}:8092", tmp_path / "home")
    assert "plain http" not in capsys.readouterr().err


def test_warning_for_remote_http(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lhub.Kit("http://bridge.example.com:8092", tmp_path / "home")
    err = capsys.readouterr().err
    assert "plain http" in err and "https" in err


def test_no_warning_for_https(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lhub.Kit("https://bridge.example.com", tmp_path / "home")
    assert "plain http" not in capsys.readouterr().err


# ----- sec S4-4: key-permission warning + audit file mode -----


def test_loose_key_permissions_warned(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    kit = lhub.Kit("http://localhost:8092", home)
    kit.ensure_key()  # creates 0600
    capsys.readouterr()
    os.chmod(kit.key_path, 0o644)

    fresh = lhub.Kit("http://localhost:8092", home)
    fresh.ensure_key()
    err = capsys.readouterr().err
    assert "group/other-readable" in err and "chmod 600" in err


def test_tight_key_permissions_not_warned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    lhub.Kit("http://localhost:8092", home).ensure_key()
    capsys.readouterr()
    lhub.Kit("http://localhost:8092", home).ensure_key()
    assert "group/other-readable" not in capsys.readouterr().err


def test_audit_log_created_owner_only(tmp_path: Path) -> None:
    kit = lhub.Kit("http://localhost:8092", tmp_path / "home")
    path = kit.append_audit({"event": "test"})
    assert path.exists()
    assert (path.stat().st_mode & 0o777) == 0o600
    # Append keeps prior lines (durable record).
    kit.append_audit({"event": "test-2"})
    lines = path.read_text().splitlines()
    assert len(lines) == 2


# ----- sec S4-5: the cached session is bound to the key's DID -----


def _write_session(home: Path, did: str, token: str) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "session.json").write_text(
        json.dumps(
            {
                "base_url": "http://localhost:8092",
                "did": did,
                "mcp_session_id": "sid-x",
                "protocol_version": "2025-06-18",
                "session_token": token,
                "expires_at": "2027-01-01T00:00:00Z",
            }
        )
    )


def test_session_for_other_did_is_dropped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    kit = lhub.Kit("http://localhost:8092", home)
    kit.ensure_key()  # the real DID of this home
    _write_session(home, "did:key:zSomeOtherIdentity", "cached-tok")

    fresh = lhub.Kit("http://localhost:8092", home)
    assert fresh._session_token == "cached-tok"  # adopted at load…
    fresh.ensure_key()
    # …and dropped once the key's DID is known and differs.
    assert fresh._session_token is None
    assert fresh._mcp_session_id is None
    assert "different DID" in capsys.readouterr().err


def test_session_for_same_did_is_kept(tmp_path: Path) -> None:
    home = tmp_path / "home"
    kit = lhub.Kit("http://localhost:8092", home)
    kit.ensure_key()
    _write_session(home, kit.did, "cached-tok")

    fresh = lhub.Kit("http://localhost:8092", home)
    fresh.ensure_key()
    assert fresh._session_token == "cached-tok"


def test_session_without_did_is_not_adopted(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(parents=True)
    (home / "session.json").write_text(
        json.dumps(
            {
                "base_url": "http://localhost:8092",
                "session_token": "unbound-tok",
                "expires_at": "2027-01-01T00:00:00Z",
            }
        )
    )
    kit = lhub.Kit("http://localhost:8092", home)
    assert kit._session_token is None


def test_did_key_still_derives(tmp_path: Path) -> None:
    """ensure_key end-to-end sanity after the fix-pass edits."""
    kit = lhub.Kit("http://localhost:8092", tmp_path / "home")
    key = kit.ensure_key()
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert kit.did.startswith("did:key:zDna")
