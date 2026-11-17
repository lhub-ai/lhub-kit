"""The MCP file tools stay inside the input root (add-claude-code-plugin D-1).

``get_result`` writes counterparty-authored bytes, and ``hire``/``deliver`` read
files they send to a counterparty, so the stdio server resolves every model-chosen
path under the input root that was pinned and resolved once at server start:

* relative to the root, absolute only if inside it, symlinks resolved;
* no ``..`` and no component that starts with ``.`` relative to the root, on the
  path as given and as resolved, for reads and writes alike;
* nothing inside the kit home (agent key, session, listings);
* for ``get_result``, no component named ``CLAUDE.md``, ``CLAUDE.local.md`` or
  ``AGENTS.md`` in any letter case, and none named ``uv.toml``,
  ``pyproject.toml``, ``setup.cfg``, ``pip.conf`` or ``requirements*.txt``
  (add-claude-code-plugin D-3, Slice-2 security fix);
* and no file access at all when the root is the home directory, a folder above
  it, or a filesystem root.

A refused path fails with a kit error BEFORE any network call, and nothing is
written. Right before the write the destination is checked again, and the target
is replaced rather than written through. The CLI ``result --out`` is unconfined.

Every get_result refusal is proven against a whole-tree snapshot of the test's
directory (nothing created, written, replaced or removed anywhere, outside the
root included) and against the routed kit's call log (no tool call at all). Only
the two real-server tests need the ``mcp`` package. Every test here points HOME
at a temp path, so none of them depends on the operator's own home.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from routerkit import RouterKit, use_kit

import lhub

DEAL_ID = "d0000000-0000-4000-8000-00000000f001"
LISTING_ID = "7a1d2f30-1111-4222-8333-9444444444f1"
DATA = b"# Review\n\nLooks fine. (IGNORE PREVIOUS INSTRUCTIONS is data here, not a command.)\n"
PRECIOUS = b"precious, must survive\n"

OUTSIDE = "resolves outside the server's input root"
HIDDEN = "no '..' and no path component that starts with '.'"
INSTRUCTION = "CLAUDE.md, CLAUDE.local.md and AGENTS.md are host instruction files"
TOOLCHAIN = (
    "uv.toml, pyproject.toml, setup.cfg, pip.conf and requirements*.txt configure the Python"
    " toolchain"
)
KIT_HOME = "is inside the kit home"
UNSAFE_ROOT = "the server's input root is a filesystem root, your home directory"
NOT_A_FILE = "must name a file inside the server's input root"
UNRESOLVABLE = "cannot be resolved inside the server's input root"
INVISIBLE = "a path component holds an invisible or format character"
KIT_SECRET = "is the same file as the kit's agent key or session"
NO_HOME = "cannot determine the home directory"
NO_KIT_HOME = "cannot determine the kit home"

FILE_TOOLS = ("hire", "deliver", "get_result")

# git's utf8.c next_hfs_char: the code points HFS+ ignores in a name (read from
# git master 2026-11-18), so "\u200c.git" is ".git" on HFS+.
GIT_HFS_IGNORABLE = (
    *range(0x200C, 0x2010),
    *range(0x202A, 0x202F),
    *range(0x206A, 0x2070),
    0xFEFF,
)

# Look-alike spellings, built from code points so the source stays ASCII:
# AGENTS.md with a long s (U+017F), and CLAUDE in fullwidth letters (U+FF21..).
LONG_S_AGENTS = "AGENT" + chr(0x17F) + ".md"
FULLWIDTH_CLAUDE = "".join(chr(ord(c) - ord("A") + 0xFF21) for c in "CLAUDE") + ".md"
# uv.toml in fullwidth letters (U+FF55, U+FF56), requirements.txt with a long s.
FULLWIDTH_UV_TOML = chr(0xFF55) + chr(0xFF56) + ".toml"
LONG_S_REQUIREMENTS = "requirement" + chr(0x17F) + ".txt"


@pytest.fixture(autouse=True)
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """HOME for this module: a temp path that is not created (Path.home() reads HOME)."""
    home = tmp_path / "fake-home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # what Path.home() reads on Windows
    return home


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The pinned input root: a project with .git/hooks, docs/ and an input file."""
    project = (tmp_path / "project").resolve()
    (project / ".git" / "hooks").mkdir(parents=True)
    (project / "docs").mkdir()
    (project / "input.txt").write_bytes(b"the job input\n")
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", project)
    return project


def outside_dir(root: Path) -> Path:
    """A directory beside the root, holding a file that must never change."""
    outside = root.parent / "outside"
    outside.mkdir(exist_ok=True)
    (outside / "victim.txt").write_bytes(PRECIOUS)
    return outside


def delivering_kit(tmp_path: Path, on_download: Callable[[], None] | None = None) -> RouterKit:
    """A kit whose deal carries a valid proof over ``DATA`` and serves ``DATA``."""
    proof = {"method": "signed-output-hash", "hash": lhub.sha256_ref(DATA)}

    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "get_deal":
            return {"deal_id": DEAL_ID, "state": "PROOF_SUBMITTED", "proof": proof}
        if name == "download_deal_file":
            if on_download is not None:
                on_download()
            return {"content_b64": base64.b64encode(DATA).decode("ascii")}
        raise AssertionError(f"unexpected tool {name}")

    kit = RouterKit(tmp_path / "kit", route)
    kit.ensure_key()
    return kit


class StopFlow(lhub.KitError):
    """Raised by the first tool call: the file passed every rule and was read."""


def stopping_kit(tmp_path: Path) -> RouterKit:
    """A kit whose first tool call (any) records its arguments and stops the flow."""

    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise StopFlow(f"stopped at {name}")

    kit = RouterKit(tmp_path / "kit", route)
    kit.ensure_key()
    return kit


def call_file_tool(tool: str, path: str) -> dict[str, Any]:
    """Call one MCP file tool directly (no server), ``path`` as its file argument."""
    if tool == "hire":
        return lhub.mcp_hire(
            listing_id=LISTING_ID, input_path=path, max_price="1.00", timeout_seconds=1
        )
    if tool == "deliver":
        return lhub.mcp_deliver(deal_id=DEAL_ID, file_path=path)
    return lhub.mcp_get_result(deal_id=DEAL_ID, out_path=path, timeout_seconds=1)


def snapshot(base: Path) -> dict[str, str]:
    """Every node under ``base``: a file's sha256, a directory, a symlink's target."""
    nodes: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(base):  # followlinks=False
        for name in (*dirnames, *filenames):
            path = Path(dirpath) / name
            key = str(path.relative_to(base))
            if path.is_symlink():
                nodes[key] = "symlink -> " + os.readlink(path)
            elif path.is_dir():
                nodes[key] = "dir"
            else:
                nodes[key] = "file " + hashlib.sha256(path.read_bytes()).hexdigest()
    return nodes


def temp_leftovers(base: Path) -> list[str]:
    return [str(p) for p in base.rglob(".lhub-kit-*")]


def server_call(name: str, arguments: dict[str, Any]) -> tuple[bool, str]:
    """One call through the REAL MCP server; skips this test without the mcp package."""
    from test_mcp_errors import call_tool  # its module-level importorskip("mcp")

    return call_tool(name, arguments)


# ---------------------------------------------------------------------------
# get_result: refused before any network call, nothing written.
# ---------------------------------------------------------------------------


def symlinked_dir_escape(root: Path) -> str:
    (root / "reports").symlink_to(outside_dir(root), target_is_directory=True)
    return "reports/new.md"


def symlinked_file_escape(root: Path) -> str:
    (root / "review.md").symlink_to(outside_dir(root) / "victim.txt")
    return "review.md"


def dangling_symlink_escape(root: Path) -> str:
    # The target does not exist yet: writing through the link would create it.
    (root / "fresh.md").symlink_to(outside_dir(root) / "planted.md")
    return "fresh.md"


def symlink_into_hidden(root: Path) -> str:
    (root / "hooks").symlink_to(root / ".git" / "hooks", target_is_directory=True)
    return "hooks/pre-commit"


def hidden_alias_of_a_visible_dir(root: Path) -> str:
    (root / ".alias").symlink_to(root / "docs", target_is_directory=True)
    return ".alias/notes.md"


def symlink_loop(root: Path) -> str:
    (root / "loop").symlink_to(root / "loop")
    return "loop/x.md"


def file_used_as_a_directory(root: Path) -> str:
    (root / "docs" / "readme.txt").write_bytes(PRECIOUS)
    return "docs/readme.txt/x.md"


def prefix_alias(root: Path) -> Path:
    """Another spelling of the root (like /var for /private/var): a symlink to it."""
    alias = root.parent / "alias"
    if not alias.is_symlink():
        alias.symlink_to(root, target_is_directory=True)
    return alias


def symlink_onto_an_instruction_file(root: Path) -> str:
    (root / "CLAUDE.md").write_bytes(PRECIOUS)
    (root / "notes.md").symlink_to(root / "CLAUDE.md")
    return "notes.md"


def symlink_onto_a_toolchain_config(root: Path) -> str:
    (root / "uv.toml").write_bytes(PRECIOUS)
    (root / "review.md").symlink_to(root / "uv.toml")
    return "review.md"


REFUSED: dict[str, tuple[Callable[[Path], str], str]] = {
    # Outside the root: relative, absolute, and through symlinks.
    "dotdot-escape": (lambda root: "../outside/new.md", OUTSIDE),
    "absolute-outside-new": (lambda root: str(outside_dir(root) / "new.md"), OUTSIDE),
    "absolute-outside-existing": (lambda root: str(outside_dir(root) / "victim.txt"), OUTSIDE),
    "symlinked-dir-escape": (symlinked_dir_escape, OUTSIDE),
    "symlinked-file-escape": (symlinked_file_escape, OUTSIDE),
    "dangling-symlink-escape": (dangling_symlink_escape, OUTSIDE),
    # '..' even when it stays inside the root, also in an absolute path spelled
    # through another name for the root (not lexically under it).
    "dotdot-staying-inside": (lambda root: "docs/../review.md", HIDDEN),
    "aliased-absolute-dotdot": (lambda root: str(prefix_alias(root) / "docs/../x.md"), HIDDEN),
    "aliased-absolute-hidden": (lambda root: str(prefix_alias(root) / ".git/hooks/x"), HIDDEN),
    # Hidden components relative to the root: by name, by absolute name, through a symlink.
    "git-hooks": (lambda root: ".git/hooks/pre-commit", HIDDEN),
    "absolute-git-hooks": (lambda root: str(root / ".git" / "hooks" / "post-checkout"), HIDDEN),
    "claude-settings": (lambda root: ".claude/settings.json", HIDDEN),
    "mcp-json": (lambda root: ".mcp.json", HIDDEN),
    "dotenv": (lambda root: ".env", HIDDEN),
    "nested-hidden-dir": (lambda root: "docs/.hidden/notes.md", HIDDEN),
    "symlink-into-hidden": (symlink_into_hidden, HIDDEN),
    "hidden-alias-of-a-visible-dir": (hidden_alias_of_a_visible_dir, HIDDEN),
    # Host instruction files (B1): every name, any letter case, any depth, as
    # given or as resolved, and as a case-insensitive filesystem or Windows
    # would open the name.
    "CLAUDE.md": (lambda root: "CLAUDE.md", INSTRUCTION),
    "claude.md-lower": (lambda root: "claude.md", INSTRUCTION),
    "Claude.Md-mixed": (lambda root: "Claude.Md", INSTRUCTION),
    "CLAUDE.local.md": (lambda root: "CLAUDE.local.md", INSTRUCTION),
    "claude.LOCAL.md-mixed": (lambda root: "claude.LOCAL.md", INSTRUCTION),
    "AGENTS.md": (lambda root: "AGENTS.md", INSTRUCTION),
    "agents.md-lower": (lambda root: "agents.md", INSTRUCTION),
    "docs/claude.md": (lambda root: "docs/claude.md", INSTRUCTION),
    "deep/AGENTS.MD": (lambda root: "docs/deep/AGENTS.MD", INSTRUCTION),
    "absolute-docs/CLAUDE.local.md": (lambda root: str(root / "docs/CLAUDE.local.md"), INSTRUCTION),
    "as-a-directory": (lambda root: "CLAUDE.md/notes.txt", INSTRUCTION),
    "symlink-onto-CLAUDE.md": (symlink_onto_an_instruction_file, INSTRUCTION),
    "long-s-AGENTS.md": (lambda root: LONG_S_AGENTS, INSTRUCTION),
    "fullwidth-CLAUDE.md": (lambda root: FULLWIDTH_CLAUDE, INSTRUCTION),
    "windows-trailing-dot": (lambda root: "CLAUDE.md.", INSTRUCTION),
    "windows-data-stream": (lambda root: "AGENTS.md::$DATA", INSTRUCTION),
    # Python toolchain config files (D-3 Slice-2 security fix): uv reads uv.toml
    # and pyproject.toml [tool.uv] from the working directory and its parents, so
    # a deliverable there could point a later install at another index. Every
    # name, any letter case, any depth, as given or as resolved, folded like the
    # instruction files.
    "uv.toml": (lambda root: "uv.toml", TOOLCHAIN),
    "pyproject.toml": (lambda root: "pyproject.toml", TOOLCHAIN),
    "setup.cfg": (lambda root: "setup.cfg", TOOLCHAIN),
    "pip.conf": (lambda root: "pip.conf", TOOLCHAIN),
    "requirements.txt": (lambda root: "requirements.txt", TOOLCHAIN),
    "requirements-dev.txt": (lambda root: "requirements-dev.txt", TOOLCHAIN),
    "UV.TOML-upper": (lambda root: "UV.TOML", TOOLCHAIN),
    "PyProject.Toml-mixed": (lambda root: "PyProject.Toml", TOOLCHAIN),
    "Requirements-Dev.TXT-mixed": (lambda root: "Requirements-Dev.TXT", TOOLCHAIN),
    "docs/pyproject.toml": (lambda root: "docs/pyproject.toml", TOOLCHAIN),
    "deep/setup.cfg": (lambda root: "docs/deep/setup.cfg", TOOLCHAIN),
    "absolute-uv.toml": (lambda root: str(root / "uv.toml"), TOOLCHAIN),
    "toolchain-as-a-directory": (lambda root: "pyproject.toml/notes.txt", TOOLCHAIN),
    "symlink-onto-uv.toml": (symlink_onto_a_toolchain_config, TOOLCHAIN),
    "fullwidth-uv.toml": (lambda root: FULLWIDTH_UV_TOML, TOOLCHAIN),
    "long-s-requirements.txt": (lambda root: LONG_S_REQUIREMENTS, TOOLCHAIN),
    "toolchain-trailing-dot": (lambda root: "uv.toml.", TOOLCHAIN),
    "toolchain-data-stream": (lambda root: "pip.conf::$DATA", TOOLCHAIN),
    # Not a file.
    "root-itself": (lambda root: ".", NOT_A_FILE),
    "empty": (lambda root: "", NOT_A_FILE),
    "existing-directory": (lambda root: "docs", NOT_A_FILE),
    # Paths resolve()/stat() cannot finish: refused legibly up front, never a
    # crash and never a late failure after the download (any Python >= 3.10).
    "nul-byte": (lambda root: "a\x00b.md", UNRESOLVABLE),
    "symlink-loop": (symlink_loop, UNRESOLVABLE),
    "over-long-name": (lambda root: "x" * 5000 + ".md", UNRESOLVABLE),
    "file-used-as-a-directory": (file_used_as_a_directory, UNRESOLVABLE),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_refused_before_any_network_call_and_nothing_written(
    case: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_out_path, reason = REFUSED[case]
    out_path = make_out_path(root)
    kit = delivering_kit(tmp_path)
    use_kit(monkeypatch, kit)
    before = snapshot(tmp_path)

    with pytest.raises(lhub.KitError, match=re.escape(reason)) as refused:
        lhub.mcp_get_result(deal_id=DEAL_ID, out_path=out_path, timeout_seconds=1)

    assert kit.tool_calls == []  # no network call: not even get_deal
    assert kit.ensure_session_calls == 0
    assert snapshot(tmp_path) == before  # nothing created, written or replaced anywhere
    message = str(refused.value)
    assert message.startswith("out_path ")
    if not Path(out_path).is_absolute():
        # The text reaches an LLM: no operator-local absolute path, no symlink target.
        assert str(tmp_path) not in message


def test_root_components_do_not_count_as_hidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "Relative to the root": a root that itself lives under a dot-directory is fine.
    project = (tmp_path / ".config" / "project").resolve()
    project.mkdir(parents=True)
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", project)
    use_kit(monkeypatch, delivering_kit(tmp_path))
    lhub.mcp_get_result(deal_id=DEAL_ID, out_path="out.md", timeout_seconds=1)
    assert (project / "out.md").read_bytes() == DATA


def test_names_that_only_resemble_an_instruction_file_are_written(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only the three names are host instruction files, not every *.md.
    use_kit(monkeypatch, delivering_kit(tmp_path))
    for name in ("README.md", "claude-notes.md", "docs/AGENTS.md.txt", "my-CLAUDE.md"):
        lhub.mcp_get_result(deal_id=DEAL_ID, out_path=name, timeout_seconds=1)
        assert (root / name).read_bytes() == DATA


def test_names_that_only_resemble_a_toolchain_config_are_written(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only the exact names (and requirements*.txt) are refused, not every *.toml or *.txt.
    use_kit(monkeypatch, delivering_kit(tmp_path))
    for name in (
        "pyproject.toml.bak",
        "my-requirements.txt",
        "requirements.md",
        "docs/uv-notes.toml",
        "setup.cfg.example",
        "pip.conf.txt",
    ):
        lhub.mcp_get_result(deal_id=DEAL_ID, out_path=name, timeout_seconds=1)
        assert (root / name).read_bytes() == DATA


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores modes")
def test_read_only_target_is_refused(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The confined writer replaces the target (below); a file the user made
    # read-only is refused instead, as a plain write would have been.
    locked = root / "locked.md"
    locked.write_bytes(PRECIOUS)
    locked.chmod(0o444)
    kit = delivering_kit(tmp_path)
    use_kit(monkeypatch, kit)
    with pytest.raises(lhub.KitError, match="names a read-only file"):
        lhub.mcp_get_result(deal_id=DEAL_ID, out_path="locked.md", timeout_seconds=1)
    assert kit.tool_calls == []
    assert locked.read_bytes() == PRECIOUS


# ---------------------------------------------------------------------------
# get_result allowed: the verified bytes land inside the root.
# ---------------------------------------------------------------------------


def symlink_staying_inside(root: Path) -> tuple[str, Path]:
    (root / "out").symlink_to(root / "docs", target_is_directory=True)
    return "out/x.md", root / "docs" / "x.md"


ALLOWED: dict[str, Callable[[Path], tuple[str, Path]]] = {
    "relative-file": lambda root: ("review.md", root / "review.md"),
    "dot-slash": lambda root: ("./review.md", root / "review.md"),
    "new-nested-dirs": lambda root: ("reviews/2026/deal.md", root / "reviews" / "2026" / "deal.md"),
    "absolute-inside": lambda root: (str(root / "docs" / "abs.md"), root / "docs" / "abs.md"),
    "aliased-absolute-inside": lambda root: (
        str(prefix_alias(root) / "docs" / "y.md"),
        root / "docs" / "y.md",
    ),
    "symlink-staying-inside": symlink_staying_inside,
}


@pytest.mark.parametrize("case", sorted(ALLOWED))
def test_allowed_paths_get_the_verified_bytes(
    case: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_path, landing = ALLOWED[case](root)
    kit = delivering_kit(tmp_path)
    use_kit(monkeypatch, kit)

    result = lhub.mcp_get_result(deal_id=DEAL_ID, out_path=out_path, timeout_seconds=1)

    assert result["delivered"] is True
    assert result["sha256"] == lhub.sha256_ref(DATA)
    assert result["out"] == str(Path(out_path))  # the caller's own path, as before
    assert landing.read_bytes() == DATA
    assert landing.is_file() and not landing.is_symlink()
    assert temp_leftovers(tmp_path) == []
    assert [name for name, _ in kit.tool_calls] == ["get_deal", "download_deal_file"]


def test_a_relative_path_resolves_against_the_root_not_the_cwd(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "server-cwd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    use_kit(monkeypatch, delivering_kit(tmp_path))
    lhub.mcp_get_result(deal_id=DEAL_ID, out_path="review.md", timeout_seconds=1)
    assert (root / "review.md").read_bytes() == DATA
    assert not (elsewhere / "review.md").exists()


def test_an_existing_file_is_replaced(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = root / "review.md"
    target.write_bytes(b"old draft\n")
    use_kit(monkeypatch, delivering_kit(tmp_path))
    lhub.mcp_get_result(deal_id=DEAL_ID, out_path="review.md", timeout_seconds=1)
    assert target.read_bytes() == DATA
    assert temp_leftovers(tmp_path) == []


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores modes")
def test_a_failed_write_is_a_kit_error_without_the_absolute_path(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The path passes every rule, but the directory cannot take the temp file
    # (a writable file in a non-writable directory cannot be replaced either):
    # a legible kit error with the OS reason, no absolute path, nothing left.
    locked_dir = root / "docs"
    (locked_dir / "existing.md").write_bytes(PRECIOUS)
    locked_dir.chmod(0o555)
    try:
        use_kit(monkeypatch, delivering_kit(tmp_path))
        for name in ("docs/new.md", "docs/existing.md"):
            with pytest.raises(lhub.KitError) as refused:
                lhub.mcp_get_result(deal_id=DEAL_ID, out_path=name, timeout_seconds=1)
            message = str(refused.value)
            assert message.startswith(f"cannot write out_path {name!r}: ")
            assert str(tmp_path) not in message
        assert [p.name for p in locked_dir.iterdir()] == ["existing.md"]
        assert (locked_dir / "existing.md").read_bytes() == PRECIOUS
    finally:
        locked_dir.chmod(0o755)


def test_a_hard_link_at_the_target_is_replaced_not_written_through(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # resolve() cannot see a hard link; replacing the name (never writing into
    # the existing inode) keeps the bytes from reaching the linked file.
    victim = outside_dir(root) / "victim.txt"
    os.link(victim, root / "notes.md")
    use_kit(monkeypatch, delivering_kit(tmp_path))
    lhub.mcp_get_result(deal_id=DEAL_ID, out_path="notes.md", timeout_seconds=1)
    assert (root / "notes.md").read_bytes() == DATA
    assert victim.read_bytes() == PRECIOUS
    assert os.stat(root / "notes.md").st_nlink == 1


@pytest.mark.parametrize(
    ("target", "reason"),
    [("hidden", HIDDEN), ("outside", OUTSIDE), ("instruction", INSTRUCTION)],
    ids=["into-git-hooks", "out-of-the-root", "onto-CLAUDE.md"],
)
def test_a_symlink_planted_during_the_download_is_refused_before_the_write(
    target: str, reason: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if target == "instruction":
        (root / "CLAUDE.md").write_bytes(PRECIOUS)
        out_path, destination = "late.md", root / "CLAUDE.md"
    else:
        out_path = "late/pre-commit"
        destination = (root / ".git" / "hooks" if target == "hidden" else outside_dir(root)) / (
            "pre-commit"
        )

    def plant() -> None:
        # The "late" name did not exist at the up-front check, so the path passed it.
        link = root / out_path.split("/")[0]
        if target == "instruction":
            link.symlink_to(destination)
        else:
            link.symlink_to(destination.parent, target_is_directory=True)

    kit = delivering_kit(tmp_path, on_download=plant)
    use_kit(monkeypatch, kit)
    with pytest.raises(lhub.KitError, match=re.escape(reason)):
        lhub.mcp_get_result(deal_id=DEAL_ID, out_path=out_path, timeout_seconds=1)

    assert [name for name, _ in kit.tool_calls] == ["get_deal", "download_deal_file"]
    if target == "instruction":
        assert destination.read_bytes() == PRECIOUS
    else:
        assert not destination.exists()
    assert temp_leftovers(tmp_path) == []


# ---------------------------------------------------------------------------
# Every MCP file tool (hire, deliver, get_result): root sanity and the kit home (B2).
# ---------------------------------------------------------------------------


def test_reads_inside_the_root_reach_the_network_with_the_right_bytes(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Control for the refusals below: a plain file inside the root is read and
    # its bytes are what the flow sends on.
    kit = stopping_kit(tmp_path)
    use_kit(monkeypatch, kit)
    with pytest.raises(StopFlow):
        call_file_tool("hire", "input.txt")
    assert kit.tool_calls[0][1]["request_ref"] == lhub.sha256_ref(b"the job input\n")
    with pytest.raises(StopFlow):
        call_file_tool("deliver", str(root / "input.txt"))
    upload = kit.tool_calls[1][1]
    assert base64.b64decode(upload["content_b64"]) == b"the job input\n"


def make_root(case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin the input root for one root-sanity case; HOME follows the case."""
    if case == "root-is-home":
        home = (tmp_path / "me").resolve()
        home.mkdir()
        pinned = home
    elif case == "root-above-home":
        home = (tmp_path / "users" / "me").resolve()
        home.mkdir(parents=True)
        pinned = home.parent
    elif case == "root-is-filesystem-root":
        home = (tmp_path / "me").resolve()
        pinned = Path(tmp_path.anchor)
    else:  # "root-inside-home": the normal case, a project in the home
        home = (tmp_path / "me").resolve()
        pinned = home / "project"
        pinned.mkdir(parents=True)
        (pinned / "input.txt").write_bytes(b"the job input\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", pinned)
    return pinned


@pytest.mark.parametrize("tool", FILE_TOOLS)
@pytest.mark.parametrize("case", ["root-is-home", "root-above-home", "root-is-filesystem-root"])
def test_a_home_or_higher_root_refuses_every_file_tool_before_any_network_call(
    case: str, tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pinned = make_root(case, tmp_path, monkeypatch)
    if pinned != Path(tmp_path.anchor):
        (pinned / "input.txt").write_bytes(b"the job input\n")
    kit = delivering_kit(tmp_path)
    use_kit(monkeypatch, kit)
    before = snapshot(tmp_path)
    with pytest.raises(lhub.KitError, match=re.escape(UNSAFE_ROOT)) as refused:
        call_file_tool(tool, "input.txt" if tool != "get_result" else "new-review.md")
    assert kit.tool_calls == []
    assert kit.ensure_session_calls == 0
    assert snapshot(tmp_path) == before
    assert str(tmp_path) not in str(refused.value)  # names no path at all


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_a_project_inside_the_home_is_a_normal_root(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pinned = make_root("root-inside-home", tmp_path, monkeypatch)
    if tool == "get_result":
        use_kit(monkeypatch, delivering_kit(tmp_path))
        call_file_tool(tool, "review.md")
        assert (pinned / "review.md").read_bytes() == DATA
    else:
        kit = stopping_kit(tmp_path)
        use_kit(monkeypatch, kit)
        with pytest.raises(StopFlow):  # read fine; stopped at the first network call
            call_file_tool(tool, "input.txt")
        assert len(kit.tool_calls) == 1


def test_the_server_start_warns_when_the_root_is_unsafe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = (tmp_path / "me").resolve()
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv(lhub.ENV_INPUT_ROOT, str(home))
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", None)
    monkeypatch.setattr(lhub, "_MCP_KIT_HOME", None)

    class FakeServer:
        def run(self) -> None:
            return None

    monkeypatch.setattr(lhub, "build_mcp_server", FakeServer)
    assert lhub.main(["mcp"]) == 0
    err = capsys.readouterr().err
    assert "warning: hire, deliver and get_result will refuse every call" in err
    assert home == lhub._MCP_INPUT_ROOT
    assert lhub.kit_home_from_env().resolve() == lhub._MCP_KIT_HOME


def kit_home_under_the_root(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A NON-default, non-hidden kit home inside the project, holding fake key files."""
    kit_home = root / "kit-state"
    (kit_home / "listings").mkdir(parents=True)
    (kit_home / "agent.pem").write_bytes(b"fake key placeholder\n")
    (kit_home / "session.json").write_bytes(b"{}\n")
    monkeypatch.setenv(lhub.ENV_KIT_HOME, str(kit_home))
    return kit_home


KIT_HOME_PATHS = {
    "hire": ["kit-state/agent.pem", "state-link/agent.pem", "kit-state/docs-link/readme.txt"],
    "deliver": ["kit-state/session.json", "state-link/session.json"],
    "get_result": ["kit-state/listings/new.json", "kit-state/agent.pem", "state-link/x.md"],
}


@pytest.mark.parametrize(
    ("tool", "path"), [(tool, path) for tool, paths in KIT_HOME_PATHS.items() for path in paths]
)
def test_paths_inside_the_kit_home_are_refused_by_every_file_tool(
    tool: str, path: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit_home = kit_home_under_the_root(root, monkeypatch)
    (root / "docs" / "readme.txt").write_bytes(b"public\n")
    (root / "state-link").symlink_to(kit_home, target_is_directory=True)  # resolves inside
    # Lexically inside the kit home, resolving out of it: refused all the same.
    (kit_home / "docs-link").symlink_to(root / "docs", target_is_directory=True)
    kit = delivering_kit(tmp_path)
    use_kit(monkeypatch, kit)
    before = snapshot(tmp_path)
    with pytest.raises(lhub.KitError, match=re.escape(KIT_HOME)):
        call_file_tool(tool, path)
    assert kit.tool_calls == []
    assert snapshot(tmp_path) == before
    assert (kit_home / "agent.pem").read_bytes() == b"fake key placeholder\n"


def test_the_pinned_kit_home_is_used_not_the_environment(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit_home = kit_home_under_the_root(root, monkeypatch)
    monkeypatch.setattr(lhub, "_MCP_KIT_HOME", kit_home)
    monkeypatch.setenv(lhub.ENV_KIT_HOME, str(tmp_path / "somewhere-else"))
    with pytest.raises(lhub.KitError, match=re.escape(KIT_HOME)):
        lhub.resolve_input_path("kit-state/agent.pem", root)


# ---------------------------------------------------------------------------
# Security round 2, R2-B1: the kit home is matched by filesystem identity.
# ---------------------------------------------------------------------------


def volume_is_case_insensitive(directory: Path) -> bool:
    probe = directory / "CaseProbe.tmp"
    probe.write_bytes(b"")
    try:
        return (directory / "caseprobe.tmp").exists()
    finally:
        probe.unlink()


@pytest.fixture
def case_insensitive_volume(tmp_path: Path) -> None:
    if not volume_is_case_insensitive(tmp_path):
        pytest.skip("the temp volume is case-sensitive: a letter-case variant names another file")


def refused_with_nothing_touched(
    tool: str, path: str, reason: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``tool`` refuses ``path`` with ``reason``: no network call, nothing written."""
    kit = delivering_kit(tmp_path)
    use_kit(monkeypatch, kit)
    before = snapshot(tmp_path)
    with pytest.raises(lhub.KitError, match=re.escape(reason)):
        call_file_tool(tool, path)
    assert kit.tool_calls == []
    assert snapshot(tmp_path) == before


CASE_VARIANTS = {
    "hire": ["KIT-STATE/agent.pem", "Kit-State/session.json"],
    "deliver": ["KIT-STATE/session.json", "kit-STATE/agent.pem"],
    "get_result": ["Kit-State/listings/x.json", "KIT-STATE/agent.pem"],
}


@pytest.mark.usefixtures("case_insensitive_volume")
@pytest.mark.parametrize(
    ("tool", "path"), [(tool, path) for tool, paths in CASE_VARIANTS.items() for path in paths]
)
def test_a_letter_case_variant_of_the_kit_home_is_refused(
    tool: str, path: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit_home = kit_home_under_the_root(root, monkeypatch)
    variant = root / path
    # The bypass this closes: on a case-insensitive volume the variant names the
    # real kit home, yet resolve() keeps its spelling, which is not under it.
    assert (root / Path(path).parts[0]).exists()
    assert not variant.resolve().is_relative_to(kit_home)
    refused_with_nothing_touched(tool, path, KIT_HOME, tmp_path, monkeypatch)
    assert (kit_home / "agent.pem").read_bytes() == b"fake key placeholder\n"


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_a_unicode_normalization_variant_of_the_kit_home_is_refused(
    tool: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A non-ASCII kit home created in NFC, asked for in NFD. On a normalization-
    # insensitive volume (APFS) both name one directory and identity matches;
    # elsewhere the NFC-folded spelling does. Refused either way.
    nfc = "caf\u00e9-kit"
    nfd = "cafe\u0301-kit"
    kit_home = root / nfc
    kit_home.mkdir()
    (kit_home / "agent.pem").write_bytes(b"fake key placeholder\n")
    monkeypatch.setenv(lhub.ENV_KIT_HOME, str(kit_home))
    assert nfc != nfd
    refused_with_nothing_touched(tool, f"{nfd}/agent.pem", KIT_HOME, tmp_path, monkeypatch)


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_a_kit_home_that_does_not_exist_yet_is_matched_by_folded_spelling(
    tool: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nothing to compare identity with yet. Without the folded spelling a write
    # could create KIT-STATE/agent.pem, and a case-insensitive volume would then
    # serve it as the kit's own key: a key planted by a counterparty.
    monkeypatch.setenv(lhub.ENV_KIT_HOME, str(root / "kit-state"))
    refused_with_nothing_touched(tool, "KIT-STATE/agent.pem", KIT_HOME, tmp_path, monkeypatch)
    assert not (root / "KIT-STATE").exists()


@pytest.mark.usefixtures("case_insensitive_volume")
def test_identity_alone_recognizes_a_case_variant_of_the_kit_home(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit_home = kit_home_under_the_root(root, monkeypatch)
    # Folding disabled: only the (st_dev, st_ino) walk can see the variant.
    monkeypatch.setattr(lhub, "_spelling", lambda path: path.parts)
    assert lhub._within(root / "KIT-STATE" / "listings" / "new.json", kit_home)
    assert lhub._within(root / "Kit-State", kit_home)
    assert not lhub._within(root / "docs" / "x.md", kit_home)


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_a_hard_link_to_the_agent_key_is_refused(
    tool: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A hard link in the project has no path tie to the kit home: only the
    # file's own identity shows it is the key (or the session).
    kit_home = tmp_path / "kit-outside"
    kit_home.mkdir()
    (kit_home / "agent.pem").write_bytes(b"fake key placeholder\n")
    (kit_home / "session.json").write_bytes(b"{}\n")
    monkeypatch.setenv(lhub.ENV_KIT_HOME, str(kit_home))
    os.link(kit_home / "agent.pem", root / "innocent.txt")
    os.link(kit_home / "session.json", root / "notes.json")
    refused_with_nothing_touched(tool, "innocent.txt", KIT_SECRET, tmp_path, monkeypatch)
    refused_with_nothing_touched(tool, "notes.json", KIT_SECRET, tmp_path, monkeypatch)


@pytest.mark.usefixtures("case_insensitive_volume")
@pytest.mark.parametrize("tool", FILE_TOOLS)
@pytest.mark.parametrize("case", ["root-is-home", "root-above-home"])
def test_a_letter_case_variant_of_the_home_as_root_is_refused(
    case: str, tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # NIT (a): the root check compares identity too, so "me" for "Me" or
    # "users" for "Users" is the home (or above it) on a case-insensitive volume.
    home = (tmp_path / "Users" / "Me").resolve()
    home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    pinned = tmp_path / "users" if case == "root-above-home" else tmp_path / "Users" / "me"
    assert pinned.exists() and pinned != home and not home.is_relative_to(pinned)
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", pinned)
    refused_with_nothing_touched(tool, "review.md", UNSAFE_ROOT, tmp_path, monkeypatch)


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_an_absolute_path_into_the_kit_home_through_another_root_spelling_is_refused(
    tool: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Spelled through a symlinked prefix, the path is not lexically under the
    # root, so only its resolved form ties it to the kit home.
    kit_home_under_the_root(root, monkeypatch)
    path = str(prefix_alias(root) / "kit-state" / "agent.pem")
    refused_with_nothing_touched(tool, path, KIT_HOME, tmp_path, monkeypatch)


@pytest.mark.parametrize("tool", FILE_TOOLS)
@pytest.mark.parametrize("case", ["root-is-home", "root-above-home"])
def test_a_root_that_does_not_exist_is_still_judged_by_spelling(
    case: str, tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nothing on disk to compare identity with: the spelling rule decides.
    pinned = tmp_path / "ghost"
    home = pinned if case == "root-is-home" else pinned / "me"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", pinned)
    assert not pinned.exists()
    refused_with_nothing_touched(tool, "review.md", UNSAFE_ROOT, tmp_path, monkeypatch)


# ---------------------------------------------------------------------------
# Security round 2, R2-B2: no invisible or format code point in a component.
# ---------------------------------------------------------------------------


INVISIBLE_PATHS = {
    "zwnj-dot-git": "\u200c.git/config",
    "zwnj-dotenv": "\u200c.env",
    "zwnj-in-CLAUDE.md": "CLAUDE\u200c.md",
    "bom-dot-claude": "\ufeff.claude/settings.json",
    "zwsp-cf-not-in-git-list": "\u200bnotes.md",
    "rtl-override": "docs/\u202egnp.md",
    "soft-hyphen": "re\u00adview.md",
    "variation-selector-not-cf": "CLAUDE\ufe0f.md",
    "hangul-filler-not-cf": "\u3164.env",
    "tag-character": "notes" + chr(0xE0041) + ".md",
    # Reserved default-ignorable code points (category Cn, not caught by the Cf test).
    "reserved-u2065": "notes" + chr(0x2065) + ".md",
    "reserved-ufff0": chr(0xFFF0) + "notes.md",
    "checked-before-the-dot-rule": ".\u200cenv",
    "checked-before-the-dotdot-rule": "docs/\u200d../input.txt",
    # Given-path check only: the '..' collapses this component away on resolution.
    "in-a-component-dotdot-removes": "x\u200c/../input.txt",
}


@pytest.mark.parametrize("case", sorted(INVISIBLE_PATHS))
@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_a_component_with_an_invisible_character_is_refused(
    tool: str, case: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    refused_with_nothing_touched(tool, INVISIBLE_PATHS[case], INVISIBLE, tmp_path, monkeypatch)


def test_every_code_point_hfs_ignores_is_refused() -> None:
    for code_point in GIT_HFS_IGNORABLE:
        assert lhub._has_ignorable(chr(code_point) + ".git"), hex(code_point)


# Every endpoint of the kit's non-Cf default-ignorable ranges, plus the variation
# selectors 17 and 256 inside the tag/selector block (U+E0100..U+E01EF).
IGNORABLE_RANGE_ENDPOINTS = (
    0x034F,
    0x115F,
    0x1160,
    0x17B4,
    0x17B5,
    0x180B,
    0x180F,
    0x2065,
    0x3164,
    0xFE00,
    0xFE0F,
    0xFFA0,
    0xFFF0,
    0xFFF8,
    0xE0000,
    0xE0100,
    0xE01EF,
    0xE0FFF,
)
# The ordinary code points just outside those ranges (neither Cf nor
# default-ignorable): a range widened by one fails here.
OUTSIDE_THE_RANGES = (
    0x034E,
    0x0350,
    0x115E,
    0x1161,
    0x17B3,
    0x17B6,
    0x180A,
    0x1810,
    0x3163,
    0x3165,
    0xFDFF,
    0xFE10,
    0xFF9F,
    0xFFA1,
    0xFFEF,
    0xDFFFF,
    0xE1000,
)


@pytest.mark.parametrize("code_point", IGNORABLE_RANGE_ENDPOINTS, ids=lambda c: f"U+{c:04X}")
def test_every_ignorable_range_endpoint_is_refused(code_point: int) -> None:
    assert lhub._has_ignorable("notes" + chr(code_point) + ".md")


@pytest.mark.parametrize("code_point", OUTSIDE_THE_RANGES, ids=lambda c: f"U+{c:04X}")
def test_code_points_just_outside_the_ranges_are_not_ignorable(code_point: int) -> None:
    assert not lhub._has_ignorable("notes" + chr(code_point) + ".md")


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_a_symlink_to_a_name_with_an_invisible_character_is_refused(
    tool: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On HFS+ "\u200c.git" IS .git; a plain-named link to it must not get through.
    disguised = root / "\u200c.git"
    disguised.mkdir()
    (disguised / "config").write_bytes(PRECIOUS)
    (root / "notes").symlink_to(disguised, target_is_directory=True)
    refused_with_nothing_touched(tool, "notes/config", INVISIBLE, tmp_path, monkeypatch)


def test_ordinary_non_ascii_names_are_still_written(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Combining marks, accents and CJK are letters, not format characters.
    use_kit(monkeypatch, delivering_kit(tmp_path))
    for name in (
        "caf\u00e9.md",
        "cafe\u0301.md",
        "na\u00efve-r\u00e9sum\u00e9.md",
        "\u65e5\u672c.md",
    ):
        lhub.mcp_get_result(deal_id=DEAL_ID, out_path=name, timeout_seconds=1)
        assert (root / name).read_bytes() == DATA


# ---------------------------------------------------------------------------
# The fail-closed branches: no home, no kit home, a pin that failed at start.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_no_determinable_home_refuses_every_file_tool(
    tool: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_home(cls: type[Path]) -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", classmethod(no_home))
    refused_with_nothing_touched(tool, "input.txt", NO_HOME, tmp_path, monkeypatch)


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_no_determinable_kit_home_refuses_every_file_tool(
    tool: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_kit_home() -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(lhub, "kit_home_from_env", no_kit_home)
    refused_with_nothing_touched(tool, "input.txt", NO_KIT_HOME, tmp_path, monkeypatch)


def test_a_kit_home_pin_that_failed_at_start_refuses_for_the_server_lifetime(
    tmp_path: Path,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(lhub.ENV_INPUT_ROOT, str(root))
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", None)
    monkeypatch.setattr(lhub, "_MCP_KIT_HOME", None)
    monkeypatch.setattr(lhub, "_MCP_KIT_HOME_UNKNOWN", False)
    real = lhub.kit_home_from_env
    calls: list[int] = []

    def fails_once() -> Path:
        # Only the pin at start fails; every later lookup would succeed.
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("Could not determine home directory.")
        return real()

    class FakeServer:
        def run(self) -> None:
            return None

    monkeypatch.setattr(lhub, "kit_home_from_env", fails_once)
    monkeypatch.setattr(lhub, "build_mcp_server", FakeServer)
    assert lhub.main(["mcp"]) == 0
    assert "warning: cannot determine the kit home" in capsys.readouterr().err
    assert lhub._MCP_KIT_HOME_UNKNOWN is True
    assert lhub.kit_home_from_env() is not None  # the lookup works again now...
    for tool in FILE_TOOLS:  # ...but the server keeps refusing, fail closed
        refused_with_nothing_touched(tool, "input.txt", NO_KIT_HOME, tmp_path, monkeypatch)


# ---------------------------------------------------------------------------
# hire/deliver reads: hidden components refused like writes; legible errors.
# ---------------------------------------------------------------------------


def secrets_in_the_project(root: Path) -> None:
    """Hidden files a model-chosen input_path must never send to a counterparty."""
    for name in (".env", ".ssh/id_rsa", ".aws/credentials", "docs/.hidden/notes.txt"):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(b"SECRET\n")
    (root / "creds").symlink_to(root / ".aws" / "credentials")


READ_REFUSED: dict[str, Callable[[Path], str]] = {
    "dotenv": lambda root: ".env",
    "ssh-key": lambda root: ".ssh/id_rsa",
    "aws-credentials": lambda root: ".aws/credentials",
    "nested-hidden": lambda root: "docs/.hidden/notes.txt",
    "dotdot-staying-inside": lambda root: "docs/../input.txt",
    "absolute-hidden": lambda root: str(root / ".env"),
    "symlink-to-hidden": lambda root: "creds",
}


@pytest.mark.parametrize("case", sorted(READ_REFUSED))
@pytest.mark.parametrize("tool", ["hire", "deliver"])
def test_reads_refuse_hidden_components_before_any_network_call(
    tool: str, case: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets_in_the_project(root)
    kit = stopping_kit(tmp_path)
    use_kit(monkeypatch, kit)
    with pytest.raises(lhub.KitError, match=re.escape(HIDDEN)) as refused:
        call_file_tool(tool, READ_REFUSED[case](root))
    assert not isinstance(refused.value, StopFlow)
    assert kit.tool_calls == []  # nothing read, nothing uploaded
    label = "input_path" if tool == "hire" else "file_path"
    assert str(refused.value).startswith(f"{label} ")


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("missing.txt", "cannot be read: No such file or directory"),
        ("docs", "cannot be read: Is a directory"),
        ("a\x00b.txt", UNRESOLVABLE),
        ("loop/x.txt", UNRESOLVABLE),
        ("../outside/victim.txt", OUTSIDE),
    ],
    ids=["missing", "directory", "nul-byte", "symlink-loop", "outside"],
)
@pytest.mark.parametrize("tool", ["hire", "deliver"])
def test_read_failures_are_kit_errors_before_any_network_call(
    tool: str, path: str, reason: str, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside_dir(root)
    (root / "loop").symlink_to(root / "loop")
    kit = stopping_kit(tmp_path)
    use_kit(monkeypatch, kit)
    with pytest.raises(lhub.KitError, match=re.escape(reason)) as refused:
        call_file_tool(tool, path)
    assert not isinstance(refused.value, StopFlow)
    assert kit.tool_calls == []
    assert str(tmp_path) not in str(refused.value)


@pytest.mark.parametrize("path", ["a\x00b.txt", "loop/x.txt", "loop"])
def test_resolve_input_path_refuses_instead_of_crashing(path: str, root: Path) -> None:
    (root / "loop").symlink_to(root / "loop")
    with pytest.raises(lhub.KitError, match=re.escape(UNRESOLVABLE)):
        lhub.resolve_input_path(path, root)


@pytest.mark.parametrize("resolver", ["read", "write"])
def test_the_pinned_root_is_not_resolved_again(
    resolver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # At start the root is a real directory and is pinned as resolved. Later
    # its own path is swapped for a symlink to another tree: re-resolving the
    # root on each call would follow the swap and widen it to that tree.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "secret.txt").write_bytes(PRECIOUS)
    pinned = (tmp_path / "project").resolve()
    pinned.mkdir()
    monkeypatch.setattr(lhub, "_MCP_INPUT_ROOT", pinned)
    pinned.rmdir()
    pinned.symlink_to(elsewhere, target_is_directory=True)
    resolve = lhub.resolve_input_path if resolver == "read" else lhub.resolve_output_path
    with pytest.raises(lhub.KitError, match=re.escape(OUTSIDE)):
        resolve("secret.txt", lhub._input_root())


# ---------------------------------------------------------------------------
# Through the real MCP server (needs mcp), and the CLI control.
# ---------------------------------------------------------------------------


def test_the_server_returns_the_refusal_as_the_cli_json(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit = delivering_kit(tmp_path)
    use_kit(monkeypatch, kit)
    with pytest.raises(lhub.KitError) as refused:
        lhub.resolve_output_path("docs/claude.md", root)
    before = snapshot(tmp_path)

    is_error, text = server_call("get_result", {"deal_id": DEAL_ID, "out_path": "docs/claude.md"})

    assert is_error
    expected = lhub.json_text({"error": str(refused.value)})
    assert text == f"Error executing tool get_result: {expected}"
    assert kit.tool_calls == []
    assert snapshot(tmp_path) == before
    assert str(root) not in text


def test_the_server_writes_an_allowed_path(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_kit(monkeypatch, delivering_kit(tmp_path))
    is_error, text = server_call("get_result", {"deal_id": DEAL_ID, "out_path": "reviews/deal.md"})
    assert not is_error
    assert json.loads(text)["delivered"] is True
    assert (root / "reviews" / "deal.md").read_bytes() == DATA


def test_the_cli_result_out_stays_unconfined(
    tmp_path: Path,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Control: a human types the CLI's paths (D-1), so `result --out` may write
    # outside the input root, under a dot-directory and onto CLAUDE.md, as before.
    use_kit(monkeypatch, delivering_kit(tmp_path))
    for out in (tmp_path / ".elsewhere" / "review.md", root / "CLAUDE.md"):
        assert lhub.main(["result", "--deal", DEAL_ID, "--out", str(out)]) == 0
        assert json.loads(capsys.readouterr().out)["delivered"] is True
        assert out.read_bytes() == DATA
