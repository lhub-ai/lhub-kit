#!/usr/bin/env python3
"""Build lhub-kit's wheel and sdist for PyPI from the kit tree.

add-kit-pypi-package design D-2 (the packaging project), D-3 (build checks) and D-7 (the
version gate and the content checks, security N2). Run from anywhere; paths are taken from
this file's location:

    python3 pypi/build.py [--tag vX.Y.Z] [--out-dir DIR]

1. The version gate (D-7). The ``version = "..."`` line of ``pypi/pyproject.toml``,
   ``KIT_VERSION`` in ``lhub.py``, the ``version`` of ``server.json`` and the version of each
   of its packages must all be equal. With ``--tag``, the tag must also be ``v`` followed by
   that version. On any difference the script exits 1 before it stages, builds or creates
   anything, ``--out-dir`` included.
2. Staging (D-2). A directory made by ``tempfile.mkdtemp()``, outside the kit tree, receives
   ``lhub.py``, ``README.md``, ``LICENSE`` (only where the tree has one) and
   ``pypi/pyproject.toml`` as ``pyproject.toml``, each read once; those bytes are what the
   checks below compare against. ``uv build`` runs there: it builds the sdist, then the wheel
   from the sdist.
3. The checks (D-3, D-7). The member names first: the wheel holds ``lhub.py`` and its
   ``.dist-info`` metadata and nothing else, and the sdist exactly its ``only-include`` list
   (``LICENSE`` only where it was staged) plus ``PKG-INFO``. Then what is inside them:
   - ``lhub.py`` in both, the sdist's ``README.md`` and ``pyproject.toml``, and ``LICENSE``
     where staged (in the sdist, and in the wheel's ``.dist-info/licenses/``), byte-equal to
     the staged files;
   - the wheel's ``METADATA`` and the sdist's ``PKG-INFO``: ``Name`` is ``lhub-kit``,
     ``Version`` is the gated version, ``Requires-Dist`` is exactly D-2's two requirements,
     and the description is the staged ``README.md``;
   - ``entry_points.txt``: exactly the two console scripts;
   - ``RECORD``: exactly the wheel's members, each other entry with its sha256 and size.
4. Only then are the wheel and the sdist copied into ``--out-dir`` (default ``dist/`` at the
   kit root), which must be absent or empty, and listed with their sizes, sha256 and members.
   The staging directory is removed either way.

Standard library only, on Python 3.10 or later. The publish workflow runs this script with
the runner's own ``python3.12``, which has none of the kit's dependencies, and ``tomllib`` is
3.11+, so the versions are read with regular expressions. ``tests/test_distribution.py``
loads this file by path for ``version_gate``, ``wheel_problems`` and ``sdist_problems``.
"""

from __future__ import annotations

import argparse
import base64
import csv
import email
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Mapping
from pathlib import Path

KIT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = KIT_ROOT / "dist"

PROJECT_NAME = "lhub-kit"
# The project name as distribution file names spell it (lhub-kit normalized).
DIST_NAME = "lhub_kit"
MODULE = "lhub.py"
README = "README.md"
LICENSE = "LICENSE"
PYPROJECT = "pypi/pyproject.toml"
SERVER_JSON = "server.json"
# D-2: the sdist's only-include list. hatchling adds PKG-INFO.
SDIST_INCLUDE = ("lhub.py", "README.md", "LICENSE", "pyproject.toml")
# The metadata hatchling 1.33.0 (pinned in pypi/pyproject.toml) writes into the wheel's
# .dist-info, plus licenses/LICENSE when LICENSE was staged.
DIST_INFO_FILES = ("METADATA", "WHEEL", "RECORD", "entry_points.txt")
# D-2's dependencies. Requires-Dist must carry exactly these, compared by name and sorted
# specifiers, because hatchling writes "mcp<3,>=1.21.1" for "mcp>=1.21.1,<3".
REQUIRES_DIST = ("cryptography>=42", "mcp>=1.21.1,<3")
# D-1's console scripts: entry_points.txt must hold exactly these.
CONSOLE_SCRIPTS = {"lhub-kit": "lhub:main", "lhub": "lhub:main"}
# hatchling copies the first .gitignore or .hgignore it finds at or above the project root
# into the sdist (hatchling/builders/config.py, vcs_exclusion_files), whatever the
# ignore-vcs setting says.
VCS_IGNORE_FILES = (".gitignore", ".hgignore")

_KIT_VERSION_LINE = re.compile(r'^KIT_VERSION = "([^"\n]*)"[ \t]*$', re.MULTILINE)
_TABLE_HEADER = re.compile(r"^\[([^\[\]\n]+)\][ \t]*(?:#[^\n]*)?$", re.MULTILINE)
_VERSION_LINE = re.compile(r'^version = "([^"\n]*)"[ \t]*(?:#[^\n]*)?$', re.MULTILINE)
_REQUIREMENT = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)")


class BuildError(Exception):
    """A refusal. main() prints it and exits 1."""


def _read_text(kit_root: Path, relative: str) -> str:
    try:
        return (kit_root / relative).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BuildError(f"cannot read {relative}: {exc}") from exc


def kit_version(text: str) -> str:
    """``KIT_VERSION`` from the text of ``lhub.py``, which must assign it on exactly one line."""
    found = _KIT_VERSION_LINE.findall(text)
    if len(found) != 1:
        raise BuildError(f"{MODULE} has {len(found)} KIT_VERSION lines, not 1")
    return str(found[0])


def packaging_version(text: str) -> str:
    """The ``version = "..."`` line of the ``[project]`` table of ``pypi/pyproject.toml``."""
    headers = list(_TABLE_HEADER.finditer(text))
    bodies = [
        text[header.end() : headers[index + 1].start() if index + 1 < len(headers) else len(text)]
        for index, header in enumerate(headers)
        if header.group(1).strip() == "project"
    ]
    if len(bodies) != 1:
        raise BuildError(f"{PYPROJECT} has {len(bodies)} [project] tables, not 1")
    found = _VERSION_LINE.findall(bodies[0])
    if len(found) != 1:
        raise BuildError(
            f"the [project] table of {PYPROJECT} has {len(found)} version lines, not 1"
        )
    return str(found[0])


def server_versions(text: str) -> list[tuple[str, object]]:
    """``(where, version)`` for ``server.json``'s own version and each of its packages'."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise BuildError(f"{SERVER_JSON} is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BuildError(f"{SERVER_JSON} is not a JSON object")
    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        raise BuildError(f"{SERVER_JSON} lists no package")
    found: list[tuple[str, object]] = [(f"{SERVER_JSON} version", data.get("version"))]
    for index, package in enumerate(packages):
        version = package.get("version") if isinstance(package, dict) else None
        found.append((f"{SERVER_JSON} packages[{index}].version", version))
    return found


def version_gate(kit_root: Path, tag: str | None = None) -> list[str]:
    """Every disagreement among the release versions (D-7). An empty list passes the gate.

    The packaging version (``pypi/pyproject.toml``) is compared with ``KIT_VERSION``, with
    ``server.json``'s version and with each of its packages' versions, and, when ``tag`` is
    given, with the tag minus its leading ``v``. A file that is missing or cannot be parsed
    is reported too, so the gate fails closed.
    """
    try:
        expected = packaging_version(_read_text(kit_root, PYPROJECT))
        found: list[tuple[str, object]] = [
            (f"KIT_VERSION in {MODULE}", kit_version(_read_text(kit_root, MODULE))),
            *server_versions(_read_text(kit_root, SERVER_JSON)),
        ]
    except BuildError as exc:
        return [str(exc)]
    problems = [f"the {PYPROJECT} version is empty"] if not expected else []
    problems.extend(
        f"{where} is {value!r}, not the {PYPROJECT} version {expected!r}"
        for where, value in found
        if value != expected
    )
    if tag is not None and tag != f"v{expected}":
        problems.append(
            f"the tag {tag!r} is not 'v' followed by the {PYPROJECT} version {expected!r}"
        )
    return problems


def _names_problems(label: str, names: list[str], expected: set[str]) -> list[str]:
    """D-3: exactly the expected member names, each once."""
    problems: list[str] = []
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        problems.append(f"{label} holds duplicate entries {duplicates}")
    extra = sorted(set(names) - expected)
    if extra:
        problems.append(f"{label} holds {extra}, outside its expected contents {sorted(expected)}")
        if any(name.rpartition("/")[2] in VCS_IGNORE_FILES for name in extra):
            problems.append(
                "hatchling copied a VCS ignore file found above the staging directory into the"
                " sdist: point TMPDIR at a directory with no .gitignore or .hgignore above it"
            )
    missing = sorted(expected - set(names))
    if missing:
        problems.append(f"{label} lacks {missing}")
    return problems


def _bytes_problems(
    label: str, contents: Mapping[str, bytes], wanted: Mapping[str, bytes]
) -> list[str]:
    """Each member named in ``wanted`` that is present holds exactly those bytes."""
    return [
        f"{label}: {member} is not byte-identical to the staged {member.rpartition('/')[2]}"
        for member, data in wanted.items()
        if member in contents and contents[member] != data
    ]


def _requirement_key(text: str) -> tuple[str, tuple[str, ...]]:
    """A requirement as its normalized name and sorted specifiers.

    Extras or an environment marker stay in the specifiers, so they never match D-2's.
    """
    match = _REQUIREMENT.fullmatch(text.strip())
    if match is None:
        return text, ()
    name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
    specifiers = tuple(sorted(part.strip() for part in match.group(2).split(",") if part.strip()))
    return name, specifiers


def _metadata_problems(label: str, data: bytes, version: str, readme: bytes) -> list[str]:
    """``METADATA`` or ``PKG-INFO``: name, version, Requires-Dist and the description."""
    message = email.message_from_string(data.decode("utf-8", errors="replace"))
    problems: list[str] = []
    for field, wanted in (("Name", PROJECT_NAME), ("Version", version)):
        found = [str(value) for value in message.get_all(field) or []]
        if found != [wanted]:
            problems.append(f"{label} {field} is {found}, not [{wanted!r}]")
    requires = [str(value) for value in message.get_all("Requires-Dist") or []]
    if sorted(map(_requirement_key, requires)) != sorted(map(_requirement_key, REQUIRES_DIST)):
        problems.append(f"{label} Requires-Dist is {requires}, not exactly {list(REQUIRES_DIST)}")
    if message.get_payload() != readme.decode("utf-8", errors="replace"):
        problems.append(f"{label}: its description is not the staged {README}")
    return problems


def _entry_points(text: str) -> dict[str, dict[str, str]]:
    """``entry_points.txt`` as ``{section: {name: target}}``."""
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), {})
        elif line and not line.startswith(("#", ";")):
            name, _, target = line.partition("=")
            if current is None:
                current = sections.setdefault("", {})
            current[name.strip()] = target.strip()
    return sections


def _record_problems(
    label: str, record: bytes, contents: Mapping[str, bytes], name: str
) -> list[str]:
    """``RECORD``: exactly the members; each entry but its own with the sha256 and size."""
    problems: list[str] = []
    rows = [row for row in csv.reader(record.decode("utf-8", errors="replace").splitlines()) if row]
    listed = [row[0] for row in rows]
    if sorted(listed) != sorted(contents):
        problems.append(
            f"{label} RECORD lists {sorted(listed)}, not the members {sorted(contents)}"
        )
    for row in rows:
        if len(row) != 3:
            problems.append(f"{label} RECORD row {row} does not have 3 fields")
            continue
        path, digest, size = row
        if path == name:
            if digest or size:
                problems.append(f"{label} RECORD gives its own entry a hash or a size")
            continue
        data = contents.get(path)
        if data is None:
            continue  # reported above
        encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if digest != f"sha256={encoded}" or size != str(len(data)):
            problems.append(f"{label} RECORD's entry for {path} does not match its content")
    return problems


def wheel_problems(wheel: Path, version: str, staged: Mapping[str, bytes]) -> list[str]:
    """D-3 and N2 for the wheel; an empty list passes.

    ``staged`` maps each staged file name (``lhub.py``, ``README.md``, ``pyproject.toml`` and
    ``LICENSE`` when there is one) to its bytes. The wheel must hold ``lhub.py`` and its
    ``.dist-info`` metadata and nothing else, with the contents the module docstring lists.
    """
    dist_info = f"{DIST_NAME}-{version}.dist-info/"
    expected = {MODULE, *(dist_info + name for name in DIST_INFO_FILES)}
    wanted = {MODULE: staged[MODULE]}
    if LICENSE in staged:
        expected.add(f"{dist_info}licenses/{LICENSE}")
        wanted[f"{dist_info}licenses/{LICENSE}"] = staged[LICENSE]
    try:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            contents = {name: archive.read(name) for name in set(names)}
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"{wheel.name}: cannot read the wheel: {exc}"]
    label = wheel.name
    problems = _names_problems(label, names, expected)
    problems.extend(_bytes_problems(label, contents, wanted))
    metadata = contents.get(dist_info + "METADATA")
    if metadata is not None:
        problems.extend(_metadata_problems(f"{label} METADATA", metadata, version, staged[README]))
    entry_points = contents.get(dist_info + "entry_points.txt")
    if entry_points is not None:
        found = _entry_points(entry_points.decode("utf-8", errors="replace"))
        if found != {"console_scripts": CONSOLE_SCRIPTS}:
            problems.append(f"{label} entry_points.txt is {found}, not {CONSOLE_SCRIPTS} alone")
    record = contents.get(dist_info + "RECORD")
    if record is not None:
        problems.extend(_record_problems(label, record, contents, dist_info + "RECORD"))
    return problems


def sdist_problems(sdist: Path, version: str, staged: Mapping[str, bytes]) -> list[str]:
    """D-3 and N2 for the sdist; an empty list passes.

    ``staged`` is as for ``wheel_problems``. The sdist must hold exactly the staged files
    from its ``only-include`` list plus ``PKG-INFO``, regular files only, each staged file
    byte-equal, and ``PKG-INFO`` with the same metadata checks as the wheel's ``METADATA``.
    Nothing is extracted: member contents are read in memory.
    """
    root = f"{DIST_NAME}-{version}/"
    included = [name for name in SDIST_INCLUDE if name in staged]
    expected = {root + name for name in included}
    expected.add(f"{root}PKG-INFO")
    problems = [
        f"{sdist.name}: {name} was staged but is not in the sdist include list"
        for name in sorted(set(staged) - set(SDIST_INCLUDE))
    ]
    try:
        with tarfile.open(sdist, mode="r:gz") as archive:
            members = archive.getmembers()
            problems.extend(
                f"{sdist.name}: {member.name} is not a regular file"
                for member in members
                if not member.isfile()
            )
            names = [member.name for member in members]
            contents: dict[str, bytes] = {}
            for member in members:
                handle = archive.extractfile(member) if member.isfile() else None
                if handle is not None:
                    contents[member.name] = handle.read()
    except (OSError, tarfile.TarError) as exc:
        return [f"{sdist.name}: cannot read the sdist: {exc}"]
    problems.extend(_names_problems(sdist.name, names, expected))
    problems.extend(
        _bytes_problems(sdist.name, contents, {root + name: staged[name] for name in included})
    )
    pkg_info = contents.get(f"{root}PKG-INFO")
    if pkg_info is not None:
        problems.extend(
            _metadata_problems(f"{sdist.name} PKG-INFO", pkg_info, version, staged[README])
        )
    return problems


def _check_out_dir(out_dir: Path) -> None:
    if out_dir.exists() and not out_dir.is_dir():
        raise BuildError(f"--out-dir {out_dir} is not a directory")
    if out_dir.is_dir() and any(out_dir.iterdir()):
        raise BuildError(
            f"--out-dir {out_dir} is not empty: it must hold only this build's two files,"
            " so empty it or name another directory"
        )


def build(kit_root: Path, version: str, out_dir: Path) -> list[Path]:
    """Steps 2-4: stage, build, check, then copy the two checked files into ``out_dir``."""
    uv = shutil.which("uv")
    if uv is None:
        raise BuildError("uv is not on PATH")
    sources = {MODULE: MODULE, README: README, "pyproject.toml": PYPROJECT}
    if (kit_root / LICENSE).is_file():
        sources[LICENSE] = LICENSE
    staging = Path(tempfile.mkdtemp(prefix="lhub-kit-build-"))
    try:
        project = staging / "project"
        built = staging / "dist"
        project.mkdir()
        staged: dict[str, bytes] = {}
        for name, relative in sources.items():
            staged[name] = (kit_root / relative).read_bytes()
            (project / name).write_bytes(staged[name])
        print(f"staged {sorted(staged)} in {project}", flush=True)
        # S603: no shell. uv is the absolute path shutil.which returned; every other
        # argument is fixed here. --no-config keeps uv.toml files and [tool.uv] tables
        # (the user's or a parent directory's) out of the build.
        done = subprocess.run(  # noqa: S603
            [uv, "build", "--no-config", "--out-dir", str(built), str(project)], check=False
        )
        if done.returncode != 0:
            raise BuildError(f"uv build exited {done.returncode}")
        wheel = built / f"{DIST_NAME}-{version}-py3-none-any.whl"
        sdist = built / f"{DIST_NAME}-{version}.tar.gz"
        expected = sorted([wheel.name, sdist.name])
        # uv writes a .gitignore into a directory it creates; it is not an artifact.
        produced = sorted(path.name for path in built.iterdir() if path.name != ".gitignore")
        if produced != expected:
            raise BuildError(f"uv build produced {produced}, not {expected}")
        problems = [
            *wheel_problems(wheel, version, staged),
            *sdist_problems(sdist, version, staged),
        ]
        if problems:
            raise BuildError("; ".join(problems))
        out_dir.mkdir(parents=True, exist_ok=True)
        copied: list[Path] = []
        for artifact in (wheel, sdist):
            shutil.copyfile(artifact, out_dir / artifact.name)
            copied.append(out_dir / artifact.name)
        return copied
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def listing(artifacts: list[Path]) -> list[str]:
    """One line per artifact (path, size, sha256), then one line per member."""
    lines: list[str] = []
    for path in artifacts:
        data = path.read_bytes()
        lines.append(f"{path}  {len(data)} bytes  sha256 {hashlib.sha256(data).hexdigest()}")
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as wheel:
                lines.extend(f"    {info.filename}  {info.file_size}" for info in wheel.infolist())
        else:
            with tarfile.open(path, mode="r:gz") as sdist:
                lines.extend(f"    {member.name}  {member.size}" for member in sdist.getmembers())
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pypi/build.py",
        description="Build lhub-kit's wheel and sdist for PyPI. The version gate runs first.",
    )
    parser.add_argument(
        "--tag",
        default=None,
        help="the release tag, v<version>: the gate then also requires it to match",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help="where the checked wheel and sdist go, absent or empty (default: dist/ at the kit root)",
    )
    args = parser.parse_args(argv)
    tag: str | None = args.tag
    out_dir: Path = args.out_dir.resolve()

    problems = version_gate(KIT_ROOT, tag)
    if problems:
        for problem in problems:
            print(f"version gate: {problem}", file=sys.stderr)
        print("version gate: refused, so nothing was staged or built", file=sys.stderr)
        return 1
    try:
        version = packaging_version(_read_text(KIT_ROOT, PYPROJECT))
        checked = f"{version}, tag {tag}" if tag is not None else f"{version}, no tag"
        print(f"version gate: passed ({checked})", flush=True)
        _check_out_dir(out_dir)
        artifacts = build(KIT_ROOT, version, out_dir)
    except BuildError as exc:
        print(f"build: refused: {exc}", file=sys.stderr)
        return 1
    print(f"built lhub-kit {version}:")
    for line in listing(artifacts):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
