"""The PyPI package and its registry entry (add-kit-pypi-package design D-8).

The kit also ships to PyPI as ``lhub-kit``, built from a packaging project separate from the
dev harness: ``pypi/pyproject.toml``, built by ``pypi/build.py``. Its registry entry is
``server.json`` and its publish workflow ``.github/workflows/publish-pypi.yml``. This module
reads only files the public lhub-ai/lhub-kit export carries (``lhub.py``, ``README.md``,
``server.json``, ``pypi/`` and the workflow), so it runs in both trees.

Every check states its denominator, what it counted, and an empty denominator fails; a
control makes each zero-count branch fire (sdd NIT-6). Items 1-6 and 8 each have negative
controls: a copy of those files in ``tmp_path``, changed in one place, that the same check
must refuse for that reason.

1. The packaging version, ``KIT_VERSION`` and both ``server.json`` versions are equal.
2. ``server.json``'s name is the README's ``mcp-name:`` value, followed by a boundary the
   registry accepts (a port of its ``containsMCPNameToken``).
3. The package entry: its identifier is the packaging name, it is ``pypi`` over ``stdio``,
   and its positional ``mcp`` selects the ``mcp`` subcommand of ``build_parser()``.
4. Each environment variable is one of the kit's ``ENV_*`` names, ``LHUB_URL``'s default is
   the kit's default base URL, and none is secret or required.
5. The description fits the registry's 100 characters and names LHUB-DEV test credit
   (REG-1); the name matches the schema pattern.
6. The packaging metadata: both scripts run ``lhub:main``, the wheel includes only
   ``lhub.py``, the dependencies are exactly D-2's, the build backend is pinned exactly, and
   the summary carries the README's sandbox sentence (security N7).
7. The version gate (scenario "A mismatched tag does not publish"). ``build.py``'s gate
   passes the matching tag (the positive control) and refuses a different tag, packaging
   version, ``KIT_VERSION`` or ``server.json`` version (negative controls, each a changed
   copy). Job ``build`` runs only checkout, setup-uv and ``pypi/build.py`` (``--tag`` under
   the same tag-ref condition as job ``publish``), then the upload; job ``publish`` needs
   ``test`` and ``build``. A real ``build.py --tag v9.9.9`` process exits 1 and leaves no
   artifact and no staging directory.
8. Workflow hygiene (scenario "Uploads carry no token"): no ``secrets``, ``password`` or
   ``pull_request_target``, no ``${{`` inside a ``run:`` script, exactly three jobs (``test``,
   ``build``, ``publish``; security N4) with ``test`` and ``build`` setting up uv alike,
   ``id-token: write`` once and only in job ``publish``, which has ``environment: pypi`` and
   runs exactly the pinned download-artifact and gh-action-pypi-publish (security N5a), and
   every ``uses:`` pinned to a 40-hex commit with its tag in a comment.
9. The README. Each command in the "From PyPI" fenced blocks that starts with ``lhub``,
   ``lhub-kit`` or ``uvx lhub-kit`` parses under ``build_parser()`` once that prefix is
   stripped, and so does the client snippet's ``args``; the command line leads with
   ``uv tool install`` (security N6a). Controls: an unknown subcommand is refused, and at
   least two commands are found. Fixed markers pin the ``mcp-name`` line (the line after the
   title), the two REG-4 sentences (security N6b) and the sandbox line (security N7).
10. The build. ``build.py`` (``uv`` as a subprocess, outside the socket guard; it may fetch
    the pinned hatchling from the index or the cache) makes a wheel of exactly ``lhub.py``
    plus ``.dist-info`` and an sdist of exactly its include list plus ``PKG-INFO``, from the
    tree as it is and from a copy with ``LICENSE`` flipped (the monorepo has none, the public
    export has one). Skipped, with the reason, only when ``uv`` is not on PATH or the backend
    cannot be fetched. ``build.py``'s own checks, member names and contents (METADATA,
    PKG-INFO, ``entry_points.txt``, RECORD and the staged files; security N2), also run on
    hand-made archives, each refusal with its control.

The workflow is read by ``_read_yaml``, a reader for the block-style YAML subset the file is
written in (the kit's lock has no YAML parser). It raises on anything outside that subset, so
a construct it would misread fails the test instead. ``pypi/build.py`` is loaded by path,
never imported as ``pypi.*``.
"""

from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import email
import hashlib
import importlib
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, NamedTuple, Protocol, cast

import pytest

import lhub

KIT_DIR = Path(__file__).resolve().parents[1]

# The files read here, relative to the kit root, as the public export carries them.
KIT_FILE = "lhub.py"
README = "README.md"
SERVER_JSON = "server.json"
PYPROJECT = "pypi/pyproject.toml"
BUILD_PY = "pypi/build.py"
WORKFLOW = ".github/workflows/publish-pypi.yml"
LICENSE = "LICENSE"
EXPORT_FILES = (KIT_FILE, README, SERVER_JSON, PYPROJECT, BUILD_PY, WORKFLOW)

# D-1, D-2 and D-5.
PACKAGE = "lhub-kit"
SERVER_NAME = "ai.lhub/lhub-kit"
MARKER_LINE = f"<!-- mcp-name: {SERVER_NAME} -->"
SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
DESCRIPTION_MAX = 100  # characters (the schema's maxLength)
# The schema's name pattern, ^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$, used with fullmatch: a JSON
# Schema "$" ends the input, while Python's "$" also matches before a final newline.
SERVER_NAME_PATTERN = re.compile(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+")
SCRIPTS = {"lhub-kit": "lhub:main", "lhub": "lhub:main"}
DEPENDENCIES = ["cryptography>=42", "mcp>=1.21.1,<3"]
BUILD_REQUIRES = ["hatchling==1.33.0"]
WHEEL_INCLUDE = ["lhub.py"]
SDIST_INCLUDE = ["lhub.py", "README.md", "LICENSE", "pyproject.toml"]
DIST_INFO_FILES = ("METADATA", "WHEEL", "RECORD", "entry_points.txt")
PACKAGING_PINS: dict[tuple[str, ...], object] = {
    ("project", "name"): PACKAGE,
    ("project", "scripts"): SCRIPTS,
    ("project", "dependencies"): DEPENDENCIES,
    ("project", "license"): "Apache-2.0",
    ("project", "readme"): "README.md",
    ("project", "requires-python"): ">=3.10",
    ("project", "urls"): {
        "Homepage": "https://lhub.ai",
        "Source": "https://github.com/lhub-ai/lhub-kit",
    },
    ("build-system", "requires"): BUILD_REQUIRES,
    ("build-system", "build-backend"): "hatchling.build",
    ("tool", "hatch", "build", "targets", "wheel", "only-include"): WHEEL_INCLUDE,
    ("tool", "hatch", "build", "targets", "sdist", "only-include"): SDIST_INCLUDE,
}
KIT_ENV_NAMES = frozenset(
    value
    for name, value in vars(lhub).items()
    if name.startswith("ENV_") and isinstance(value, str)
)
# D-4 and security N7: the README's sandbox sentence, whose words the PyPI summary repeats.
SANDBOX_LINE = (
    "The default marketplace, `https://lhub.ai`, currently runs as a **sandbox with a test"
    " currency, LHUB-DEV**. No real money is involved."
)
SUMMARY_WORDS = ("sandbox with a test currency, LHUB-DEV", "No real money is involved.")

# D-7: the workflow's triggers, the tag-ref condition shared by the tagged build step and job
# publish, and each job's steps, as the action a step runs (its pin dropped) or its script.
TRIGGERS = {"push": {"tags": ["v*"]}, "workflow_dispatch": None}
TAG_REF_IF = "startsWith(github.ref, 'refs/tags/v')"
NOT_TAG_REF_IF = "${{ !startsWith(github.ref, 'refs/tags/v') }}"
TEST_RUN = "uv run --frozen pytest -q"
TAG_BUILD_RUN = 'python3.12 pypi/build.py --tag "$GITHUB_REF_NAME"'
BUILD_RUN = "python3.12 pypi/build.py"
JOBS = ["build", "publish", "test"]  # sorted
TEST_STEPS = ["actions/checkout", "astral-sh/setup-uv", TEST_RUN]
BUILD_STEPS = [
    "actions/checkout",
    "astral-sh/setup-uv",
    TAG_BUILD_RUN,
    BUILD_RUN,
    "actions/upload-artifact",
]
PUBLISH_STEPS = ["actions/download-artifact", "pypa/gh-action-pypi-publish"]
USES_LINE = re.compile(r"^[ \t]*(?:- )?uses:[ \t]*(\S+)(.*)$", re.MULTILINE)
RUN_LINE = re.compile(r"^[ \t]*(?:- )?run:", re.MULTILINE)
PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}")
TAG_COMMENT = re.compile(r" # v[0-9]+(?:\.[0-9]+)*")


# ---------------------------------------------------------------------------
# Trees, copies and check results.
# ---------------------------------------------------------------------------


class Tree(NamedTuple):
    """A kit tree: the real one, or a copy of the export files in ``tmp_path``."""

    root: Path

    def path(self, relative: str) -> Path:
        return self.root / relative

    def text(self, relative: str) -> str:
        return self.path(relative).read_text(encoding="utf-8")


REAL = Tree(KIT_DIR)


def _copy(base: Path) -> Tree:
    """A copy of the export files (never LICENSE) under ``base``."""
    root = base / "kit"
    for relative in EXPORT_FILES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(KIT_DIR / relative, target)
    return Tree(root)


def _changed(base: Path, relative: str, change: Callable[[str], str]) -> Tree:
    """A copy of the export files in which ``change`` rewrote ``relative``."""
    tree = _copy(base)
    before = tree.text(relative)
    after = change(before)
    assert after != before, f"the negative control left {relative} unchanged"
    tree.path(relative).write_text(after, encoding="utf-8")
    return tree


def _replace(old: str, new: str) -> Callable[[str], str]:
    """A change that replaces the first ``old``, which must be present."""

    def change(text: str) -> str:
        assert old in text, f"the negative control's anchor {old!r} is missing"
        return text.replace(old, new, 1)

    return change


def _edit_json(edit: Callable[[dict[str, Any]], object]) -> Callable[[str], str]:
    """A change that applies ``edit`` to the parsed JSON object and writes it back."""

    def change(text: str) -> str:
        data = json.loads(text)
        assert isinstance(data, dict)
        edit(data)
        return json.dumps(data, indent=2) + "\n"

    return change


class Checked(NamedTuple):
    """One check's outcome: what it counted (its denominator) and what it found wrong."""

    counted: int
    unit: str
    problems: list[str]


def _checked(counted: int, unit: str, problems: list[str]) -> Checked:
    if counted == 0:
        problems = [f"nothing to check: 0 {unit}", *problems]
    return Checked(counted, unit, problems)


def _assert_clean(result: Checked, count: int) -> None:
    assert not result.problems, f"checked {result.counted} {result.unit}: {result.problems}"
    assert result.counted == count, f"counted {result.counted} {result.unit}, not {count}"


def _assert_refused(result: Checked, reason: str) -> None:
    assert any(reason in problem for problem in result.problems), (
        f"the check ({result.counted} {result.unit}) did not refuse for {reason!r}:"
        f" {result.problems}"
    )


def _json_object(tree: Tree, relative: str) -> dict[str, Any]:
    data = json.loads(tree.text(relative))
    assert isinstance(data, dict), f"{relative} is not a JSON object"
    return data


def _packaging(tree: Tree) -> dict[str, Any]:
    """``pypi/pyproject.toml`` parsed by a TOML parser (``build.py`` reads it by regex)."""
    # tomllib is 3.11+ and mypy reads this module as Python 3.10 (the dev config), so the
    # parser is looked up at run time: the standard library's, else the lock's tomli, which
    # is installed for Python < 3.11.
    try:
        toml = importlib.import_module("tomllib")
    except ModuleNotFoundError:
        toml = importlib.import_module("tomli")
    data = toml.loads(tree.text(PYPROJECT))
    assert isinstance(data, dict), f"{PYPROJECT} is not a TOML table"
    return data


def _get(data: object, *keys: str) -> object:
    """``data[k1][k2]...``, or None where a key is missing or a value is not an object."""
    node = data
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _packages(tree: Tree) -> list[Any]:
    return _list(_json_object(tree, SERVER_JSON).get("packages"))


def _parsed(argv: list[str]) -> argparse.Namespace | str:
    """The kit parser's namespace for ``argv``, or its usage error (nothing runs)."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            return lhub.build_parser().parse_args(argv)
        except SystemExit as exc:
            return f"exit {exc.code}: {stderr.getvalue().strip()}"


def _selects_mcp(argv: list[str]) -> str | None:
    """None when ``argv`` selects the kit's ``mcp`` subcommand, else why not."""
    parsed = _parsed(argv)
    if isinstance(parsed, str):
        return f"the kit's parser refuses {argv}: {parsed}"
    if getattr(parsed, "func", None) is not lhub.cmd_mcp:
        return f"{argv} does not select the kit's mcp subcommand"
    return None


# ---------------------------------------------------------------------------
# 1. The versions agree.
# ---------------------------------------------------------------------------


def kit_version_assigned(tree: Tree) -> object:
    """The value the tree's ``lhub.py`` assigns to ``KIT_VERSION``, read with ast."""
    values: list[object] = []
    for node in ast.parse(tree.text(KIT_FILE)).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if (
            isinstance(target, ast.Name)
            and target.id == "KIT_VERSION"
            and isinstance(node.value, ast.Constant)
        ):
            values.append(node.value.value)
    return values[0] if len(values) == 1 else None


def versions_check(tree: Tree) -> Checked:
    reference_key = f"{PYPROJECT} version"
    server = _json_object(tree, SERVER_JSON)
    versions: dict[str, object] = {
        reference_key: _get(_packaging(tree), "project", "version"),
        f"KIT_VERSION in {KIT_FILE}": kit_version_assigned(tree),
        f"{SERVER_JSON} version": server.get("version"),
    }
    packages = _list(server.get("packages"))
    for index, package in enumerate(packages):
        versions[f"{SERVER_JSON} packages[{index}].version"] = _get(package, "version")
    reference = versions[reference_key]
    problems: list[str] = []
    if not packages:
        problems.append(f"{SERVER_JSON} lists no package, so no package version is compared")
    if not isinstance(reference, str) or not reference:
        problems.append(f"the {reference_key} is {reference!r}")
    problems.extend(
        f"{where} is {value!r}, not the {reference_key} {reference!r}"
        for where, value in versions.items()
        if value != reference
    )
    return _checked(len(versions), "versions", problems)


def test_the_versions_agree() -> None:
    _assert_clean(versions_check(REAL), count=4)
    # The ast read is the imported value, so the check reads what the kit runs.
    assert kit_version_assigned(REAL) == lhub.KIT_VERSION


@pytest.mark.parametrize(
    ("relative", "change", "reason"),
    [
        pytest.param(
            PYPROJECT,
            _replace(f'version = "{lhub.KIT_VERSION}"', 'version = "9.9.9"'),
            "not the pypi/pyproject.toml version '9.9.9'",
            id="packaging-version",
        ),
        pytest.param(
            KIT_FILE,
            _replace(f'KIT_VERSION = "{lhub.KIT_VERSION}"', 'KIT_VERSION = "9.9.9"'),
            "KIT_VERSION in lhub.py is '9.9.9'",
            id="kit-version",
        ),
        pytest.param(
            SERVER_JSON,
            _edit_json(lambda data: data.update(version="9.9.9")),
            "server.json version is '9.9.9'",
            id="server-version",
        ),
        pytest.param(
            SERVER_JSON,
            _edit_json(lambda data: data["packages"][0].update(version="9.9.9")),
            "server.json packages[0].version is '9.9.9'",
            id="package-version",
        ),
        pytest.param(
            SERVER_JSON,
            _edit_json(lambda data: data.update(packages=[])),
            "lists no package",
            id="no-package",
        ),
    ],
)
def test_the_versions_check_refuses_a_difference(
    tmp_path: Path, relative: str, change: Callable[[str], str], reason: str
) -> None:
    _assert_refused(versions_check(_changed(tmp_path, relative, change)), reason)


# ---------------------------------------------------------------------------
# 2. The README's mcp-name marker names the server.
# ---------------------------------------------------------------------------

_SERVER_NAME_CHAR = re.compile(r"[A-Za-z0-9._/-]")


def registry_accepts(readme: str, server_name: str) -> bool:
    """The registry's ``containsMCPNameToken`` (internal/validators/registries/mcpname.go).

    ``mcp-name: <server name>`` must be followed by the end of the text, a character that
    cannot continue a server name, or a comment close (``-->`` or ``--!>``). Design Context
    states the same rule in prose: whitespace, a newline, a tag or ``-->``. The kit's marker
    ``<!-- mcp-name: ai.lhub/lhub-kit -->`` puts a space before ``-->``, which meets both.
    """
    token = f"mcp-name: {server_name}"
    start = readme.find(token)
    while start >= 0:
        rest = readme[start + len(token) :]
        if not rest or not _SERVER_NAME_CHAR.match(rest) or rest.startswith(("-->", "--!>")):
            return True
        start = readme.find(token, start + 1)
    return False


def marker_check(tree: Tree) -> Checked:
    readme = tree.text(README)
    name = _json_object(tree, SERVER_JSON).get("name")
    declared = re.findall(r"mcp-name: ([A-Za-z0-9._/-]*)", readme)
    problems: list[str] = []
    if len(declared) > 1:
        problems.append(f"the README declares {len(declared)} mcp-name values: {declared}")
    problems.extend(
        f"the README's mcp-name is {value!r}, not server.json's name {name!r}"
        for value in declared
        if value != name
    )
    if declared and not (isinstance(name, str) and registry_accepts(readme, name)):
        problems.append(f"'mcp-name: {name}' is not followed by a boundary the registry accepts")
    return _checked(len(declared), "mcp-name markers", problems)


def test_the_readme_marker_names_the_server() -> None:
    _assert_clean(marker_check(REAL), count=1)
    assert _json_object(REAL, SERVER_JSON)["name"] == SERVER_NAME


def test_the_registry_boundary_port_matches_its_rules() -> None:
    # The cases of the registry's own rule: end of text, a non-name character, a comment
    # close with or without a space; a longer name is only a prefix.
    accepted = ["mcp-name: a/b", "mcp-name: a/b\n", "<!-- mcp-name: a/b -->", "mcp-name: a/b-->"]
    refused = ["mcp-name: a/b-pro", "mcp-name: a/bc", "mcp-name: a/b.v2", "mcp-name: a/b/c"]
    assert [registry_accepts(text, "a/b") for text in accepted] == [True] * len(accepted)
    assert [registry_accepts(text, "a/b") for text in refused] == [False] * len(refused)
    assert registry_accepts("mcp-name: a/b-pro and mcp-name: a/b ", "a/b")


@pytest.mark.parametrize(
    ("relative", "change", "reason"),
    [
        pytest.param(
            README,
            _replace(MARKER_LINE, "<!-- mcp-name: ai.lhub/lhub-kitx -->"),
            "not followed by a boundary",
            id="glued-character",
        ),
        pytest.param(
            SERVER_JSON,
            _edit_json(lambda data: data.update(name="ai.lhub/other")),
            "not server.json's name 'ai.lhub/other'",
            id="other-name",
        ),
        pytest.param(
            README,
            _replace(MARKER_LINE + "\n", ""),
            "nothing to check: 0 mcp-name markers",
            id="no-marker",
        ),
        pytest.param(
            README,
            _replace("\n## Buy\n", f"\n{MARKER_LINE}\n\n## Buy\n"),
            "declares 2 mcp-name values",
            id="two-markers",
        ),
    ],
)
def test_the_marker_check_refuses_a_wrong_marker(
    tmp_path: Path, relative: str, change: Callable[[str], str], reason: str
) -> None:
    _assert_refused(marker_check(_changed(tmp_path, relative, change)), reason)


# ---------------------------------------------------------------------------
# 3. The package entry.
# ---------------------------------------------------------------------------


def package_check(tree: Tree) -> Checked:
    packages = _packages(tree)
    name = _get(_packaging(tree), "project", "name")
    problems = [] if len(packages) == 1 else [f"server.json lists {len(packages)} packages, not 1"]
    for index, package in enumerate(packages):
        where = f"packages[{index}]"
        identifier = _get(package, "identifier")
        if identifier != name:
            problems.append(
                f"{where}.identifier is {identifier!r}, not the packaging name {name!r}"
            )
        if _get(package, "registryType") != "pypi":
            problems.append(
                f"{where}.registryType is {_get(package, 'registryType')!r}, not 'pypi'"
            )
        if _get(package, "transport") != {"type": "stdio"}:
            problems.append(f"{where}.transport is {_get(package, 'transport')!r}, not stdio")
        if _get(package, "runtimeHint") != "uvx":
            problems.append(f"{where}.runtimeHint is {_get(package, 'runtimeHint')!r}, not 'uvx'")
        arguments = _list(_get(package, "packageArguments"))
        if [_get(argument, "type") for argument in arguments] != ["positional"]:
            problems.append(f"{where}.packageArguments is {arguments!r}, not one positional")
        argv = [str(_get(argument, "value")) for argument in arguments]
        reason = _selects_mcp(argv)
        if reason is not None:
            problems.append(f"{where}.packageArguments: {reason}")
    return _checked(len(packages), "packages", problems)


def test_the_package_entry_runs_the_kit_mcp_server() -> None:
    _assert_clean(package_check(REAL), count=1)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(
            _edit_json(lambda data: data["packages"][0].update(identifier="lhub_kit")),
            "not the packaging name 'lhub-kit'",
            id="identifier",
        ),
        pytest.param(
            _edit_json(lambda data: data["packages"][0].update(registryType="npm")),
            "registryType is 'npm'",
            id="registry-type",
        ),
        pytest.param(
            _edit_json(lambda data: data["packages"][0].update(transport={"type": "sse"})),
            "not stdio",
            id="transport",
        ),
        pytest.param(
            _edit_json(
                lambda data: data["packages"][0].update(
                    packageArguments=[{"type": "positional", "value": "serve-mcp"}]
                )
            ),
            "the kit's parser refuses ['serve-mcp']",
            id="not-a-subcommand",
        ),
        pytest.param(
            _edit_json(
                lambda data: data["packages"][0].update(
                    packageArguments=[{"type": "positional", "value": "find"}]
                )
            ),
            "does not select the kit's mcp subcommand",
            id="another-subcommand",
        ),
        pytest.param(
            _edit_json(lambda data: data.update(packages=[])),
            "nothing to check: 0 packages",
            id="no-package",
        ),
    ],
)
def test_the_package_check_refuses_a_wrong_entry(
    tmp_path: Path, change: Callable[[str], str], reason: str
) -> None:
    _assert_refused(package_check(_changed(tmp_path, SERVER_JSON, change)), reason)


# ---------------------------------------------------------------------------
# 4. The environment variables.
# ---------------------------------------------------------------------------


def env_check(tree: Tree) -> Checked:
    variables = [
        variable
        for package in _packages(tree)
        for variable in _list(_get(package, "environmentVariables"))
    ]
    names = [_get(variable, "name") for variable in variables]
    problems: list[str] = []
    if not KIT_ENV_NAMES:
        problems.append("the kit defines no ENV_* names")
    for variable in variables:
        name = _get(variable, "name")
        if name not in KIT_ENV_NAMES:
            problems.append(f"{name!r} is not one of the kit's ENV_* names {sorted(KIT_ENV_NAMES)}")
        if _get(variable, "isSecret") not in (None, False):
            problems.append(f"{name} is marked secret")
        if _get(variable, "isRequired") is not False:
            problems.append(f"{name} is not marked isRequired false, but the kit runs without it")
        description = _get(variable, "description")
        if not isinstance(description, str) or not description.strip():
            problems.append(f"{name} has no description")
        if name == lhub.ENV_BASE_URL and _get(variable, "default") != lhub.DEFAULT_BASE_URL:
            problems.append(
                f"{name}'s default is {_get(variable, 'default')!r}, not the kit's"
                f" {lhub.DEFAULT_BASE_URL!r}"
            )
    duplicates = sorted({str(name) for name in names if names.count(name) > 1})
    if duplicates:
        problems.append(f"listed more than once: {duplicates}")
    if lhub.ENV_BASE_URL not in names:
        problems.append(f"{lhub.ENV_BASE_URL} is not listed, so its default is unchecked")
    return _checked(len(variables), "environment variables", problems)


def test_the_environment_variables_are_the_kits() -> None:
    _assert_clean(env_check(REAL), count=3)


def _add_variable(variable: dict[str, Any]) -> Callable[[dict[str, Any]], object]:
    return lambda data: data["packages"][0]["environmentVariables"].append(variable)


def _set_on_variable(name: str, **fields: object) -> Callable[[dict[str, Any]], object]:
    def edit(data: dict[str, Any]) -> None:
        for variable in data["packages"][0]["environmentVariables"]:
            if variable["name"] == name:
                variable.update(fields)

    return edit


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(
            _edit_json(
                _add_variable({"name": "LHUB_TOKEN", "description": "x", "isRequired": False})
            ),
            "'LHUB_TOKEN' is not one of the kit's ENV_* names",
            id="unknown-name",
        ),
        pytest.param(
            _edit_json(_set_on_variable("LHUB_URL", default="https://example.com")),
            "LHUB_URL's default is 'https://example.com'",
            id="other-default",
        ),
        pytest.param(
            _edit_json(_set_on_variable("LHUB_KIT_HOME", isSecret=True)),
            "LHUB_KIT_HOME is marked secret",
            id="secret",
        ),
        pytest.param(
            _edit_json(_set_on_variable("LHUB_KIT_INPUT_ROOT", isRequired=True)),
            "LHUB_KIT_INPUT_ROOT is not marked isRequired false",
            id="required",
        ),
        pytest.param(
            _edit_json(lambda data: data["packages"][0].update(environmentVariables=[])),
            "nothing to check: 0 environment variables",
            id="none",
        ),
    ],
)
def test_the_environment_check_refuses_a_wrong_variable(
    tmp_path: Path, change: Callable[[str], str], reason: str
) -> None:
    _assert_refused(env_check(_changed(tmp_path, SERVER_JSON, change)), reason)


# ---------------------------------------------------------------------------
# 5. The description and the name.
# ---------------------------------------------------------------------------


def description_check(tree: Tree) -> Checked:
    server = _json_object(tree, SERVER_JSON)
    fields = {key: server.get(key) for key in ("name", "description", "title")}
    present = [value for value in fields.values() if isinstance(value, str)]
    problems: list[str] = []
    description = fields["description"]
    if not isinstance(description, str) or not 1 <= len(description) <= DESCRIPTION_MAX:
        length = len(description) if isinstance(description, str) else None
        problems.append(f"the description is {length} characters, not 1 to {DESCRIPTION_MAX}")
    title = fields["title"]
    if title is not None and not (isinstance(title, str) and 1 <= len(title) <= DESCRIPTION_MAX):
        problems.append(f"the title {title!r} is not 1 to {DESCRIPTION_MAX} characters")
    name = fields["name"]
    if not (
        isinstance(name, str)
        and 3 <= len(name) <= 200
        and SERVER_NAME_PATTERN.fullmatch(name) is not None
    ):
        problems.append(f"the name {name!r} does not match the schema pattern")
    if not any(
        isinstance(text, str) and "LHUB-DEV test credit" in text for text in (description, title)
    ):
        problems.append("neither the description nor the title names LHUB-DEV test credit")
    if server.get("$schema") != SCHEMA_URL:
        problems.append(f"$schema is {server.get('$schema')!r}, not {SCHEMA_URL!r}")
    return _checked(len(present), "name, description and title fields", problems)


def test_the_description_and_name_fit_the_registry() -> None:
    _assert_clean(description_check(REAL), count=3)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(
            _edit_json(
                lambda data: data.update(
                    description=data["description"]
                    + "x" * (DESCRIPTION_MAX + 1 - len(data["description"]))
                )
            ),
            f"the description is {DESCRIPTION_MAX + 1} characters",
            id="description-101",
        ),
        pytest.param(
            _edit_json(lambda data: data.update(name="ai.lhub/lhub kit")),
            "does not match the schema pattern",
            id="name-space",
        ),
        pytest.param(
            _edit_json(lambda data: data.update(name="ai.lhub/lhub/kit")),
            "does not match the schema pattern",
            id="name-two-slashes",
        ),
        pytest.param(
            _edit_json(
                lambda data: data.update(
                    description=data["description"].replace("LHUB-DEV", "sandbox")
                )
            ),
            "names LHUB-DEV test credit",
            id="no-lhub-dev",
        ),
        pytest.param(
            _edit_json(lambda data: [data.pop(key) for key in ("name", "description", "title")]),
            "nothing to check: 0 name, description and title fields",
            id="no-fields",
        ),
    ],
)
def test_the_description_check_refuses_what_the_registry_would(
    tmp_path: Path, change: Callable[[str], str], reason: str
) -> None:
    _assert_refused(description_check(_changed(tmp_path, SERVER_JSON, change)), reason)


# ---------------------------------------------------------------------------
# 6. The packaging metadata.
# ---------------------------------------------------------------------------


def packaging_check(tree: Tree) -> Checked:
    data = _packaging(tree)
    problems = [
        f"{'.'.join(keys)} is {_get(data, *keys)!r}, not {wanted!r}"
        for keys, wanted in PACKAGING_PINS.items()
        if _get(data, *keys) != wanted
    ]
    classifiers = [str(item) for item in _list(_get(data, "project", "classifiers"))]
    licenses = [item for item in classifiers if item.startswith("License ::")]
    if licenses:
        problems.append(f"License classifiers {licenses} beside the PEP 639 license expression")
    summary = _get(data, "project", "description")
    absent = [
        words for words in SUMMARY_WORDS if not (isinstance(summary, str) and words in summary)
    ]
    if absent:
        problems.append(f"the summary {summary!r} lacks the README's sandbox words {absent}")
    for target in sorted(set(SCRIPTS.values())):
        module, _, attribute = target.partition(":")
        if module != "lhub" or not callable(getattr(lhub, attribute, None)):
            problems.append(f"the script target {target} is not a function of the kit")
    return _checked(len(PACKAGING_PINS), "pinned metadata fields", problems)


def test_the_packaging_metadata_is_d2s() -> None:
    _assert_clean(packaging_check(REAL), count=len(PACKAGING_PINS))


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(
            _replace('\nlhub = "lhub:main"', '\nlhub = "lhub:cli"'),
            "project.scripts is",
            id="script-target",
        ),
        pytest.param(
            _replace('only-include = ["lhub.py"]', 'only-include = ["lhub.py", "tests"]'),
            "tool.hatch.build.targets.wheel.only-include is",
            id="wheel-include",
        ),
        pytest.param(
            _replace('"mcp>=1.21.1,<3",', '"mcp>=1.21.1,<3",\n    "httpx",'),
            "project.dependencies is",
            id="extra-dependency",
        ),
        pytest.param(
            _replace('"mcp>=1.21.1,<3",', '"mcp>=1.2",'),
            "project.dependencies is",
            id="dependency-specifier",
        ),
        pytest.param(
            _replace('requires = ["hatchling==1.33.0"]', 'requires = ["hatchling>=1.27"]'),
            "build-system.requires is",
            id="backend-unpinned",
        ),
        pytest.param(
            _replace(
                '"Programming Language :: Python :: 3 :: Only",',
                '"Programming Language :: Python :: 3 :: Only",\n'
                '    "License :: OSI Approved :: Apache Software License",',
            ),
            "License classifiers",
            id="license-classifier",
        ),
        pytest.param(
            _replace("currently runs as a sandbox with a test currency", "runs a marketplace"),
            "lacks the README's sandbox words",
            id="summary-without-sandbox",
        ),
    ],
)
def test_the_packaging_check_refuses_other_metadata(
    tmp_path: Path, change: Callable[[str], str], reason: str
) -> None:
    _assert_refused(packaging_check(_changed(tmp_path, PYPROJECT, change)), reason)


# ---------------------------------------------------------------------------
# The YAML subset reader the workflow checks use.
# ---------------------------------------------------------------------------


class _YamlError(ValueError):
    """The text left the YAML subset _read_yaml reads."""


_YAML_KEY = re.compile(r"([A-Za-z0-9_][A-Za-z0-9_.-]*):(?: +(.*))?$")
# Characters that open a construct outside the subset, and a block sequence item.
_YAML_REFUSED_START = (*"{[&*!|>%@`?,", "- ")
# A flow sequence item the subset reads: a bare identifier, as in "needs: [test, build]".
_YAML_FLOW_ITEM = re.compile(r"[A-Za-z0-9_.-]+")


def _quoted_end(text: str) -> int:
    """The index of the quote that closes the scalar opening ``text``."""
    quote, index = text[0], 1
    while index < len(text):
        if text[index] == quote:
            if quote == "'" and text[index + 1 : index + 2] == "'":
                index += 2
                continue
            return index
        if quote == '"' and text[index] == "\\":
            raise _YamlError(f"an escape in a double-quoted scalar: {text!r}")
        index += 1
    raise _YamlError(f"an unterminated quoted scalar: {text!r}")


def _uncomment(text: str) -> str:
    """``text`` without its trailing comment (a ``#`` first or after a space)."""
    text = text.strip()
    if text.startswith("#"):
        return ""
    if text[:1] in ("'", '"'):
        end = _quoted_end(text)
        rest = text[end + 1 :].strip()
        if rest and not rest.startswith("#"):
            raise _YamlError(f"text after a quoted scalar: {text!r}")
        return text[: end + 1]
    cut = text.find(" #")
    return text if cut < 0 else text[:cut].rstrip()


def _scalar(text: str) -> object:
    if text[:1] == "'":
        return text[1:-1].replace("''", "'")
    if text[:1] == '"':
        return text[1:-1]
    if text in ("{}", "[]"):
        return {} if text == "{}" else []
    if text.startswith("[") and text.endswith("]"):
        items = [item.strip() for item in text[1:-1].split(",")]
        if not all(_YAML_FLOW_ITEM.fullmatch(item) for item in items):
            raise _YamlError(f"a flow sequence outside the subset: {text!r}")
        return items
    if text.startswith(_YAML_REFUSED_START) or ": " in text or text.endswith(":"):
        raise _YamlError(f"a scalar outside the subset: {text!r}")
    return text


class _YamlReader:
    def __init__(self, text: str) -> None:
        self.lines = text.split("\n")
        self.pos = 0

    def fail(self, message: str) -> _YamlError:
        return _YamlError(f"line {self.pos + 1}: {message}")

    def peek(self) -> int | None:
        """The indentation of the next content line (blank and comment lines skipped)."""
        while self.pos < len(self.lines):
            body = self.lines[self.pos].lstrip(" ")
            if body and not body.startswith("#"):
                return len(self.lines[self.pos]) - len(body)
            self.pos += 1
        return None

    def mapping(self, indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while (current := self.peek()) is not None and current >= indent:
            if current > indent:
                raise self.fail("unexpected indentation")
            body = self.lines[self.pos][indent:]
            if body == "-" or body.startswith("- "):
                raise self.fail("a sequence item where a key was expected")
            match = _YAML_KEY.match(body)
            if match is None:
                raise self.fail(f"not a 'key: value' line: {body!r}")
            key = match.group(1)
            if key in result:
                raise self.fail(f"a duplicate key {key!r}")
            self.pos += 1
            result[key] = self.value(_uncomment(match.group(2) or ""), indent)
        return result

    def value(self, rest: str, indent: int) -> object:
        """The value of a key at ``indent`` whose line ends with ``rest``."""
        if rest == "|":
            return self.literal(indent)
        if rest:
            return _scalar(rest)
        current = self.peek()
        if current is None or current <= indent:
            return None
        body = self.lines[self.pos][current:]
        if body == "-" or body.startswith("- "):
            return self.sequence(current)
        return self.mapping(current)

    def sequence(self, indent: int) -> list[object]:
        items: list[object] = []
        while (current := self.peek()) is not None and current >= indent:
            if current > indent:
                raise self.fail("unexpected indentation")
            body = self.lines[self.pos][indent:]
            if not body.startswith("- "):
                raise self.fail("a key where a sequence item was expected")
            item = body[2:]
            if _YAML_KEY.match(item):
                # "- key: value" opens a mapping whose keys sit two columns right of the dash.
                self.lines[self.pos] = " " * (indent + 2) + item
                items.append(self.mapping(indent + 2))
            else:
                self.pos += 1
                items.append(_scalar(_uncomment(item)))
        return items

    def literal(self, indent: int) -> str:
        """A ``|`` block: the lines indented deeper than its key, blank lines kept."""
        lines: list[str] = []
        block_indent: int | None = None
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.strip():
                current = len(line) - len(line.lstrip(" "))
                if current <= indent:
                    break
                if block_indent is None:
                    block_indent = current
                elif current < block_indent:
                    raise self.fail("a literal line indented less than the block's first line")
                lines.append(line[block_indent:])
            else:
                lines.append("")
            self.pos += 1
        if block_indent is None:
            raise self.fail("an empty literal block")
        while lines and not lines[-1]:
            lines.pop()
        return "\n".join(lines) + "\n"


def _read_yaml(text: str) -> dict[str, Any]:
    """Read the block-style YAML subset the workflow is written in.

    Read: block mappings, block sequences indented under their key, plain and quoted
    scalars (kept as strings; an empty value is None), ``{}``, ``[]`` and flow sequences of
    bare identifiers (``[test, build]``), ``|`` literal blocks, and comments. Anything else
    (other flow collections, anchors, aliases, tags, folded or chomped blocks, tabs,
    duplicate keys, document markers, escapes) raises _YamlError.
    """
    if "\t" in text:
        raise _YamlError("a tab character")
    reader = _YamlReader(text)
    if reader.peek() != 0:
        raise reader.fail("the document does not start at column 0")
    return reader.mapping(0)


def test_the_yaml_reader_reads_its_subset() -> None:
    pin = "0" * 40
    text = (
        "# a comment\n"
        "name: x  # trailing comment\n"
        "on:\n"
        "  push:\n"
        "    tags:\n"
        '      - "v*"\n'
        "  workflow_dispatch:\n"
        "permissions: {}\n"
        "jobs:\n"
        "  j:\n"
        "    needs: [a, b-c]\n"
        "    if: ${{ !startsWith(github.ref, 'refs/tags/v') }}\n"
        "    steps:\n"
        f"      - uses: a/b@{pin} # v1\n"
        "        with:\n"
        "          k: 'it''s'\n"
        "      - run: |\n"
        "          echo one\n"
        "\n"
        "          # a shell comment\n"
        "          echo two\n"
        "      - run: echo three\n"
    )
    assert _read_yaml(text) == {
        "name": "x",
        "on": {"push": {"tags": ["v*"]}, "workflow_dispatch": None},
        "permissions": {},
        "jobs": {
            "j": {
                "needs": ["a", "b-c"],
                "if": "${{ !startsWith(github.ref, 'refs/tags/v') }}",
                "steps": [
                    {"uses": f"a/b@{pin}", "with": {"k": "it's"}},
                    {"run": "echo one\n\n# a shell comment\necho two\n"},
                    {"run": "echo three"},
                ],
            }
        },
    }


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("a: {b: 1}\n", id="flow-mapping"),
        pytest.param('a: [b, "c"]\n', id="flow-sequence-quoted-item"),
        pytest.param("a: [b, [c]]\n", id="flow-sequence-nested"),
        pytest.param("a: [b, ]\n", id="flow-sequence-empty-item"),
        pytest.param("a: &x 1\n", id="anchor"),
        pytest.param("a: *x\n", id="alias"),
        pytest.param("a: !tag 1\n", id="tag"),
        pytest.param("a: >\n  folded\n", id="folded"),
        pytest.param("a: |-\n  chomped\n", id="chomped"),
        pytest.param("a: 1\na: 2\n", id="duplicate-key"),
        pytest.param("a:\n\tb: 1\n", id="tab"),
        pytest.param("a:\n- 1\n", id="sequence-at-key-column"),
        pytest.param("---\na: 1\n", id="document-marker"),
        pytest.param('a: "x\\"y"\n', id="escape"),
        pytest.param("a: b: c\n", id="colon-in-plain-scalar"),
        pytest.param("  a: 1\n", id="indented-document"),
        pytest.param("a:\n  b: 1\n    c: 2\n", id="over-indented"),
    ],
)
def test_the_yaml_reader_refuses_what_it_cannot_read(text: str) -> None:
    with pytest.raises(_YamlError):
        _read_yaml(text)


def _job(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    job = _get(workflow, "jobs", name)
    return job if isinstance(job, dict) else {}


def _steps(workflow: dict[str, Any], job: str) -> list[dict[str, Any]]:
    return [step for step in _list(_get(workflow, "jobs", job, "steps")) if isinstance(step, dict)]


def _step_kind(step: dict[str, Any]) -> str:
    """A step as the action it runs (its pin dropped) or the script it runs."""
    if "uses" in step:
        return str(step["uses"]).partition("@")[0]
    return str(step.get("run", "")).strip()


def _needs_problems(workflow: dict[str, Any]) -> list[str]:
    """Job publish needs both test and build (security N4)."""
    needs = _job(workflow, "publish").get("needs")
    if isinstance(needs, list) and sorted(needs) == ["build", "test"]:
        return []
    return [f"job publish needs {needs!r}, not both test and build"]


# ---------------------------------------------------------------------------
# 7. The version gate.
# ---------------------------------------------------------------------------


class _Build(Protocol):
    """What this module uses of ``pypi/build.py``."""

    KIT_ROOT: Path

    def version_gate(self, kit_root: Path, tag: str | None = None) -> list[str]: ...

    def wheel_problems(
        self, wheel: Path, version: str, staged: Mapping[str, bytes]
    ) -> list[str]: ...

    def sdist_problems(
        self, sdist: Path, version: str, staged: Mapping[str, bytes]
    ) -> list[str]: ...


def _load_build() -> _Build:
    # Loaded from its path, never put in sys.modules (scripts/canary/test_canary_house.py).
    spec = importlib.util.spec_from_file_location(
        "lhub_kit_pypi_build_under_test", KIT_DIR / BUILD_PY
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {BUILD_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(_Build, module)


BUILD = _load_build()


def test_the_gate_passes_the_matching_tag() -> None:
    # The positive control: the real tree, with and without the release tag.
    assert BUILD.version_gate(KIT_DIR, f"v{lhub.KIT_VERSION}") == []
    assert BUILD.version_gate(KIT_DIR) == []
    assert BUILD.KIT_ROOT == KIT_DIR


@pytest.mark.parametrize(
    "tag",
    [
        pytest.param("v9.9.9", id="other-version"),
        pytest.param(lhub.KIT_VERSION, id="no-v"),
        pytest.param(f"v{lhub.KIT_VERSION}.1", id="longer"),
        pytest.param(f"V{lhub.KIT_VERSION}", id="capital-v"),
        pytest.param("", id="empty"),
    ],
)
def test_the_gate_refuses_a_tag_that_differs(tag: str) -> None:
    problems = BUILD.version_gate(KIT_DIR, tag)
    assert any(f"the tag {tag!r}" in problem for problem in problems), problems


@pytest.mark.parametrize(
    ("relative", "change", "reason"),
    [
        pytest.param(
            PYPROJECT,
            _replace(f'version = "{lhub.KIT_VERSION}"', 'version = "9.9.9"'),
            "not the pypi/pyproject.toml version '9.9.9'",
            id="packaging-version",
        ),
        pytest.param(
            KIT_FILE,
            _replace(f'KIT_VERSION = "{lhub.KIT_VERSION}"', 'KIT_VERSION = "9.9.9"'),
            "KIT_VERSION in lhub.py is '9.9.9'",
            id="kit-version",
        ),
        pytest.param(
            SERVER_JSON,
            _edit_json(lambda data: data.update(version="9.9.9")),
            "server.json version is '9.9.9'",
            id="server-version",
        ),
        pytest.param(
            SERVER_JSON,
            _edit_json(lambda data: data["packages"][0].update(version="9.9.9")),
            "server.json packages[0].version is '9.9.9'",
            id="package-version",
        ),
    ],
)
def test_the_gate_refuses_a_version_that_differs(
    tmp_path: Path, relative: str, change: Callable[[str], str], reason: str
) -> None:
    tree = _changed(tmp_path, relative, change)
    for tag in (f"v{lhub.KIT_VERSION}", None):
        problems = BUILD.version_gate(tree.root, tag)
        assert any(reason in problem for problem in problems), (tag, problems)


def test_the_gate_fails_closed_on_a_missing_file(tmp_path: Path) -> None:
    tree = _copy(tmp_path)
    tree.path(SERVER_JSON).unlink()
    problems = BUILD.version_gate(tree.root, f"v{lhub.KIT_VERSION}")
    assert len(problems) == 1, problems
    assert problems[0].startswith("cannot read server.json:"), problems


def gate_wiring_check(tree: Tree) -> Checked:
    """Job build runs only checkout, setup-uv and the gated build.py (``--tag`` under the
    publish condition), then the upload; job publish needs test and build."""
    try:
        workflow = _read_yaml(tree.text(WORKFLOW))
    except _YamlError as exc:
        return _checked(0, "build-job steps", [f"the workflow is outside the YAML subset: {exc}"])
    steps = _steps(workflow, "build")
    kinds = [_step_kind(step) for step in steps]
    problems: list[str] = []
    if kinds != BUILD_STEPS:
        problems.append(f"job build runs {kinds}, not {BUILD_STEPS}")
    for script, wanted in ((TAG_BUILD_RUN, TAG_REF_IF), (BUILD_RUN, NOT_TAG_REF_IF)):
        conditions = [step.get("if") for step in steps if _step_kind(step) == script]
        if conditions != [wanted]:
            problems.append(f"the build step {script!r} runs under {conditions}, not [{wanted!r}]")
    problems.extend(_needs_problems(workflow))
    publish = _job(workflow, "publish")
    if publish.get("if") != TAG_REF_IF:
        problems.append(f"job publish's if is {publish.get('if')!r}, not {TAG_REF_IF!r}")
    return _checked(len(steps), "build-job steps", problems)


def test_the_workflow_gates_the_build_before_upload_and_publish() -> None:
    _assert_clean(gate_wiring_check(REAL), count=len(BUILD_STEPS))


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(
            _replace(f"run: {TAG_BUILD_RUN}", f"run: {BUILD_RUN}"),
            "job build runs",
            id="no-tag",
        ),
        pytest.param(
            _replace(
                "      - name: Version gate and build, tag\n",
                f"      - name: Test\n        run: {TEST_RUN}\n"
                "      - name: Version gate and build, tag\n",
            ),
            "job build runs",
            id="tests-in-build",
        ),
        pytest.param(
            _replace("    needs: [test, build]\n", ""),
            "job publish needs None",
            id="no-needs",
        ),
        pytest.param(
            _replace("    needs: [test, build]\n", "    needs: build\n"),
            "job publish needs 'build'",
            id="needs-build-only",
        ),
        pytest.param(
            _replace(f"    if: {TAG_REF_IF}\n    runs-on", "    if: always()\n    runs-on"),
            "job publish's if is 'always()'",
            id="publish-always",
        ),
        pytest.param(
            _replace(f"        if: {TAG_REF_IF}\n", "        if: github.event_name == 'push'\n"),
            f"the build step {TAG_BUILD_RUN!r} runs under",
            id="tag-step-condition",
        ),
    ],
)
def test_the_wiring_check_refuses_an_ungated_publish(
    tmp_path: Path, change: Callable[[str], str], reason: str
) -> None:
    _assert_refused(gate_wiring_check(_changed(tmp_path, WORKFLOW, change)), reason)


def test_a_mismatched_tag_exits_1_and_leaves_nothing(tmp_path: Path) -> None:
    out = tmp_path / "out"  # not created: the refused build must not create it either
    temp = tmp_path / "temp"
    temp.mkdir()
    env = {**os.environ, "TMPDIR": str(temp)}
    # The positive control for "no staging directory": the child's tempfile uses TMPDIR.
    probe = subprocess.run(
        [sys.executable, "-I", "-c", "import tempfile; print(tempfile.gettempdir())"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert Path(probe.stdout.strip()).resolve() == temp.resolve()
    done = subprocess.run(
        [sys.executable, "-I", str(KIT_DIR / BUILD_PY), "--tag", "v9.9.9", "--out-dir", str(out)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 1, (done.returncode, done.stdout, done.stderr)
    assert "version gate: the tag 'v9.9.9' is not 'v' followed by" in done.stderr
    assert "nothing was staged or built" in done.stderr
    assert done.stdout == ""
    assert not out.exists()
    assert list(temp.iterdir()) == []


# ---------------------------------------------------------------------------
# 8. Workflow hygiene.
# ---------------------------------------------------------------------------


def hygiene_check(tree: Tree) -> Checked:
    text = tree.text(WORKFLOW)
    problems = [
        f"the workflow mentions {word!r}"
        for word in ("secrets", "password", "pull_request_target")
        if word in text.lower()
    ]
    try:
        workflow = _read_yaml(text)
    except _YamlError as exc:
        return _checked(
            0, "uses: lines", [*problems, f"the workflow is outside the YAML subset: {exc}"]
        )
    if workflow.get("on") != TRIGGERS:
        problems.append(f"the triggers are {workflow.get('on')!r}, not {TRIGGERS!r}")
    jobs = workflow.get("jobs")
    job_names = sorted(jobs) if isinstance(jobs, dict) else []
    if job_names != JOBS:
        problems.append(f"the workflow has jobs {job_names}, not exactly test, build and publish")
    steps = [(job, step) for job in job_names for step in _steps(workflow, job)]

    runs = [(job, str(step["run"])) for job, step in steps if "run" in step]
    if not runs:
        problems.append("no run: script was found to check")
    problems.extend(
        f"job {job} puts an expression inside a run: script: {run!r}"
        for job, run in runs
        if "${{" in run
    )
    if len(RUN_LINE.findall(text)) != len(runs):
        problems.append(f"{len(RUN_LINE.findall(text))} run: lines in the text, {len(runs)} read")

    scopes: dict[str, object] = {"workflow": workflow.get("permissions")}
    scopes.update({job: _get(workflow, "jobs", job, "permissions") for job in job_names})
    holders = [scope for scope, granted in scopes.items() if _get(granted, "id-token") == "write"]
    if holders != ["publish"] or text.count("id-token: write") != 1:
        problems.append(
            f"id-token: write is granted to {holders} and written {text.count('id-token: write')}"
            " times, not once to job publish"
        )
    expected_scopes = {
        "workflow": {},
        "build": {"contents": "read"},
        "publish": {"id-token": "write"},
        "test": {"contents": "read"},
    }
    if scopes != expected_scopes:
        problems.append(f"the permissions are {scopes!r}, not {expected_scopes!r}")

    uses = [(job, str(step["uses"])) for job, step in steps if "uses" in step]
    lines = USES_LINE.findall(text)
    if len(lines) != len(uses):
        problems.append(f"{len(lines)} uses: lines in the text, {len(uses)} read")
    for ref, rest in lines:
        if PINNED.fullmatch(ref) is None:
            problems.append(f"{ref} is not pinned to a 40-hex commit")
        if TAG_COMMENT.fullmatch(rest) is None:
            problems.append(f"{ref} has no '# vX.Y.Z' tag comment beside it")
    checkouts = [step for _, step in steps if _step_kind(step) == "actions/checkout"]
    if len(checkouts) != 2 or any(
        _get(step, "with", "persist-credentials") != "false" for step in checkouts
    ):
        problems.append("the test and build checkouts do not both set persist-credentials: false")
    setups = [
        (step.get("uses"), step.get("with"))
        for _, step in steps
        if _step_kind(step) == "astral-sh/setup-uv"
    ]
    if len(setups) != 2 or setups[0] != setups[1]:
        problems.append(
            f"the test and build jobs do not set up uv with the same pin and options: {setups}"
        )
    test_kinds = [_step_kind(step) for step in _steps(workflow, "test")]
    if test_kinds != TEST_STEPS:
        problems.append(f"job test runs {test_kinds}, not {TEST_STEPS}")

    # Job publish (security N5a): the pypi environment, both other jobs first, and exactly
    # the two pinned actions in order, the publisher with no inputs.
    publish = _job(workflow, "publish")
    if publish.get("environment") != "pypi":
        problems.append(f"job publish's environment is {publish.get('environment')!r}, not 'pypi'")
    problems.extend(_needs_problems(workflow))
    publish_steps = _steps(workflow, "publish")
    refs = [str(step.get("uses", "")) for step in publish_steps]
    if [_step_kind(step) for step in publish_steps] != PUBLISH_STEPS or not all(
        PINNED.fullmatch(ref) for ref in refs
    ):
        problems.append(f"job publish runs {refs}, not exactly the pinned {PUBLISH_STEPS}")
    if any("with" in step for step in publish_steps if _step_kind(step) == PUBLISH_STEPS[1]):
        problems.append("pypa/gh-action-pypi-publish is given an input")
    return _checked(len(uses), "uses: lines", problems)


def test_the_workflow_holds_no_credential_and_pins_every_action() -> None:
    _assert_clean(hygiene_check(REAL), count=7)


def _repin_first_action(text: str) -> str:
    match = USES_LINE.search(text)
    assert match is not None
    ref = match.group(1)
    return text.replace(ref, ref.partition("@")[0] + "@v7", 1)


def _add_publish_step(text: str) -> str:
    """A third, pinned action at the end of job publish (the workflow's last job)."""
    match = USES_LINE.search(text)
    assert match is not None and text.endswith("\n")
    return text + f"      - name: Extra\n        uses: {match.group(1)}{match.group(2)}\n"


def _swap_publish_steps(text: str) -> str:
    """Job publish's two steps in the other order."""
    head, sep, tail = text.partition("      - name: Download the distributions\n")
    download, sep2, publish = tail.partition("      - name: Publish through Trusted Publishing\n")
    assert sep and sep2
    return head + sep2 + publish + sep + download


def _no_uses_lines(text: str) -> str:
    """Every action step turned into a script step, so no ``uses:`` line is left."""
    return re.sub(r"uses: [^\n]*", "run: echo no-action", text)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(
            _replace(
                "      - name: Publish through Trusted Publishing\n",
                "      - name: Publish through Trusted Publishing\n"
                "        with:\n"
                "          password: ${{ secrets.PYPI_API_TOKEN }}\n",
            ),
            "mentions 'secrets'",
            id="token-input",
        ),
        pytest.param(
            _replace(
                "    name: Build and check\n    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n"
                "    permissions:\n      contents: read\n",
                "    name: Build and check\n    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n"
                "    permissions:\n      contents: read\n      id-token: write\n",
            ),
            "id-token: write is granted to ['build', 'publish']",
            id="id-token-in-build",
        ),
        pytest.param(_repin_first_action, "is not pinned to a 40-hex commit", id="tag-pin"),
        pytest.param(
            _replace(f"run: {TEST_RUN}", f"run: {TEST_RUN} -k ${{{{ github.ref_name }}}}"),
            "puts an expression inside a run: script",
            id="expression-in-run",
        ),
        pytest.param(
            lambda text: (
                text + "\n  sign:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo\n"
            ),
            "not exactly test, build and publish",
            id="fourth-job",
        ),
        pytest.param(
            _replace("    environment: pypi\n", ""),
            "job publish's environment is None",
            id="no-environment",
        ),
        pytest.param(_add_publish_step, "job publish runs", id="third-publish-action"),
        pytest.param(
            lambda text: re.sub(
                r"actions/download-artifact@[0-9a-f]{40}",
                "actions/cache@0123456789abcdef0123456789abcdef01234567",
                text,
            ),
            "job publish runs",
            id="publish-action-swapped",
        ),
        pytest.param(_swap_publish_steps, "job publish runs", id="publish-steps-reordered"),
        pytest.param(
            _replace('version: "0.13.9"', 'version: "0.13.8"'),
            "do not set up uv with the same pin and options",
            id="setup-uv-differs",
        ),
        pytest.param(
            _replace(f"run: {TEST_RUN}\n", f"run: {TEST_RUN} -x\n"),
            "job test runs",
            id="test-job-script",
        ),
        pytest.param(_no_uses_lines, "nothing to check: 0 uses: lines", id="no-uses-lines"),
        pytest.param(
            _replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request_target:\n"),
            "mentions 'pull_request_target'",
            id="pull-request-target",
        ),
        pytest.param(
            _replace("persist-credentials: false", "persist-credentials: true"),
            "persist-credentials: false",
            id="persisted-credentials",
        ),
        pytest.param(
            _replace("permissions: {}\n", "permissions: write-all\n"),
            "the permissions are",
            id="workflow-permissions",
        ),
        pytest.param(
            lambda text: text.replace(" # v7.0.1\n", "\n", 1),
            "has no '# vX.Y.Z' tag comment",
            id="no-tag-comment",
        ),
    ],
)
def test_the_hygiene_check_refuses_a_credential_or_an_unpinned_action(
    tmp_path: Path, change: Callable[[str], str], reason: str
) -> None:
    _assert_refused(hygiene_check(_changed(tmp_path, WORKFLOW, change)), reason)


# ---------------------------------------------------------------------------
# 9. The README: the From PyPI commands and the fixed markers.
# ---------------------------------------------------------------------------

_FENCE = re.compile(r"^```([^\n`]*)\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
_FROM_PYPI = re.compile(r"^## From PyPI[ \t]*\n(.*?)(?=^## |\Z)", re.MULTILINE | re.DOTALL)
SHELL_FENCES = frozenset({"sh", "bash", "shell", "console", ""})
KIT_PREFIXES = (("uvx", PACKAGE), (PACKAGE,), ("lhub",))
INSTALL_PHRASES = (
    f"uvx {PACKAGE} mcp",
    f"uv tool install {PACKAGE}",
    f"pipx install {PACKAGE}",
    f"pip install {PACKAGE}",
)


class ShownCommand(NamedTuple):
    """A fenced line that runs the kit: as written, and its arguments after the prefix."""

    line: str
    argv: list[str]


def from_pypi_section(readme: str) -> str | None:
    match = _FROM_PYPI.search(readme)
    return match.group(1) if match else None


def shown_commands(section: str) -> list[ShownCommand]:
    """Each line of the shell fences that starts with ``uvx lhub-kit``, ``lhub-kit`` or ``lhub``."""
    found: list[ShownCommand] = []
    for language, block in _FENCE.findall(section):
        if language.strip() not in SHELL_FENCES:
            continue
        for line in block.replace("\\\n", " ").splitlines():
            tokens = shlex.split(line, comments=True)
            for prefix in KIT_PREFIXES:
                if tuple(tokens[: len(prefix)]) == prefix:
                    found.append(ShownCommand(line.strip(), tokens[len(prefix) :]))
                    break
    return found


def readme_check(tree: Tree) -> Checked:
    readme = tree.text(README)
    section = from_pypi_section(readme)
    if section is None:
        return _checked(0, "kit commands", ["the README has no '## From PyPI' section"])
    problems: list[str] = []
    if readme.find("\n## From PyPI\n") > readme.find("\n## Buy\n"):
        problems.append("the From PyPI section does not come before Buy")
    commands = shown_commands(section)
    for command in commands:
        parsed = _parsed(command.argv)
        if isinstance(parsed, str):
            problems.append(f"{command.line!r}: the kit's parser refuses it: {parsed}")
    if len(commands) < 2:
        problems.append(f"the From PyPI blocks show {len(commands)} kit commands, fewer than 2")
    for phrase in INSTALL_PHRASES:
        if phrase not in section:
            problems.append(f"the From PyPI section does not show {phrase!r}")
    # Security N6a: the command line leads with an isolated install; pip is the fallback.
    if section.find(f"uv tool install {PACKAGE}") > section.find(f"pip install {PACKAGE}"):
        problems.append("the command line does not lead with uv tool install")
    problems.extend(_client_snippet_problems(section))
    return _checked(len(commands), "kit commands", problems)


def _client_snippet_problems(section: str) -> list[str]:
    """The JSON client configuration: ``uvx lhub-kit mcp`` with the input root set."""
    blocks = [block for language, block in _FENCE.findall(section) if language.strip() == "json"]
    if len(blocks) != 1:
        return [f"the From PyPI section has {len(blocks)} JSON client snippets, not 1"]
    try:
        servers = _get(json.loads(blocks[0]), "mcpServers")
    except ValueError as exc:
        return [f"the client snippet is not JSON: {exc}"]
    entries = list(servers.values()) if isinstance(servers, dict) else []
    if len(entries) != 1:
        return [f"the client snippet configures {len(entries)} servers, not 1"]
    problems: list[str] = []
    entry = entries[0]
    args = [str(item) for item in _list(_get(entry, "args"))]
    if _get(entry, "command") != "uvx" or args[:1] != [PACKAGE]:
        problems.append(
            f"the client snippet runs {_get(entry, 'command')!r} {args}, not uvx {PACKAGE}"
        )
    reason = _selects_mcp(args[1:])
    if reason is not None:
        problems.append(f"the client snippet's args: {reason}")
    env = _get(entry, "env")
    keys = set(env) if isinstance(env, dict) else set()
    if lhub.ENV_INPUT_ROOT not in keys or not keys <= KIT_ENV_NAMES:
        problems.append(f"the client snippet's env is {sorted(keys)}, not the input root alone")
    return problems


def test_the_readme_from_pypi_commands_parse() -> None:
    result = readme_check(REAL)
    assert not result.problems, result.problems
    assert result.counted >= 2, f"found {result.counted} kit commands"
    section = from_pypi_section(REAL.text(README)) or ""
    # uvx lhub-kit mcp; lhub init after uv tool install; lhub init in the pip fallback.
    assert [command.argv for command in shown_commands(section)] == [["mcp"], ["init"], ["init"]]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        pytest.param(
            _replace("\nlhub init\n", "\nlhub initialise\n"),
            "'lhub initialise': the kit's parser refuses it",
            id="unknown-subcommand",
        ),
        pytest.param(
            _replace('"lhub-kit", "mcp"', '"lhub-kit", "serve"'),
            "the client snippet's args",
            id="snippet-subcommand",
        ),
        pytest.param(
            lambda text: text.replace("\nlhub init\n", "\n"),
            "show 1 kit commands, fewer than 2",
            id="one-command",
        ),
        pytest.param(
            lambda text: text.replace("\nlhub init\n", "\n").replace(
                "\nuvx lhub-kit mcp\n", "\nuvx --version\n"
            ),
            "nothing to check: 0 kit commands",
            id="no-command",
        ),
        pytest.param(
            _replace(
                "```sh\nuv tool install lhub-kit\nlhub init\n```",
                "```sh\nlhub init\n```",
            ),
            "does not show 'uv tool install lhub-kit'",
            id="no-uv-tool-install",
        ),
    ],
)
def test_the_readme_command_check_refuses_a_wrong_command(
    tmp_path: Path, change: Callable[[str], str], reason: str
) -> None:
    assert isinstance(_parsed(["no-such-command"]), str)
    _assert_refused(readme_check(_changed(tmp_path, README, change)), reason)


def test_the_mcp_name_marker_is_the_line_after_the_title() -> None:
    lines = REAL.text(README).splitlines()
    assert lines[0].startswith("# "), f"the README's first line is not its title: {lines[0]!r}"
    assert lines[1] == MARKER_LINE, f"the line after the title is {lines[1]!r}, not {MARKER_LINE!r}"


README_MARKERS: dict[str, tuple[str, ...]] = {
    "always-allow (REG-4)": (
        'Don\'t choose "always allow" for `get_result`, `hire`, `deliver`, `accept` or `inbox`.',
        "Your MCP client's per-call permission prompt is where you see the exact file path that"
        " `get_result`, `hire` or `deliver` will read or write, and the last check before"
        " `accept` releases funds or `inbox` countersigns orders.",
        "For the same reason, don't accept a shell \"don't ask again\" rule for `lhub`,"
        " `lhub-kit` or `uvx lhub-kit` commands.",
    ),
    "sandbox (REG-1)": (SANDBOX_LINE,),
    "command-line": (
        "install the package as a tool of its own with `uv tool install` (or"
        " `pipx install lhub-kit`), then run `init` once:",
        "Without uv or pipx, use `pip` inside a virtual environment of its own:",
        "python3 -m venv ~/.lhub-kit-env",
        "Keep that environment in your home directory, outside every project, as above: the MCP"
        " server's file tools must never be able to write into it.",
    ),
    "opening-sentence": (
        "The same file is also published on PyPI as the `lhub-kit` package, which adds `mcp` for"
        " the MCP server",
    ),
    "input-root": (
        "Set `LHUB_KIT_INPUT_ROOT` to the project directory.",
        "a server started in your home directory or in `/` without it refuses every one of"
        " their calls",
    ),
}


def _prose(text: str) -> str:
    """``text`` with blockquote markers dropped and whitespace collapsed, so a marker phrase
    survives line wrapping inside a ``>`` block too."""
    return " ".join(re.sub(r"^> ?", "", text, flags=re.MULTILINE).split())


@pytest.mark.parametrize("statement", sorted(README_MARKERS))
def test_the_readme_carries_the_pypi_statement(statement: str) -> None:
    text = _prose(REAL.text(README))
    missing = [marker for marker in README_MARKERS[statement] if _prose(marker) not in text]
    assert not missing, f"the README lacks its {statement} statement: missing {missing}"


def test_the_sandbox_line_is_near_the_top() -> None:
    # Security N7: before the first section, in the blockquote that opens the README.
    readme = REAL.text(README)
    assert 0 <= readme.find("> The default marketplace") < readme.find("\n## ")


def test_the_readme_states_the_mcp_toolset_once() -> None:
    # tests/test_mcp_toolset.py reads the tool list after the first "exposing exactly: ".
    assert REAL.text(README).count("exposing exactly: ") == 1


# ---------------------------------------------------------------------------
# 10. The build.
# ---------------------------------------------------------------------------

PLACEHOLDER_LICENSE = (
    "Apache License\nVersion 2.0, January 2004\n(placeholder for the build test)\n"
)


def _license_flipped(base: Path) -> Tree:
    """A copy of the export files with LICENSE where the tree has none, and none where it has one."""
    tree = _copy(base)
    if not REAL.path(LICENSE).is_file():
        tree.path(LICENSE).write_text(PLACEHOLDER_LICENSE, encoding="utf-8")
    return tree


def _backend_unfetchable(uv: str) -> str | None:
    """None when uv resolves the pinned build backend (from the index or its cache)."""
    done = subprocess.run(
        [
            uv,
            "pip",
            "compile",
            "--no-config",
            "--quiet",
            "--no-header",
            "--python-version",
            "3.10",
            "-",
        ],
        input=BUILD_REQUIRES[0] + "\n",
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if done.returncode == 0:
        return None
    return (done.stderr.strip() or f"uv pip compile exited {done.returncode}")[-1500:]


def _requirement_key(text: str) -> tuple[str, tuple[str, ...]]:
    """A requirement's name and its sorted specifiers ("mcp<3,>=1.21.1" == "mcp>=1.21.1,<3")."""
    match = re.fullmatch(r"([A-Za-z0-9._-]+)\s*(.*)", text.strip())
    assert match is not None, f"not a requirement: {text!r}"
    specifiers = tuple(sorted(part.strip() for part in match.group(2).split(",") if part.strip()))
    return match.group(1).lower(), specifiers


def _entry_points(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
        elif line and current is not None:
            name, _, target = line.partition("=")
            current[name.strip()] = target.strip()
    return sections


def _metadata_problems(metadata: str, *, licensed: bool, readme: str) -> list[str]:
    message = email.message_from_string(metadata)
    problems: list[str] = []
    singles = {
        "Name": PACKAGE,
        "Version": lhub.KIT_VERSION,
        "License-Expression": "Apache-2.0",
        "Requires-Python": ">=3.10",
        "Description-Content-Type": "text/markdown",
    }
    for field, wanted in singles.items():
        found = message.get_all(field)
        if found != [wanted]:
            problems.append(f"METADATA {field} is {found!r}, not [{wanted!r}]")
    requires = sorted(
        _requirement_key(str(item)) for item in message.get_all("Requires-Dist") or []
    )
    if requires != sorted(_requirement_key(item) for item in DEPENDENCIES):
        problems.append(f"METADATA Requires-Dist is {message.get_all('Requires-Dist')!r}")
    classifiers = [str(item) for item in message.get_all("Classifier") or []]
    if any(item.startswith("License ::") for item in classifiers):
        problems.append(f"METADATA carries a License classifier: {classifiers}")
    license_files = message.get_all("License-File") or []
    if license_files != ([LICENSE] if licensed else []):
        problems.append(f"METADATA License-File is {license_files!r}")
    # PyPI's description is this body, and the registry reads the marker from it.
    if message.get_payload() != readme:
        problems.append("the METADATA description is not the README")
    return problems


def built_check(tree: Tree, out: Path) -> Checked:
    """The real build's output, checked here independently of build.py.

    The denominator is the number of archive members read, so an empty ``out`` or empty
    archives are refused rather than passed.
    """
    version = lhub.KIT_VERSION
    wheel_name = f"lhub_kit-{version}-py3-none-any.whl"
    sdist_name = f"lhub_kit-{version}.tar.gz"
    unit = "archive members"
    produced = sorted(path.name for path in out.iterdir()) if out.is_dir() else []
    if produced != sorted([wheel_name, sdist_name]):
        return _checked(0, unit, [f"{out} holds {produced}, not exactly the wheel and the sdist"])
    licensed = tree.path(LICENSE).is_file()
    kit = tree.path(KIT_FILE).read_bytes()
    problems: list[str] = []

    dist_info = f"lhub_kit-{version}.dist-info/"
    wanted = {KIT_FILE, *(dist_info + name for name in DIST_INFO_FILES)}
    if licensed:
        wanted.add(f"{dist_info}licenses/{LICENSE}")
    with zipfile.ZipFile(out / wheel_name) as wheel:
        members = wheel.namelist()
        counted = len(members)
        if sorted(members) != sorted(wanted):
            return _checked(
                counted, unit, [f"the wheel holds {sorted(members)}, not {sorted(wanted)}"]
            )
        module = wheel.read(KIT_FILE)
        if module != kit:
            problems.append(
                f"the wheel's lhub.py has sha256 {hashlib.sha256(module).hexdigest()}, the tree's"
                f" {hashlib.sha256(kit).hexdigest()}"
            )
        if (
            licensed
            and wheel.read(f"{dist_info}licenses/{LICENSE}") != tree.path(LICENSE).read_bytes()
        ):
            problems.append("the wheel's license file is not the tree's LICENSE")
        metadata = wheel.read(dist_info + "METADATA").decode("utf-8")
        entry_points = _entry_points(wheel.read(dist_info + "entry_points.txt").decode("utf-8"))
    problems.extend(_metadata_problems(metadata, licensed=licensed, readme=tree.text(README)))
    if entry_points != {"console_scripts": SCRIPTS}:
        problems.append(f"the wheel's entry points are {entry_points}, not {SCRIPTS} alone")

    root = f"lhub_kit-{version}/"
    wanted = {root + name for name in SDIST_INCLUDE if licensed or name != LICENSE}
    wanted.add(f"{root}PKG-INFO")
    sources = {KIT_FILE: KIT_FILE, "README.md": README, "pyproject.toml": PYPROJECT}
    if licensed:
        sources[LICENSE] = LICENSE
    with tarfile.open(out / sdist_name, mode="r:gz") as sdist:
        entries = sdist.getmembers()
        counted += len(entries)
        names = sorted(entry.name for entry in entries)
        if names != sorted(wanted):
            return _checked(
                counted, unit, [*problems, f"the sdist holds {names}, not {sorted(wanted)}"]
            )
        problems.extend(
            f"the sdist's {entry.name} is not a regular file"
            for entry in entries
            if not entry.isfile()
        )
        for name, source in sources.items():
            handle = sdist.extractfile(root + name)
            if handle is None or handle.read() != tree.path(source).read_bytes():
                problems.append(f"the sdist's {name} is not byte-identical to the tree's {source}")
    return _checked(counted, unit, problems)


@pytest.mark.parametrize("variant", ["tree-as-is", "license-flipped"])
def test_the_build_is_the_single_file_wheel_and_its_sdist(tmp_path: Path, variant: str) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not on PATH, so pypi/build.py cannot build: wheel and sdist unchecked")
    tree = REAL if variant == "tree-as-is" else _license_flipped(tmp_path / "copy")
    out = tmp_path / "dist"
    done = subprocess.run(
        [sys.executable, "-I", str(tree.path(BUILD_PY)), "--out-dir", str(out)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if done.returncode != 0:
        unfetchable = _backend_unfetchable(uv)
        if unfetchable is not None:
            pytest.skip(f"the build backend {BUILD_REQUIRES[0]} cannot be fetched: {unfetchable}")
        pytest.fail(
            f"pypi/build.py exited {done.returncode}:\n{done.stdout}\n{done.stderr}", pytrace=False
        )
    assert "version gate: passed" in done.stdout
    # Wheel: lhub.py and 4 dist-info files; sdist: 3 staged files and PKG-INFO; plus LICENSE
    # in each when the tree has one.
    licensed = tree.path(LICENSE).is_file()
    _assert_clean(built_check(tree, out), count=11 if licensed else 9)


def test_the_build_check_refuses_nothing_to_check(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    _assert_refused(built_check(REAL, empty), "nothing to check: 0 archive members")
    hollow = tmp_path / "hollow"
    hollow.mkdir()
    _wheel(hollow / f"lhub_kit-{lhub.KIT_VERSION}-py3-none-any.whl", {})
    _sdist(hollow / f"lhub_kit-{lhub.KIT_VERSION}.tar.gz", {})
    _assert_refused(built_check(REAL, hollow), "nothing to check: 0 archive members")


# build.py's own checks, on hand-made archives, so each refusal is exercised with no uv and
# no network: the member names (D-3) and what is inside (security N2).

_VERSION = lhub.KIT_VERSION
_DIST_INFO = f"lhub_kit-{_VERSION}.dist-info/"
_METADATA = f"{_DIST_INFO}METADATA"
_ENTRY_POINTS = f"{_DIST_INFO}entry_points.txt"
_RECORD = f"{_DIST_INFO}RECORD"
_SDIST_ROOT = f"lhub_kit-{_VERSION}/"
# How hatchling 1.33.0 writes D-2's two requirements in METADATA and PKG-INFO.
HATCHLING_REQUIRES = ("cryptography>=42", "mcp<3,>=1.21.1")
ENTRY_POINTS = b"[console_scripts]\nlhub = lhub:main\nlhub-kit = lhub:main\n"
# What build.py stages: the file name in the staging directory and its bytes.
STAGED: dict[str, bytes] = {
    KIT_FILE: (KIT_DIR / KIT_FILE).read_bytes(),
    README: (KIT_DIR / README).read_bytes(),
    "pyproject.toml": (KIT_DIR / PYPROJECT).read_bytes(),
}
LICENSED = {**STAGED, LICENSE: PLACEHOLDER_LICENSE.encode()}


def _metadata(
    staged: Mapping[str, bytes],
    *,
    name: str = PACKAGE,
    version: str = _VERSION,
    requires: tuple[str, ...] = HATCHLING_REQUIRES,
    description: bytes | None = None,
) -> bytes:
    """METADATA or PKG-INFO the way hatchling writes it: headers, a blank line, the README."""
    head = [
        "Metadata-Version: 2.5",
        f"Name: {name}",
        f"Version: {version}",
        *(f"Requires-Dist: {requirement}" for requirement in requires),
        "Description-Content-Type: text/markdown",
    ]
    body = staged[README] if description is None else description
    return ("\n".join(head) + "\n\n").encode() + body


def _record(members: Mapping[str, bytes]) -> bytes:
    """RECORD for ``members``: each with its sha256 (urlsafe base64) and size, then itself."""
    rows = []
    for path, data in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        rows.append(f"{path},sha256={digest},{len(data)}")
    rows.append(f"{_RECORD},,")
    return ("\n".join(rows) + "\n").encode()


def _wheel_members(
    staged: Mapping[str, bytes],
    *,
    replace: Mapping[str, bytes] | None = None,
    drop: tuple[str, ...] = (),
    record: Callable[[dict[str, bytes]], bytes] = _record,
) -> dict[str, bytes]:
    """A wheel the way hatchling builds it from ``staged``, changed as asked; RECORD last."""
    members = {
        KIT_FILE: staged[KIT_FILE],
        _METADATA: _metadata(staged),
        f"{_DIST_INFO}WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        _ENTRY_POINTS: ENTRY_POINTS,
    }
    if LICENSE in staged:
        members[f"{_DIST_INFO}licenses/{LICENSE}"] = staged[LICENSE]
    members.update(replace or {})
    for name in drop:
        del members[name]
    members[_RECORD] = record(members)
    return members


def _sdist_members(
    staged: Mapping[str, bytes],
    *,
    replace: Mapping[str, bytes] | None = None,
    drop: tuple[str, ...] = (),
) -> dict[str, bytes]:
    """An sdist the way hatchling builds it from ``staged``, changed as asked."""
    members = {_SDIST_ROOT + name: data for name, data in staged.items()}
    members[f"{_SDIST_ROOT}PKG-INFO"] = _metadata(staged)
    members.update(replace or {})
    for name in drop:
        del members[name]
    return members


def _wheel(path: Path, members: Mapping[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def _sdist(path: Path, members: Mapping[str, bytes], link: str | None = None) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if link is not None:
            info = tarfile.TarInfo(link)
            info.type = tarfile.SYMTYPE
            info.linkname = "lhub.py"
            archive.addfile(info)
    return path


def test_the_build_checks_accept_what_hatchling_builds(tmp_path: Path) -> None:
    # The positive control for every refusal below, with and without LICENSE.
    for label, staged in (("plain", STAGED), ("licensed", LICENSED)):
        wheel = _wheel(tmp_path / f"{label}.whl", _wheel_members(staged))
        sdist = _sdist(tmp_path / f"{label}.tar.gz", _sdist_members(staged))
        assert BUILD.wheel_problems(wheel, _VERSION, staged) == [], label
        assert BUILD.sdist_problems(sdist, _VERSION, staged) == [], label


def _with_metadata(**fields: Any) -> dict[str, bytes]:
    return _wheel_members(STAGED, replace={_METADATA: _metadata(STAGED, **fields)})


def _with_entry_points(text: bytes) -> dict[str, bytes]:
    return _wheel_members(STAGED, replace={_ENTRY_POINTS: text})


@pytest.mark.parametrize(
    ("members", "staged", "reason"),
    [
        pytest.param(
            _wheel_members(STAGED, replace={"extra.py": b""}),
            STAGED,
            "'extra.py'",
            id="another-module",
        ),
        pytest.param(
            _wheel_members(STAGED, replace={"lhub_extra/__init__.py": b""}),
            STAGED,
            "lhub_extra/__init__.py",
            id="package",
        ),
        pytest.param(
            _wheel_members(STAGED, replace={KIT_FILE: STAGED[KIT_FILE] + b"#"}),
            STAGED,
            "lhub.py is not byte-identical",
            id="changed-module",
        ),
        pytest.param(
            _wheel_members(STAGED, drop=(KIT_FILE,)), STAGED, "lacks ['lhub.py']", id="no-module"
        ),
        pytest.param(
            _wheel_members(STAGED),
            LICENSED,
            f"lacks ['{_DIST_INFO}licenses/LICENSE']",
            id="no-license",
        ),
        pytest.param(
            _wheel_members(LICENSED, replace={f"{_DIST_INFO}licenses/{LICENSE}": b"other"}),
            LICENSED,
            "licenses/LICENSE is not byte-identical",
            id="other-license",
        ),
        pytest.param(
            _with_metadata(name="lhub-kit2"),
            STAGED,
            "METADATA Name is ['lhub-kit2']",
            id="metadata-name",
        ),
        pytest.param(
            _with_metadata(version="9.9.9"),
            STAGED,
            "METADATA Version is ['9.9.9']",
            id="metadata-version",
        ),
        pytest.param(
            _with_metadata(requires=(*HATCHLING_REQUIRES, "httpx")),
            STAGED,
            "METADATA Requires-Dist is",
            id="extra-requirement",
        ),
        pytest.param(
            _with_metadata(requires=HATCHLING_REQUIRES[:1]),
            STAGED,
            "METADATA Requires-Dist is",
            id="missing-requirement",
        ),
        pytest.param(
            _with_metadata(requires=("cryptography>=42", "mcp>=1.2")),
            STAGED,
            "METADATA Requires-Dist is",
            id="loose-specifier",
        ),
        pytest.param(
            _with_metadata(
                requires=("cryptography>=42", "mcp<3,>=1.21.1; python_version >= '3.10'")
            ),
            STAGED,
            "METADATA Requires-Dist is",
            id="marker",
        ),
        pytest.param(
            _with_metadata(description=b"# another README\n"),
            STAGED,
            "description is not the staged README.md",
            id="metadata-description",
        ),
        pytest.param(
            _with_entry_points(ENTRY_POINTS + b"lhub-admin = lhub:main\n"),
            STAGED,
            "entry_points.txt is",
            id="extra-script",
        ),
        pytest.param(
            _with_entry_points(ENTRY_POINTS.replace(b"lhub = lhub:main", b"lhub = lhub:cli")),
            STAGED,
            "entry_points.txt is",
            id="script-target",
        ),
        pytest.param(
            _with_entry_points(ENTRY_POINTS + b"[gui_scripts]\nlhub-gui = lhub:main\n"),
            STAGED,
            "entry_points.txt is",
            id="gui-scripts",
        ),
        pytest.param(
            _wheel_members(STAGED, record=lambda members: _record({**members, _METADATA: b"x"})),
            STAGED,
            f"RECORD's entry for {_METADATA} does not match its content",
            id="record-hash",
        ),
        pytest.param(
            _wheel_members(
                STAGED,
                record=lambda members: _record(
                    {name: data for name, data in members.items() if name != KIT_FILE}
                ),
            ),
            STAGED,
            "RECORD lists",
            id="record-missing-member",
        ),
        pytest.param(
            _wheel_members(STAGED, record=lambda members: _record({**members, "ghost.py": b""})),
            STAGED,
            "RECORD lists",
            id="record-extra-entry",
        ),
        pytest.param(
            _wheel_members(
                STAGED,
                record=lambda members: _record(members).replace(
                    f"{_RECORD},,".encode(), f"{_RECORD},sha256=x,1".encode()
                ),
            ),
            STAGED,
            "RECORD gives its own entry a hash or a size",
            id="record-self-hash",
        ),
    ],
)
def test_the_wheel_check_refuses_anything_but_the_single_file(
    tmp_path: Path, members: dict[str, bytes], staged: dict[str, bytes], reason: str
) -> None:
    wheel = _wheel(tmp_path / "bad.whl", members)
    problems = BUILD.wheel_problems(wheel, _VERSION, staged)
    assert any(reason in problem for problem in problems), problems


@pytest.mark.parametrize(
    ("members", "staged", "link", "reason"),
    [
        pytest.param(
            _sdist_members(STAGED, replace={_SDIST_ROOT + "tests/test_x.py": b""}),
            STAGED,
            None,
            "tests/test_x.py",
            id="extra-file",
        ),
        pytest.param(
            _sdist_members(STAGED),
            STAGED,
            _SDIST_ROOT + "link.py",
            "is not a regular file",
            id="symlink",
        ),
        pytest.param(
            _sdist_members(STAGED, replace={_SDIST_ROOT + ".gitignore": b"*\n"}),
            STAGED,
            None,
            "point TMPDIR",
            id="vcs-ignore",
        ),
        pytest.param(
            _sdist_members(STAGED, replace={_SDIST_ROOT + KIT_FILE: b"#"}),
            STAGED,
            None,
            "lhub.py is not byte-identical",
            id="changed-module",
        ),
        pytest.param(
            _sdist_members(STAGED, drop=(f"{_SDIST_ROOT}PKG-INFO",)),
            STAGED,
            None,
            f"lacks ['{_SDIST_ROOT}PKG-INFO']",
            id="no-pkg-info",
        ),
        pytest.param(
            _sdist_members(STAGED, replace={_SDIST_ROOT + "pyproject.toml": b"[project]\n"}),
            STAGED,
            None,
            "pyproject.toml is not byte-identical",
            id="other-pyproject",
        ),
        pytest.param(
            _sdist_members(STAGED, replace={_SDIST_ROOT + README: b"# another README\n"}),
            STAGED,
            None,
            "README.md is not byte-identical",
            id="other-readme",
        ),
        pytest.param(
            _sdist_members(LICENSED, replace={_SDIST_ROOT + LICENSE: b"other"}),
            LICENSED,
            None,
            "LICENSE is not byte-identical",
            id="other-license",
        ),
        pytest.param(
            _sdist_members(STAGED),
            LICENSED,
            None,
            f"lacks ['{_SDIST_ROOT}LICENSE']",
            id="no-license",
        ),
        pytest.param(
            _sdist_members(
                STAGED, replace={f"{_SDIST_ROOT}PKG-INFO": _metadata(STAGED, version="9.9.9")}
            ),
            STAGED,
            None,
            "PKG-INFO Version is ['9.9.9']",
            id="pkg-info-version",
        ),
        pytest.param(
            _sdist_members(
                STAGED, replace={f"{_SDIST_ROOT}PKG-INFO": _metadata(STAGED, requires=("mcp",))}
            ),
            STAGED,
            None,
            "PKG-INFO Requires-Dist is",
            id="pkg-info-requires",
        ),
    ],
)
def test_the_sdist_check_refuses_anything_outside_its_include_list(
    tmp_path: Path,
    members: dict[str, bytes],
    staged: dict[str, bytes],
    link: str | None,
    reason: str,
) -> None:
    sdist = _sdist(tmp_path / "bad.tar.gz", members, link)
    problems = BUILD.sdist_problems(sdist, _VERSION, staged)
    assert any(reason in problem for problem in problems), problems
