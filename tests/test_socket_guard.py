"""Positive control for the conftest's socket guard (fix-kit-default-url D-6; canon C-3).

The guard counts as evidence only once it has been seen refusing. These tests
show a non-loopback connect refused at every entry point BEFORE the real function
is reached (a recorder stands in for the real functions, so even a broken guard
would send nothing), a loopback connect let through, both to the recorder and to
a real listening socket, and the two leaks the new default makes possible stopped:
an unstubbed ``find`` with no marketplace configured, and the same request sent
through a loopback proxy.
"""

from __future__ import annotations

import contextlib
import os
import re
import socket
import subprocess
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from socketguard import SocketGuard, is_loopback_address, is_loopback_host

import lhub

GUARDED = ("connect", "connect_ex", "create_connection")
NON_LOOPBACK = [
    pytest.param("192.0.2.1", id="ipv4-documentation"),
    pytest.param("10.0.0.1", id="ipv4-private"),
    pytest.param("0.0.0.0", id="ipv4-unspecified"),  # noqa: S104 - a refused address, never bound
    pytest.param("2001:db8::1", id="ipv6-documentation"),
    pytest.param("::ffff:192.0.2.1", id="ipv6-mapped-ipv4"),
    pytest.param("lhub.ai", id="the-public-default"),
    pytest.param("localhost.evil.invalid", id="localhost-prefix"),
    pytest.param("127.0.0.1.nip.io", id="name-resolving-to-loopback"),
    pytest.param("", id="empty"),
]
LOOPBACK = [
    pytest.param("127.0.0.1", id="ipv4"),
    pytest.param("127.255.255.254", id="ipv4-top-of-127/8"),
    pytest.param("::1", id="ipv6"),
    pytest.param("localhost", id="name"),
    pytest.param("LocalHost", id="name-mixed-case"),
]
PROXY_VARIABLES = (
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "all_proxy",
    "ALL_PROXY",
)


class ReachedReal(Exception):
    """Raised by the recorder: the guard let a call through to the real function."""


class Recorder:
    """Stands in for the real connect functions behind the guard."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def stub(self, name: str) -> Callable[..., Any]:
        def record(*args: Any, **_kwargs: Any) -> Any:
            self.calls.append((name, args))
            raise ReachedReal(name)

        return record


@pytest.fixture
def recorder(_socket_guard: SocketGuard, monkeypatch: pytest.MonkeyPatch) -> Recorder:
    stand_in = Recorder()
    for name in GUARDED:
        monkeypatch.setitem(_socket_guard.real, name, stand_in.stub(name))
    return stand_in


def _ipv6_sockets() -> bool:
    """Whether this host can create an AF_INET6 socket (creating one connects nothing)."""
    if not socket.has_ipv6:
        return False
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
    except OSError:
        return False
    return True


IPV6_SOCKETS = _ipv6_sockets()


def family_of(host: str) -> socket.AddressFamily:
    # The guard decides on the host either way; the family only has to exist.
    return socket.AF_INET6 if ":" in host and IPV6_SOCKETS else socket.AF_INET


def test_the_guard_is_installed_for_every_test(
    _socket_guard: SocketGuard, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The autouse fixture replaced all three entry points (monkeypatch removes
    # them at teardown; socket.socket inherits connect from _socket.socket).
    assert "connect" in socket.socket.__dict__
    assert "connect_ex" in socket.socket.__dict__
    assert socket.create_connection.__module__ == "socketguard"
    assert urllib.request.getproxies() == {}
    assert _socket_guard.installed()
    # Control for install()'s own check: one entry point put back is detected.
    with monkeypatch.context() as patch:
        patch.setattr(socket, "create_connection", _socket_guard.real["create_connection"])
        assert not _socket_guard.installed()
    assert _socket_guard.installed()


@pytest.mark.parametrize("host", NON_LOOPBACK)
def test_a_non_loopback_connect_is_refused_before_the_real_function(
    host: str, recorder: Recorder, _socket_guard: SocketGuard
) -> None:
    assert not is_loopback_host(host)
    with socket.socket(family_of(host), socket.SOCK_STREAM) as sock:
        with pytest.raises(pytest.fail.Exception, match="socket guard"):
            sock.connect((host, 443))
        with pytest.raises(pytest.fail.Exception, match="socket guard"):
            sock.connect_ex((host, 443))
    with pytest.raises(pytest.fail.Exception, match="socket guard"):
        socket.create_connection((host, 443))
    assert recorder.calls == []  # nothing reached a real function
    assert _socket_guard.refused == [
        f"connect to {(host, 443)!r}",
        f"connect_ex to {(host, 443)!r}",
        f"create_connection to {(host, 443)!r}",
    ]
    _socket_guard.refused.clear()  # expected refusals: keep the teardown check quiet


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no AF_UNIX on this platform")
def test_a_unix_socket_connect_is_refused(
    tmp_path: Path, recorder: Recorder, _socket_guard: SocketGuard
) -> None:
    path = str(tmp_path / "s.sock")
    assert not is_loopback_address(socket.AF_UNIX, path)
    with (
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock,
        pytest.raises(pytest.fail.Exception, match="socket guard"),
    ):
        sock.connect(path)
    assert recorder.calls == []
    assert _socket_guard.refused == [f"connect to {path!r}"]
    _socket_guard.refused.clear()


@pytest.mark.parametrize("host", LOOPBACK)
def test_a_loopback_connect_reaches_the_real_function(
    host: str, recorder: Recorder, _socket_guard: SocketGuard
) -> None:
    assert is_loopback_host(host)
    with socket.socket(family_of(host), socket.SOCK_STREAM) as sock:
        with pytest.raises(ReachedReal):
            sock.connect((host, 9))
        with pytest.raises(ReachedReal):
            sock.connect_ex((host, 9))
    with pytest.raises(ReachedReal):
        socket.create_connection((host, 9))
    assert [name for name, _args in recorder.calls] == list(GUARDED)
    assert _socket_guard.refused == []


def test_a_real_loopback_connection_is_made() -> None:
    # No recorder: the guard hands loopback to the real functions, end to end.
    with socket.create_server(("127.0.0.1", 0)) as server:
        server.settimeout(5)
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            server.accept()[0].close()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(("localhost", port))
            server.accept()[0].close()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            assert client.connect_ex(("127.0.0.1", port)) == 0
            server.accept()[0].close()


def test_an_unstubbed_find_with_no_url_is_refused_not_sent(
    monkeypatch: pytest.MonkeyPatch, recorder: Recorder, _socket_guard: SocketGuard
) -> None:
    # The leak D-1 makes possible: the kit's real transport, nothing configured.
    monkeypatch.delenv(lhub.ENV_BASE_URL, raising=False)
    with pytest.raises(pytest.fail.Exception, match=r"create_connection to \('lhub\.ai', 443\)"):
        lhub.main(["find"])
    assert recorder.calls == []
    assert _socket_guard.refused == ["create_connection to ('lhub.ai', 443)"]
    _socket_guard.refused.clear()


def test_a_loopback_proxy_cannot_carry_a_public_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: Recorder, _socket_guard: SocketGuard
) -> None:
    for name in PROXY_VARIABLES:
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    for name in ("no_proxy", "NO_PROXY"):  # an ambient bypass list must not decide the control
        monkeypatch.delenv(name, raising=False)
    url = "https://lhub.invalid" + lhub.MCP_PATH
    # Control: an opener that honours those variables turns the public request
    # into a LOOPBACK connect to the proxy, which a loopback rule alone allows.
    honouring = urllib.request.build_opener(
        urllib.request.ProxyHandler(urllib.request.getproxies_environment())
    )
    with pytest.raises(ReachedReal):
        honouring.open(url, data=b"{}", timeout=5)
    assert [(name, args[0]) for name, args in recorder.calls] == [
        ("create_connection", ("127.0.0.1", 9))
    ]
    recorder.calls.clear()
    # The kit's own path: urlopen's opener is built with no proxies, so the
    # request goes to the public host itself, and is refused.
    kit = lhub.Kit("https://lhub.invalid", tmp_path / "home")
    with pytest.raises(pytest.fail.Exception, match=r"\('lhub\.invalid', 443\)"):
        kit._http_post(url, b"{}", {})
    assert recorder.calls == []
    assert _socket_guard.refused == ["create_connection to ('lhub.invalid', 443)"]
    _socket_guard.refused.clear()


def test_a_swallowed_refusal_still_fails_the_test(
    recorder: Recorder, _socket_guard: SocketGuard
) -> None:
    # A handler that swallows even BaseException cannot hide a refusal: it is
    # recorded, and the fixture's teardown check fails the test on it.
    with contextlib.suppress(BaseException):  # the swallowing this test is about
        socket.create_connection(("192.0.2.1", 443))
    assert _socket_guard.refused == ["create_connection to ('192.0.2.1', 443)"]
    with pytest.raises(pytest.fail.Exception, match="1 non-loopback connect"):
        _socket_guard.check_at_teardown()
    _socket_guard.refused.clear()
    _socket_guard.check_at_teardown()  # nothing recorded: passes
    assert recorder.calls == []


# The fixture wiring itself (sdd NIT 2): the test above calls check_at_teardown()
# by hand, so it stays green if the conftest stops calling it. This control runs
# pytest in a CHILD process over byte copies of this directory's real conftest.py
# and socketguard.py: a test that names no fixture and swallows a refusal must fail
# at teardown, so deleting the conftest's check_at_teardown() call, or its autouse,
# turns it red. The child's probe connects to a missing AF_UNIX path: the guard
# refuses it before the real connect, and with no guard it fails locally, so no
# network is involved either way.
CHILD_TESTS = """\
import contextlib
import socket


def test_the_guard_reaches_a_test_that_names_no_fixture():
    assert "connect" in socket.socket.__dict__


def test_swallows_a_refusal():
    with contextlib.suppress(BaseException):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect("absent.sock")
"""


def run_child_pytest(root: Path, target: Path) -> subprocess.CompletedProcess[str]:
    """pytest in a child process over ``target``, with ``root`` as its rootdir."""
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    env = {name: value for name, value in os.environ.items() if not name.startswith("PYTEST_")}
    argv = [
        sys.executable,
        "-I",
        "-m",
        "pytest",
        "-q",
        "-rE",
        "--color=no",
        "-p",
        "no:cacheprovider",
        f"--basetemp={root / 'basetemp'}",
        str(target),
    ]
    return subprocess.run(
        argv, cwd=root, env=env, capture_output=True, text=True, timeout=120, check=False
    )


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="the child's probe is an AF_UNIX path")
def test_the_conftest_fails_a_test_that_swallowed_a_refusal(tmp_path: Path) -> None:
    here = Path(__file__).resolve().parent
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in ("conftest.py", "socketguard.py"):
        (tests / name).write_bytes((here / name).read_bytes())
    (tests / "test_child.py").write_text(CHILD_TESTS, encoding="utf-8")
    proc = run_child_pytest(tmp_path, tests)
    report = proc.stdout + proc.stderr
    assert proc.returncode == 1, report
    # Both bodies pass; the swallowing test's teardown is the one error.
    assert re.search(r"\b2 passed, 1 error\b", proc.stdout), report
    assert "ERROR at teardown of test_swallows_a_refusal" in proc.stdout, report
    assert "1 non-loopback connect(s) refused during this test" in proc.stdout, report
