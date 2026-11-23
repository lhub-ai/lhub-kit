"""Test guard: a socket may connect only to loopback (fix-kit-default-url design D-6).

The kit's built-in marketplace is the public sandbox, ``https://lhub.ai`` (D-1),
so a test that forgets to stub the transport would reach production. Under this
guard it fails instead: anything but loopback is refused at the three connect
entry points, ``socket.socket.connect``, ``socket.socket.connect_ex`` and
``socket.create_connection``. Each checks the address it is given BEFORE it
connects or resolves anything; a name passed to them is never resolved to decide.

Allowed: an AF_INET or AF_INET6 connect to 127.0.0.0/8, ``::1`` or the name
``localhost``. Refused: every other host name or address, and every other address
family (AF_UNIX paths included).

Name lookups made outside those entry points are NOT guarded. A direct resolver
call (``socket.getaddrinfo``, ``socket.gethostbyname``) still sends its DNS query,
and code that resolves a name itself and then connects to the resulting address is
refused only at that connect, after the query has gone out. What the guard
promises is no connection to a non-loopback host, not no DNS traffic.

Every socket, TLS sockets included, connects through ``connect`` or
``connect_ex``. ``create_connection`` is checked on the host it is given, so
urllib's path (http.client calls it with the URL's host) is refused before that
name is resolved. urllib's proxy discovery (the environment and the macOS system
settings) is switched off for the test: a loopback proxy would otherwise carry a
request for a public host past a loopback-only rule.

A refusal raises pytest's ``Failed``, a ``BaseException``, so no ``except
Exception`` (the kit's fail-safes, its ``OSError`` to ``KitTransportError``
mapping) can turn it into a handled outcome. Every refusal is also recorded and
fails the test at teardown, so not even a handler that swallows ``BaseException``
hides one. ``install`` checks its own work and refuses to start a test behind a
partly installed guard.

Boundary: in-process and under pytest only. A child process is not covered (each
child-process test pins its own loopback or ``.invalid`` URL), running a test file
directly with ``python`` bypasses the conftest, and UDP ``sendto`` is not covered
(neither the kit nor the canary uses UDP).

Used by ``clients/lhub-kit/tests/conftest.py`` and ``scripts/canary/conftest.py``
(the canary loads this file by path). Positive controls:
``tests/test_socket_guard.py`` and ``scripts/canary/test_canary_target.py``.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from collections.abc import Callable
from typing import Any, NoReturn

import pytest

LOOPBACK_NAME = "localhost"
IP_FAMILIES = (socket.AF_INET, socket.AF_INET6)


def is_loopback_host(host: object) -> bool:
    """True only for ``localhost`` (any letter case) and loopback IP literals."""
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii")
        except UnicodeDecodeError:
            return False
    if not isinstance(host, str):
        return False
    if host.lower() == LOOPBACK_NAME:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_loopback_address(family: int, address: object) -> bool:
    """True only for an AF_INET or AF_INET6 address tuple whose host is loopback."""
    if family not in IP_FAMILIES:
        return False
    if not isinstance(address, tuple) or not address:
        return False
    return is_loopback_host(address[0])


def _no_proxies() -> dict[str, str]:
    return {}


class SocketGuard:
    """One test's guard: what it refused, and the real functions it hands loopback to."""

    def __init__(self, real: dict[str, Callable[..., Any]]) -> None:
        # Looked up at call time, so a positive control can put a recorder here
        # and prove that a refused connect never reached the real function.
        self.real = real
        self.wrappers: dict[str, Callable[..., Any]] = {}
        self.refused: list[str] = []

    def installed(self) -> bool:
        """True while every entry point is this guard's wrapper and proxies are off."""
        current = {
            "connect": socket.socket.__dict__.get("connect"),
            "connect_ex": socket.socket.__dict__.get("connect_ex"),
            "create_connection": socket.create_connection,
        }
        return (
            set(self.wrappers) == set(current)
            and all(current[name] is self.wrappers[name] for name in current)
            and urllib.request.getproxies is _no_proxies
        )

    def refuse(self, what: str) -> NoReturn:
        self.refused.append(what)
        pytest.fail(
            f"socket guard (fix-kit-default-url D-6): refused {what}; a test may connect"
            " only to loopback (127.0.0.0/8, ::1, localhost). Stub the transport, or use"
            " a loopback or .invalid URL."
        )

    def check_at_teardown(self) -> None:
        """Fail the test if anything was refused, even if the refusal was swallowed."""
        if self.refused:
            pytest.fail(
                f"socket guard (fix-kit-default-url D-6): {len(self.refused)} non-loopback"
                f" connect(s) refused during this test: {self.refused}",
                pytrace=False,
            )


def install(monkeypatch: pytest.MonkeyPatch) -> SocketGuard:
    """Install the guard for one test; ``monkeypatch`` removes it at teardown."""
    guard = SocketGuard(
        {
            "connect": socket.socket.connect,
            "connect_ex": socket.socket.connect_ex,
            "create_connection": socket.create_connection,
        }
    )

    def connect(sock: socket.socket, address: Any) -> None:
        if not is_loopback_address(sock.family, address):
            guard.refuse(f"connect to {address!r}")
        guard.real["connect"](sock, address)

    def connect_ex(sock: socket.socket, address: Any) -> int:
        if not is_loopback_address(sock.family, address):
            guard.refuse(f"connect_ex to {address!r}")
        return int(guard.real["connect_ex"](sock, address))

    def create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
        host = address[0] if isinstance(address, tuple) and address else address
        if not is_loopback_host(host):
            guard.refuse(f"create_connection to {address!r}")
        conn: socket.socket = guard.real["create_connection"](address, *args, **kwargs)
        return conn

    guard.wrappers = {
        "connect": connect,
        "connect_ex": connect_ex,
        "create_connection": create_connection,
    }
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    # urllib's ProxyHandler reads getproxies() when urlopen builds its opener;
    # dropping the cached opener makes the next urlopen build one under this patch.
    monkeypatch.setattr(urllib.request, "getproxies", _no_proxies)
    monkeypatch.setattr(urllib.request, "_opener", None)
    if not guard.installed():  # fail closed: no test runs behind a partial guard
        raise RuntimeError("socket guard: an entry point is not patched; refusing to run the test")
    return guard
