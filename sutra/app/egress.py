"""An outbound-connection allow-list for installations whose data must stay inside the customer's network.

With ``SUTRA_EGRESS=allowlist`` the server refuses to open a connection to any host that is not on the list
(``SUTRA_EGRESS_ALLOW``: host names, ``.example.in`` or ``*.example.in`` for every subdomain, IP addresses or CIDR
ranges). Private, loopback and link-local addresses and single-label names (``postgres``, ``jira``) are always allowed
because they cannot leave the network. Cloud services are therefore off until the administrator names them: Teams, Jira
Cloud, the Anthropic API, the CISA and FIRST feeds, a scanner's cloud console.

How it works: Python's name lookup (``socket.getaddrinfo``) and ``socket.socket.connect`` are wrapped in this process,
which covers ``httpx``, ``urllib``, ``smtplib`` and the Anthropic SDK alike. A connection to a public IP address is
allowed only if that address was returned for an allowed host name.

What it is not: a firewall. Code that bypasses Python's socket module (a C library that resolves and connects by
itself, such as ``libpq`` talking to PostgreSQL) is not covered, and a compromised process could undo the wrapper. Put
the same rule on the network (default-deny egress from the Sutra server) and treat this as the second lock, the one that
also tells an administrator exactly what was blocked and why.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from collections import OrderedDict
from datetime import UTC, datetime

POLICIES = ("open", "allowlist")
KEEP = 50


class EgressBlocked(OSError):
    """A connection was refused by the egress policy. The message names the host and what to change."""


def parse_allow(text: str) -> list[str]:
    return [t.strip().lower() for t in text.replace("\n", ",").split(",") if t.strip()]


def _ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]").split("%")[0])
    except ValueError:
        return None


def _internal(ip) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


class EgressGuard:
    def __init__(self, policy: str = "allowlist", allow: list[str] | None = None):
        if policy not in POLICIES:
            raise ValueError(f"SUTRA_EGRESS must be one of {', '.join(POLICIES)}, got {policy!r}")
        self.policy = policy
        self.allow = list(allow or [])
        self.nets, self.names = [], []
        for entry in self.allow:
            try:
                self.nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self.names.append(entry[1:] if entry.startswith("*.") else entry)
        self._lock = threading.Lock()
        self._blocked: OrderedDict[str, dict] = OrderedDict()
        self._resolved: set[str] = set()  # addresses returned for allowed names

    # ----- decisions -----
    def host_allowed(self, host: str | None) -> bool:
        if self.policy == "open" or not host:
            return True
        host = host.strip().lower().rstrip(".")
        ip = _ip(host)
        if ip is not None:
            return _internal(ip) or any(ip in n for n in self.nets)
        if host == "localhost" or "." not in host:
            return True
        return any(host == n or (n.startswith(".") and host.endswith(n)) for n in self.names)

    def ip_allowed(self, address: str) -> bool:
        if self.policy == "open":
            return True
        ip = _ip(address)
        return ip is None or _internal(ip) or any(ip in n for n in self.nets) or address in self._resolved

    def _record(self, host: str, why: str) -> None:
        with self._lock:
            row = self._blocked.pop(host, None) or {"host": host, "count": 0}
            row.update(count=row["count"] + 1, last=datetime.now(UTC).isoformat(timespec="seconds"), why=why)
            self._blocked[host] = row
            while len(self._blocked) > KEEP:
                self._blocked.popitem(last=False)

    def refuse(self, host: str) -> EgressBlocked:
        why = (f"Blocked by this server's outbound-connection policy: {host} is not on the allow-list. "
               f"An administrator can add it to SUTRA_EGRESS_ALLOW if data may be sent there.")
        self._record(host, why)
        return EgressBlocked(why)

    def status(self) -> dict:
        with self._lock:
            blocked = list(reversed(self._blocked.values()))
        return {"policy": self.policy, "allow": self.allow, "blocked": blocked,
                "note": ("Outbound connections are limited to the allow-list. Private network addresses are always "
                         "allowed." if self.policy == "allowlist" else
                         "Outbound connections are not restricted by Sutra (SUTRA_EGRESS=open).")}


# ----- installing the guard in this process -----
_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_current: EgressGuard | None = None


def _getaddrinfo(host, *args, **kwargs):
    guard = _current
    if guard is not None and isinstance(host, (str, bytes)):
        name = host.decode() if isinstance(host, bytes) else host
        if not guard.host_allowed(name):
            raise guard.refuse(name)
        result = _real_getaddrinfo(host, *args, **kwargs)
        if _ip(name) is None:
            guard._resolved.update(r[4][0] for r in result)
        return result
    return _real_getaddrinfo(host, *args, **kwargs)


def _check_address(sock: socket.socket, address) -> None:
    guard = _current
    if guard is None or sock.family not in (socket.AF_INET, socket.AF_INET6) or not isinstance(address, tuple):
        return
    if not guard.ip_allowed(str(address[0])):
        raise guard.refuse(str(address[0]))


def _connect(self, address):
    _check_address(self, address)
    return _real_connect(self, address)


def _connect_ex(self, address):
    _check_address(self, address)
    return _real_connect_ex(self, address)


def install(guard: EgressGuard) -> None:
    """Make ``guard`` the process-wide policy (an ``open`` guard removes the restriction)."""
    global _current
    _current = guard if guard.policy != "open" else None
    socket.getaddrinfo = _getaddrinfo
    socket.socket.connect = _connect
    socket.socket.connect_ex = _connect_ex


def uninstall(guard: EgressGuard | None = None) -> None:
    """Remove the policy, but only if ``guard`` is still the active one (one app's shutdown cannot lift another's)."""
    global _current
    if guard is not None and _current is not guard:
        return
    _current = None
    socket.getaddrinfo = _real_getaddrinfo
    socket.socket.connect = _real_connect
    socket.socket.connect_ex = _real_connect_ex
