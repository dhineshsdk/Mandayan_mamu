"""An interactive device CLI over SSH (paramiko) that can only send allowlisted commands.

- **Host keys are pinned.** The caller passes the fingerprint it expects (OpenSSH's ``SHA256:...`` form). With none,
  the first key seen is accepted and reported in :attr:`CliSession.host_key` so the caller can pin it; after that a
  different key raises :class:`~sutra_connectors.errors.HostKeyError`. No known_hosts file, agent or local key is used.
- **Read-only.** :meth:`CliSession.run` refuses any command that is not on the allowlist the collector passes in.
- **Output.** Network CLIs echo the command and end the output with the prompt; both are removed, line endings become
  ``\\n``, and a ``--More--`` pager prompt (if paging could not be switched off) is answered with a space.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable

import paramiko

from .errors import ApiError, AuthenticationError, ConfigurationError, HostKeyError, ReadOnlyViolation

_PROMPT = re.compile(r"[A-Za-z0-9_.\-@/:()]+[#>]")
_MORE = re.compile(r"\s*-+\s*More\s*-+\s*$")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def fingerprint(key: paramiko.PKey) -> str:
    """The OpenSSH SHA-256 fingerprint of a host key (``SHA256:`` and unpadded base64), as ``ssh-keygen -l`` shows."""
    return key.fingerprint


class _PinnedHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, name: str, expected: str):
        self.name, self.expected, self.seen = name, expected, ""

    def missing_host_key(self, client, hostname, key):
        self.seen = fingerprint(key)
        if self.expected and self.seen != self.expected:
            raise HostKeyError(f"{self.name}: {hostname} presented host key {self.seen}, not the pinned "
                               f"{self.expected}. If the device was replaced, clear the pinned key and collect again.")


def _last(buf: str) -> str:
    return buf.rsplit("\n", 1)[-1].strip()


def _clean(text: str) -> str:
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "")
    while "\x08" in text:  # backspaces some CLIs send after a pager prompt
        text = re.sub(r".?\x08", "", text, count=1)
    return text


class CliSession:
    """One SSH shell to a network device."""

    def __init__(
        self,
        name: str,
        host: str,
        username: str,
        password: str,
        *,
        allow: Iterable[str],
        port: int = 22,
        host_key: str = "",
        timeout: float = 30.0,
        command_timeout: float = 300.0,
        client_factory: Callable[[], paramiko.SSHClient] = paramiko.SSHClient,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not host:
            raise ConfigurationError(f"{name}: the device address is required")
        if not username or not password:
            raise ConfigurationError(f"{name}: user name and password are required")
        if host_key and not host_key.startswith("SHA256:"):
            raise ConfigurationError(f"{name}: a pinned host key must be an OpenSSH SHA256 fingerprint")
        self.name, self.host, self.port = name, host, port
        self._username, self._password = username, password
        self._allow = frozenset(allow)
        self._timeout, self._command_timeout = timeout, command_timeout
        self._policy = _PinnedHostKey(name, host_key)
        self._client_factory, self._clock = client_factory, clock
        self._client: paramiko.SSHClient | None = None
        self._chan = None
        self.prompt = ""

    @property
    def host_key(self) -> str:
        return self._policy.seen

    def open(self) -> str:
        """Connect and log in; returns the prompt (``switch1#`` or ``switch1>``)."""
        client = self._client_factory()
        client.set_missing_host_key_policy(self._policy)
        try:
            client.connect(self.host, port=self.port, username=self._username, password=self._password,
                           timeout=self._timeout, auth_timeout=self._timeout, banner_timeout=self._timeout,
                           look_for_keys=False, allow_agent=False)
        except HostKeyError:
            client.close()
            raise
        except paramiko.AuthenticationException as exc:
            client.close()
            raise AuthenticationError(f"{self.name}: {self.host} refused the user name or password") from exc
        except (OSError, paramiko.SSHException) as exc:
            client.close()
            raise ApiError(f"{self.name}: could not open SSH to {self.host}:{self.port}: "
                           f"{type(exc).__name__}: {exc}") from exc
        self._client = client
        self._chan = client.invoke_shell(term="vt100", width=511, height=1000)
        self._chan.settimeout(1.0)
        self._chan.send("\n")
        self.prompt = _last(self._read_until(lambda buf: _PROMPT.fullmatch(_last(buf)) is not None, self._timeout))
        return self.prompt

    def run(self, command: str) -> str:
        """Send one allowlisted command and return its output without the echo and the prompt."""
        if command not in self._allow:
            raise ReadOnlyViolation(f"{self.name}: {command!r} is not on the read-only command list")
        if self._chan is None:
            raise ConfigurationError(f"{self.name}: open() first")
        self._chan.send(command + "\n")

        def answered(buf: str) -> bool:  # the echo of this command, then output, then the prompt again
            echo = buf.find(command)
            return echo >= 0 and "\n" in buf[echo:] and _last(buf) == self.prompt

        buf = self._read_until(answered, self._command_timeout)
        out = buf[buf.find(command) + len(command):].split("\n", 1)[1]  # drop anything before and the echo line
        return out[:out.rfind("\n") + 1] if "\n" in out else ""  # drop the prompt

    def _read_until(self, done: Callable[[str], bool], timeout: float) -> str:
        assert self._chan is not None
        deadline = self._clock() + timeout
        buf = ""
        while True:
            if buf and done(buf):
                return buf
            if _MORE.search(buf):
                buf = _MORE.sub("", buf)
                self._chan.send(" ")
            if self._clock() > deadline:
                raise ApiError(f"{self.name}: {self.host} did not return to the prompt within {timeout:.0f}s")
            try:
                data = self._chan.recv(65536)
            except TimeoutError:  # socket.timeout
                continue
            if not data:
                raise ApiError(f"{self.name}: {self.host} closed the SSH session")
            buf = _clean(buf + data.decode("utf-8", errors="replace"))

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = self._chan = None

    def __enter__(self) -> CliSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
