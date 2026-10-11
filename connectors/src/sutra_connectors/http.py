"""HTTP plumbing shared by the connectors: read-only allowlist, retries, rate-limit waits, error mapping.

Every connector talks to its scanner through one :class:`HttpSession`. The session refuses any request whose method
and path are not on the connector's allowlist, so a coding mistake cannot turn into a write against a customer's
scanner. Allowlisted ``POST`` requests exist only where the vendor's read API itself is a ``POST`` (a search or an
export job), never for a call that changes scanner data.
"""

from __future__ import annotations

import email.utils
import logging
import random
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__
from .errors import ApiError, AuthenticationError, ConfigurationError, RateLimitError, ReadOnlyViolation

log = logging.getLogger("sutra_connectors")

USER_AGENT = f"Sutra-Connectors/{__version__}"


@dataclass(frozen=True)
class RetryPolicy:
    """How hard to try before giving up on one request.

    ``max_attempts`` counts the first try. Waits grow as ``backoff_base * 2**n`` with full jitter, capped at
    ``backoff_max``. A wait the server asks for (``Retry-After`` or a vendor header) is honoured as given, up to
    ``max_server_wait``; a longer request fails the call rather than stalling a scheduled pull for hours.
    """

    max_attempts: int = 6
    backoff_base: float = 2.0
    backoff_max: float = 120.0
    max_server_wait: float = 900.0
    retry_statuses: frozenset[int] = field(default_factory=lambda: frozenset({429, 500, 502, 503, 504}))

    def backoff(self, attempt: int, rng: random.Random) -> float:
        return rng.uniform(0, min(self.backoff_max, self.backoff_base * (2 ** attempt)))


@dataclass(frozen=True)
class Allow:
    """One allowlisted request shape: an HTTP method, a regular expression the whole path must match and, for APIs
    that pick the operation with a parameter (Qualys ``action=``), parameter values the request must carry in its
    query string or form body."""

    method: str
    path: str
    require: tuple[tuple[str, str], ...] = ()

    def matches(self, method: str, path: str, params: dict[str, str]) -> bool:
        return (self.method == method and re.fullmatch(self.path, path) is not None
                and all(params.get(k) == v for k, v in self.require))


def parse_retry_after(value: str | None, now: Callable[[], datetime] | None = None) -> float | None:
    """Seconds to wait from a ``Retry-After`` header (RFC 9110 section 10.2.3: delay-seconds or an HTTP-date)."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    current = now() if now else datetime.now(timezone.utc)
    return max(0.0, (when - current).total_seconds())


# A hook returns how long to wait before retrying this response, or None to use the default rules.
RetryHook = Callable[[httpx.Response], "float | None"]
# An error hook turns an error response into (readable detail, vendor error code or None).
ErrorHook = Callable[[httpx.Response], "tuple[str, str | None]"]


def require_https(url: str, setting: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        raise ConfigurationError(f"{setting} must be an https:// URL, got {url!r}")
    return url.rstrip("/")


class HttpSession:
    """A small wrapper around :class:`httpx.Client` with the rules above.

    ``transport`` and ``sleep`` exist so tests can run against mocked responses without waiting.
    """

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        headers: dict[str, str],
        allow: Iterable[Allow],
        auth: httpx.Auth | None = None,
        timeout: float = 120.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        retry_hook: RetryHook | None = None,
        error_hook: ErrorHook | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ):
        self.name = name
        self.base_url = require_https(base_url, "base_url")
        self._allow = tuple(allow)
        self._retry = retry or RetryPolicy()
        self._retry_hook = retry_hook
        self._error_hook = error_hook
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"User-Agent": USER_AGENT, **headers},
            auth=auth,
            timeout=timeout,
            verify=verify,
            transport=transport,
            follow_redirects=False,  # never forward credentials to another host
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | list[tuple[str, Any]] | None = None,
        data: dict[str, Any] | None = None,
        json: Any = None,
        ok_statuses: Iterable[int] = (),
    ) -> httpx.Response:
        """Send one allowlisted request, retrying transient failures. Returns any 2xx response.

        ``ok_statuses`` lists non-2xx statuses the caller handles itself (for example a 409 that names an export
        job already running); they are returned instead of raised.
        """
        method = method.upper()
        given = {str(k): str(v) for k, v in (params.items() if isinstance(params, dict) else params or [])}
        given.update({str(k): str(v) for k, v in (data or {}).items()})
        if not any(a.matches(method, path, given) for a in self._allow):
            raise ReadOnlyViolation(f"{self.name}: {method} {path} is not on the read-only allowlist")
        ok = set(ok_statuses)
        last_problem = ""
        for attempt in range(self._retry.max_attempts):
            try:
                resp = self._client.request(method, path, params=params, data=data, json=json)
            except httpx.TransportError as exc:
                last_problem = f"{type(exc).__name__}: {exc}"
                wait = self._retry.backoff(attempt, self._rng)
                log.warning("%s: %s %s failed (%s); retry %d in %.1fs", self.name, method, path, last_problem,
                            attempt + 1, wait)
                self._pause(attempt, wait)
                continue
            if resp.is_success or resp.status_code in ok:
                return resp
            if resp.status_code in (401, 403):
                raise AuthenticationError(
                    f"{self.name}: {method} {path} returned HTTP {resp.status_code}; check the API credentials "
                    "and that the account has read access")
            wait = self._retry_hook(resp) if self._retry_hook else None
            if wait is None and resp.status_code in self._retry.retry_statuses:
                wait = parse_retry_after(resp.headers.get("Retry-After"))
                if wait is None:
                    wait = self._retry.backoff(attempt, self._rng)
            if wait is None:
                detail, code = self._error_hook(resp) if self._error_hook else (_snippet(resp), None)
                raise ApiError(f"{self.name}: {method} {path} returned HTTP {resp.status_code}: {detail}",
                               status=resp.status_code, code=code)
            if wait > self._retry.max_server_wait:
                raise RateLimitError(f"{self.name}: server asked to wait {wait:.0f}s, more than the "
                                     f"{self._retry.max_server_wait:.0f}s limit")
            last_problem = f"HTTP {resp.status_code}"
            log.warning("%s: %s %s returned %s; retry %d in %.1fs", self.name, method, path, last_problem,
                        attempt + 1, wait)
            self._pause(attempt, wait)
        if last_problem.startswith("HTTP 429") or last_problem.startswith("HTTP 409"):
            raise RateLimitError(f"{self.name}: {method} {path} still rate limited after "
                                 f"{self._retry.max_attempts} attempts")
        raise ApiError(f"{self.name}: {method} {path} failed after {self._retry.max_attempts} attempts "
                       f"({last_problem})")

    def _pause(self, attempt: int, wait: float) -> None:
        if attempt + 1 < self._retry.max_attempts:
            self._sleep(wait)


def _snippet(resp: httpx.Response, limit: int = 300) -> str:
    text = " ".join(resp.text.split())
    return text[:limit] + ("..." if len(text) > limit else "")
