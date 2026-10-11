"""Exceptions raised by the connectors. Messages never contain credentials."""

from __future__ import annotations


class ConnectorError(Exception):
    """Base class for every error a connector raises."""


class ConfigurationError(ConnectorError):
    """The connector was given settings it cannot work with (missing key, bad URL, bad option)."""


class ReadOnlyViolation(ConnectorError):
    """A request outside the connector's read-only allowlist was attempted. Never retried."""


class AuthenticationError(ConnectorError):
    """The scanner rejected the credentials (HTTP 401) or the account lacks permission (HTTP 403)."""


class RateLimitError(ConnectorError):
    """The scanner kept refusing requests for rate or concurrency reasons after every retry."""


class ApiError(ConnectorError):
    """The scanner returned an error response, or a body this library cannot parse.

    ``status`` is the HTTP status, ``code`` the vendor's own error code when the body carries one.
    """

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


class ExportFailed(ConnectorError):
    """An asynchronous export job ended in a failed or cancelled state, or did not finish in time."""


class HostKeyError(ConnectorError):
    """An SSH server presented a host key other than the one pinned for it: the device was replaced or rebuilt, or
    something is intercepting the connection. Never retried."""
