from datetime import datetime, timezone

import httpx
import pytest

from sutra_connectors.errors import ApiError, AuthenticationError, ConfigurationError, RateLimitError, ReadOnlyViolation
from sutra_connectors.http import Allow, HttpSession, RetryPolicy, parse_retry_after


def session(handler, sleeps, **kw):
    return HttpSession(name="test", base_url="https://scanner.example", headers={"X-Key": "k"},
                       allow=[Allow("GET", r"/things/\d+"), Allow("POST", r"/search")],
                       transport=httpx.MockTransport(handler), sleep=sleeps.append,
                       retry=kw.pop("retry", RetryPolicy(max_attempts=4, backoff_base=1, backoff_max=8)), **kw)


def test_rejects_requests_off_the_allowlist():
    s = session(lambda r: httpx.Response(200), [])
    with pytest.raises(ReadOnlyViolation):
        s.request("DELETE", "/things/1")
    with pytest.raises(ReadOnlyViolation):
        s.request("GET", "/things/1/delete")


def test_requires_https():
    with pytest.raises(ConfigurationError):
        HttpSession(name="t", base_url="http://scanner.example", headers={}, allow=[])


def test_sends_user_agent_and_headers():
    seen = {}

    def handler(req):
        seen.update(req.headers)
        return httpx.Response(200, json={})

    session(handler, []).request("GET", "/things/1")
    assert seen["x-key"] == "k"
    assert seen["user-agent"].startswith("Sutra-Connectors/")


def test_honours_retry_after_on_429():
    calls, sleeps = [], []

    def handler(req):
        calls.append(req)
        if len(calls) < 3:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, json={"ok": True})

    assert session(handler, sleeps).request("GET", "/things/1").json() == {"ok": True}
    assert sleeps == [7.0, 7.0]


def test_backs_off_on_5xx_and_transport_errors():
    calls, sleeps = [], []

    def handler(req):
        calls.append(req)
        if len(calls) == 1:
            raise httpx.ConnectError("boom", request=req)
        if len(calls) == 2:
            return httpx.Response(503)
        return httpx.Response(200)

    session(handler, sleeps).request("GET", "/things/1")
    assert len(sleeps) == 2 and all(0 <= s <= 8 for s in sleeps)


def test_gives_up_after_max_attempts():
    sleeps = []
    with pytest.raises(RateLimitError):
        session(lambda r: httpx.Response(429, headers={"Retry-After": "1"}), sleeps).request("GET", "/things/1")
    assert len(sleeps) == 3  # no pointless sleep after the last attempt
    with pytest.raises(ApiError):
        session(lambda r: httpx.Response(500), []).request("GET", "/things/1")


def test_refuses_waits_longer_than_the_limit():
    s = session(lambda r: httpx.Response(429, headers={"Retry-After": "3600"}), [],
                retry=RetryPolicy(max_server_wait=60))
    with pytest.raises(RateLimitError):
        s.request("GET", "/things/1")


def test_auth_failures_are_not_retried():
    sleeps = []
    with pytest.raises(AuthenticationError):
        session(lambda r: httpx.Response(401), sleeps).request("GET", "/things/1")
    assert sleeps == []


def test_other_4xx_raise_api_error_with_status():
    with pytest.raises(ApiError) as e:
        session(lambda r: httpx.Response(400, text="bad filter"), []).request("POST", "/search")
    assert e.value.status == 400 and "bad filter" in str(e.value)


def test_ok_statuses_are_returned():
    assert session(lambda r: httpx.Response(409), []).request("POST", "/search", ok_statuses=[409]).status_code == 409


def test_retry_hook_takes_precedence():
    calls, sleeps = [], []

    def handler(req):
        calls.append(req)
        return httpx.Response(409 if len(calls) == 1 else 200, headers={"X-Wait": "11"})

    session(handler, sleeps, retry_hook=lambda r: float(r.headers["X-Wait"]) if r.status_code == 409 else None) \
        .request("GET", "/things/1")
    assert sleeps == [11.0]


def test_does_not_follow_redirects():
    s = session(lambda r: httpx.Response(302, headers={"Location": "https://elsewhere.example/"}), [])
    with pytest.raises(ApiError):
        s.request("GET", "/things/1")


def test_parse_retry_after():
    now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    assert parse_retry_after("30") == 30.0
    assert parse_retry_after("Sun, 11 Oct 2026 12:00:45 GMT", now=lambda: now) == 45.0
    assert parse_retry_after("Sun, 11 Oct 2026 11:00:00 GMT", now=lambda: now) == 0.0
    assert parse_retry_after("soon") is None
    assert parse_retry_after(None) is None
