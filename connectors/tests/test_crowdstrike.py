import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from sutra_connectors.crowdstrike import CrowdStrikeConnector
from sutra_connectors.errors import ApiError, AuthenticationError, ConfigurationError, ReadOnlyViolation
from sutra_connectors.http import RetryPolicy

FIX = Path(__file__).parent / "fixtures" / "crowdstrike"
NOW = datetime(2025, 3, 25, 12, 0, tzinfo=timezone.utc)


def load(name):
    return json.loads((FIX / name).read_text())


class FakeFalcon:
    """Serves the token, Spotlight combined query and device endpoints as FalconPy and Elastic describe them."""

    def __init__(self, expire_first_token=False, vuln_error=None):
        self.requests = []
        self.tokens = 0
        self.expire_first_token = expire_first_token
        self.vuln_error = vuln_error

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        p = req.url.path
        if p == "/oauth2/token":
            self.tokens += 1
            return httpx.Response(201, json={"access_token": f"tok{self.tokens}", "token_type": "bearer",
                                             "expires_in": 1799})
        if self.expire_first_token and req.headers.get("authorization") == "Bearer tok1":
            return httpx.Response(401, json={"errors": [{"code": 401, "message": "access denied, invalid bearer"}]})
        if p == "/spotlight/combined/vulnerabilities/v1":
            if self.vuln_error:
                return httpx.Response(200, json={"meta": {}, "resources": [], "errors": [self.vuln_error]})
            after = req.url.params.get("after")
            return httpx.Response(200, json=load("vulns_page2.json" if after == "page-2-token" else "vulns_page1.json"))
        if p == "/devices/queries/devices/v1":
            ids = [d["device_id"] for d in load("devices.json")["resources"]]
            return httpx.Response(200, json={"meta": {"pagination": {"offset": 0, "limit": 5000, "total": len(ids)}},
                                             "resources": ids, "errors": []})
        if p == "/devices/entities/devices/v2" and req.method == "POST":
            wanted = set(json.loads(req.content)["ids"])
            body = load("devices.json")
            body["resources"] = [d for d in body["resources"] if d["device_id"] in wanted]
            return httpx.Response(200, json=body)
        return httpx.Response(404)


def connector(fake, **kw):
    return CrowdStrikeConnector("CID", "SECRET", transport=httpx.MockTransport(fake), sleep=lambda s: None,
                                clock=lambda: NOW, retry=RetryPolicy(max_attempts=2, backoff_base=0), **kw)


def test_full_pull_asks_for_open_and_reopened_with_facets_and_pages():
    fake = FakeFalcon()
    findings = list(connector(fake).iter_findings())
    token, first, second = fake.requests
    assert parse_qs(token.content.decode()) == {"client_id": ["CID"], "client_secret": ["SECRET"]}
    q = parse_qs(first.url.query.decode())
    assert q["filter"] == ["status:['open','reopen']"] and q["limit"] == ["5000"]
    assert q["facet"] == ["cve", "host_info", "remediation"] and q["sort"] == ["updated_timestamp|asc"]
    assert first.headers["authorization"] == "Bearer tok1" and "after" not in q
    assert parse_qs(second.url.query.decode())["after"] == ["page-2-token"]
    # Three of four records: the one marked "expired" is left out.
    assert [f.state for f in findings] == ["open", "open", "reopened"]


def test_incremental_pull_filters_on_updated_time():
    fake = FakeFalcon()
    list(connector(fake).iter_findings(datetime(2025, 3, 1, 5, 30, tzinfo=timezone.utc)))
    assert parse_qs(fake.requests[1].url.query.decode())["filter"] == ["updated_timestamp:>='2025-03-01T05:30:00Z'"]


def test_maps_records_to_findings():
    linux, windows, _ = connector(FakeFalcon()).iter_findings()
    assert linux.scanner == "CrowdStrike" and linux.scanner_ref == "Spotlight CVE-2025-26465"
    assert linux.source == "crowdstrike-api:api.crowdstrike.com"
    assert linux.record_id == "897580adb4ab4540a457536faa42de18_eda961728a22320da280bd9d181a798b"
    assert (linux.ip, linux.hostname, linux.os) == ("1.128.0.0", "ub24-50-10-154", "Ubuntu 24.04")
    assert linux.title == "CVE-2025-26465 in openssh 1:9.6p1-3ubuntu13.4"
    assert linux.severity == "medium" and linux.cvss == 6.8 and linux.cves == ("CVE-2025-26465",)
    assert (linux.package, linux.installed, linux.fixed_version) == ("openssh", "1:9.6p1-3ubuntu13.4",
                                                                     "1:9.6p1-3ubuntu13.8")
    assert linux.port == "22,80" and linux.first_seen == datetime(2025, 2, 20, 10, 10, 24, tzinfo=timezone.utc)
    assert linux.last_seen == datetime(2025, 2, 18, tzinfo=timezone.utc)  # the host's last report
    assert "openssh to version 1:9.6p1-3ubuntu13.8" in linux.solution
    # The recommended remediation is picked, not the minimum one.
    assert windows.severity == "high" and windows.fixed_version == "KB5053594"
    assert windows.package == "Windows Server 2016" and windows.installed == "1607"


def test_hosts_skip_devices_not_seen_recently():
    fake = FakeFalcon()
    hosts = list(connector(fake).iter_hosts())
    assert [h.hostname for h in hosts] == ["WIN-7TSM15JR429"]  # the Mac last reported in 2023
    h = hosts[0]
    assert h.ip == "192.168.90.30" and h.last_seen == datetime(2025, 3, 20, 10, 2, 9, tzinfo=timezone.utc)
    detail = next(r for r in fake.requests if r.url.path == "/devices/entities/devices/v2")
    assert detail.method == "POST" and len(json.loads(detail.content)["ids"]) == 2
    longer = list(connector(FakeFalcon(), host_window=timedelta(days=3650)).iter_hosts())
    assert len(longer) == 2


def test_renews_an_expired_token_once():
    fake = FakeFalcon(expire_first_token=True)
    assert len(list(connector(fake).iter_findings())) == 3
    assert fake.tokens == 2


def test_errors_in_the_body_are_raised():
    with pytest.raises(AuthenticationError, match="scopes"):
        list(connector(FakeFalcon(vuln_error={"code": 403, "message": "access denied, authorization failed"}))
             .iter_findings())
    with pytest.raises(ApiError, match="bad filter"):
        list(connector(FakeFalcon(vuln_error={"code": 400, "message": "bad filter"})).iter_findings())


def test_configuration_and_read_only():
    with pytest.raises(ConfigurationError):
        CrowdStrikeConnector("", "x")
    with pytest.raises(ConfigurationError):
        CrowdStrikeConnector("a", "b", base_url="http://api.crowdstrike.com")
    with pytest.raises(ConfigurationError):
        CrowdStrikeConnector("a", "b", page_size=6000)
    c = connector(FakeFalcon(), member_cid="child")
    with pytest.raises(ReadOnlyViolation):
        c.http.request("DELETE", "/devices/entities/devices/v2")
    fake = FakeFalcon()
    list(connector(fake, member_cid="child").iter_findings())
    assert parse_qs(fake.requests[0].content.decode())["member_cid"] == ["child"]
