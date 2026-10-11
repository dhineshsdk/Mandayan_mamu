import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from sutra_connectors.errors import ApiError, AuthenticationError, ConfigurationError
from sutra_connectors.http import RetryPolicy
from sutra_connectors.tenable_sc import TenableSCConnector

FIX = Path(__file__).parent / "fixtures" / "tenable_sc"
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)


def load(name):
    return json.loads((FIX / name).read_text())


class FakeSC:
    def __init__(self, pages):
        self.pages = pages  # (tool, sourceType) -> list of envelopes, one per page
        self.requests = []

    def __call__(self, req):
        self.requests.append(req)
        if req.url.path == "/rest/currentUser":
            return httpx.Response(200, json={"type": "regular", "response": {"username": "sutra-ro"},
                                             "error_code": 0, "error_msg": ""})
        body = json.loads(req.content)
        pages = self.pages[(body["query"]["tool"], body["sourceType"])]
        n = body["query"]["startOffset"] // (body["query"]["endOffset"] - body["query"]["startOffset"])
        return httpx.Response(200, json=pages[n] if n < len(pages) else _empty())


def _empty():
    return {"type": "regular", "response": {"returnedRecords": 0, "results": []}, "error_code": 0}


def connector(handler, **kw):
    return TenableSCConnector("https://sc.plant.example.in", "AK", "SK", transport=httpx.MockTransport(handler),
                              sleep=lambda s: None, clock=lambda: NOW,
                              retry=RetryPolicy(max_attempts=2, backoff_base=0), **kw)


def bodies(fake):
    return [json.loads(r.content) for r in fake.requests if r.url.path == "/rest/analysis"]


def test_full_pull_request_and_auth_header():
    fake = FakeSC({("vulndetails", "cumulative"): [load("vulndetails_cumulative.json")]})
    findings = list(connector(fake).iter_findings())
    assert fake.requests[0].headers["x-apikey"] == "accesskey=AK; secretkey=SK;"
    assert fake.requests[0].url == "https://sc.plant.example.in/rest/analysis"
    assert bodies(fake) == [{
        "type": "vuln", "sourceType": "cumulative",
        "query": {"type": "vuln", "tool": "vulndetails", "startOffset": 0, "endOffset": 2000,
                  "filters": [{"filterName": "severity", "operator": "=", "value": "1,2,3,4"}]},
    }]
    assert len(findings) == 2


def test_maps_vulndetails():
    fake = FakeSC({("vulndetails", "cumulative"): [load("vulndetails_cumulative.json")]})
    f1, f2 = connector(fake).iter_findings()
    assert f1.source == "tenable-sc:sc.plant.example.in" and f1.scanner_ref == "Plugin 156860"
    assert f1.record_id == "1|10.30.2.11|gw01.corp.example.in|443|TCP|156860"
    assert (f1.severity, f1.cvss, f1.state) == ("critical", 9.8, "open")
    assert f1.cves == ("CVE-2023-4966", "CVE-2023-4967")
    assert f1.evidence.strip().startswith("Installed version : 13.1-49.13")  # <plugin_output> wrapper removed
    assert f1.last_seen == datetime.fromtimestamp(1791936107, tz=timezone.utc)
    assert f1.hostname == "gw01.corp.example.in" and f1.os == "Citrix NetScaler"
    # Empty cvssV3 falls back to v2; NetBIOS DOMAIN\HOST becomes HOST; hasBeenMitigated=1 means reopened.
    assert (f2.cvss, f2.hostname, f2.state) == (5.0, "ENG-WS04", "reopened")
    assert f2.cves == ("CVE-1999-0519", "CVE-1999-0520")
    assert f2.record_id == "3|10.30.5.40|445|TCP|26920"


def test_incremental_pull_reads_cumulative_and_patched_with_day_ranges():
    fake = FakeSC({("vulndetails", "cumulative"): [load("vulndetails_cumulative.json")],
                   ("vulndetails", "patched"): [load("vulndetails_patched.json")]})
    since = datetime(2026, 10, 9, 18, 0, tzinfo=timezone.utc)  # 1.75 days ago -> "0:2"
    findings = list(connector(fake).iter_findings(since))
    b = bodies(fake)
    assert [x["sourceType"] for x in b] == ["cumulative", "patched"]
    assert b[0]["query"]["filters"][1] == {"filterName": "lastSeen", "operator": "=", "value": "0:2"}
    assert b[1]["query"]["filters"][1] == {"filterName": "lastMitigated", "operator": "=", "value": "0:2"}
    fixed = findings[-1]
    assert fixed.state == "fixed" and fixed.last_fixed == datetime.fromtimestamp(1791500000, tz=timezone.utc)


def test_pages_until_a_short_page():
    page = load("vulndetails_cumulative.json")
    full = copy.deepcopy(page)
    full["response"]["results"] = page["response"]["results"] * 50  # 100 rows = one full page
    fake = FakeSC({("vulndetails", "cumulative"): [full, full, page]})
    findings = list(connector(fake, page_size=100).iter_findings())
    assert [(x["query"]["startOffset"], x["query"]["endOffset"]) for x in bodies(fake)] == [(0, 100), (100, 200),
                                                                                           (200, 300)]
    assert len(findings) == 202


def test_error_code_in_body_raises():
    def handler(req):
        return httpx.Response(200, json={"type": "regular", "response": "", "error_code": 146,
                                         "error_msg": "Invalid filter 'lastSeen'"})

    with pytest.raises(ApiError) as e:
        list(connector(handler).iter_findings())
    assert e.value.code == "146" and "Invalid filter" in str(e.value)


def test_forbidden_is_an_auth_error():
    with pytest.raises(AuthenticationError):
        list(connector(lambda r: httpx.Response(403)).iter_findings())


def test_unknown_severity_is_skipped(caplog):
    page = load("vulndetails_cumulative.json")
    page["response"]["results"][0]["severity"] = {"id": "9", "name": "?"}
    fake = FakeSC({("vulndetails", "cumulative"): [page]})
    assert len(list(connector(fake).iter_findings())) == 1
    assert "unknown severity" in caplog.text


def test_hosts_from_sumip():
    fake = FakeSC({("sumip", "cumulative"): [load("sumip.json")]})
    (h,) = connector(fake).iter_hosts()
    assert bodies(fake)[0]["query"]["tool"] == "sumip" and bodies(fake)[0]["query"]["filters"] == []
    assert h.host_id == "02ebb260-30ed-4bf8-9e2c-92a8614cda1a"
    assert h.ips == ("10.30.2.11",) and h.hostnames == ("gw01.corp.example.in", "GW01")
    assert h.os == "cpe:/o:citrix:netscaler"
    assert h.last_seen == datetime.fromtimestamp(1791936107, tz=timezone.utc)


def test_check_and_settings():
    fake = FakeSC({})
    assert connector(fake).check() == {"username": "sutra-ro"}
    with pytest.raises(ConfigurationError):
        TenableSCConnector("http://sc.example", "AK", "SK")
    with pytest.raises(ConfigurationError):
        TenableSCConnector("https://sc.example", "AK", "SK", page_size=50000)
    assert "SK" not in repr(TenableSCConnector("https://sc.example", "AK", "SKSECRET"))
