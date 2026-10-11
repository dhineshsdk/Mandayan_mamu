"""Nozomi Networks connector.

Fixtures are Elastic's Nozomi Networks pipeline test records and sample event (elastic/integrations,
``packages/nozomi_networks/data_stream/node_cve`` and ``asset``), unchanged, wrapped in the query endpoint's
``result`` envelope. Their values are Elastic's own test data (for example the iPad record also carries a PLC's
``node_*`` fields).
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from sutra_connectors.errors import ApiError, AuthenticationError, ConfigurationError, ReadOnlyViolation
from sutra_connectors.http import RetryPolicy
from sutra_connectors.models import STATE_FIXED, STATE_OPEN
from sutra_connectors.nozomi import NozomiConnector

FIX = Path(__file__).parent / "fixtures" / "nozomi"
NOW = datetime(2025, 5, 20, tzinfo=timezone.utc)
URL = "https://guardian.plant.example"


def load(name):
    return json.loads((FIX / name).read_text())


class FakeNozomi:
    def __init__(self, page_size=None, error=None, status=200):
        self.requests = []
        self.page_size, self.error, self.status = page_size, error, status

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if self.status != 200:
            return httpx.Response(self.status, text="Unauthorized")
        assert req.url.path == "/api/open/query/do"
        if self.error:
            return httpx.Response(200, json={"result": None, "error": self.error})
        q = req.url.params["query"]
        rows = load("node_cves.json" if q.startswith("node_cves") else "assets.json")["result"]
        if self.page_size:
            page = int(req.url.params["page"])
            rows = rows[(page - 1) * self.page_size:page * self.page_size]
        return httpx.Response(200, json={"result": rows, "error": None})


def connector(fake, **kw):
    return NozomiConnector(URL, "sutra-reader", "pw", transport=httpx.MockTransport(fake), sleep=lambda s: None,
                           clock=lambda: NOW, retry=RetryPolicy(max_attempts=2, backoff_base=0), **kw)


def test_full_pull_reads_unresolved_vulnerabilities():
    fake = FakeNozomi()
    findings = list(connector(fake).iter_findings())
    req = fake.requests[0]
    assert req.headers["authorization"].startswith("Basic ")
    p = req.url.params
    assert p["query"] == "node_cves | sort time asc" and p["page"] == "1" and p["count"] == "500"
    assert p["skip_total_count"] == "true" and p["default_filters"] == "false"
    # Four records, one resolved.
    assert len(findings) == 3 and {f.state for f in findings} == {STATE_OPEN}


def test_maps_an_ot_vulnerability():
    modicon = [f for f in connector(FakeNozomi()).iter_findings() if f.cves == ("CVE-2018-7844",)][0]
    assert modicon.scanner == "Nozomi" and modicon.source == "nozomi-api:guardian.plant.example"
    assert (modicon.ip, modicon.hostname) == ("81.2.69.142", "plc160.ACME0.xyz.com")
    assert modicon.package == "Schneider Electric BMXP342020 Modicon M340 Processor Module"
    assert modicon.installed == "v2.9"
    assert modicon.fixed_version == "" and modicon.severity == "high" and modicon.cvss == 7.5
    assert "Confirmed (likelihood 1)" in modicon.evidence and "Production_A" in modicon.evidence
    assert "OEM" in modicon.solution


def test_hotfix_and_end_of_life_records():
    by_cve = {f.scanner_ref: f for f in connector(FakeNozomi()).iter_findings()}
    ipad = by_cve["Nozomi CVE-2021-30992"]
    assert ipad.ip == "175.16.199.24"  # "localhost" and 0.0.0.0 are not addresses
    assert ipad.fixed_version == "KB3074683" and "KB3074683" in ipad.solution
    eol = by_cve["Nozomi CVE-EOL"]
    assert eol.cves == () and eol.severity == "critical" and eol.hostname == "HMI-A101"


def test_incremental_pull_includes_resolved():
    fake = FakeNozomi()
    found = list(connector(fake).iter_findings(datetime(2025, 3, 1, tzinfo=timezone.utc)))
    assert fake.requests[0].url.params["query"] == "node_cves | where time > 1740787200000 | sort time asc"
    assert [f.state for f in found].count(STATE_FIXED) == 1


def test_pages_until_a_short_page():
    fake = FakeNozomi(page_size=2)
    assert len(list(connector(fake, page_size=2).iter_findings())) == 3
    assert [r.url.params["page"] for r in fake.requests] == ["1", "2", "3"]


def test_assets_active_recently():
    fake = FakeNozomi()
    hosts = list(connector(fake).iter_hosts())
    assert fake.requests[0].url.params["query"] == (
        f"assets | where last_activity_time > {int((NOW - timedelta(days=30)).timestamp() * 1000)} "
        "| sort last_activity_time asc")
    # The record whose only address is 0.0.0.0 and whose name is that address is left out.
    assert [(h.ips, h.hostnames) for h in hosts] == [
        (("67.43.156.0",), ("hostname",)), (("203.0.113.50",), ("string-epoch-uptime-host",)),
        (("203.0.113.10",), ("cmc-asset",))]


def test_errors_and_configuration():
    with pytest.raises(ApiError, match="query rejected"):
        list(connector(FakeNozomi(error="unknown table")).iter_findings())
    with pytest.raises(AuthenticationError):
        list(connector(FakeNozomi(status=401)).iter_findings())
    with pytest.raises(ConfigurationError):
        NozomiConnector("", "a", "b")
    with pytest.raises(ConfigurationError):
        NozomiConnector("http://guardian", "a", "b")
    with pytest.raises(ReadOnlyViolation):
        connector(FakeNozomi()).http.request("POST", "/api/open/query/do")
