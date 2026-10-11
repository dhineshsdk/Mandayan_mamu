import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from sutra_connectors.errors import ApiError, ConfigurationError, ExportFailed
from sutra_connectors.http import RetryPolicy
from sutra_connectors.tenable_vm import TenableVMConnector

FIX = Path(__file__).parent / "fixtures" / "tenable_vm"
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
JOB = "d7f1b2c4-1111-4222-8333-444455556666"


def load(name):
    return json.loads((FIX / name).read_text())


class FakeTenable:
    """Serves the documented export flow: request, status polling, chunk download."""

    def __init__(self, statuses, chunks, kind="vulns", start_status=200):
        self.statuses = list(statuses)
        self.chunks = chunks
        self.kind = kind
        self.start_status = start_status
        self.requests = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        p = req.url.path
        if req.method == "POST" and p == f"/{self.kind}/export":
            if self.start_status == 409:
                return httpx.Response(409, json={"active_job_id": JOB, "failure_reason": "Duplicate export"})
            return httpx.Response(200, json={"export_uuid": JOB})
        if p == f"/{self.kind}/export/{JOB}/status":
            return httpx.Response(200, json=self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0])
        if p.startswith(f"/{self.kind}/export/{JOB}/chunks/"):
            return httpx.Response(200, json=self.chunks[int(p.rsplit("/", 1)[1])])
        if p == f"/{self.kind}/export/{JOB}/cancel":
            return httpx.Response(200, json={"status": "CANCELLED"})
        return httpx.Response(404)


def connector(fake, sleeps=None, **kw):
    return TenableVMConnector("AK", "SK", transport=httpx.MockTransport(fake),
                              sleep=(sleeps if sleeps is not None else []).append, clock=lambda: NOW,
                              retry=RetryPolicy(max_attempts=2, backoff_base=0), **kw)


def test_full_pull_request_body_and_headers():
    fake = FakeTenable([{"status": "FINISHED", "chunks_available": [1]}], {1: load("vulns_chunk_1.json")})
    findings = list(connector(fake).iter_findings())
    start = fake.requests[0]
    assert start.headers["x-apikeys"] == "accessKey=AK; secretKey=SK;"
    assert start.headers["user-agent"].startswith("Integration/1.0 (Sutra; Sutra Connectors; Build/")
    body = json.loads(start.content)
    assert body == {"num_assets": 500, "include_unlicensed": False,
                    "filters": {"since": int((NOW - timedelta(days=365)).timestamp()),
                                "state": ["OPEN", "REOPENED"], "severity": ["low", "medium", "high", "critical"]}}
    assert len(findings) == 2


def test_incremental_pull_includes_fixed_and_uses_since_only():
    since = datetime(2026, 10, 10, 5, 0, tzinfo=timezone.utc)
    fake = FakeTenable([{"status": "FINISHED", "chunks_available": []}], {})
    list(connector(fake).iter_findings(since))
    filters = json.loads(fake.requests[0].content)["filters"]
    assert filters["since"] == int(since.timestamp())
    assert filters["state"] == ["OPEN", "REOPENED", "FIXED"]
    assert not {"first_found", "last_found", "last_fixed"} & filters.keys()


def test_maps_records_to_findings():
    fake = FakeTenable([{"status": "FINISHED", "chunks_available": [1, 2]}],
                       {1: load("vulns_chunk_1.json"), 2: load("vulns_chunk_2.json")})
    f1, f2, f3 = connector(fake).iter_findings()
    assert f1.scanner == "Tenable" and f1.scanner_ref == "Plugin 170112"
    assert f1.source == "tenable-vm:cloud.tenable.com"
    assert f1.record_id == "0f3e2d1c-aaaa-4bbb-8ccc-000000000001"
    assert (f1.ip, f1.hostname, f1.os) == ("10.20.1.15", "his-db01.plant.example.in", "Red Hat Enterprise Linux 8.6")
    assert f1.severity == "high" and f1.cvss == 7.4 and f1.cves == ("CVE-2023-0286", "CVE-2023-0215")
    assert f1.state == "open" and f1.port == "0" and f1.protocol == "TCP"
    assert f1.first_seen == datetime(2026, 3, 2, 9, 14, 11, tzinfo=timezone.utc)
    assert "Should be" in f1.evidence
    # No fqdn: falls back to hostname. No cvss3: falls back to v2. No finding_id: composite key.
    assert f2.hostname == "hmi-07" and f2.cvss == 5.0 and f2.state == "reopened"
    assert f2.record_id == "7c9f0d3b-7d2c-4b9f-8e8c-2a3b4c5d6e7f:96982:445:TCP"
    assert f3.state == "fixed" and f3.last_fixed == datetime(2026, 10, 5, 11, 22, 33, tzinfo=timezone.utc)


def test_downloads_chunks_while_processing_each_once():
    statuses = [
        {"status": "QUEUED", "chunks_available": []},
        {"status": "PROCESSING", "chunks_available": [2]},
        {"status": "PROCESSING", "chunks_available": [2, 1]},
        {"status": "FINISHED", "chunks_available": [1, 2]},
    ]
    sleeps = []
    fake = FakeTenable(statuses, {1: load("vulns_chunk_1.json"), 2: load("vulns_chunk_2.json")})
    findings = list(connector(fake, sleeps, poll_interval=5, poll_interval_max=12).iter_findings())
    chunk_paths = [r.url.path for r in fake.requests if "/chunks/" in r.url.path]
    assert chunk_paths == [f"/vulns/export/{JOB}/chunks/2", f"/vulns/export/{JOB}/chunks/1"]
    assert len(findings) == 3
    assert sleeps == [5, 10, 12]


def test_reuses_running_export_on_409():
    fake = FakeTenable([{"status": "FINISHED", "chunks_available": [1]}], {1: load("vulns_chunk_1.json")},
                       start_status=409)
    assert len(list(connector(fake).iter_findings())) == 2


@pytest.mark.parametrize("status", [
    {"status": "ERROR", "reason": "The export request timed out. Try again."},
    {"status": "CANCELLED"},
    {"status": "FINISHED", "chunks_available": [], "chunks_failed": [3], "reason": "1 of 3 chunks failed"},
])
def test_failed_exports_raise(status):
    with pytest.raises(ExportFailed):
        list(connector(FakeTenable([status], {})).iter_findings())


def test_timeout_cancels_the_export():
    ticks = iter(range(0, 100000, 3600))
    fake = FakeTenable([{"status": "PROCESSING", "chunks_available": []}], {})
    c = connector(fake, export_timeout=timedelta(hours=2))
    c._monotonic = lambda: next(ticks)
    with pytest.raises(ExportFailed):
        list(c.iter_findings())
    assert fake.requests[-1].url.path == f"/vulns/export/{JOB}/cancel"


def test_skips_unknown_severity_and_non_json_is_an_error(caplog):
    bad = [dict(load("vulns_chunk_1.json")[0], severity="severe")]
    fake = FakeTenable([{"status": "FINISHED", "chunks_available": [1]}], {1: bad})
    assert list(connector(fake).iter_findings()) == []
    assert "unknown severity" in caplog.text

    def handler(req):
        return httpx.Response(200, text="<html>maintenance</html>")

    with pytest.raises(ApiError):
        list(connector(handler).iter_findings())


def test_asset_export_full_and_incremental():
    fake = FakeTenable([{"status": "FINISHED", "chunks_available": [1]}], {1: load("assets_chunk_1.json")},
                       kind="assets")
    hosts = list(connector(fake, asset_chunk_size=2000).iter_hosts())
    assert json.loads(fake.requests[0].content) == {"chunk_size": 2000}
    h1, h2 = hosts
    assert h1.host_id == "6b8e9c2a-6c1b-4a8e-9d7b-1f2a3b4c5d6e"
    assert h1.ips == ("10.20.1.15",)
    assert h1.hostnames == ("his-db01.plant.example.in", "his-db01", "HIS-DB01")
    assert h1.last_seen == datetime(2026, 10, 9, 22, 1, 47, tzinfo=timezone.utc)
    assert h2.hostname == "HMI-07" and h2.os.startswith("Microsoft Windows 7")

    since = datetime(2026, 10, 10, tzinfo=timezone.utc)
    fake = FakeTenable([{"status": "FINISHED", "chunks_available": []}], {}, kind="assets")
    list(connector(fake).iter_hosts(since))
    assert json.loads(fake.requests[0].content)["filters"] == {"updated_at": int(since.timestamp())}


@pytest.mark.parametrize("kw", [{"num_assets": 10}, {"num_assets": 6000}, {"asset_chunk_size": 50},
                                {"severities": ("urgent",)}, {"severities": ()}])
def test_rejects_bad_settings(kw):
    with pytest.raises(ConfigurationError):
        TenableVMConnector("AK", "SK", **kw)


def test_requires_keys_and_hides_them_in_repr():
    with pytest.raises(ConfigurationError):
        TenableVMConnector("", "SK")
    assert "SK" not in repr(TenableVMConnector("AK", "SECRETVALUE"))
