"""Milestone 4: live threat intel. The CISA KEV catalog decides "actively exploited", EPSS scores are attached to
each CVE, a failed or malformed feed keeps the last good copy, and until a feed is fetched every CVE is marked as
coming from the shipped sample list.

``fixtures/kev_2026-10-08_trimmed.json`` is the real CISA catalog (version 2026.10.08, from
github.com/cisagov/kev-data), cut down to the CVEs in the synthetic estate plus eight others; entries are unchanged.
The EPSS responses below follow the shape of the FIRST API (``data``: ``cve``, ``epss``, ``percentile``, ``date`` as
strings) but their numbers are made up for the test.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from sutra.app import cli, intel
from sutra.app.config import Settings
from sutra.app.main import create_app

D = "vindhyapower.example"
ADMIN, VM, MANAGER = f"admin@{D}", f"aisha.khan@{D}", f"arjun.mehta@{D}"
KEV = (Path(__file__).parent / "fixtures" / "kev_2026-10-08_trimmed.json").read_bytes()


class Feeds:
    """Plays CISA and FIRST. ``kev`` is the body to serve, or an int status code."""

    def __init__(self):
        self.kev: bytes | int = KEV
        self.epss_calls: list[list[str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.cisa.gov":
            if isinstance(self.kev, int):
                return httpx.Response(self.kev, text="unavailable")
            return httpx.Response(200, content=self.kev, headers={"content-type": "application/json"})
        if request.url.host == "api.first.org":
            cves = request.url.params["cve"].split(",")
            self.epss_calls.append(cves)
            data = [{"cve": c, "epss": "0.012340000" if i % 2 else "0.943580000",
                     "percentile": "0.780000000" if i % 2 else "0.999450000", "date": "2026-10-10"}
                    for i, c in enumerate(cves)]
            return httpx.Response(200, json={"status": "OK", "total": len(data), "data": data})
        return httpx.Response(404)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ws")
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=0)}
    app = create_app(settings, background=False)
    feeds = Feeds()
    app.state.intel.transport = httpx.MockTransport(feeds)
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords, feeds


def client(env, email):
    app, passwords = env[0], env[1]
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


def jquery(c):
    rcs = c.get("/api/root-causes").json()["root_causes"]
    return next(r for r in rcs if "CVE-2020-11023" in {x["id"] for x in r["cves"]})


def test_live_kev_and_epss_replace_the_sample(env):
    app, _, feeds = env
    vm = client(env, VM)
    before = vm.get("/api/data/intel").json()
    assert not before["live"] and not before["kev"]
    rc = jquery(vm)
    # The sample list knows only CVE-2020-11022 (public exploit), so the root cause is "poc", labelled as a sample.
    assert rc["exploitation"] == "poc"
    assert {c["source"] for c in rc["cves"] if c["exploitation"] != "none"} == {"sample"}

    assert client(env, MANAGER).post("/api/data/intel/refresh").status_code == 403
    out = vm.post("/api/data/intel/refresh").json()
    assert out["results"]["kev"] == {"ok": True, "count": 20}
    assert out["live"] and out["kev"]["catalog_version"] == "2026.10.08"
    assert out["with_epss"] == sum(len(b) for b in feeds.epss_calls) > 0

    rc = jquery(vm)
    cves = {c["id"]: c for c in rc["cves"]}
    assert rc["exploitation"] == "active"  # CISA lists CVE-2020-11023
    kev = cves["CVE-2020-11023"]
    assert kev["source"] == "CISA KEV" and kev["kev_added"] and not kev["ransomware"]
    assert kev["name"] == "JQuery Cross-Site Scripting (XSS) Vulnerability"
    assert cves["CVE-2020-11022"]["source"] == "curated"  # public exploit code: the curated list, still labelled
    assert all("epss" in c and 0 <= c["epss"] <= 1 for c in rc["cves"])

    log4j = next(r for r in vm.get("/api/root-causes").json()["root_causes"]
                 if "CVE-2021-44228" in {x["id"] for x in r["cves"]})
    assert {c["id"]: c for c in log4j["cves"]}["CVE-2021-44228"]["ransomware"] is True
    headline = vm.post("/api/headline", json={"query": "CVE-2021-44228"}).json()
    assert headline["intel"]["source"] == "CISA KEV" and "epss" in headline["intel"]
    audit = client(env, ADMIN).get("/api/audit").json()
    assert "data.intel_refresh" in {e["action"] for e in audit["events"]}


def test_a_failed_or_malformed_feed_keeps_the_last_good_copy(env):
    app, _, feeds = env
    vm = client(env, VM)
    try:
        feeds.kev = 503
        out = vm.post("/api/data/intel/refresh").json()
        assert not out["results"]["kev"]["ok"] and "503" in out["kev"]["error"]
        assert out["live"] and out["kev"]["count"] == 20  # still the catalog fetched earlier
        feeds.kev = json.dumps({"title": "x", "vulnerabilities": [{"cveID": "not a cve"}] * 10}).encode()
        out = vm.post("/api/data/intel/refresh").json()
        assert "do not look like CVE records" in out["kev"]["error"]
        assert jquery(vm)["exploitation"] == "active"
    finally:
        feeds.kev = KEV
    out = vm.post("/api/data/intel/refresh").json()
    assert out["results"]["kev"]["ok"] and out["kev"]["error"] == ""


def test_epss_is_asked_in_batches_and_a_restart_keeps_the_feeds(env, tmp_path):
    feeds = Feeds()
    store = intel.IntelStore(tmp_path, transport=httpx.MockTransport(feeds))
    cves = {f"CVE-2024-{n:05d}" for n in range(250)} | {"not-a-cve"}
    assert store.fetch_epss(cves) == 250
    assert [len(b) for b in feeds.epss_calls] == [100, 100, 50]
    assert store.due()
    store.fetch_kev()
    assert not store.due()
    again = intel.IntelStore(tmp_path).build()  # read back from disk, as after a restart
    assert again["CVE-2021-44228"]["exploitation"] == "active"
    assert again["CVE-2024-00001"] == {"exploitation": "none", "epss": 0.01234, "epss_percentile": 0.78,
                                       "epss_date": "2026-10-10"}
