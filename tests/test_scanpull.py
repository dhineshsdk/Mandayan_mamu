"""Milestone 4: scanner API pulls. A pull through the connectors gives the same analysis as the exported files, closes
a job whose fix the scanners confirm, imports nothing when any scanner fails, and never returns a stored secret.

The scanner APIs are played by a fake connector that serves the synthetic estate's next-month scans as API records;
the HTTP side of each connector is tested in ``connectors/tests``."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sutra_connectors import ScannerFinding, ScannerHost

from sutra import ingest, pipeline, synth
from sutra.app import cli, vault
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import Dataset, ScannerConnection, utcnow

D = "vindhyapower.example"
ADMIN, VM, LINUX, MANAGER, HEAD = (f"admin@{D}", f"aisha.khan@{D}", f"it.infra.linux.team@{D}",
                                   f"arjun.mehta@{D}", f"neha.joshi@{D}")


def _dt(d):
    return datetime(d.year, d.month, d.day) if d else None


class FakeScanner:
    """Serves the rows of one exported scan file as API records."""

    def __init__(self, path, fail=False):
        self.rows = ingest.LOADERS[ingest.detect_format(path)](path)
        self.source = f"fake-api:{path.name}"
        self.fail = fail

    def iter_findings(self, since=None):
        if self.fail:
            raise RuntimeError("HTTP 503 from the scanner")
        for r in self.rows:
            if r["kind"] == "info":
                continue
            yield ScannerFinding(scanner=r["scanner"], scanner_ref=r["ref"], source=self.source,
                                 record_id=f"{r['file']}:{r['row']}", ip=r["ip"], hostname=r["host"], os=r["os"],
                                 title=r["title"], severity=r["severity"], cvss=r["cvss"], cves=tuple(r["cves"]),
                                 port=r["port"], protocol="tcp", evidence=r["evidence"], solution=r["solution"],
                                 state="open", first_seen=_dt(r["first"]), last_seen=_dt(r["last"]))

    def iter_hosts(self, since=None):
        seen = {}
        for r in self.rows:
            key = (r["ip"], r["host"])
            last = seen.get(key)
            seen[key] = max(filter(None, (last, r["last"])), default=None)
        for (ip, host), last in seen.items():
            yield ScannerHost(scanner=self.rows[0]["scanner"], source=self.source, host_id=ip or host,
                              ips=(ip,) if ip else (), hostnames=(host,) if host else (), os="", first_seen=None,
                              last_seen=_dt(last))

    def close(self):
        pass


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ws")
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    month1 = synth.generate(tmp_path_factory.mktemp("m1"), profile="power", month=1)
    scans = [p for k, p in month1.items() if ingest.detect_format(p) in ("qualys", "tenable", "nessus")]
    app = create_app(settings, background=False)
    state = {"fail": set()}
    files = {}

    def factory(conn, secret, transport=None):
        assert secret == f"secret-{conn.name}"  # decrypted from the database
        return FakeScanner(files[conn.name], fail=conn.name in state["fail"])

    app.state.puller.factory = factory
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords, scans, files, state, month1


def client(env, email):
    app, passwords = env[0], env[1]
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


def add(env, admin, name, kind, path):
    env[3][name] = path
    url = {"qualys": "https://qualysapi.qg1.apps.qualys.in", "tenable_vm": "", "tenable_sc": "https://sc.example.in"}
    r = admin.post("/api/data/connections", json={"kind": kind, "name": name, "base_url": url[kind],
                                                   "username": "svc-sutra", "secret": f"secret-{name}"})
    assert r.status_code == 201, r.text
    return r.json()


def test_connections_are_admin_only_and_secrets_never_leave(env):
    app = env[0]
    admin = client(env, ADMIN)
    assert client(env, VM).post("/api/data/connections", json={}).status_code == 403
    bad = admin.post("/api/data/connections", json={"kind": "qualys", "name": "x", "base_url": "http://q.example",
                                                    "username": "u", "secret": "s"})
    assert bad.status_code == 400 and "https://" in bad.json()["error"]
    names = {"qualys": "Qualys", "tenable": "Tenable SC", "nessus": "Plant Nessus"}
    kinds = {"qualys": "qualys", "tenable": "tenable_sc", "nessus": "tenable_sc"}
    for path in env[2]:
        fmt = ingest.detect_format(path)
        c = add(env, admin, names[fmt], kinds[fmt], path)
        assert c["has_secret"] and "secret" not in c
    listing = client(env, VM).get("/api/data/connections").json()
    assert "secret-" not in json.dumps(listing)
    assert listing["connections"][0]["base_url"] == "https://qualysapi.qg1.apps.qualys.in"
    with app.state.sessionmaker() as db:
        stored = db.scalars(select(ScannerConnection.secret)).first()
    assert "secret-" not in stored  # encrypted at rest


def test_a_failed_scanner_imports_nothing(env):
    app, _, _, _, state, _ = env
    with app.state.sessionmaker() as db:
        before = db.scalars(select(Dataset.id).order_by(Dataset.id.desc())).first()
    state["fail"] = {"Qualys"}
    try:
        pull = client(env, VM).post("/api/data/pulls")
        assert pull.status_code == 202
        _wait(app)  # the pull runs on a thread
        done = client(env, VM).get(f"/api/data/pulls/{pull.json()['pull']}").json()
    finally:
        state["fail"] = set()
    assert done["status"] == "failed" and done["dataset"] is None
    assert any("503" in r["error"] for r in done["results"])
    with app.state.sessionmaker() as db:
        assert db.scalars(select(Dataset.id).order_by(Dataset.id.desc())).first() == before


def _wait(app, seconds=60):
    deadline = utcnow() + timedelta(seconds=seconds)
    while app.state.puller.busy() and utcnow() < deadline:
        time.sleep(0.05)
    assert not app.state.puller.busy()


def test_api_pull_matches_the_files_and_closes_a_proved_fix(env):
    app, _, scans, _, _, month1 = env
    team = client(env, LINUX)
    task = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if "Log4j" in t["title"])
    j = team.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "patch"}).json()
    for who in (MANAGER, VM, HEAD)[:len(j["steps"])]:
        assert client(env, who).post(f"/api/jobs/{j['pk']}/decision", json={"action": "approve"}).status_code == 200
    pull = client(env, VM).post("/api/data/pulls").json()["pull"]
    _wait(app)
    done = client(env, VM).get(f"/api/data/pulls/{pull}").json()
    assert done["status"] == "ok", done
    with app.state.sessionmaker() as db:
        ds = db.get(Dataset, done["dataset"])
        assert ds.kind == "api" and ds.is_current
        assert {f["format"] for f in ds.files} == {"rows", "cmdb"}  # the asset register is carried over
    # Same analysis as importing the exported files of the same month.
    files_res = pipeline.run(scans, month1["cmdb"])
    api_res = app.state.analysis.result
    assert len(api_res.findings) == len(files_res.findings)
    assert sorted(r.key for r in api_res.root_causes) == sorted(r.key for r in files_res.root_causes)
    assert {a for a, x in api_res.assets.items() if x.scanned_by} == \
        {a for a, x in files_res.assets.items() if x.scanned_by}
    job = team.get(f"/api/jobs/{j['pk']}").json()
    assert job["status"] == "verified-fixed"
    audit = client(env, ADMIN).get("/api/audit").json()
    assert "data.pull" in {e["action"] for e in audit["events"]}


def test_only_one_pull_at_a_time_and_schedule(env):
    app = env[0]
    admin = client(env, ADMIN)
    assert admin.put("/api/data/connections-schedule", json={"enabled": True, "hour": 2}).status_code == 200
    assert client(env, VM).put("/api/data/connections-schedule", json={"enabled": False, "hour": 2}).status_code == 403
    puller = app.state.puller
    with app.state.sessionmaker() as db:
        last = db.scalars(select(Dataset.created_at).order_by(Dataset.id.desc())).first()
        # 01:00 IST is before the slot; 02:30 IST the next day is due, unless a pull started after 02:00 IST.
        day = (last + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        assert not puller.due(db, day - timedelta(hours=5, minutes=30) + timedelta(hours=1))
        assert puller.due(db, day - timedelta(hours=5, minutes=30) + timedelta(hours=2, minutes=30))
    assert puller._lock.acquire(blocking=False)
    try:
        assert client(env, VM).post("/api/data/pulls").status_code == 409
    finally:
        puller._lock.release()


def test_vault_refuses_a_different_server_key():
    sealed = vault.seal("key-one", "s3cret")
    assert vault.open_("key-one", sealed) == "s3cret"
    with pytest.raises(vault.CannotDecrypt):
        vault.open_("key-two", sealed)


def test_crowdstrike_pull_through_the_real_connector(tmp_path):
    """A CrowdStrike connection pulled with the real connector against a fake Falcon API (the connector's own test
    double and fixtures, which come from Elastic's CrowdStrike integration test data)."""
    import sys
    from pathlib import Path

    import httpx

    sys.path.insert(0, str(Path(__file__).parents[1] / "connectors" / "tests"))
    try:
        from test_crowdstrike import FakeFalcon
    finally:
        sys.path.pop(0)
    settings = Settings(workspace=tmp_path, database_url=f"sqlite:///{tmp_path / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=0)}
    app = create_app(settings, background=False)
    app.state.puller.transport = httpx.MockTransport(FakeFalcon())
    with TestClient(app, base_url="https://testserver"):
        env = (app, passwords)
        r = client(env, ADMIN).post("/api/data/connections", json={
            "kind": "crowdstrike", "name": "Falcon", "base_url": "", "username": "client-id", "secret": "s3cret"})
        assert r.status_code == 201 and r.json()["base_url"] == "https://api.crowdstrike.com"
        pull = client(env, VM).post("/api/data/pulls").json()["pull"]
        _wait(app)
        done = client(env, VM).get(f"/api/data/pulls/{pull}").json()
    # Both fixture hosts last reported in 2025 or earlier, more than 30 days ago, so neither counts as assessed now.
    assert done["status"] == "ok", done
    assert done["results"][0]["findings"] == 3 and done["results"][0]["hosts"] == 0
    res = app.state.analysis.result
    kb = next(f for f in res.findings if f.fixed == "KB5053594")
    assert kb.package == "Microsoft Windows OS patch"


def test_aws_inspector_pull_through_the_real_connector(tmp_path):
    """An Amazon Inspector connection pulled with the real connector against the connector's own fake API (fixtures
    from Elastic's AWS Inspector integration test data)."""
    import sys
    from pathlib import Path

    import httpx

    sys.path.insert(0, str(Path(__file__).parents[1] / "connectors" / "tests"))
    try:
        from test_aws_inspector import FakeInspector
    finally:
        sys.path.pop(0)
    settings = Settings(workspace=tmp_path, database_url=f"sqlite:///{tmp_path / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=0)}
    app = create_app(settings, background=False)
    app.state.puller.transport = httpx.MockTransport(FakeInspector())
    with TestClient(app, base_url="https://testserver"):
        env = (app, passwords)
        admin = client(env, ADMIN)
        bad = admin.post("/api/data/connections", json={
            "kind": "aws_inspector", "name": "AWS", "base_url": "https://inspector.example.com",
            "username": "AKIDEXAMPLE", "secret": "s3cret"})
        assert bad.status_code == 400 and "Inspector's endpoint" in bad.json()["error"]
        r = admin.post("/api/data/connections", json={
            "kind": "aws_inspector", "name": "AWS Mumbai", "base_url": "", "username": "AKIDEXAMPLE",
            "secret": "s3cret"})
        assert r.status_code == 201 and r.json()["base_url"] == "https://inspector2.ap-south-1.amazonaws.com"
        pull = client(env, VM).post("/api/data/pulls").json()["pull"]
        _wait(app)
        done = client(env, VM).get(f"/api/data/pulls/{pull}").json()
    # 35 package findings, one of them closed; the coverage records were last scanned in 2025, so none is current.
    assert done["status"] == "ok", done
    assert done["results"][0]["findings"] == 34 and done["results"][0]["hosts"] == 0
    res = app.state.analysis.result
    # One Inspector finding names openssh, openssh-clients and openssh-server: one Sutra finding (they share the
    # CVE on one host) that keeps all three as sources, with the epoch stripped from the fixed version.
    (ssh,) = [f for f in res.findings if "CVE-2025-32728" in f.cves]
    assert len(ssh.sources) == 3 and ssh.fixed == "7.4p1-22.amzn2.0.10"
