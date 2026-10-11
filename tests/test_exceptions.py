"""Risk acceptance: a team asks to accept a root cause's risk until a date, the request goes through the approval
chain (with the CISO's final sign-off for SSVC Act), and the acceptance expires on its own."""

from __future__ import annotations

from datetime import datetime, time, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli, drafting, sweeper
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AuditEvent, Job

D = "vindhyapower.example"
NSEC, MANAGER, VM, HEAD, CISO = (f"network.security.team@{D}", f"meera.pillai@{D}", f"aisha.khan@{D}",
                                 f"neha.joshi@{D}", f"ciso@{D}")
WHY = "The vendor fix needs a firmware upgrade that waits for the next appliance refresh."


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ws")
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    app = create_app(settings)
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords


def client(env, email):
    app, passwords = env
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


def citrix(c):
    return next(t for t in c.get("/api/portal").json()["teams"][0]["tasks"] if "Citrix" in t["title"])


def request(c, rc_id, **kw):
    body = {"rc_id": rc_id, "team": "Network Security", "mode": "exception", "justification": WHY,
            "control": "WAF rule blocking the exploit path; admin interface reachable only from the jump host",
            "expires_on": (drafting.today() + timedelta(days=60)).isoformat(), **kw}
    return c.post("/api/jobs", json=body)


def test_a_request_must_say_why_what_holds_the_risk_and_until_when(env):
    team = client(env, NSEC)
    rc = citrix(team)["id"]
    today = drafting.today()
    assert request(team, rc, justification="because").status_code == 400
    assert request(team, rc, control=" ").status_code == 400
    assert request(team, rc, expires_on=today.isoformat()).status_code == 400
    assert request(team, rc, expires_on=(today + timedelta(days=366)).isoformat()).status_code == 400


def test_act_risk_needs_the_ciso_and_expires(env):
    app, _ = env
    team = client(env, NSEC)
    rc = citrix(team)["id"]
    r = request(team, rc)
    assert r.status_code == 201, r.text
    job = r.json()
    assert job["status"] == "pending" and job["ssvc"] == "Act" and job["draft"] is None
    assert [s["role"] for s in job["steps"]] == ["manager", "vm_analyst", "vertical_head", "ciso"]
    assert job["exception"]["justification"] == WHY
    assert request(team, rc).status_code == 409  # one request at a time
    # A fix may still be raised while the risk is (being) accepted.
    assert team.post("/api/jobs", json={"rc_id": rc, "team": "Network Security", "mode": "manual"}).status_code == 201

    ciso = client(env, CISO)
    assert ciso.post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"}).status_code == 403
    for who in (MANAGER, VM, HEAD):
        r = client(env, who).post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
        assert r.status_code == 200, r.text
    assert r.json()["status"] == "pending"  # still waiting for the CISO
    # The VM analyst cannot sign the CISO step too.
    assert client(env, VM).post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"}).status_code == 403
    r = ciso.post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
    assert r.status_code == 200 and r.json()["status"] == "accepted"

    expires = drafting.today() + timedelta(days=60)
    noon_ist = datetime.combine(expires, time(6, 30))  # 12:00 IST, as naive UTC
    assert sweeper.sweep(app.state.sessionmaker, noon_ist)["expired"] == 0  # good through its last day
    assert sweeper.sweep(app.state.sessionmaker, noon_ist + timedelta(days=1))["expired"] == 1
    with app.state.sessionmaker() as db:
        assert db.get(Job, job["pk"]).status == "expired"
        assert db.scalars(select(AuditEvent).where(AuditEvent.action == "job.exception_expired",
                                                   AuditEvent.target_id == str(job["pk"]))).one()
    # Expired, the team can ask again.
    assert request(team, rc).status_code == 201


def test_ciso_signs_only_risk_acceptance(env):
    """The CISO's approve right does not reach patch-job steps."""
    app, _ = env
    team = client(env, f"it.infra.linux.team@{D}")
    task = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if not t["is_ot"])
    job = team.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "patch"}).json()
    r = client(env, CISO).post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
    assert r.status_code == 403
