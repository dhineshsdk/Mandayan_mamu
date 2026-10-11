"""SLA timers: approval steps that stall are escalated to the next approver once, and fixes that miss their due
date are recorded as breaches. Escalation informs; it never lets anyone sign a step that is not theirs."""

from __future__ import annotations

from datetime import datetime, time, timedelta

import pytest
from fastapi.testclient import TestClient

from sutra.app import cli, drafting, sweeper
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import Job

D = "vindhyapower.example"
LINUX, MANAGER, VM, HEAD, CISO, ADMIN = (f"it.infra.linux.team@{D}", f"arjun.mehta@{D}", f"aisha.khan@{D}",
                                         f"neha.joshi@{D}", f"ciso@{D}", f"admin@{D}")


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


def raise_job(c, words):
    task = next(t for t in c.get("/api/portal").json()["teams"][0]["tasks"] if words in t["title"])
    r = c.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "patch"})
    assert r.status_code == 201, r.text
    return r.json()


def opened(app, pk, position=0):
    with app.state.sessionmaker() as db:
        job = db.get(Job, pk)
        step = next(s for s in job.steps if s.position == position)
        return step.opened_at


def test_a_stalled_step_is_escalated_once_to_the_next_approver(env):
    app, _ = env
    job = raise_job(client(env, LINUX), "Tomcat")  # Attend: manager, VM analyst, vertical head
    assert job["due_on"] == (drafting.today() + timedelta(days=30)).isoformat()
    start = opened(app, job["pk"])
    assert sweeper.sweep(app.state.sessionmaker, start + timedelta(hours=47))["escalated"] == 0
    assert sweeper.sweep(app.state.sessionmaker, start + timedelta(hours=49))["escalated"] == 1
    assert sweeper.sweep(app.state.sessionmaker, start + timedelta(hours=60))["escalated"] == 0  # once only

    vm = client(env, VM)
    listing = vm.get("/api/jobs").json()
    assert job["pk"] in [j["pk"] for j in listing["escalated_to_me"]]
    assert job["pk"] not in [j["pk"] for j in listing["waiting_for_me"]]
    assert vm.post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"}).status_code == 403
    detail = vm.get(f"/api/jobs/{job['pk']}").json()
    assert detail["steps"][0]["escalated_to"] == "VM analyst"
    assert "job.step_escalated" in [a["action"] for a in detail["audit"]]
    # Someone else's team: not escalated to them.
    other = client(env, f"karan.malhotra@{D}").get("/api/jobs").json()
    assert job["pk"] not in [j["pk"] for j in other["escalated_to_me"]]

    # The manager signs; the VM analyst's step starts its own clock.
    assert client(env, MANAGER).post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"}).status_code == 200
    assert vm.post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"}).status_code == 200
    # The last step escalates to the CISO.
    head_opened = opened(app, job["pk"], 2)
    assert sweeper.sweep(app.state.sessionmaker, head_opened + timedelta(hours=73))["escalated"] == 1
    assert job["pk"] in [j["pk"] for j in client(env, CISO).get("/api/jobs").json()["escalated_to_me"]]
    assert job["pk"] in [j["pk"] for j in client(env, HEAD).get("/api/jobs").json()["waiting_for_me"]]


def test_a_missed_fix_date_is_a_breach_and_the_job_stays_open(env):
    app, _ = env
    job = raise_job(client(env, LINUX), "Self-signed")  # Track: 180 days
    due = datetime.fromisoformat(job["due_on"]).date()
    noon = datetime.combine(due, time(6, 30))  # 12:00 IST
    team = client(env, LINUX)
    sweeper.sweep(app.state.sessionmaker, noon)
    assert not team.get(f"/api/jobs/{job['pk']}").json()["sla_breached"]  # on time through its due date
    sweeper.sweep(app.state.sessionmaker, noon + timedelta(days=1))
    sweeper.sweep(app.state.sessionmaker, noon + timedelta(days=2))
    detail = team.get(f"/api/jobs/{job['pk']}").json()
    assert detail["sla_breached"] and detail["status"] == "pending"
    assert [a["action"] for a in detail["audit"]].count("job.sla_breached") == 1


def test_service_levels_are_set_by_the_customer(env):
    admin = client(env, ADMIN)
    cfg = admin.get("/api/admin/sla").json()
    assert cfg["sla"]["fix_days"]["Act"] == 14
    bad = {"step_hours": {"manager": 0}, "fix_days": {}}
    assert admin.put("/api/admin/sla", json=bad).status_code == 400
    assert admin.put("/api/admin/sla", json={"step_hours": {}, "fix_days": {"Attend": 10}}).status_code == 200
    assert admin.get("/api/admin/sla").json()["sla"]["fix_days"] == {"Act": 14, "Attend": 10, "Track*": 90,
                                                                       "Track": 180}
    team = client(env, LINUX)
    task = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if "rhel8-base" in t["title"])
    job = team.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "manual"}).json()
    assert job["due_on"] == (drafting.today() + timedelta(days=10)).isoformat()
