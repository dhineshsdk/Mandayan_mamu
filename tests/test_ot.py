"""OT plans: the plant engineer records OEM approval, the compensating control, the shutdown slot and the execution.
Only engineers of the job's plant can record; execution needs approvals, the OEM's yes and a slot; and recording an
execution never closes the job (a rescan does)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli, drafting
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import Outbox

D = "vindhyapower.example"
TEAM, MANAGER, VM, HEAD = (f"c.i.unit.2.team@{D}", f"suresh.patil@{D}", f"aisha.khan@{D}", f"p.venkatesh@{D}")
THERMAL, SOLAR = f"plant.engineer.vindhya.thermal.plant@{D}", f"plant.engineer.solar.park.jodhpur@{D}"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ws")
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    app = create_app(settings, background=False)
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords


def client(env, email):
    app, passwords = env
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


@pytest.fixture(scope="module")
def job(env):
    team = client(env, TEAM)
    task = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if "hmi-win7e" in t["title"])
    r = team.post("/api/jobs", json={"rc_id": task["id"], "team": "C&I - Unit 2", "mode": "patch"})
    assert r.status_code == 201, r.text
    assert r.json()["is_ot"]
    return r.json()


def today():
    return drafting.today()


def test_only_the_plants_engineers_see_the_plan(env, job):
    plans = client(env, THERMAL).get("/api/ot").json()["plans"]
    mine = next(p for p in plans if p["pk"] == job["pk"])
    assert mine["sites"] == ["Vindhya Thermal Plant"] and mine["stage"] == "approvals"
    assert mine["oem"] == "not-requested"
    solar = client(env, SOLAR)
    assert job["pk"] not in [p["pk"] for p in solar.get("/api/ot").json()["plans"]]
    assert solar.get(f"/api/ot/{job['pk']}").status_code == 404
    on = today().isoformat()
    assert solar.post(f"/api/ot/{job['pk']}/oem", json={"state": "requested", "on": on}).status_code == 404
    assert client(env, TEAM).post(f"/api/ot/{job['pk']}/oem", json={"state": "requested", "on": on}).status_code == 403


def test_oem_approval_needs_the_oems_reference(env, job):
    eng = client(env, THERMAL)
    url = f"/api/ot/{job['pk']}/oem"
    tomorrow = (today() + timedelta(days=1)).isoformat()
    assert eng.post(url, json={"state": "requested", "on": tomorrow}).status_code == 400
    r = eng.post(url, json={"state": "requested", "on": today().isoformat(), "reference": "SIE-CASE-1"})
    assert r.status_code == 200 and r.json()["plan"]["oem"]["state"] == "requested"
    assert eng.post(url, json={"state": "approved", "on": today().isoformat(), "reference": ""}).status_code == 200
    plan = eng.get(f"/api/ot/{job['pk']}").json()["plan"]
    assert plan["oem"]["reference"] == "SIE-CASE-1"  # kept from the request when the approval gives none
    assert eng.post(url, json={"state": "refused", "on": today().isoformat()}).status_code == 400  # needs a note


def test_execution_waits_for_approvals_and_a_slot(env, job):
    eng = client(env, THERMAL)
    run = {"on": today().isoformat(), "result": "applied"}
    r = eng.post(f"/api/ot/{job['pk']}/execution", json=run)
    assert r.status_code == 409 and "approved" in r.json()["error"]
    for who in (MANAGER, VM, HEAD):
        r = client(env, who).post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
        assert r.status_code == 200, r.text
    assert eng.get(f"/api/ot/{job['pk']}").json()["plan"]["stage"] == "slot"
    r = eng.post(f"/api/ot/{job['pk']}/execution", json=run)
    assert r.status_code == 409 and "slot" in r.json()["error"]

    slot = {"on": (today() - timedelta(days=1)).isoformat(), "start": "06:00", "hours": 36,
            "confirmed_with": "Shift charge engineer, Unit 2"}
    assert eng.post(f"/api/ot/{job['pk']}/slot", json=slot).status_code == 400  # not in the past
    slot["on"] = (today() + timedelta(days=10)).isoformat()
    assert eng.post(f"/api/ot/{job['pk']}/slot", json={**slot, "start": "6am"}).status_code == 400
    r = eng.post(f"/api/ot/{job['pk']}/slot", json=slot)
    assert r.status_code == 200 and r.json()["plan"]["stage"] == "ready"
    r = eng.post(f"/api/ot/{job['pk']}/control", json={"control": "Engineering VLAN ACL limits RDP to the jump host",
                                                       "on": today().isoformat()})
    assert r.status_code == 200 and r.json()["plan"]["control"]["on"] == today().isoformat()


def test_execution_is_recorded_but_only_a_rescan_closes_the_job(env, job):
    app, _ = env
    eng = client(env, THERMAL)
    url = f"/api/ot/{job['pk']}/execution"
    assert eng.post(url, json={"on": today().isoformat(), "result": "rolled-back"}).status_code == 400  # say why
    assert eng.post(url, json={"on": today().isoformat(), "result": "applied", "hosts": ["nope"]}).status_code == 400
    r = eng.post(url, json={"on": today().isoformat(), "result": "rolled-back",
                            "note": "HMI lost its OPC link after the update; restored from backup"})
    assert r.json()["plan"]["stage"] == "ready"  # still to do
    r = eng.post(url, json={"on": today().isoformat(), "result": "applied"})
    plan = r.json()["plan"]
    assert plan["stage"] == "executed" and len(plan["executions"]) == 2
    assert plan["executions"][-1]["hosts"] == job["hosts"]
    detail = client(env, TEAM).get(f"/api/jobs/{job['pk']}").json()
    assert detail["status"] == "approved"  # not fixed until a rescan says so
    assert detail["ot_plan"]["stage"] == "executed" and not detail["ot_plan"]["can_act"]
    actions = [a["action"] for a in detail["audit"]]
    for a in ("ot.oem_requested", "ot.oem_approved", "ot.slot_confirmed", "ot.control", "ot.executed"):
        assert a in actions
    with app.state.sessionmaker() as db:
        told = set(db.scalars(select(Outbox.recipient).where(Outbox.job_id == job["pk"], Outbox.event == "ot",
                                                             Outbox.kind == "email")))
    assert told == {TEAM, MANAGER}


def test_it_jobs_have_no_ot_plan(env):
    team = client(env, f"it.infra.linux.team@{D}")
    task = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if "Tomcat" in t["title"])
    j = team.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "patch"}).json()
    assert team.get(f"/api/jobs/{j['pk']}").json()["ot_plan"] is None
    assert client(env, THERMAL).get(f"/api/ot/{j['pk']}").status_code == 404
