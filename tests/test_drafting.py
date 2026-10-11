"""Patch-job drafts through sutra_patchdraft: cited drafts, windows from the maintenance policy, no invented
shutdown dates, and approvals that open only once a draft exists."""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sutra_patchdraft import template_only
from sutra_patchdraft.windows import SHUTDOWN_NOT_SET

from sutra.app import cli, drafting
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AuditEvent, Job

D = "vindhyapower.example"
LINUX, UNIT2, COAL = f"it.infra.linux.team@{D}", f"c.i.unit.2.team@{D}", f"c.i.coal.handling.team@{D}"
ADMIN, MANAGER = f"admin@{D}", f"arjun.mehta@{D}"


class SlowDrafter:
    """Stands in for a Claude-backed drafter: reports AI as available and holds each draft until released."""

    ai_available = True

    def __init__(self):
        self.release = threading.Event()
        self.inner = template_only()

    def draft(self, inp):
        assert self.release.wait(10)
        return self.inner.draft(inp)


def make_env(tmp_path_factory, drafter):
    ws = tmp_path_factory.mktemp("ws")
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    return create_app(settings, drafter=drafter), passwords


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    app, passwords = make_env(tmp_path_factory, template_only())
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords


def client(env, email):
    app, passwords = env
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


def raise_first(c, team, ot):
    task = next(t for t in c.get("/api/portal").json()["teams"][0]["tasks"] if t["is_ot"] == ot)
    r = c.post("/api/jobs", json={"rc_id": task["id"], "team": team, "mode": "patch"})
    assert r.status_code == 201, r.text
    return r.json()


def test_it_draft_is_cited_and_scheduled_after_today(env):
    job = raise_first(client(env, LINUX), "IT Infra - Linux", ot=False)
    d = job["draft"]
    assert job["status"] == "pending" and job["steps"][0]["state"] == "current"
    assert d["lane"] == "it" and d["source"] == "template" and d["executable"]
    assert d["fallback_reason"]  # says why no model was used
    assert set(d["target_asset_ids"]) <= set(job["hosts"]) and d["targets"]
    assert all(s["cites"] for s in d["steps"])
    first = drafting.today() + timedelta(days=(5 - drafting.today().weekday()) % 7 or 7)  # next Saturday
    assert d["rings"][0]["window"].startswith(f"{first:%a %d %b %Y}, 22:00")


def test_ot_plan_never_invents_a_shutdown_date(env):
    d = raise_first(client(env, UNIT2), "C&I - Unit 2", ot=True)["draft"]
    assert d["lane"] == "ot" and not d["executable"] and d["oem_approval"] == "Pending"
    assert d["window"] == SHUTDOWN_NOT_SET
    assert any("shutdown" in a.lower() for a in d["assumptions"])
    assert d["compensating_controls"]


def test_named_shutdown_and_window_come_from_the_policy(env):
    admin = client(env, ADMIN)
    m = admin.get("/api/admin/maintenance").json()
    assert "Vindhya Thermal Plant" in m["ot_sites"] and m["ai_drafting"] is False
    day = drafting.today() + timedelta(days=40)
    body = {"weekday": 6, "start": "01:30", "duration_hours": 3, "timezone_label": "IST",
            "ot_shutdowns": {"Vindhya Thermal Plant": day.isoformat()}}
    assert admin.put("/api/admin/maintenance", json={**body, "start": "25:00"}).status_code == 422
    assert admin.put("/api/admin/maintenance", json=body).status_code == 200
    d = raise_first(client(env, COAL), "C&I - Coal Handling", ot=True)["draft"]
    assert d["window"] == f"Planned shutdown {day:%a %d %b %Y}"
    app, _ = env
    with app.state.sessionmaker() as db:
        ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "admin.maintenance_changed")).one()
        assert ev.detail["after"]["ot_shutdowns"] == {"Vindhya Thermal Plant": day.isoformat()}
        policy = drafting.policy_for(db, {"Vindhya Thermal Plant", "Solar Park"})
        assert policy.ot_shutdown is None  # one slot cannot cover two sites
        assert policy.weekday == 6 and policy.duration_hours == 3


def test_nobody_approves_before_the_draft_exists(tmp_path_factory):
    slow = SlowDrafter()
    env = make_env(tmp_path_factory, slow)
    app, _ = env
    with TestClient(app, base_url="https://testserver"):
        job = raise_first(client(env, LINUX), "IT Infra - Linux", ot=False)
        assert job["status"] == "drafting" and job["draft"] is None
        assert all(s["state"] == "waiting" for s in job["steps"])
        mgr = client(env, MANAGER)
        r = mgr.post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
        assert r.status_code in (403, 409)
        # A second job for the same root cause is refused while the first is drafting.
        r = client(env, LINUX).post("/api/jobs", json={"rc_id": job["rc_id"], "team": "IT Infra - Linux",
                                                         "mode": "patch"})
        assert r.status_code == 409
        slow.release.set()
        app.state.drafts.wait(10)
        after = mgr.get(f"/api/jobs/{job['pk']}").json()
        assert after["status"] == "pending" and after["draft"]["lane"] == "it"
        assert after["steps"][0]["state"] == "current" and after["can_decide"]
        assert "job.drafted" in [a["action"] for a in after["audit"]]


def test_drafts_interrupted_by_a_restart_are_finished(env):
    app, _ = env
    job = raise_first(client(env, f"platform.engineering.team@{D}"), "Platform Engineering", ot=False)
    with app.state.sessionmaker() as db:
        j = db.get(Job, job["pk"])
        j.status, j.draft = "drafting", None
        for s in j.steps:
            s.state = "waiting"
        db.commit()
    drafting.resume(app.state.drafts, app.state.analysis.result)
    with app.state.sessionmaker() as db:
        j = db.get(Job, job["pk"])
        assert j.status == "pending" and j.draft["lane"] == "it" and j.steps[0].state == "current"
