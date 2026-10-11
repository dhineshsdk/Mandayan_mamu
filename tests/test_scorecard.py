"""Milestone 3 exit check: on demo data a job goes from the team through approvals to "fixed" on rescan with no
manual status edit, and appears in the team's scorecard and the CISO dashboard. Scorecards are limited to the
person's scope."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from sutra.app import cli
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import Job, Observation

D = "vindhyapower.example"
LINUX, MANAGER, VM, HEAD, CISO = (f"it.infra.linux.team@{D}", f"arjun.mehta@{D}", f"aisha.khan@{D}",
                                  f"neha.joshi@{D}", f"ciso@{D}")


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
def fixed_job(env):
    team = client(env, LINUX)
    before = client(env, MANAGER).get("/api/scorecards").json()["teams"][0]
    task = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if "Log4j" in t["title"])
    j = team.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "patch"}).json()
    for who in (MANAGER, VM, HEAD)[:len(j["steps"])]:
        r = client(env, who).post(f"/api/jobs/{j['pk']}/decision", json={"action": "approve"})
        assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved"
    during = client(env, MANAGER).get("/api/scorecards").json()["teams"][0]
    assert during["jobs_open"] == before["jobs_open"] + 1
    assert during["without_job"] < before["without_job"]  # the Log4j findings now have a job
    # The next month's scans: Log4j is gone (sutra.synth.FIXED_IN_FOLLOWUP). Nobody edits the status.
    assert client(env, VM).post("/api/data/demo", json={"profile": "power", "month": 1}).status_code == 200
    return client(env, LINUX).get(f"/api/jobs/{j['pk']}").json()


def test_the_fix_reaches_the_team_scorecard(env, fixed_job):
    app, _ = env
    assert fixed_job["status"] == "verified-fixed"
    card = client(env, MANAGER).get("/api/scorecards").json()
    assert [t["team"] for t in card["teams"]] == ["IT Infra - Linux"] and not card["org_wide"]
    linux = card["teams"][0]
    assert linux["fixed"] == 1 and linux["jobs_open"] == 0 and linux["fixed_on_time"] == 1
    with app.state.sessionmaker() as db:
        job = db.get(Job, fixed_job["pk"])
        first = db.scalar(select(func.min(Observation.first_seen)).where(
            Observation.dataset_id == job.dataset_id, Observation.rc_key == job.rc_key,
            Observation.asset_id.in_(job.hosts)))
    assert linux["median_days_to_fix"] == (job.fixed_on - first).days > 0
    assert linux["on_time_pct"] == 100


def test_ciso_sees_every_team_and_plant(env, fixed_job):
    app, _ = env
    card = client(env, CISO).get("/api/scorecards").json()
    assert card["org_wide"]
    assert card["totals"]["open_findings"] == len(app.state.analysis.result.findings)
    assert sum(t["open_findings"] for t in card["teams"]) == card["totals"]["open_findings"]
    assert card["totals"]["fixed"] == 1
    assert {"IT Infra - Linux", "C&I - Unit 2"} <= {t["team"] for t in card["teams"]}
    assert "Vindhya Thermal Plant" in {p["site"] for p in card["plants"]}
    assert [p["as_of"] for p in card["trend"]] == sorted(p["as_of"] for p in card["trend"])
    assert len(card["trend"]) == 2 and card["trend"][-1]["open_findings"] == card["totals"]["open_findings"]


def test_vertical_head_sees_only_their_vertical(env, fixed_job):
    card = client(env, HEAD).get("/api/scorecards").json()
    verticals = {t["vertical"] for t in card["teams"]}
    assert verticals == {"Corporate IT"}
    assert "C&I - Unit 2" not in {t["team"] for t in card["teams"]}
