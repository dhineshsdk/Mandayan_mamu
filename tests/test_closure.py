"""Milestone 3, verified closure: a job goes from the team through approvals to "fixed" on rescan with no manual
status edit; a job whose findings are still reported stays open; closed jobs reopen if the findings come back."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli, closure
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AssetSnapshot, Dataset, Job, JobCheck, Observation

D = "vindhyapower.example"
LINUX, UNIT2 = f"it.infra.linux.team@{D}", f"c.i.unit.2.team@{D}"
MANAGER, VM, HEAD = f"arjun.mehta@{D}", f"aisha.khan@{D}", f"neha.joshi@{D}"


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


def task(c, words):
    return next(t for t in c.get("/api/portal").json()["teams"][0]["tasks"] if words in t["title"])


@pytest.fixture(scope="module")
def jobs(env):
    """Month 0: raise and fully approve a Log4j job and a RHEL image job, and a manual fix on the plant HMIs.
    Then import month 1, in which Log4j is gone everywhere (sutra.synth.FIXED_IN_FOLLOWUP)."""
    team = client(env, LINUX)
    out = {}
    for name, words in (("log4j", "Log4j"), ("rhel", "rhel8-base-v3")):
        j = team.post("/api/jobs", json={"rc_id": task(team, words)["id"], "team": "IT Infra - Linux",
                                         "mode": "patch"}).json()
        for who in (MANAGER, VM, HEAD)[:len(j["steps"])]:
            r = client(env, who).post(f"/api/jobs/{j['pk']}/decision", json={"action": "approve"})
            assert r.status_code == 200, r.text
        assert r.json()["status"] == "approved"
        out[name] = j
    plant = client(env, UNIT2)
    out["hmi"] = plant.post("/api/jobs", json={"rc_id": task(plant, "hmi-win7e")["id"], "team": "C&I - Unit 2",
                                               "mode": "manual", "ticket": "CHG-4411"}).json()
    assert client(env, VM).post("/api/data/demo", json={"profile": "power", "month": 1}).status_code == 200
    return out


def test_job_closes_when_the_rescan_proves_the_fix(env, jobs):
    j = client(env, LINUX).get(f"/api/jobs/{jobs['log4j']['pk']}").json()
    assert j["status"] == "verified-fixed"
    app, _ = env
    with app.state.sessionmaker() as db:
        latest = db.scalars(select(Dataset).order_by(Dataset.id.desc())).first()
    assert j["fixed_on"] == latest.as_of.isoformat() and j["closed_at"]
    assert j["checks"][-1]["outcome"] == "fixed" and j["checks"][-1]["still_open"] == 0
    assert j["checks"][-1]["fixed"] == j["targets"] > 0
    assert "job.rescan_fixed" in [a["action"] for a in j["audit"]]


def test_job_stays_open_while_findings_are_still_reported(env, jobs):
    for name, status in (("rhel", "approved"), ("hmi", "fixing-manually")):
        j = client(env, VM).get(f"/api/jobs/{jobs[name]['pk']}").json()
        assert j["status"] == status
        assert j["checks"][-1]["outcome"] in ("not-fixed", "partly-fixed") and j["checks"][-1]["still_open"] > 0
        assert j["fixed_on"] is None


def test_nobody_can_set_a_job_fixed_by_hand(env, jobs):
    for action in ("fixed", "close", "verified-fixed"):
        r = client(env, MANAGER).post(f"/api/jobs/{jobs['rhel']['pk']}/decision", json={"action": action})
        assert r.status_code == 422


def _later_import(db, days, present):
    """An import ``days`` after the latest, whose scans report ``present`` and scanned every earlier asset."""
    latest = db.scalars(select(Dataset).order_by(Dataset.id.desc())).first()
    ds = Dataset(org_name=latest.org_name, kind="upload", files=[], is_current=False,
                 as_of=latest.as_of + timedelta(days=days), summary={})
    db.add(ds)
    db.flush()
    for a in db.scalars(select(AssetSnapshot.asset_id).where(AssetSnapshot.dataset_id == latest.id)):
        db.add(AssetSnapshot(dataset_id=ds.id, asset_id=a, scanned=True))
    for a, fp in present:
        db.add(Observation(dataset_id=ds.id, asset_id=a, fingerprint=fp))
    db.flush()
    return ds


def test_a_closed_job_reopens_when_its_findings_return(env, jobs):
    app, _ = env
    with app.state.sessionmaker() as db:
        job = db.get(Job, jobs["log4j"]["pk"])
        back = [tuple(job.targets[0])]
        closure.verify(db, _later_import(db, 30, back))
        assert job.status == "reopened" and job.fixed_on is None
        # An older file uploaded late does not close it again.
        closure.verify(db, _later_import(db, -45, []))
        assert job.status == "reopened"
        outcomes = db.scalars(select(JobCheck.outcome).where(JobCheck.job_id == job.id).order_by(JobCheck.id)).all()
        assert outcomes == ["fixed", "reopened"]
        # The next clean rescan closes it again.
        closure.verify(db, _later_import(db, 60, []))
        assert job.status == "verified-fixed"
        db.rollback()


def test_a_host_that_was_not_rescanned_proves_nothing(env, jobs):
    app, _ = env
    with app.state.sessionmaker() as db:
        job = db.get(Job, jobs["rhel"]["pk"])
        latest = db.scalars(select(Dataset).order_by(Dataset.id.desc())).first()
        ds = Dataset(org_name="x", kind="upload", files=[], is_current=False,
                     as_of=latest.as_of + timedelta(days=30), summary={})
        db.add(ds)
        db.flush()  # no snapshots: nothing was scanned, nothing reported
        closure.verify(db, ds)
        check = db.scalars(select(JobCheck).where(JobCheck.job_id == job.id, JobCheck.dataset_id == ds.id)).one()
        assert check.outcome == "not-rescanned" and check.fixed == 0 and job.status == "approved"
        db.rollback()
