"""Milestone 2 exit check: two imports a month apart show what was fixed, what is new and what is still open,
per team. Uses the synthetic power company: month 0, then the same estate 30 days later (sutra.synth)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra import synth
from sutra.app import cli
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AssetSnapshot, Dataset, Observation

D = "vindhyapower.example"
VM, MEMBER, EXEC = f"aisha.khan@{D}", f"it.infra.linux.team@{D}", f"executive@{D}"


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


@pytest.fixture(scope="module")
def two_months(env):
    """Raise a job on month 0, then import month 1 through the API, as an analyst would."""
    app, _ = env
    member = client(env, MEMBER)
    portal = member.get("/api/portal").json()
    task = next(t for t in portal["teams"][0]["tasks"] if not t["is_ot"])
    job = member.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "manual",
                                         "ticket": "CHG0001"}).json()
    r = client(env, VM).post("/api/data/demo", json={"profile": "power", "month": 1})
    assert r.status_code == 200, r.text
    with app.state.sessionmaker() as db:
        old, new = db.scalars(select(Dataset).order_by(Dataset.id)).all()[-2:]
    return {"job": job, "task": task, "old": old, "new": new}


def test_every_import_is_kept_with_both_timestamps(env, two_months):
    old, new = two_months["old"], two_months["new"]
    assert (new.as_of - old.as_of).days == 30
    assert new.created_at >= old.created_at
    app, _ = env
    with app.state.sessionmaker() as db:
        for ds in (old, new):
            n = len(db.scalars(select(Observation.id).where(Observation.dataset_id == ds.id)).all())
            assert n == ds.summary["findings"] > 0


def test_changes_per_team_fixed_new_and_still_open(env, two_months):
    out = client(env, VM).get("/api/history/changes").json()
    assert out["from"]["id"] == two_months["old"].id and out["to"]["id"] == two_months["new"].id
    t = out["totals"]
    assert t["fixed"] > 0 and t["new"] > 0 and t["still_open"] > 0
    teams = {x["team"]: x for x in out["teams"]}
    # Synthetic story (sutra.synth.FIXED_IN_FOLLOWUP): Log4j was fixed everywhere in month 1.
    fixed_titles = [i["title"] for x in out["teams"] for i in x["items"]["fixed"]]
    assert any("log4j" in s.lower() for s in fixed_titles)
    remaining = [i for x in out["teams"] for i in x["items"]["still_open"] + x["items"]["new"]]
    assert not any("log4j" in i["title"].lower() for i in remaining)
    # New this month: the Chrome flaw (sutra.synth.FOLLOWUP_NEW) on laptops.
    new_titles = [i["title"] for x in out["teams"] for i in x["items"]["new"]]
    assert new_titles and all("chrome" in s.lower() for s in new_titles)
    # OT findings wait for a shutdown, so plant teams have nothing fixed.
    assert teams["C&I - Unit 2"]["fixed"] == 0 and teams["C&I - Unit 2"]["still_open"] > 0
    # Per-team counts add up to the totals.
    for k in ("fixed", "new", "still_open", "not_rescanned"):
        assert sum(x[k] for x in out["teams"]) == t[k]


def test_counts_match_the_two_imports(env, two_months):
    out = client(env, VM).get("/api/history/changes").json()
    t = out["totals"]
    assert t["still_open"] + t["fixed"] + t["not_rescanned"] == two_months["old"].summary["findings"]
    assert t["still_open"] + t["new"] == two_months["new"].summary["findings"]


def test_team_sees_only_its_own_changes(env, two_months):
    out = client(env, MEMBER).get("/api/history/changes").json()
    assert [x["team"] for x in out["teams"]] == ["IT Infra - Linux"]
    assert out["detail"] is True


def test_board_only_people_get_totals_without_hosts(env, two_months):
    out = client(env, EXEC).get("/api/history/changes").json()
    assert out["detail"] is False and "items" not in out["teams"][0]


def test_first_seen_survives_a_scan_without_history(env, two_months):
    """.nessus files carry no first-seen date; the earlier import keeps the finding's age."""
    app, _ = env
    old, new = two_months["old"], two_months["new"]
    with app.state.sessionmaker() as db:
        before = {(o.asset_id, o.fingerprint): o for o in db.scalars(select(Observation)
                                                                     .where(Observation.dataset_id == old.id))}
        after = {(o.asset_id, o.fingerprint): o for o in db.scalars(select(Observation)
                                                                    .where(Observation.dataset_id == new.id))}
        both = before.keys() & after.keys()
        assert both
        for k in both:
            assert after[k].first_seen == before[k].first_seen
            assert after[k].first_imported_at == before[k].first_imported_at
        ot = [k for k in both if after[k].site == "Vindhya Thermal Plant"]
        # Without the earlier import these would read as first seen on the month-1 scan date.
        assert ot and all(after[k].first_seen <= old.as_of for k in ot)
        assert any((new.as_of - after[k].first_seen).days >= 180 for k in ot)  # seen in the baseline scan


def test_unregistered_hosts_keep_their_id(env, two_months):
    app, _ = env
    with app.state.sessionmaker() as db:
        ids = [set(db.scalars(select(AssetSnapshot.asset_id).where(AssetSnapshot.dataset_id == d.id,
                                                                   AssetSnapshot.in_cmdb.is_(False))))
               for d in (two_months["old"], two_months["new"])]
    assert ids[0] and ids[0] == ids[1]


def test_unowned_assets_are_a_coverage_gap(env, two_months):
    assets = client(env, VM).get("/api/assets").json()
    unowned = set(assets["coverage"]["unowned"])
    assert set(assets["coverage"]["unknown"]) <= unowned
    board = client(env, EXEC).get("/api/board").json()
    assert board["coverage"]["unowned"] == len(unowned)


def test_jobs_survive_a_new_import(env, two_months):
    member = client(env, MEMBER)
    jobs = member.get("/api/jobs").json()["jobs"]
    assert two_months["job"]["pk"] in [j["pk"] for j in jobs]
    # Root-cause IDs are renumbered per import; the job is tied to the stable key.
    portal = member.get("/api/portal").json()
    same = [t for t in portal["teams"][0]["tasks"] if t["title"] == two_months["task"]["title"]]
    if same:  # still open in month 1: a second job for the same root cause is refused
        r = member.post("/api/jobs", json={"rc_id": same[0]["id"], "team": "IT Infra - Linux", "mode": "manual"})
        assert r.status_code == 409


def test_synthetic_followup_is_deterministic(tmp_path):
    a = synth.generate(tmp_path / "a", profile="power", month=1)
    b = synth.generate(tmp_path / "b", profile="power", month=1)
    for k in a:
        assert a[k].read_bytes() == b[k].read_bytes(), k
    assert "nessus_baseline" not in a
