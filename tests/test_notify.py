"""Notifications and tickets: who is told what, the exact requests sent to Jira, ServiceNow and Teams, retries, and
nothing invented when an integration is not configured. No network: httpx.MockTransport and a fake SMTP server."""

from __future__ import annotations

import json
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli, notify, sweeper
from sutra.app.config import Settings
from sutra.app.integrations import Senders
from sutra.app.main import create_app
from sutra.app.models import Job, Outbox, utcnow

D = "vindhyapower.example"
LINUX, MANAGER, VM, HEAD = (f"it.infra.linux.team@{D}", f"arjun.mehta@{D}", f"aisha.khan@{D}", f"neha.joshi@{D}")
SENT_MAIL: list = []


class FakeSMTP:
    def __init__(self, host, port, timeout=None, **kw):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        pass

    def send_message(self, msg):
        SENT_MAIL.append(msg)


class Recorder:
    """Plays Jira, ServiceNow and Teams. ``fail`` makes every request answer 503."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.fail = False
        self.next_issue = 100

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            return httpx.Response(503)
        path = request.url.path
        if request.url.host == "acme.atlassian.net":
            if path == "/rest/api/3/issue" and request.method == "POST":
                self.next_issue += 1
                return httpx.Response(201, json={"id": "1", "key": f"LNX-{self.next_issue}", "self": "x"})
            if path.endswith("/transitions") and request.method == "GET":
                moves = [{"id": "21", "name": "Start", "to": {"name": "In Progress"}},
                         {"id": "31", "name": "Resolve", "to": {"name": "Done"}}]
                return httpx.Response(200, json={"transitions": moves})
            return httpx.Response(204 if path.endswith("/transitions") else 201, json={})
        if request.url.host == "acme.service-now.com":
            if request.method == "POST":
                return httpx.Response(201, json={"result": {"sys_id": "a" * 32, "number": "CHG0030001"}})
            return httpx.Response(200, json={"result": {}})
        if request.url.host == "teams.example.in":
            return httpx.Response(202)
        return httpx.Response(404)

    def to(self, host, method=None):
        return [r for r in self.requests if r.url.host == host and (method is None or r.method == method)]


def configured(ws):
    return Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}", base_url="https://sutra.example.in",
                    smtp_host="smtp.example.in", smtp_from="sutra@vindhyapower.example",
                    teams_webhook_url="https://teams.example.in/workflows/abc",
                    jira_url="https://acme.atlassian.net", jira_user="svc-sutra@vindhyapower.example",
                    jira_token="token-1", jira_done_status="Done", servicenow_url="https://acme.service-now.com",
                    servicenow_user="svc_sutra", servicenow_password="pw-1")


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ws")
    settings = configured(ws)
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    app = create_app(settings, background=False)  # the test sends; no thread may reach the network
    rec = Recorder()
    senders = Senders(settings, transport=httpx.MockTransport(rec), smtp=FakeSMTP)
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords, rec, senders


def client(env, email):
    app, passwords = env[0], env[1]
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


def run(env, **kw):
    app, _, _, senders = env
    return notify.dispatch(app.state.sessionmaker, senders, **kw)


@pytest.fixture(scope="module")
def job(env):
    team = client(env, LINUX)
    task = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if "Tomcat" in t["title"])
    j = team.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "patch"}).json()
    assert j["jira"] == ""  # no key until Jira issues one
    SENT_MAIL.clear()
    run(env)
    return j


def test_raising_a_job_creates_the_jira_issue_and_servicenow_record(env, job):
    _, _, rec, _ = env
    create = rec.to("acme.atlassian.net", "POST")[0]
    assert create.url.path == "/rest/api/3/issue"
    assert create.headers["authorization"].startswith("Basic ")
    fields = json.loads(create.content)["fields"]
    assert fields["project"] == {"key": "LNX"} and fields["issuetype"] == {"name": "Task"}
    assert fields["summary"].startswith(f"[Sutra {job['id']}] Patch job: Apache Tomcat")
    assert fields["description"]["type"] == "doc"  # Atlassian Document Format on API v3
    assert "https://sutra.example.in/#/job/" in json.dumps(fields["description"])
    snow = rec.to("acme.service-now.com", "POST")[0]
    assert snow.url.path == "/api/now/table/change_request"
    assert json.loads(snow.content)["short_description"].startswith(f"[Sutra {job['id']}]")
    detail = client(env, LINUX).get(f"/api/jobs/{job['pk']}").json()
    assert detail["jira"] == "LNX-101" and detail["jira_url"] == "https://acme.atlassian.net/browse/LNX-101"
    assert detail["servicenow"] == "CHG0030001"
    # The manager is asked to decide, by email.
    assert [m["To"] for m in SENT_MAIL] == [MANAGER]
    assert "needs your decision as Manager" in SENT_MAIL[0].get_content()


def test_each_decision_tells_the_next_person_and_the_ticket(env, job):
    _, _, rec, _ = env
    SENT_MAIL.clear()
    client(env, MANAGER).post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
    run(env)
    assert [m["To"] for m in SENT_MAIL] == [VM]  # everyone holding the VM analyst role
    client(env, VM).post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
    client(env, HEAD).post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
    SENT_MAIL.clear()
    before = len(rec.requests)
    run(env)
    assert [m["To"] for m in SENT_MAIL] == [HEAD, LINUX]  # head asked; then the raiser told it is approved
    new = rec.requests[before:]
    comment = next(r for r in new if r.url.path == "/rest/api/3/issue/LNX-101/comment")
    assert "has every approval it needs" in json.dumps(json.loads(comment.content))
    note = next(r for r in new if r.url.host == "acme.service-now.com")
    assert note.method == "PATCH" and json.loads(note.content)["work_notes"].startswith(f"{job['id']} for IT Infra")


def test_proved_fix_moves_the_issue_to_done(env, job):
    app, _, rec, _ = env
    with app.state.sessionmaker() as db:
        j = db.get(Job, job["pk"])
        notify.rescan(db, j, "fixed", j.created_at.date())
        db.commit()
    before = len(rec.requests)
    run(env)
    new = rec.requests[before:]
    move = [r for r in new if r.url.path.endswith("/transitions") and r.method == "POST"]
    assert len(move) == 1 and json.loads(move[0].content) == {"transition": {"id": "31"}}


def test_escalation_goes_to_teams(env):
    app, _, rec, _ = env
    team = client(env, LINUX)
    task = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if "Self-signed" in t["title"])
    j = team.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "patch"}).json()
    with app.state.sessionmaker() as db:
        opened = db.get(Job, j["pk"]).steps[0].opened_at
    sweeper.sweep(app.state.sessionmaker, opened + timedelta(hours=49))
    run(env)
    card = json.loads(rec.to("teams.example.in")[-1].content)
    assert card["type"] == "message"
    att = card["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert "Escalated to you" in att["content"]["body"][0]["text"]
    assert att["content"]["actions"][0]["url"] == f"https://sutra.example.in/#/job/{j['pk']}"


def test_failures_are_retried_then_given_up(env):
    app, _, rec, _ = env
    with app.state.sessionmaker() as db:
        db.add(Outbox(kind="teams", subject="t", body="b"))
        db.commit()
        row_id = db.scalars(select(Outbox.id).order_by(Outbox.id.desc())).first()
    rec.fail = True
    try:
        now = utcnow()
        for i in range(notify.MAX_ATTEMPTS):
            run(env, now=now)
            now += timedelta(minutes=2 ** (i + 1) + 1)
    finally:
        rec.fail = False
    with app.state.sessionmaker() as db:
        row = db.get(Outbox, row_id)
        assert row.status == "failed" and row.attempts == notify.MAX_ATTEMPTS and "503" in row.last_error
    admin = client(env, f"admin@{D}")
    status = admin.get("/api/admin/integrations").json()
    assert status["jira"]["enabled"] and "token-1" not in json.dumps(status)  # secrets never leave the server
    assert any(p["id"] == row_id for p in status["problems"])
    assert admin.post("/api/admin/integrations/retry").json()["queued"] >= 1


def test_unconfigured_integrations_are_skipped_not_invented(tmp_path):
    settings = Settings(workspace=tmp_path, database_url=f"sqlite:///{tmp_path / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    app = create_app(settings)
    with TestClient(app, base_url="https://testserver"):
        c = TestClient(app, base_url="https://testserver")
        r = c.post("/api/auth/login", json={"email": LINUX, "password": passwords[LINUX]})
        c.headers["x-csrf-token"] = r.json()["csrf_token"]
        task = c.get("/api/portal").json()["teams"][0]["tasks"][0]
        j = c.post("/api/jobs", json={"rc_id": task["id"], "team": "IT Infra - Linux", "mode": "manual"}).json()
        counts = notify.dispatch(app.state.sessionmaker, Senders(settings))
        assert counts["sent"] == 0 and counts["skipped"] >= 2
        assert c.get(f"/api/jobs/{j['pk']}").json()["jira"] == ""


def test_jira_data_center_uses_a_bearer_token_and_plain_text(tmp_path):
    rec = Recorder()
    s = Settings(workspace=tmp_path, database_url="sqlite://", jira_url="https://acme.atlassian.net",
                 jira_token="pat-1", jira_api="2")
    Senders(s, transport=httpx.MockTransport(rec)).jira_comment("LNX-1", "hello")
    r = rec.requests[0]
    assert r.url.path == "/rest/api/2/issue/LNX-1/comment" and r.headers["authorization"] == "Bearer pat-1"
    assert json.loads(r.content) == {"body": "hello"}
