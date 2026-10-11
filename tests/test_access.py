"""Milestone 1 exit check: roles, module access, scope and separation of duties, all enforced by the server.

For every role, the screens it should have work and every other API answers 403. A manager cannot approve
another team's job and nobody approves their own job. The data is the synthetic power-company demo.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli
from sutra.app.catalog import CATALOG_PATH
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AuditEvent, ModuleGrant, User, utcnow

DOMAIN = "vindhyapower.example"

# One account per role, as created by `sutra demo-users` from the synthetic ownership chart.
ACCOUNTS = {
    "team_member": f"it.infra.linux.team@{DOMAIN}",
    "team_manager": f"arjun.mehta@{DOMAIN}",  # manager of IT Infra - Linux
    "vm_analyst": f"aisha.khan@{DOMAIN}",
    "vertical_head": f"neha.joshi@{DOMAIN}",  # head of Corporate IT
    "plant_engineer": f"plant.engineer.vindhya.thermal.plant@{DOMAIN}",
    "ciso": f"ciso@{DOMAIN}",
    "compliance_officer": f"compliance@{DOMAIN}",
    "executive": f"executive@{DOMAIN}",
    "auditor": f"auditor@{DOMAIN}",
    "admin": f"admin@{DOMAIN}",
}

# Read screens: (method, path, json body). Each one is guarded by one module action.
SCREENS = {
    "board": ("GET", "/api/board", None),
    "board_pack": ("GET", "/api/board/pack", None),
    "briefing": ("GET", "/api/board/briefing", None),
    "ai_status": ("GET", "/api/admin/ai", None),
    "root_causes": ("GET", "/api/root-causes", None),
    "receipts": ("GET", "/api/downloads/receipts.json", None),
    "assets": ("GET", "/api/assets", None),
    "headline": ("POST", "/api/headline", {"query": "log4j"}),
    "portal": ("GET", "/api/portal", None),
    "jobs": ("GET", "/api/jobs", None),
    "ot_plans": ("GET", "/api/ot", None),
    "scorecards": ("GET", "/api/scorecards", None),
    "uploads": ("GET", "/api/data/uploads", None),
    "datasets": ("GET", "/api/data/datasets", None),
    "connections": ("GET", "/api/data/connections", None),
    "intel": ("GET", "/api/data/intel", None),
    "admin_users": ("GET", "/api/admin/users", None),
    "directory": ("GET", "/api/admin/directory", None),
    "admin_catalog": ("GET", "/api/admin/catalog", None),
    "admin_ownership": ("GET", "/api/admin/ownership", None),
    "approval_rules": ("GET", "/api/admin/approval-rules", None),
    "maintenance": ("GET", "/api/admin/maintenance", None),
    "sla": ("GET", "/api/admin/sla", None),
    "integrations": ("GET", "/api/admin/integrations", None),
    "audit": ("GET", "/api/audit", None),
    "audit_csv": ("GET", "/api/audit.csv", None),
    "compliance": ("GET", "/api/compliance/entities", None),
    "compliance_meta": ("GET", "/api/compliance/meta", None),
}
# Actions: sent with a body that is rejected after the access check, so "allowed" means "not 401/403".
ACTIONS = {
    "rc_explanation": ("GET", "/api/root-causes/RC-001/explanation", None),  # 404 when outside the person's scope
    "raise_job": ("POST", "/api/jobs", {}),
    "cmp_record": ("POST", "/api/compliance/entities", {}),
    "cmp_finding": ("POST", "/api/compliance/audits/999999/findings", {}),
    "decide_job": ("POST", "/api/jobs/999999/decision", {}),
    "ot_record": ("POST", "/api/ot/999999/oem", {}),
    "upload": ("POST", "/api/data/uploads", None),
    "analyze": ("POST", "/api/data/analyze", {"org": "x"}),
    "demo": ("POST", "/api/data/demo", {}),
    "add_connection": ("POST", "/api/data/connections", {}),
    "start_pull": ("POST", "/api/data/pulls", None),
    "create_user": ("POST", "/api/admin/users", {}),
    "update_user": ("PATCH", "/api/admin/users/999999", {}),
    "set_licence": ("PATCH", "/api/admin/modules/M-RC", {}),
    "set_rules": ("PUT", "/api/admin/approval-rules", {}),
    "set_maintenance": ("PUT", "/api/admin/maintenance", {}),
    "set_sla": ("PUT", "/api/admin/sla", {}),
    "outbox_retry": ("POST", "/api/admin/integrations/retry", {}),
    "ownership_upload": ("POST", "/api/admin/ownership", None),
}

# What each role may reach. Written out by hand so a wrong catalogue entry fails the test.
EXPECTED = {
    "team_member": {"portal", "jobs", "raise_job"},
    "team_manager": {"portal", "jobs", "decide_job", "scorecards"},
    "vm_analyst": {"board", "board_pack", "briefing", "rc_explanation", "root_causes", "receipts", "assets",
            "headline", "jobs", "uploads", "datasets", "decide_job", "upload", "analyze", "demo", "connections",
            "intel", "start_pull"},
    "vertical_head": {"board", "board_pack", "briefing", "rc_explanation", "root_causes", "receipts", "jobs",
            "decide_job", "scorecards"},
    "plant_engineer": {"portal", "ot_plans", "ot_record"},
    "ciso": {"board", "board_pack", "briefing", "rc_explanation", "ai_status", "root_causes", "receipts", "jobs",
            "decide_job", "scorecards", "approval_rules", "set_rules", "maintenance", "set_maintenance", "sla",
            "set_sla", "compliance", "compliance_meta", "cmp_record", "cmp_finding"},
    "compliance_officer": {"board", "board_pack", "briefing", "audit", "audit_csv", "compliance",
            "compliance_meta", "cmp_record", "cmp_finding"},
    "executive": {"board", "board_pack", "briefing"},
    "auditor": {"audit", "audit_csv", "compliance", "compliance_meta"},
    "admin": {"ai_status", "uploads", "datasets", "connections", "intel", "add_connection", "start_pull",
            "admin_users", "directory", "admin_catalog", "admin_ownership", "approval_rules", "audit",
            "audit_csv", "upload", "analyze", "demo", "create_user", "update_user", "set_licence", "set_rules",
            "ownership_upload", "maintenance", "set_maintenance", "sla", "set_sla", "integrations",
            "outbox_retry"},
}


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ws")
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    passwords = {email: pw for email, pw, _ in cli.demo_users(settings, "power")}
    app = create_app(settings)
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords


def client(env, email: str | None = None) -> TestClient:
    app, passwords = env
    c = TestClient(app, base_url="https://testserver")
    if email:
        r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
        assert r.status_code == 200, r.text
        c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


def call(c: TestClient, method: str, path: str, body):
    return c.request(method, path, json=body) if body is not None else c.request(method, path)


def test_catalogue_roles_are_all_covered():
    roles = {r["key"] for r in json.loads(CATALOG_PATH.read_text())["roles"]}
    assert roles == set(EXPECTED) == set(ACCOUNTS)


@pytest.mark.parametrize("role", sorted(EXPECTED))
def test_role_matrix(env, role):
    c = client(env, ACCOUNTS[role])
    for name, (method, path, body) in {**SCREENS, **ACTIONS}.items():
        r = call(c, method, path, body)
        if name in EXPECTED[role]:
            assert r.status_code not in (401, 403), f"{role} should reach {name}: {r.status_code} {r.text[:200]}"
            if name in SCREENS:
                assert r.status_code == 200, f"{role} {name}: {r.status_code} {r.text[:200]}"
        else:
            assert r.status_code == 403, f"{role} must be refused {name}: got {r.status_code}"


def test_navigation_lists_only_the_persons_modules(env):
    me = client(env, ACCOUNTS["executive"]).get("/api/auth/me").json()
    assert [m["key"] for m in me["modules"]] == ["M-BRD"]
    me = client(env, ACCOUNTS["team_member"]).get("/api/auth/me").json()
    assert sorted(m["key"] for m in me["modules"]) == ["M-PJ", "M-TP"]
    assert me["raise_for_teams"] == ["IT Infra - Linux"]


def test_every_api_needs_a_session(env):
    c = client(env)
    for method, path, body in [*SCREENS.values(), *ACTIONS.values(), ("GET", "/api/auth/me", None),
                               ("GET", "/api/status", None)]:
        assert call(c, method, path, body).status_code == 401, path


def test_state_changes_need_the_csrf_token(env):
    c = client(env, ACCOUNTS["team_member"])
    del c.headers["x-csrf-token"]
    assert c.post("/api/jobs", json={"rc_id": "RC-001", "team": "IT Infra - Linux"}).status_code == 403
    c.headers["x-csrf-token"] = "wrong"
    assert c.post("/api/jobs", json={"rc_id": "RC-001", "team": "IT Infra - Linux"}).status_code == 403


def test_cross_site_post_is_refused(env):
    c = client(env)
    r = c.post("/api/auth/login", json={"email": "x@y", "password": "z"}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403


# ---------- scope ----------

def test_team_member_sees_only_their_teams_assets(env):
    portal = client(env, ACCOUNTS["team_member"]).get("/api/portal").json()
    owners = {a["owner"] for a in portal["assets"].values()}
    assert owners == {"IT Infra - Linux"}
    assert {t["owner"] for t in portal["teams"]} == {"IT Infra - Linux"}


def test_plant_engineer_sees_only_their_site(env):
    portal = client(env, ACCOUNTS["plant_engineer"]).get("/api/portal").json()
    assert portal["assets"]
    assert {a["site"] for a in portal["assets"].values()} == {"Vindhya Thermal Plant"}


def test_vertical_head_board_is_limited_to_the_vertical(env):
    whole = client(env, ACCOUNTS["executive"]).get("/api/board").json()
    vertical = client(env, ACCOUNTS["vertical_head"]).get("/api/board").json()
    assert 0 < vertical["portfolio"]["ale_mean"] < whole["portfolio"]["ale_mean"]
    assert vertical["headline"]["findings"] < whole["headline"]["findings"]
    rcs = client(env, ACCOUNTS["vertical_head"]).get("/api/root-causes").json()
    teams = {a["owner"] for a in rcs["assets"].values()}
    chart = {t["team"]: t["vertical"] for t in client(env, ACCOUNTS["admin"]).get("/api/admin/ownership").json()}
    assert teams and all(chart[t] == "Corporate IT" for t in teams)


def test_board_does_not_ship_host_lists_or_evidence(env):
    board = client(env, ACCOUNTS["executive"]).get("/api/board").json()
    assert "findings" not in board and "assets" not in board
    assert "asset_ids" not in board["root_causes"][0]


# ---------- patch jobs: separation of duties ----------

def _rc_for(env, team: str) -> str:
    portal = client(env, ACCOUNTS["team_member"]).get("/api/portal").json()
    team_row = next(t for t in portal["teams"] if t["owner"] == team)
    jobs = client(env, ACCOUNTS["team_member"]).get("/api/jobs").json()["jobs"]
    taken = {j["rc_id"] for j in jobs if j["team"] == team and j["status"] in ("pending", "approved")}
    return next(t["id"] for t in team_row["tasks"] if t["id"] not in taken and not t["is_ot"])


def test_full_approval_chain_and_separation_of_duties(env):
    member = client(env, ACCOUNTS["team_member"])
    rc = _rc_for(env, "IT Infra - Linux")
    job = member.post("/api/jobs", json={"rc_id": rc, "team": "IT Infra - Linux", "mode": "patch"})
    assert job.status_code == 201, job.text
    job = job.json()
    pk = job["pk"]
    assert job["steps"][0]["role"] == "manager" and job["steps"][1]["role"] == "vm_analyst"

    # The raiser cannot approve (no approve right at all).
    assert member.post(f"/api/jobs/{pk}/decision", json={"action": "approve"}).status_code == 403
    # A manager of another team cannot see or approve it.
    other = client(env, f"kavya.iyer@{DOMAIN}")  # manager of IT Infra - Windows
    assert other.post(f"/api/jobs/{pk}/decision", json={"action": "approve"}).status_code in (403, 404)
    # The VM analyst cannot jump the queue.
    vm = client(env, ACCOUNTS["vm_analyst"])
    r = vm.post(f"/api/jobs/{pk}/decision", json={"action": "approve"})
    assert r.status_code == 403 and "manager" in r.json()["error"].lower()

    mgr = client(env, ACCOUNTS["team_manager"])
    r = mgr.post(f"/api/jobs/{pk}/decision", json={"action": "approve", "comment": "ok"})
    assert r.status_code == 200 and r.json()["steps"][0]["state"] == "approved"
    # The manager cannot sign the next step too.
    assert mgr.post(f"/api/jobs/{pk}/decision", json={"action": "approve"}).status_code == 403

    r = vm.post(f"/api/jobs/{pk}/decision", json={"action": "approve"})
    assert r.status_code == 200
    if len(job["steps"]) == 3:
        assert r.json()["status"] == "pending"
        # Another vertical's head is refused; the right one approves.
        wrong = client(env, f"karan.malhotra@{DOMAIN}")
        assert wrong.post(f"/api/jobs/{pk}/decision", json={"action": "approve"}).status_code in (403, 404)
        r = client(env, ACCOUNTS["vertical_head"]).post(f"/api/jobs/{pk}/decision", json={"action": "approve"})
        assert r.status_code == 200
    assert r.json()["status"] == "approved"

    detail = mgr.get(f"/api/jobs/{pk}").json()
    actions = [a["action"] for a in detail["audit"]]
    assert actions[0] == "job.raise" and actions.count("job.approve") == len(job["steps"])
    assert "job.decision_denied" in actions


def test_nobody_approves_their_own_job_even_as_the_teams_manager(env):
    app, passwords = env
    admin = client(env, ACCOUNTS["admin"])
    users = admin.get("/api/admin/users").json()
    arjun = next(u for u in users if u["email"] == ACCOUNTS["team_manager"])
    roles = [{k: r[k] for k in ("role", "scope_type", "scope_value")} for r in arjun["roles"]]
    r = admin.put(f"/api/admin/users/{arjun['id']}/roles",
                  json=[*roles, {"role": "team_member", "scope_type": "team", "scope_value": "IT Infra - Linux"}])
    assert r.status_code == 200, r.text
    try:
        mgr = client(env, ACCOUNTS["team_manager"])
        rc = _rc_for(env, "IT Infra - Linux")
        job = mgr.post("/api/jobs", json={"rc_id": rc, "team": "IT Infra - Linux", "mode": "patch"}).json()
        r = mgr.post(f"/api/jobs/{job['pk']}/decision", json={"action": "approve"})
        assert r.status_code == 403 and "raised this job" in r.json()["error"]
    finally:
        admin.put(f"/api/admin/users/{arjun['id']}/roles", json=roles)


def test_team_member_cannot_raise_for_another_team(env):
    member = client(env, ACCOUNTS["team_member"])
    rcs = client(env, ACCOUNTS["vm_analyst"]).get("/api/root-causes").json()["root_causes"]
    rc = next(r for r in rcs if r["owners"] and "IT Infra - Linux" not in r["owners"])
    assert member.post("/api/jobs", json={"rc_id": rc["id"], "team": rc["owners"][0]}).status_code == 403


def test_acting_person_comes_from_the_session_not_the_body(env):
    member = client(env, ACCOUNTS["team_member"])
    rc = _rc_for(env, "IT Infra - Linux")
    r = member.post("/api/jobs", json={"rc_id": rc, "team": "IT Infra - Linux", "mode": "manual",
                                       "ticket": "CHG1", "actor": "Arjun Mehta", "raised_by": 1})
    assert r.status_code == 201
    assert r.json()["raised_by"] == "IT Infra - Linux engineer (demo account)"


# ---------- sign-in and accounts ----------

def test_wrong_passwords_lock_the_account(env):
    app, passwords = env
    email = f"anil.sharma@{DOMAIN}"
    c = client(env)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"email": email, "password": "wrong-password-123"}).status_code == 401
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 429
    admin = client(env, ACCOUNTS["admin"])
    uid = next(u["id"] for u in admin.get("/api/admin/users").json() if u["email"] == email)
    assert admin.patch(f"/api/admin/users/{uid}", json={"unlock": True}).status_code == 200
    assert c.post("/api/auth/login", json={"email": email, "password": passwords[email]}).status_code == 200


def test_unknown_email_gets_the_same_answer(env):
    r = client(env).post("/api/auth/login", json={"email": "nobody@nowhere.example", "password": "whatever-123"})
    assert r.status_code == 401
    assert r.json()["error"] == "Email or password is wrong, or the account is disabled."


def test_new_user_must_change_temporary_password(env):
    admin = client(env, ACCOUNTS["admin"])
    r = admin.post("/api/admin/users", json={"email": "new.exec@vindhyapower.example", "name": "New Exec",
                                             "roles": [{"role": "executive", "scope_type": "org"}]})
    assert r.status_code == 201, r.text
    temp = r.json()["temporary_password"]
    c = client(env)
    me = c.post("/api/auth/login", json={"email": "new.exec@vindhyapower.example", "password": temp}).json()
    c.headers["x-csrf-token"] = me["csrf_token"]
    assert me["user"]["must_change_password"]
    assert c.get("/api/board").status_code == 403
    assert c.post("/api/auth/password", json={"current": temp, "new": "short"}).status_code == 400
    assert c.post("/api/auth/password", json={"current": temp, "new": "a-much-longer-passphrase"}).status_code == 200
    assert c.get("/api/board").status_code == 200


def test_deny_grant_removes_a_module_and_allow_grant_adds_one(env):
    admin = client(env, ACCOUNTS["admin"])
    users = admin.get("/api/admin/users").json()
    ciso = next(u for u in users if u["email"] == ACCOUNTS["ciso"])
    r = admin.post(f"/api/admin/users/{ciso['id']}/grants",
                   json={"module": "M-RC", "action": "*", "effect": "deny", "reason": "Board only for now"})
    assert r.status_code == 201, r.text
    deny_id = next(g["id"] for g in r.json()["grants"] if g["effect"] == "deny")
    r = admin.post(f"/api/admin/users/{ciso['id']}/grants",
                   json={"module": "M-HC", "action": "view", "effect": "allow", "reason": "Asked for headline checks"})
    allow_id = next(g["id"] for g in r.json()["grants"] if g["effect"] == "allow")
    c = client(env, ACCOUNTS["ciso"])
    assert c.get("/api/root-causes").status_code == 403
    assert c.post("/api/headline", json={"query": "log4j"}).status_code == 200
    admin.delete(f"/api/admin/grants/{deny_id}")
    admin.delete(f"/api/admin/grants/{allow_id}")
    assert c.get("/api/root-causes").status_code == 200
    assert c.post("/api/headline", json={"query": "log4j"}).status_code == 403


def test_unbuilt_or_unlicensed_modules_grant_nothing(env):
    admin = client(env, ACCOUNTS["admin"])
    exec_ = client(env, ACCOUNTS["executive"])
    assert admin.patch("/api/admin/modules/M-BRD", json={"licensed": False}).status_code == 200
    try:
        assert exec_.get("/api/board").status_code == 403
        assert exec_.get("/api/auth/me").json()["modules"] == []
    finally:
        admin.patch("/api/admin/modules/M-BRD", json={"licensed": True})
    # Unlicensing M-CMP takes the compliance module away from the compliance officer too.
    officer = client(env, ACCOUNTS["compliance_officer"])
    assert officer.get("/api/compliance/entities").status_code == 200
    assert admin.patch("/api/admin/modules/M-CMP", json={"licensed": False}).status_code == 200
    try:
        assert officer.get("/api/compliance/entities").status_code == 403
        assert "M-CMP" not in {m["key"] for m in officer.get("/api/auth/me").json()["modules"]}
    finally:
        admin.patch("/api/admin/modules/M-CMP", json={"licensed": True})


def test_admin_cannot_change_their_own_access(env):
    admin = client(env, ACCOUNTS["admin"])
    me = admin.get("/api/auth/me").json()["user"]["id"]
    assert admin.put(f"/api/admin/users/{me}/roles", json=[]).status_code == 403
    assert admin.patch(f"/api/admin/users/{me}", json={"is_active": False}).status_code == 403
    assert admin.post(f"/api/admin/users/{me}/grants", json={"module": "M-BRD", "action": "view", "effect": "allow",
                                                               "reason": "self"}).status_code == 403


def test_auditor_access_must_expire_and_expired_accounts_cannot_sign_in(env):
    app, passwords = env
    admin = client(env, ACCOUNTS["admin"])
    r = admin.post("/api/admin/users", json={"email": "aud2@vindhyapower.example", "name": "Auditor 2",
                                             "roles": [{"role": "auditor", "scope_type": "org"}]})
    assert r.status_code == 400 and "expiry" in r.json()["error"]
    with app.state.sessionmaker() as db:
        user = db.scalars(select(User).where(User.email == ACCOUNTS["auditor"])).one()
        user.expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    try:
        r = client(env).post("/api/auth/login", json={"email": ACCOUNTS["auditor"],
                                                      "password": passwords[ACCOUNTS["auditor"]]})
        assert r.status_code == 401
    finally:
        with app.state.sessionmaker() as db:
            user = db.scalars(select(User).where(User.email == ACCOUNTS["auditor"])).one()
            user.expires_at = utcnow() + timedelta(days=30)
            db.commit()


def test_disabling_a_user_ends_their_sessions(env):
    admin = client(env, ACCOUNTS["admin"])
    c = client(env, f"meera.pillai@{DOMAIN}")
    assert c.get("/api/auth/me").status_code == 200
    uid = next(u["id"] for u in admin.get("/api/admin/users").json() if u["email"] == f"meera.pillai@{DOMAIN}")
    assert admin.patch(f"/api/admin/users/{uid}", json={"is_active": False}).status_code == 200
    assert c.get("/api/auth/me").status_code == 401
    admin.patch(f"/api/admin/users/{uid}", json={"is_active": True})


def test_logout_ends_the_session(env):
    c = client(env, ACCOUNTS["executive"])
    assert c.post("/api/auth/logout").status_code == 200
    assert c.get("/api/board").status_code == 401


def test_sign_ins_grants_and_refusals_are_audited(env):
    app, _ = env
    with app.state.sessionmaker() as db:
        actions = set(db.scalars(select(AuditEvent.action)))
    assert {"auth.login", "auth.login_failed", "auth.locked", "access.denied", "admin.grant_added",
            "admin.grant_removed", "admin.roles_changed", "admin.user_created", "job.raise", "job.approve"} <= actions


def test_session_cookie_is_httponly_secure_and_lax(env):
    app, passwords = env
    r = TestClient(app, base_url="https://testserver").post(
        "/api/auth/login", json={"email": ACCOUNTS["executive"], "password": passwords[ACCOUNTS["executive"]]})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie


def test_security_headers(env):
    r = client(env).get("/")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_auditor_access_is_read_only_whatever_else_is_given(env):
    admin = client(env, ACCOUNTS["admin"])
    app, _ = env
    with app.state.sessionmaker() as db:
        uid = db.scalars(select(User.id).where(User.email == ACCOUNTS["auditor"])).one()
    # Never combined with another role, and never given more than view.
    r = admin.put(f"/api/admin/users/{uid}/roles", json=[{"role": "auditor", "scope_type": "org"},
                                                          {"role": "compliance_officer", "scope_type": "org"}])
    assert r.status_code == 400 and "cannot be combined" in r.json()["error"]
    r = admin.post(f"/api/admin/users/{uid}/grants", json={"module": "M-CMP", "action": "act", "effect": "allow",
                                                           "scope_type": "org", "reason": "help with evidence"})
    assert r.status_code == 400 and "view" in r.json()["error"]
    # A grant made before the role was given does not survive it either.
    with app.state.sessionmaker() as db:
        user = db.get(User, uid)
        user.grants.append(ModuleGrant(module_key="M-CMP", action="act", effect="allow", scope_type="org"))
        db.commit()
    try:
        auditor = client(env, ACCOUNTS["auditor"])
        me = auditor.get("/api/auth/me").json()
        assert me["user"]["read_only"] is True and me["user"]["expires_at"]
        assert {a for m in me["modules"] for a in m["actions"]} == {"view"}
        assert auditor.post("/api/compliance/entities", json={"name": "x", "entity_type": "generator"}).status_code \
            == 403
    finally:
        with app.state.sessionmaker() as db:
            user = db.get(User, uid)
            user.grants = [g for g in user.grants if g.module_key != "M-CMP"]
            db.commit()
