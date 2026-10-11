"""Milestone 4: Entra ID directory sync. Group members get the mapped roles and single sign-on accounts, people who
leave lose them, roles given by hand are never touched, and a failed read changes nothing.

Microsoft Graph is played by a fake that follows the request and response shapes of the official SDK
(msgraph-sdk 1.64.0): ``/v1.0/groups/{id}``, ``/v1.0/groups/{id}/transitiveMembers/graph.user``, ``value`` and
``@odata.nextLink``. The people, IDs and groups are invented for the test."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli, directory
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import Setting, User, UserRole

D = "vindhyapower.example"
ADMIN, VM = f"admin@{D}", f"aisha.khan@{D}"
TENANT = "11111111-2222-3333-4444-555555555555"
G_VM, G_PLANT = "aaaaaaaa-0000-0000-0000-000000000001", "aaaaaaaa-0000-0000-0000-000000000002"


def member(oid, name, email, enabled=True, upn=None):
    return {"@odata.type": "#microsoft.graph.user", "id": oid, "displayName": name, "mail": email,
            "userPrincipalName": upn or email, "accountEnabled": enabled}


class FakeGraph:
    def __init__(self):
        self.groups = {
            G_VM: ("SG-Sutra-VM-Analysts", [member("u-1", "Ravi Iyer", f"ravi.iyer@{D}"),
                                            member("u-2", "Disabled Person", f"gone@{D}", enabled=False),
                                            member("u-3", "Aisha Khan", None, upn=f"Aisha.Khan@{D}")]),
            G_PLANT: ("SG-Sutra-Plant-Unit2", [member("u-4", "Meena Rao", f"meena.rao@{D}")]),
        }
        self.fail_group = None
        self.next_host = "graph.microsoft.com"
        self.token_forms = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.url.host == "login.microsoftonline.com":
            assert req.url.path == f"/{TENANT}/oauth2/v2.0/token"
            self.token_forms.append(parse_qs(req.content.decode()))
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": "tok"})
        assert req.headers["authorization"] == "Bearer tok"
        parts = req.url.path.split("/")  # ['', 'v1.0', 'groups', id, ...]
        gid = parts[3]
        if gid == self.fail_group:
            return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied",
                                                       "message": "Insufficient privileges"}})
        if gid not in self.groups:
            return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound", "message": "nope"}})
        name, users = self.groups[gid]
        if len(parts) == 4:
            return httpx.Response(200, json={"id": gid, "displayName": name})
        assert parts[4:] == ["transitiveMembers", "graph.user"]
        if req.url.params.get("page") == "2":
            return httpx.Response(200, json={"value": users[1:]})
        assert req.url.params["$select"] == directory.USER_FIELDS
        nxt = f"https://{self.next_host}/v1.0/groups/{gid}/transitiveMembers/graph.user?page=2"
        return httpx.Response(200, json={"value": users[:1], **({"@odata.nextLink": nxt} if users[1:] else {})})


@pytest.fixture()
def env(tmp_path):
    settings = Settings(workspace=tmp_path, database_url=f"sqlite:///{tmp_path / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=0)}
    app = create_app(settings, background=False)
    fake = FakeGraph()
    app.state.directory.transport = httpx.MockTransport(fake)
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords, fake


def client(env, email):
    app, passwords = env[0], env[1]
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


def configure(admin):
    r = admin.put("/api/admin/directory", json={"enabled": True, "tenant_id": TENANT, "client_id": "app-1",
                                                "secret": "graph-secret"})
    assert r.status_code == 200, r.text
    assert admin.post("/api/admin/directory/maps", json={"group_id": G_VM, "role": "vm_analyst"}).status_code == 201
    r = admin.post("/api/admin/directory/maps", json={"group_id": G_PLANT, "role": "plant_engineer",
                                                      "scope_type": "site", "scope_value": "Unit 2"})
    assert r.status_code == 201, r.text


def user(app, email):
    with app.state.sessionmaker() as db:
        u = db.scalars(select(User).where(User.email == email)).first()
        return u and {"active": u.is_active, "state": u.directory_state, "dir": u.directory_id,
                      "password": bool(u.password_hash),
                      "roles": sorted((r.role_key, r.scope_value, r.source) for r in u.roles)}


def test_configuration_is_admin_only_and_keeps_the_secret(env):
    admin = client(env, ADMIN)
    assert client(env, VM).get("/api/admin/directory").status_code == 403
    configure(admin)
    d = admin.get("/api/admin/directory").json()
    assert d["config"]["has_secret"] and "secret" not in d["config"]
    with env[0].state.sessionmaker() as db:
        assert "graph-secret" not in str(db.get(Setting, directory.SETTING).value)
    bad = admin.post("/api/admin/directory/maps", json={"group_id": G_VM, "role": "auditor"})
    assert bad.status_code == 400 and "by hand" in bad.json()["error"]
    wrong = admin.post("/api/admin/directory/maps", json={"group_id": G_VM, "role": "plant_engineer"})
    assert wrong.status_code == 422 or "per site" in wrong.json()["error"]
    http = admin.put("/api/admin/directory", json={"enabled": True, "tenant_id": TENANT, "client_id": "app-1",
                                                   "graph_url": "http://graph.example"})
    assert http.status_code == 400


def test_sync_creates_links_and_removes(env):
    app, _, fake = env
    admin = client(env, ADMIN)
    configure(admin)
    out = admin.post("/api/admin/directory/sync").json()
    assert out["status"]["ok"] and out["status"]["created"] == 2 and out["status"]["linked"] == 1
    assert {m["group_name"] for m in out["maps"]} == {"SG-Sutra-VM-Analysts", "SG-Sutra-Plant-Unit2"}
    assert fake.token_forms[0]["scope"] == ["https://graph.microsoft.com/.default"]
    ravi = user(app, f"ravi.iyer@{D}")
    assert ravi["roles"] == [("vm_analyst", "", "entra")] and not ravi["password"] and ravi["state"] == "active"
    assert user(app, f"meena.rao@{D}")["roles"] == [("plant_engineer", "Unit 2", "entra")]
    assert user(app, f"gone@{D}") is None  # disabled in Entra ID
    # The existing account is matched by sign-in name and keeps its hand-given role; the same role is not doubled.
    aisha = user(app, VM)
    assert aisha["dir"] == "u-3" and aisha["roles"] == [("vm_analyst", "", "manual")]

    # Ravi and Aisha leave the group. Ravi's synced role goes and, with no roles left, his account is disabled.
    fake.groups[G_VM] = (fake.groups[G_VM][0], fake.groups[G_VM][1][1:2])
    admin.post("/api/admin/directory/sync")
    ravi = user(app, f"ravi.iyer@{D}")
    assert ravi["roles"] == [] and not ravi["active"] and ravi["state"] == "removed"
    assert user(app, VM)["state"] == "left" and user(app, VM)["active"]  # hand-given role kept
    # He comes back: enabled again.
    fake.groups[G_VM] = (fake.groups[G_VM][0], [member("u-1", "Ravi Iyer", f"ravi.iyer@{D}")])
    admin.post("/api/admin/directory/sync")
    assert user(app, f"ravi.iyer@{D}")["active"]
    events = {e["action"] for e in admin.get("/api/audit").json()["events"]}
    assert {"directory.sync", "directory.user_created", "directory.user_disabled", "directory.user_enabled"} <= events


def test_hand_edits_keep_synced_roles(env):
    app = env[0]
    admin = client(env, ADMIN)
    configure(admin)
    admin.post("/api/admin/directory/sync")
    meena = next(u for u in admin.get("/api/admin/users").json() if u["email"] == f"meena.rao@{D}")
    r = admin.put(f"/api/admin/users/{meena['id']}/roles", json=[{"role": "executive"}])
    assert r.status_code == 200, r.text
    assert user(app, f"meena.rao@{D}")["roles"] == [("executive", "", "manual"), ("plant_engineer", "Unit 2", "entra")]


def test_a_failed_read_changes_nothing(env):
    app, _, fake = env
    admin = client(env, ADMIN)
    configure(admin)
    fake.fail_group = G_PLANT
    r = admin.post("/api/admin/directory/sync")
    assert r.status_code == 502 and "GroupMember.Read.All" in r.json()["error"]
    assert user(app, f"ravi.iyer@{D}") is None
    st = admin.get("/api/admin/directory").json()["status"]
    assert st["ok"] is False and "GroupMember.Read.All" in st["error"]
    fake.fail_group, fake.next_host = None, "evil.example"
    r = admin.post("/api/admin/directory/sync")
    assert r.status_code == 502 and "another host" in r.json()["error"]


def test_refuses_to_remove_the_last_administrator(env):
    app, _, fake = env
    admin = client(env, ADMIN)
    configure(admin)
    assert admin.post("/api/admin/directory/maps", json={"group_id": G_VM, "role": "admin"}).status_code == 201
    admin.post("/api/admin/directory/sync")
    with app.state.sessionmaker() as db:  # only synced administrators remain
        for row in db.scalars(select(UserRole).where(UserRole.role_key == "admin", UserRole.source == "manual")):
            db.delete(row)
        db.commit()
    fake.groups[G_VM] = (fake.groups[G_VM][0], [])
    with app.state.sessionmaker() as db:
        with pytest.raises(directory.DirectoryError, match="nobody able to administer"):
            directory.run(db, app.state.settings.secret_key, app.state.directory.transport)
    assert user(app, f"ravi.iyer@{D}")["roles"] == [("admin", "", "entra"), ("vm_analyst", "", "entra")]
