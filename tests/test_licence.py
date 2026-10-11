"""Milestone 7: licence keys switch modules on and off per customer, checked offline."""

from __future__ import annotations

import json
from datetime import date, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli, licence
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AuditEvent, Module

D = "vindhyapower.example"
ADMIN, ANALYST = f"admin@{D}", f"aisha.khan@{D}"
TODAY = date(2027, 1, 15)


@pytest.fixture(scope="module")
def vendor(tmp_path_factory):
    d = tmp_path_factory.mktemp("vendor")
    private, public = licence.generate_keypair()
    (d / "private.pem").write_bytes(private)
    (d / "public.pem").write_bytes(public)
    return SimpleNamespace(dir=d, private=private, public=public, public_path=d / "public.pem")


def key(vendor, modules=("M-RC", "M-BRD"), expires=TODAY + timedelta(days=200), customer="Vindhya Power", lid="C-1"):
    return licence.issue(vendor.private, customer, list(modules), expires, lid, issued=TODAY - timedelta(days=100))


# ---------------------------------------------------------------- the key itself
def test_roundtrip_and_what_it_says(vendor):
    lic = licence.verify(key(vendor), licence.load_public_key(vendor.public_path))
    assert (lic.customer, lic.id, lic.modules) == ("Vindhya Power", "C-1", ("M-BRD", "M-RC"))
    assert lic.grants("M-RC") and lic.grants("M-ADM") and not lic.grants("M-OT")


def test_whitespace_from_copy_and_paste_is_ignored(vendor):
    pub = licence.load_public_key(vendor.public_path)
    k = key(vendor)
    assert licence.verify(f"  {k[:30]}\n{k[30:]}\n", pub).id == "C-1"


def test_a_changed_key_is_refused(vendor):
    pub = licence.load_public_key(vendor.public_path)
    head, body, sig = key(vendor).split(".")
    forged = json.loads(licence._unb64(body))
    forged["modules"] = ["*"]
    for token in (f"{head}.{licence._b64(licence._canonical(forged))}.{sig}", f"{head}.{body}.{sig[:-4]}AAAA",
                  f"{head}.{body}", "SUTRA1", "hello", f"OTHER.{body}.{sig}"):
        with pytest.raises(licence.LicenceError):
            licence.verify(token, pub)


def test_a_key_from_another_vendor_is_refused(vendor):
    _, other_public = licence.generate_keypair()
    other = vendor.dir / "other.pem"
    other.write_bytes(other_public)
    with pytest.raises(licence.LicenceError, match="signature"):
        licence.verify(key(vendor), licence.load_public_key(other))


def test_issue_checks_its_inputs(vendor):
    with pytest.raises(licence.LicenceError):
        licence.issue(vendor.private, "", ["M-RC"], TODAY + timedelta(days=5), "x")
    with pytest.raises(licence.LicenceError):
        licence.issue(vendor.private, "A", [], TODAY + timedelta(days=5), "x")
    with pytest.raises(licence.LicenceError, match="after the issue"):
        licence.issue(vendor.private, "A", ["M-RC"], TODAY - timedelta(days=1), "x", issued=TODAY)
    with pytest.raises(licence.LicenceError, match="private key"):
        licence.issue(vendor.public, "A", ["M-RC"], TODAY + timedelta(days=5), "x")


def test_states_by_date():
    lic = licence.Licence("C", "Cust", TODAY, TODAY + timedelta(days=100), ("M-RC", "M-NOPE"))
    built = {"M-RC", "M-BRD", "M-ADM"}
    ok = licence.evaluate(lic, built, TODAY)
    assert ok.state == "valid" and ok.keys == {"M-RC", "M-ADM"} and "M-NOPE" in ok.warnings[0]
    soon = licence.evaluate(lic, built, lic.expires - timedelta(days=10))
    assert soon.state == "valid" and any("10 days" in w for w in soon.warnings)
    last = licence.evaluate(lic, built, lic.expires)
    assert last.state == "valid" and last.days_left == 0
    grace = licence.evaluate(lic, built, lic.expires + timedelta(days=licence.GRACE_DAYS))
    assert grace.state == "grace" and "M-RC" in grace.keys
    gone = licence.evaluate(lic, built, lic.expires + timedelta(days=licence.GRACE_DAYS + 1))
    assert gone.state == "expired" and gone.keys == {"M-ADM"}
    star = licence.evaluate(licence.Licence("C", "Cust", TODAY, TODAY + timedelta(days=9), ("*",)), built, TODAY)
    assert star.keys == built


# ---------------------------------------------------------------- the application
class Clock:
    def __init__(self):
        self.now = TODAY

    def __call__(self):
        return self.now


@pytest.fixture()
def env(tmp_path, vendor):
    ws = tmp_path / "ws"
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}", require_licence=True)
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    app = create_app(settings)
    clock = Clock()
    app.state.licences = licence.LicenceService(True, vendor.public_path, clock)
    with TestClient(app, base_url="https://testserver"):
        yield SimpleNamespace(app=app, passwords=passwords, clock=clock, settings=settings)


def login(env, email):
    c = TestClient(env.app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": env.passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c, r.json()


def modules_of(me):
    return {m["key"] for m in me["modules"]}


def test_without_a_key_a_required_licence_leaves_only_administration(env):
    admin, me = login(env, ADMIN)
    assert modules_of(me) == {"M-ADM"}
    assert "No licence" in me["licence_notice"]
    assert admin.get("/api/admin/licence").json()["state"] == "none"
    analyst, me = login(env, ANALYST)
    assert modules_of(me) == set() and analyst.get("/api/root-causes").status_code == 403


def test_installing_a_key_switches_exactly_its_modules_on(env, vendor):
    admin, _ = login(env, ADMIN)
    r = admin.put("/api/admin/licence", json={"key": key(vendor)})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "valid" and r.json()["licence"]["customer"] == "Vindhya Power"
    assert modules_of(admin.get("/api/auth/me").json()) == {"M-ADM"}  # the admin role holds no RC permission
    analyst, me = login(env, ANALYST)
    assert modules_of(me) == {"M-RC", "M-BRD"}
    assert analyst.get("/api/root-causes").status_code == 200 and analyst.get("/api/board").status_code == 200
    assert analyst.get("/api/assets").status_code == 403, "a module outside the key is off for everyone"
    with env.app.state.sessionmaker() as db:
        ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "admin.licence_installed")).one()
        assert ev.detail["customer"] == "Vindhya Power" and "token" not in json.dumps(ev.detail)


def test_the_admin_switch_cannot_turn_on_a_module_outside_the_key(env, vendor):
    admin, _ = login(env, ADMIN)
    admin.put("/api/admin/licence", json={"key": key(vendor)})
    r = admin.patch("/api/admin/modules/M-OT", json={"licensed": True})
    assert r.status_code == 400 and "not in this installation's licence" in r.json()["error"]
    cat = admin.get("/api/admin/catalog").json()
    flags = {m["key"]: m["in_licence"] for m in cat["modules"]}
    assert flags["M-RC"] and flags["M-ADM"] and not flags["M-OT"]
    assert admin.patch("/api/admin/modules/M-BRD", json={"licensed": False}).status_code == 200
    analyst, me = login(env, ANALYST)
    assert modules_of(me) == {"M-RC"}


def test_bad_keys_are_refused_and_recorded(env, vendor):
    admin, _ = login(env, ADMIN)
    k = key(vendor)
    r = admin.put("/api/admin/licence", json={"key": k[:-6] + "AAAAAA"})
    assert r.status_code == 400 and "signature" in r.json()["error"]
    assert admin.put("/api/admin/licence", json={"key": "not a key at all"}).status_code == 400
    old = key(vendor, expires=TODAY - timedelta(days=licence.GRACE_DAYS + 5))
    r = admin.put("/api/admin/licence", json={"key": old})
    assert r.status_code == 400 and "expired" in r.json()["error"]
    assert admin.get("/api/admin/licence").json()["state"] == "none"
    with env.app.state.sessionmaker() as db:
        n = len(db.scalars(select(AuditEvent).where(AuditEvent.action == "admin.licence_rejected")).all())
    assert n == 3


def test_expiry_grace_and_renewal(env, vendor):
    admin, _ = login(env, ADMIN)
    k = key(vendor, expires=TODAY + timedelta(days=10))
    admin.put("/api/admin/licence", json={"key": k})
    _, me = login(env, ANALYST)
    assert "10 days" in me["licence_notice"] and "M-RC" in modules_of(me)

    env.clock.now = TODAY + timedelta(days=20)
    _, me = login(env, ANALYST)
    assert "M-RC" in modules_of(me) and "grace" not in me["licence_notice"] and "expired" in me["licence_notice"]
    assert admin.get("/api/admin/licence").json()["state"] == "grace"

    env.clock.now = TODAY + timedelta(days=10 + licence.GRACE_DAYS + 1)
    analyst, me = login(env, ANALYST)
    assert modules_of(me) == set() and analyst.get("/api/root-causes").status_code == 403
    assert admin.get("/api/admin/licence").status_code == 200, "the administrator can always renew"

    renewed = licence.issue(vendor.private, "Vindhya Power", ["*"], env.clock.now + timedelta(days=365), "C-2",
                            issued=env.clock.now)
    assert admin.put("/api/admin/licence", json={"key": renewed}).status_code == 200
    _, me = login(env, ANALYST)
    assert "M-RC" in modules_of(me) and me["licence_notice"] is None


def test_a_stored_key_that_no_longer_verifies_turns_modules_off(env, vendor, tmp_path):
    admin, _ = login(env, ADMIN)
    admin.put("/api/admin/licence", json={"key": key(vendor)})
    other = tmp_path / "other.pem"
    other.write_bytes(licence.generate_keypair()[1])
    env.app.state.licences = licence.LicenceService(True, other, env.clock)
    _, me = login(env, ANALYST)
    assert modules_of(me) == set()
    assert admin.get("/api/admin/licence").json()["state"] == "invalid"


def test_a_build_without_a_vendor_key_says_so(env, tmp_path):
    env.app.state.licences = licence.LicenceService(True, tmp_path / "missing.pem", env.clock)
    admin, _ = login(env, ADMIN)
    st = admin.get("/api/admin/licence").json()
    assert st["vendor_key_in_build"] is False
    r = admin.put("/api/admin/licence", json={"key": "SUTRA1.a.b"})
    assert r.status_code == 400 and "no vendor public key" in r.json()["error"]


def test_without_requirement_everything_built_runs_and_says_evaluation(tmp_path):
    ws = tmp_path / "ws"
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    assert settings.require_licence is False
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    app = create_app(settings)
    with TestClient(app, base_url="https://testserver") as c:
        r = c.post("/api/auth/login", json={"email": ANALYST, "password": passwords[ANALYST]})
        assert "M-RC" in modules_of(r.json()) and r.json()["licence_notice"] is None
        c.headers["x-csrf-token"] = r.json()["csrf_token"]
        with app.state.sessionmaker() as db:
            assert app.state.licences.entitlement(db).state == "open"
            assert db.get(Module, "M-RC").licensed


def test_non_admins_cannot_read_or_install(env, vendor):
    admin, _ = login(env, ADMIN)
    admin.put("/api/admin/licence", json={"key": key(vendor, modules=("*",))})
    analyst, _ = login(env, ANALYST)
    assert analyst.get("/api/admin/licence").status_code == 403
    assert analyst.put("/api/admin/licence", json={"key": key(vendor)}).status_code == 403


# ---------------------------------------------------------------- command line
def test_cli_keygen_issue_show_install(tmp_path, capsys, vendor):
    out = tmp_path / "keys"
    ns = lambda **kw: SimpleNamespace(**kw)  # noqa: E731
    cli.licence_command(ns(lcmd="keygen", out=out))
    priv, pub = out / "sutra-licence-private.pem", out / "sutra-licence-public.pem"
    assert priv.stat().st_mode & 0o077 == 0, "the private key is readable by its owner only"
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        cli.licence_command(ns(lcmd="keygen", out=out))
    capsys.readouterr()
    cli.licence_command(ns(lcmd="issue", private_key=priv, customer="Plant Co", id="P-9",
                           modules="M-RC, M-OT", expires="2030-01-01"))
    token = capsys.readouterr().out.strip()
    cli.licence_command(ns(lcmd="show", key=token, public_key=pub))
    shown = capsys.readouterr().out
    assert "Plant Co" in shown and "M-OT" in shown
    with pytest.raises(SystemExit, match="signature"):
        cli.licence_command(ns(lcmd="show", key=token, public_key=vendor.public_path))
    with pytest.raises(SystemExit, match="YYYY|date"):
        cli.licence_command(ns(lcmd="issue", private_key=priv, customer="x", id="x", modules="M-RC",
                               expires="soon"))
    ws = tmp_path / "ws"
    import os
    os.environ["SUTRA_LICENCE_PUBLIC_KEY"] = str(pub)
    try:
        cli.licence_command(ns(lcmd="install", key=token, workspace=ws))
    finally:
        del os.environ["SUTRA_LICENCE_PUBLIC_KEY"]
    assert "Licensed to Plant Co" in capsys.readouterr().out
