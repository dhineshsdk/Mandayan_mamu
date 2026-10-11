"""Milestone 7: `sutra doctor` finds unsafe or unfinished installations, and the app sends HSTS."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sutra.app import backup, cli, doctor, licence
from sutra.app.config import Settings
from sutra.app.main import create_app

GOOD_ENV = {
    "SUTRA_SECRET_KEY": "s" * 48, "SUTRA_BASE_URL": "https://sutra.plant.example.in", "SUTRA_EGRESS": "allowlist",
    "SUTRA_REQUIRE_LICENCE": "1", "SUTRA_OIDC_ISSUER": "https://login.example.in", "SUTRA_OIDC_CLIENT_ID": "id",
    "SUTRA_AI_PROVIDER": "off",
}


def by_name(checks):
    return {c.name: c for c in checks}


@pytest.fixture()
def install(tmp_path):
    ws = tmp_path / "ws"
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    cli.create_admin(settings, "root@plant.example.in", "Root", password="a long enough password 1!")
    os.chmod(ws, 0o700)
    os.chmod(ws / "sutra.db", 0o600)
    return ws


def env_for(ws, **kw):
    return {**GOOD_ENV, "SUTRA_WORKSPACE": str(ws), "SUTRA_BACKUP_DIR": str(ws / "backups"), **kw}


def test_a_hardened_installation_has_no_failures_and_names_what_is_left(install):
    backup.create(install, f"sqlite:///{install / 'sutra.db'}", install / "backups", "pw pw pw pw")
    checks = doctor.run(env_for(install), install, euid=1000)
    c = by_name(checks)
    assert [x for x in checks if x.level == "FAIL"] == []
    assert c["outbound connections"].level == "PASS" and c["backup encryption"].level == "PASS"
    assert c["licence key"].level == "WARN" and "No licence key" in c["licence key"].detail
    assert c["demo accounts"].level == "PASS" and c["administrator"].level == "PASS" and c["schema"].level == "PASS"
    assert c["AI model"].level == "PASS"


def test_a_careless_installation_fails_loudly(install):
    os.chmod(install / ".secret_key", 0o644)
    env = {"SUTRA_WORKSPACE": str(install), "SUTRA_COOKIE_SECURE": "0", "SUTRA_SECRET_KEY": "short"}
    c = by_name(doctor.run(env, install, euid=0))
    assert c["secure cookies"].level == "FAIL" and c["secret key"].level == "FAIL"
    for warn in ("service user", "base URL", "sign-in", "outbound connections", "licence", "backups"):
        assert c[warn].level == "WARN", warn
    env = {"SUTRA_WORKSPACE": str(install)}
    assert by_name(doctor.run(env, install, euid=1000))["secret key"].level == "FAIL", "key file is world-readable"


def test_world_readable_files_are_reported(install):
    os.chmod(install, 0o755)  # noqa: S103 - a deliberately unsafe mode under test
    os.chmod(install / "sutra.db", 0o644)
    c = by_name(doctor.run(env_for(install), install, euid=1000))
    assert c["workspace permissions"].level == "WARN" and c["database permissions"].level == "FAIL"


def test_demo_accounts_and_a_missing_admin_and_a_stale_schema_fail(tmp_path):
    ws = tmp_path / "ws"
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    cli.demo_users(settings, "power", months=1)
    c = by_name(doctor.run(env_for(ws), ws, euid=1000))
    assert c["demo accounts"].level == "FAIL" and "synthetic demo accounts" in c["demo accounts"].detail
    from alembic.script import ScriptDirectory

    from sutra.app import migrate
    older = [r.revision for r in ScriptDirectory.from_config(migrate.config("sqlite://")).walk_revisions()][1]
    ws2 = tmp_path / "ws2"
    ws2.mkdir()
    os.chmod(ws2, 0o700)
    migrate.upgrade(f"sqlite:///{ws2 / 'sutra.db'}", older)
    c2 = by_name(doctor.run(env_for(ws2), ws2, euid=1000))
    assert c2["schema"].level == "FAIL" and "python -m sutra upgrade" in c2["schema"].detail
    assert c2["administrator"].level == "FAIL"


def test_missing_workspace_and_database(tmp_path):
    out = doctor.run({"SUTRA_WORKSPACE": str(tmp_path / "nope")}, euid=1000)
    assert [(c.level, c.name) for c in out if c.level == "FAIL"] == [("FAIL", "workspace")]
    ws = tmp_path / "empty"
    ws.mkdir(mode=0o700)
    c = by_name(doctor.run(env_for(ws), ws, euid=1000))
    assert c["database"].level == "FAIL"


def test_backup_age_and_encryption(install):
    url = f"sqlite:///{install / 'sutra.db'}"
    path = backup.create(install, url, install / "backups")
    c = by_name(doctor.run(env_for(install), install, euid=1000))
    assert c["backups"].level == "PASS" and c["backup encryption"].level == "WARN"
    later = datetime.now(UTC) + timedelta(days=5)
    c = by_name(doctor.run(env_for(install), install, now=later, euid=1000))
    assert c["backups"].level == "WARN" and "days old" in c["backups"].detail
    old = time.time() - 86400 * 3
    os.utime(path, (old, old))
    assert by_name(doctor.run(env_for(install), install, euid=1000))["backups"].level == "WARN"


def test_cloud_model_is_flagged_unless_the_policy_blocks_it(install):
    open_env = env_for(install, SUTRA_EGRESS="open", SUTRA_AI_PROVIDER="auto", ANTHROPIC_API_KEY="k")
    assert by_name(doctor.run(open_env, install, euid=1000))["AI model"].level == "WARN"
    blocked = env_for(install, SUTRA_AI_PROVIDER="anthropic", ANTHROPIC_API_KEY="k")
    assert by_name(doctor.run(blocked, install, euid=1000))["AI model"].level == "PASS"
    allowed = env_for(install, SUTRA_AI_PROVIDER="anthropic", ANTHROPIC_API_KEY="k",
                      SUTRA_EGRESS_ALLOW="api.anthropic.com")
    assert by_name(doctor.run(allowed, install, euid=1000))["AI model"].level == "WARN"
    local = env_for(install, SUTRA_AI_LOCAL_URL="http://10.0.0.5:8000/v1", ANTHROPIC_API_KEY="k",
                    SUTRA_AI_PROVIDER="auto")
    assert by_name(doctor.run(local, install, euid=1000))["AI model"].level == "PASS"


def test_the_stored_licence_is_checked(install, tmp_path, monkeypatch):
    from datetime import date
    from types import SimpleNamespace

    private, public = licence.generate_keypair()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(public)
    other = tmp_path / "other.pem"
    other.write_bytes(licence.generate_keypair()[1])
    monkeypatch.setenv("SUTRA_LICENCE_PUBLIC_KEY", str(pub))

    def install_key(days):
        token = licence.issue(private, "Plant Co", ["M-RC"], date.today() + timedelta(days=days), f"P-{days}",
                              issued=date.today() - timedelta(days=5))
        cli.licence_command(SimpleNamespace(lcmd="install", key=token, workspace=install))

    install_key(200)
    c = by_name(doctor.run(env_for(install, SUTRA_LICENCE_PUBLIC_KEY=str(pub)), install, euid=1000))
    assert c["licence key"].level == "PASS" and "Plant Co" in c["licence key"].detail
    c = by_name(doctor.run(env_for(install, SUTRA_LICENCE_PUBLIC_KEY=str(other)), install, euid=1000))
    assert c["licence key"].level == "FAIL" and "not valid" in c["licence key"].detail
    install_key(10)
    c = by_name(doctor.run(env_for(install, SUTRA_LICENCE_PUBLIC_KEY=str(pub)), install, euid=1000))
    assert c["licence key"].level == "WARN" and "10 days" in c["licence key"].detail
    c = by_name(doctor.run(env_for(install, SUTRA_LICENCE_PUBLIC_KEY=str(tmp_path / "none.pem")), install, euid=1000))
    assert c["licence key"].level == "FAIL" and "no vendor public key" in c["licence key"].detail


def test_command_exit_code_and_json(install, capsys, monkeypatch):
    from types import SimpleNamespace

    for k in ("SUTRA_SECRET_KEY", "SUTRA_BASE_URL", "SUTRA_EGRESS", "SUTRA_REQUIRE_LICENCE", "SUTRA_BACKUP_DIR",
              "SUTRA_DATABASE_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SUTRA_COOKIE_SECURE", "0")
    with pytest.raises(SystemExit) as e:
        cli.doctor_command(SimpleNamespace(workspace=install, json=False))
    assert e.value.code == 1 and "FAIL  secure cookies" in capsys.readouterr().out
    monkeypatch.delenv("SUTRA_COOKIE_SECURE")
    cli.doctor_command(SimpleNamespace(workspace=install, json=True))
    assert '"name": "secure cookies"' in capsys.readouterr().out


def test_hsts_is_sent_only_when_cookies_are_secure(tmp_path):
    for secure, expected in ((True, True), (False, False)):
        ws = tmp_path / f"w{secure}"
        settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}", cookie_secure=secure)
        with TestClient(create_app(settings), base_url="https://testserver") as c:
            r = c.get("/api/auth/config")
            assert ("strict-transport-security" in r.headers) is expected
            if expected:
                assert "max-age=31536000" in r.headers["strict-transport-security"]
