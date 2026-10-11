"""Milestone 4: read-only firewall and switch configuration collection.

Collections run through the real collectors (``sutra_connectors``); the devices are played by fake HTTP endpoints and
a fake SSH client. Real device output and configurations come from the connector fixtures
(``connectors/tests/fixtures/netdevices``, sources in its README)."""

from __future__ import annotations

import json
import socket
import time
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import ConfigSnapshot, NetworkDevice, utcnow

FIX = Path(__file__).resolve().parent.parent / "connectors" / "tests" / "fixtures" / "netdevices"
D = "vindhyapower.example"
ADMIN, VM, LINUX = f"admin@{D}", f"aisha.khan@{D}", f"it.infra.linux.team@{D}"
KEY_A = "SHA256:ycS795wsjuIr0nSPSIF04ZIYVyiDxObuAAu8w9eJlX8"
KEY_B = "SHA256:Bnew0000000000000000000000000000000000000000"
FORTI_SECRET = "        set password ENC SH2nlSm9pHsMdbV4Mm5/0FU7Uf6SsAA="


class Devices:
    """The fake devices' current state, changed by the tests."""

    def __init__(self):
        self.forti_config = (FIX / "fortios_firewall_policy.conf").read_text()
        self.forti_config = self.forti_config.replace(
            'config system global\n', 'config system global\n    set admin-sport 8443\n', 1) + "\n".join([
                "config system admin", '    edit "admin"', FORTI_SECRET, "    next", "end", ""])
        self.panos_fail = False
        self.host_key = KEY_A
        self.ios_config = "Building configuration...\n\n" + (FIX / "ios_as1border1.cfg").read_text()

    def http(self, req: httpx.Request) -> httpx.Response:
        if req.url.host == "fw1.plant.example.in":
            assert req.headers["authorization"] == "Bearer forti-token"
            if req.url.path.endswith("/system/status"):
                return httpx.Response(200, json=json.loads((FIX / "fortigate_status.json").read_text()))
            return httpx.Response(200, text=self.forti_config)
        if req.url.host == "pa-dc.example.in":
            if self.panos_fail:
                return httpx.Response(503, text="Service Unavailable")
            if b"type=op" in req.content:
                return httpx.Response(200, text=(FIX / "panos_system_info.xml").read_text())
            config = (FIX / "panos_iron_skillet_full.xml").read_text()
            return httpx.Response(200, text=f'<response status="success"><result>{config}</result></response>')
        return httpx.Response(404)

    def ssh_client(self):
        devices = self

        class Key:
            fingerprint = devices.host_key

        class Channel:
            def __init__(self):
                self.queue = bytearray()

            def settimeout(self, t):
                pass

            def send(self, s):
                if s == "\n":
                    self.queue += b"\r\nas1border1#"
                    return
                cmd = s.strip()
                out = {"show running-config": devices.ios_config,
                       "show version": (FIX / "ios_show_version_cat4500.raw").read_text(),
                       "show ip arp": (FIX / "ios_show_ip_arp.raw").read_text(),
                       "show mac address-table": (FIX / "ios_show_mac_address_table2.raw").read_text()}.get(cmd, "")
                self.queue += f"{cmd}\r\n{out}\r\nas1border1#".replace("\n", "\r\n").replace("\r\r", "\r").encode()

            def recv(self, n):
                if not self.queue:
                    raise socket.timeout()
                data = bytes(self.queue[:4096])
                del self.queue[:4096]
                return data

        class Client:
            def set_missing_host_key_policy(self, policy):
                self.policy = policy

            def connect(self, host, **kw):
                assert (host, kw["port"], kw["username"], kw["password"]) == ("10.20.0.2", 2222, "sutra-ro", "pw-ios")
                self.policy.missing_host_key(self, host, Key())

            def invoke_shell(self, **kw):
                return Channel()

            def close(self):
                pass

        return Client()


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ws")
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    app = create_app(settings, background=False)
    devices = Devices()
    app.state.collector.transport = httpx.MockTransport(devices.http)
    app.state.collector.client_factory = devices.ssh_client
    with TestClient(app, base_url="https://testserver"):
        yield app, passwords, devices


def client(env, email):
    app, passwords = env[0], env[1]
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


def _wait(app, seconds=60):
    deadline = utcnow() + timedelta(seconds=seconds)
    while app.state.collector.busy() and utcnow() < deadline:
        time.sleep(0.05)
    assert not app.state.collector.busy()


def collect(env, device=None):
    r = client(env, VM).post("/api/data/devices/collect", json={"device": device})
    assert r.status_code == 202, r.text
    _wait(env[0])
    return {d["name"]: d for d in client(env, VM).get("/api/data/devices").json()["devices"]}


def test_devices_are_admin_only_checked_and_secrets_never_leave(env):
    admin, vm = client(env, ADMIN), client(env, VM)
    forti = {"kind": "fortigate", "name": "FW1 plant", "address": "https://fw1.plant.example.in/",
             "secret": "forti-token", "site": "Plant 1"}
    assert vm.post("/api/data/devices", json=forti).status_code == 403
    assert client(env, LINUX).get("/api/data/devices").status_code == 403
    bad = admin.post("/api/data/devices", json={**forti, "address": "http://fw1.plant.example.in"})
    assert bad.status_code == 400 and "https://" in bad.json()["error"]
    no_user = admin.post("/api/data/devices", json={"kind": "cisco_ios", "name": "x", "address": "10.20.0.2",
                                                    "secret": "pw"})
    assert no_user.status_code == 400 and "user name" in no_user.json()["error"]
    bad_host = admin.post("/api/data/devices", json={"kind": "cisco_ios", "name": "x", "address": "ssh://10.20.0.2",
                                                     "username": "u", "secret": "pw"})
    assert bad_host.status_code == 400
    f = admin.post("/api/data/devices", json=forti)
    assert f.status_code == 201, f.text
    assert f.json()["address"] == "https://fw1.plant.example.in" and f.json()["has_secret"]
    p = admin.post("/api/data/devices", json={"kind": "panos", "name": "PA DC", "address": "https://pa-dc.example.in",
                                              "secret": "pan-key"})
    s = admin.post("/api/data/devices", json={"kind": "cisco_ios", "name": "Core switch",
                                              "address": "10.20.0.2:2222", "username": "sutra-ro",
                                              "secret": "pw-ios"})
    assert p.status_code == s.status_code == 201
    assert s.json()["address"] == "10.20.0.2:2222" and s.json()["host_key"] == ""
    listing = json.dumps(vm.get("/api/data/devices").json())
    assert "forti-token" not in listing and "pan-key" not in listing and "pw-ios" not in listing
    with env[0].state.sessionmaker() as db:
        stored = " ".join(db.scalars(select(NetworkDevice.secret)))
    assert "forti-token" not in stored and "pw-ios" not in stored  # encrypted at rest


def test_collection_stores_masked_configs_and_only_real_changes(env):
    app, _, devices = env
    vm = client(env, VM)
    got = collect(env)
    forti, pa, sw = got["FW1 plant"], got["PA DC"], got["Core switch"]
    assert forti["last_status"] == pa["last_status"] == sw["last_status"] == "first"
    assert forti["current"]["version"] == "v7.2.8" and forti["current"]["facts"] == {"firewall_policies": 5}
    assert pa["current"]["version"] == "10.1.11-h4" and pa["current"]["facts"] == {"security_rules": 2}
    assert sw["current"]["hostname"] == "as1border1" and sw["current"]["mac_table"] > 0 and sw["current"]["arp"] == 1
    assert sw["host_key"] == KEY_A  # pinned on first use
    snap = vm.get(f"/api/data/snapshots/{forti['current']['id']}").json()
    assert "SH2nlSm9" not in snap["config"] and "set password ENC SUTRA-MASKED" in snap["config"]
    assert snap["masked"] == 1
    with app.state.sessionmaker() as db:
        assert "SH2nlSm9" not in " ".join(db.scalars(select(ConfigSnapshot.config)))
        assert "md5_hash" not in " ".join(db.scalars(select(ConfigSnapshot.config)))  # PAN-OS phash masked

    # Same configuration again, with only the lines IOS rewrites by itself changed: no new snapshot.
    devices.ios_config = devices.ios_config.replace("Building configuration...",
                                                    "Building configuration...\n! Last configuration change at 10:01")
    again = collect(env)
    assert {d["last_status"] for d in again.values()} == {"unchanged"}
    assert {d["snapshots"] for d in again.values()} == {1}

    # A real change on the FortiGate: one more snapshot and a diff that shows it.
    devices.forti_config = devices.forti_config.replace("set admin-sport 8443", "set admin-sport 443")
    changed = collect(env, forti["id"])
    assert changed["FW1 plant"]["last_status"] == "changed" and changed["FW1 plant"]["snapshots"] == 2
    assert changed["PA DC"]["last_status"] == "unchanged"  # not collected this time
    history = vm.get(f"/api/data/devices/{forti['id']}/snapshots").json()["snapshots"]
    d = vm.get(f"/api/data/snapshots/{history[0]['id']}/diff").json()
    assert d["from"] == history[1]["id"] and (d["added"], d["removed"]) == (1, 1)
    assert "-    set admin-sport 8443" in d["lines"] and "+    set admin-sport 443" in d["lines"]
    first = vm.get(f"/api/data/snapshots/{history[1]['id']}/diff").json()
    assert first["from"] is None and first["removed"] == 0
    dl = vm.get(f"/api/data/snapshots/{history[0]['id']}/download")
    assert dl.status_code == 200 and "attachment" in dl.headers["content-disposition"]
    assert dl.headers["content-disposition"].endswith('.conf"') and "set admin-sport 443" in dl.text
    actions = {e["action"] for e in client(env, ADMIN).get("/api/audit").json()["events"]}
    assert {"data.device_add", "data.config_collect", "data.config_view", "data.config_download",
            "data.device_host_key_pinned"} <= actions


def test_one_failing_device_does_not_stop_the_others(env):
    _, _, devices = env
    devices.panos_fail = True
    try:
        got = collect(env)
    finally:
        devices.panos_fail = False
    assert got["PA DC"]["last_status"] == "failed" and "503" in got["PA DC"]["last_error"]
    assert got["FW1 plant"]["last_status"] == "unchanged" and got["Core switch"]["last_status"] == "unchanged"
    assert got["PA DC"]["current"]["version"] == "10.1.11-h4"  # the last good configuration is kept


def test_a_changed_host_key_stops_collection_until_an_admin_clears_it(env):
    _, _, devices = env
    devices.host_key = KEY_B
    got = collect(env)
    sw = got["Core switch"]
    assert sw["last_status"] == "failed" and "HostKeyError" in sw["last_error"] and sw["host_key"] == KEY_A
    admin = client(env, ADMIN)
    body = {"kind": "cisco_ios", "name": "Core switch", "address": "10.20.0.2:2222", "username": "sutra-ro"}
    assert client(env, VM).put(f"/api/data/devices/{sw['id']}", json={**body, "clear_host_key": True}).status_code \
        == 403
    r = admin.put(f"/api/data/devices/{sw['id']}", json={**body, "clear_host_key": True})
    assert r.status_code == 200 and r.json()["host_key"] == "" and r.json()["has_secret"]  # password kept
    got = collect(env, sw["id"])
    assert got["Core switch"]["last_status"] == "unchanged" and got["Core switch"]["host_key"] == KEY_B
    bad = admin.put(f"/api/data/devices/{sw['id']}", json={**body, "host_key": "MD5:aa"})
    assert bad.status_code == 400


def test_one_collection_at_a_time_and_daily_schedule(env):
    app = env[0]
    collector = app.state.collector
    assert collector._lock.acquire(blocking=False)
    try:
        assert client(env, VM).post("/api/data/devices/collect", json={}).status_code == 409
    finally:
        collector._lock.release()
    admin = client(env, ADMIN)
    assert admin.put("/api/data/connections-schedule", json={"enabled": True, "hour": 2}).status_code == 200
    with app.state.sessionmaker() as db:
        last = max(db.scalars(select(NetworkDevice.last_attempt_at)))
        day = (last + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        ist = timedelta(hours=5, minutes=30)
        assert not collector.due(db, last)  # every device was tried after today's slot
        assert not collector.due(db, day - ist + timedelta(hours=1))  # 01:00 IST: before the slot
        assert collector.due(db, day - ist + timedelta(hours=2, minutes=30))
    admin.put("/api/data/connections-schedule", json={"enabled": False, "hour": 2})
    with app.state.sessionmaker() as db:
        assert not collector.due(db, day - ist + timedelta(hours=2, minutes=30))


def test_deleting_a_device_deletes_its_history(env):
    admin = client(env, ADMIN)
    devices = admin.get("/api/data/devices").json()["devices"]
    pa = next(d for d in devices if d["name"] == "PA DC")
    assert client(env, VM).delete(f"/api/data/devices/{pa['id']}").status_code == 403
    assert admin.delete(f"/api/data/devices/{pa['id']}").status_code == 200
    with env[0].state.sessionmaker() as db:
        assert not db.scalars(select(ConfigSnapshot).where(ConfigSnapshot.device_id == pa["id"])).first()
    assert admin.get(f"/api/data/devices/{pa['id']}/snapshots").status_code == 404
