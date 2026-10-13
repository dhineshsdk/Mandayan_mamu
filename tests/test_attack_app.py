"""Attack surface in the app: who may see and change it, and the report built from stored configurations.

The devices and their configurations are the invented sample network in ``examples/attack-surface`` (stored directly
as the latest snapshot of each device, as a collection would leave them)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sutra.app import cli
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AuditEvent, ConfigSnapshot, NetworkDevice, utcnow

SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "attack-surface"
D = "vindhyapower.example"
ADMIN, VM, LINUX = f"admin@{D}", f"aisha.khan@{D}", f"it.infra.linux.team@{D}"
ZONES = json.loads((SAMPLE / "zones.json").read_text())


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


def add_device(app, kind, name, config, fmt):
    with app.state.sessionmaker() as db:
        d = NetworkDevice(kind=kind, name=name, address="x", secret="", site="Plant")
        db.add(d)
        db.flush()
        if config is not None:
            now = utcnow()
            db.add(ConfigSnapshot(device_id=d.id, collected_at=now, last_seen_at=now, digest=name, config_format=fmt,
                                  config=config))
        db.commit()
        return d.id


@pytest.fixture(scope="module")
def ids(env):
    app = env[0]
    return {"fw-edge": add_device(app, "fortigate", "fw-edge", (SAMPLE / "fw-edge.conf").read_text(), "fortios"),
            "fw-plant": add_device(app, "panos", "fw-plant", (SAMPLE / "fw-plant.xml").read_text(), "panos-xml"),
            "sw-ot-core": add_device(app, "cisco_ios", "sw-ot-core", (SAMPLE / "sw-ot-core.cfg").read_text(), "ios")}


def test_only_the_security_roles_can_open_it(env, ids):
    for email in (ADMIN, LINUX):
        assert client(env, email).get("/api/attack").status_code == 403
        assert client(env, email).put("/api/attack/zones", json={"zones": []}).status_code == 403
    modules = client(env, VM).get("/api/auth/me").json()["modules"]
    assert {"key": "M-ATK", "actions": ["act", "view"]} in [{"key": m["key"], "actions": sorted(m["actions"])}
                                                           for m in modules]


def test_without_zones_it_says_what_is_missing(env, ids):
    r = client(env, VM).get("/api/attack").json()
    assert r["paths"] == [] and any("No OT zone" in n for n in r["notes"])
    assert {c["device"] for c in r["coverage"]} == set(ids) and r["can_act"]
    assert sorted(r["devices_without_hits"]) == sorted(ids)


def test_zones_are_checked_and_replace_the_old_ones(env, ids):
    vm = client(env, VM)
    for bad, text in (([{"name": "OT", "kind": "ot", "cidrs": ["10.50.0.0/99"]}], "not a network"),
                      ([{"name": "OT", "kind": "ot", "cidrs": []}], "at least one network"),
                      ([{"name": "A", "kind": "it", "cidrs": ["10.0.0.0/8"]},
                        {"name": "a", "kind": "ot", "cidrs": ["10.1.0.0/16"]}], "different"),
                      ([{"name": "V6", "kind": "ot", "cidrs": ["2001:db8::/32"]}], "IPv4")):
        r = vm.put("/api/attack/zones", json={"zones": bad})
        assert r.status_code == 400 and text in r.json()["error"], r.text
    assert client(env, VM).get("/api/attack").json()["zones"] == []  # nothing half-saved
    assert vm.put("/api/attack/zones", json=ZONES).json() == {"zones": 4}
    zones = vm.get("/api/attack").json()["zones"]
    assert [z["name"] for z in zones] == ["Internet", "Corporate IT", "DMZ", "Plant OT"]
    assert zones[0]["cidrs"] == [] and zones[0]["ranges"]  # the internet defaults to the public addresses
    with env[0].state.sessionmaker() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == "attack.zones_set")).first()
        assert event and event.actor_email == VM


def test_report_finds_the_planted_paths_and_rules(env, ids):
    r = client(env, VM).get("/api/attack").json()
    internet = [p for p in r["paths"] if p["src_kind"] == "internet"]
    assert len(internet) == 1 and internet[0]["severity"] == "critical" and internet[0]["services"] == ["tcp/3389"]
    assert [h["device"] for h in internet[0]["hops"]] == ["fw-edge", "fw-plant", "sw-ot-core"]
    assert internet[0]["hops"][1]["rules"][0]["key"] == "Vendor remote support"
    assert r["summary"]["critical"] >= 2 and r["paths"][0]["severity"] == "critical"
    kinds = {(f["kind"], f["device"], f["rule"]["key"]) for f in r["findings"]}
    assert {("broad", "fw-edge", "5"), ("shadowed", "fw-edge", "7"), ("disabled", "fw-edge", "9")} <= kinds
    assert not any(f["kind"] == "unused" for f in r["findings"])  # no hit counts loaded yet
    assert r["chokepoints"][0]["sole"] >= 1


def test_hit_counts_make_rules_unused(env, ids):
    vm = client(env, VM)
    uploads = {"fw-edge": ("fortios_json", "hits/fw-edge.json", "2025-10-09T00:00:00"),
               "fw-plant": ("panos_xml", "hits/fw-plant.xml", None),
               "sw-ot-core": ("ios_access_lists", "hits/sw-ot-core.txt", "2025-10-09T00:00:00")}
    for name, (fmt, path, since) in uploads.items():
        r = vm.post(f"/api/attack/hits/{ids[name]}",
                    json={"format": fmt, "text": (SAMPLE / path).read_text(), "since": since})
        assert r.status_code == 200 and r.json()["rules"] > 3, r.text
    r = vm.get("/api/attack").json()
    assert r["devices_without_hits"] == []
    unused = {(f["device"], f["rule"]["key"]) for f in r["findings"] if f["kind"] == "unused"}
    assert {("fw-edge", "5"), ("fw-plant", "Temporary commissioning"), ("sw-ot-core", "SCADA-OUT 50")} <= unused
    safest = {(c["device"], c["rule"]["key"]) for c in r["chokepoints"] if c["unused"]}
    assert ("fw-plant", "Temporary commissioning") in safest
    # a new upload replaces the old; a bad one changes nothing
    bad = vm.post(f"/api/attack/hits/{ids['fw-edge']}", json={"format": "fortios_json", "text": "{\"results\": []}"})
    assert bad.status_code == 400
    csv = {"format": "csv", "text": "rule,hits\n5,3\n"}
    assert vm.post(f"/api/attack/hits/{ids['fw-edge']}", json=csv).status_code == 200
    r = vm.get("/api/attack").json()
    still = {(f["device"], f["rule"]["key"]) for f in r["findings"] if f["kind"] == "unused"}
    assert ("fw-edge", "5") not in still
    assert vm.post("/api/attack/hits/999", json=csv).status_code == 404
    assert vm.delete(f"/api/attack/hits/{ids['fw-edge']}").status_code == 200
    assert vm.delete(f"/api/attack/hits/{ids['fw-edge']}").status_code == 404
    assert "fw-edge" in vm.get("/api/attack").json()["devices_without_hits"]


def test_one_unreadable_device_does_not_hide_the_others(env, ids):
    app = env[0]
    add_device(app, "panos", "fw-broken", "<config><devices>", "panos-xml")
    add_device(app, "cisco_ios", "sw-new", None, "ios")
    r = client(env, VM).get("/api/attack").json()
    problems = {p["device"]: p["problem"] for p in r["problems"]}
    assert "could not be read" in problems["fw-broken"] and "No configuration" in problems["sw-new"]
    assert any(p["src_kind"] == "internet" for p in r["paths"])
