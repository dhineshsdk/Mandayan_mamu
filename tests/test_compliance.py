"""Milestone 5: the Compliance module (M-CMP). Audits and findings recorded in Sutra run through the CEA rule pack
(``sutra_compliance``); a finding linked to a patch job is closed only by the rescan that verified the job.

Dates are set relative to today (Indian calendar date), so the states asserted hold whenever the tests run. The
entities, audits, findings and auditors below are invented for the tests."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sutra_compliance import verify_audit_pack

from sutra.app import cli
from sutra.app import compliance as cmp
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AuditEvent

D = "vindhyapower.example"
LINUX, MANAGER, VM, HEAD = f"it.infra.linux.team@{D}", f"arjun.mehta@{D}", f"aisha.khan@{D}", f"neha.joshi@{D}"
OFFICER, AUDITOR, CISO = f"compliance@{D}", f"auditor@{D}", f"ciso@{D}"


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


def ok(r, code=200):
    assert r.status_code == code, r.text
    return r.json()


def days(n: int) -> str:
    return (cmp.today_local() + timedelta(days=n)).isoformat()


@pytest.fixture(scope="module")
def log4j_job(env):
    """Raise and approve the Log4j job in month 0; the month 1 import proves it fixed (sutra.synth)."""
    team = client(env, LINUX)
    rc = next(t for t in team.get("/api/portal").json()["teams"][0]["tasks"] if "Log4j" in t["title"])
    j = ok(team.post("/api/jobs", json={"rc_id": rc["id"], "team": "IT Infra - Linux", "mode": "patch"}), 201)
    for who in (MANAGER, VM, HEAD)[:len(j["steps"])]:
        ok(client(env, who).post(f"/api/jobs/{j['pk']}/decision", json={"action": "approve"}))
    ok(client(env, VM).post("/api/data/demo", json={"profile": "power", "month": 1}))
    j = ok(team.get(f"/api/jobs/{j['pk']}"))
    assert j["status"] == "verified-fixed"
    return j


def finding_of(detail: dict, ref: str) -> dict:
    return next(f for a in detail["audits"] for f in a["findings"] if f["ref"] == ref)


def test_who_can_read_and_who_can_record(env):
    officer, auditor = client(env, OFFICER), client(env, AUDITOR)
    e = ok(officer.post("/api/compliance/entities", json={"name": "Access Check Station", "entity_type": "generator",
                                                          "capacity_mw": 120}), 201)
    assert ok(auditor.get("/api/compliance/entities"))["can_act"] is False
    assert ok(client(env, CISO).get(f"/api/compliance/entities/{e['id']}"))["can_act"] is True
    # The auditor reads but cannot record anything.
    assert auditor.post("/api/compliance/entities", json={"name": "X", "entity_type": "generator"}).status_code == 403
    assert auditor.post(f"/api/compliance/entities/{e['id']}/audits", json={
        "ref": "A", "auditor": "X", "auditor_status": "unknown", "started_on": days(-1)}).status_code == 403
    # People without the module get nothing, not even the list.
    for who in (LINUX, VM, f"executive@{D}"):
        assert client(env, who).get("/api/compliance/entities").status_code == 403
    ok(officer.delete(f"/api/compliance/entities/{e['id']}"))


def test_the_fix_clock_shows_honest_states(env):
    officer = client(env, OFFICER)
    e = ok(officer.post("/api/compliance/entities", json={"name": "Unit 2 Thermal", "entity_type": "generator",
                                                          "capacity_mw": 600, "site": "Vindhya Thermal Plant"}), 201)
    a = ok(officer.post(f"/api/compliance/entities/{e['id']}/audits", json={
        "ref": "CSA-1", "auditor": "Example Auditors LLP", "auditor_status": "cert_in_empanelled",
        "started_on": days(-70), "report_submitted_on": days(-45)}), 201)
    f = ok(officer.post(f"/api/compliance/audits/{a['id']}/findings", json={
        "ref": "F-1", "severity": "Critical", "title": "SMBv1 enabled on the historian", "asset_ids": ["HIST-01"]}),
        201)
    low = ok(officer.post(f"/api/compliance/audits/{a['id']}/findings", json={
        "ref": "F-2", "severity": "low", "title": "Banner discloses version"}), 201)

    d = ok(officer.get(f"/api/compliance/entities/{e['id']}"))
    clock = finding_of(d, "F-1")["clock"]
    report = date.fromisoformat(days(-45))
    assert clock["state"] == "overdue_uncompensated" and clock["breach"] is True
    assert clock["clock_starts_on"] == report.isoformat()
    assert clock["due_on"] == cmp.pack().fix_rule_for("critical").duration.after(report).isoformat()
    assert clock["citations"][0]["rule_id"] == "CEA-FIX-CRITICAL-HIGH"
    assert finding_of(d, "F-2")["clock"]["state"] == "open"  # 3 months for low findings
    # The regulation starts on 1 April 2027: before then the readiness view counts the breach, the status does not.
    if cmp.today_local() < date(2027, 4, 1):
        assert clock["in_force"] is False
        assert d["assessment"]["status_if_in_force"] == "non_compliant"

    # A compensating control in place turns the breach into an overdue-but-compensated finding.
    ok(officer.post(f"/api/compliance/findings/{f['id']}/controls", json={
        "description": "SMB blocked from the corporate VLAN at the plant firewall", "implemented_on": days(-5),
        "approved_by": "Plant CISO"}), 201)
    # A fix scheduled for the next shutdown is shown with the clock; it does not stop it.
    ok(officer.put(f"/api/compliance/findings/{f['id']}", json={
        "ref": "F-1", "severity": "critical", "title": "SMBv1 enabled on the historian", "asset_ids": ["HIST-01"],
        "planned_on": days(40), "planned_reason": "Unit 2 annual overhaul", "planned_reference": "SD-2027-02"}))
    d = ok(officer.get(f"/api/compliance/entities/{e['id']}"))
    item = finding_of(d, "F-1")
    clock = item["clock"]
    assert clock["state"] == "overdue_compensated" and clock["breach"] is False
    assert clock["compensating_controls_active"] == [item["controls"][0]["ref"]]
    assert clock["scheduled_fix_on"] == days(40) and clock["scheduled_fix_reason"] == "Unit 2 annual overhaul"
    assert "Unit 2 annual overhaul" in clock["explanation"]
    assert clock["fix_needs_pre_deployment_audit"] is True  # Second Schedule: fixes for critical findings

    # Withdrawing the control brings the breach back.
    ok(officer.put(f"/api/compliance/controls/{item['controls'][0]['id']}", json={
        "description": "SMB blocked from the corporate VLAN at the plant firewall", "implemented_on": days(-5),
        "withdrawn_on": days(-1), "approved_by": "Plant CISO"}))
    assert finding_of(ok(officer.get(f"/api/compliance/entities/{e['id']}")), "F-1")["clock"]["state"] == \
        "overdue_uncompensated"

    # A fix recorded by hand closes it, late.
    ok(officer.put(f"/api/compliance/findings/{f['id']}", json={
        "ref": "F-1", "severity": "critical", "title": "SMBv1 enabled on the historian", "fixed_on": days(0)}))
    item = finding_of(ok(officer.get(f"/api/compliance/entities/{e['id']}")), "F-1")
    assert item["clock"]["state"] == "fixed_late" and item["fixed_source"] == "recorded"
    ok(officer.delete(f"/api/compliance/findings/{low['id']}"))


def test_bad_records_are_refused(env):
    officer = client(env, OFFICER)
    bad_type = officer.post("/api/compliance/entities", json={"name": "Bad", "entity_type": "power_station"})
    assert bad_type.status_code == 400
    e = ok(officer.post("/api/compliance/entities", json={"name": "Checks Substation",
                                                          "entity_type": "transmission_licensee"}), 201)
    audits = f"/api/compliance/entities/{e['id']}/audits"
    base = {"ref": "A-1", "auditor": "Example LLP", "auditor_status": "other", "started_on": days(-30)}
    assert officer.post(audits, json={**base, "report_submitted_on": days(1)}).status_code == 400  # in the future
    assert officer.post(audits, json={**base, "report_submitted_on": days(-40)}).status_code == 400  # before start
    a = ok(officer.post(audits, json=base), 201)
    assert officer.post(audits, json=base).status_code == 400  # same reference twice
    findings = f"/api/compliance/audits/{a['id']}/findings"
    assert officer.post(findings, json={"ref": "F", "severity": "urgent", "title": "x"}).status_code == 400
    assert officer.post(findings, json={"ref": "F", "severity": "high", "title": "x", "planned_on": days(9)}) \
        .status_code == 400  # a scheduled fix must say what it is scheduled for
    assert officer.post(findings, json={"ref": "F", "severity": "high", "title": "x", "job_id": 999999}) \
        .status_code == 400
    # An entity with audits on record cannot be removed.
    assert officer.delete(f"/api/compliance/entities/{e['id']}").status_code == 400


def test_a_linked_job_closes_the_finding_only_through_its_rescan(env, log4j_job):
    officer = client(env, OFFICER)
    fixed_on = date.fromisoformat(log4j_job["fixed_on"])
    e = ok(officer.post("/api/compliance/entities", json={"name": "Corporate Data Centre SLDC link",
                                                          "entity_type": "sldc"}), 201)
    a = ok(officer.post(f"/api/compliance/entities/{e['id']}/audits", json={
        "ref": "CSA-2", "auditor": "Example Auditors LLP", "auditor_status": "cert_in_empanelled",
        "started_on": (fixed_on - timedelta(days=30)).isoformat(),
        "report_submitted_on": (fixed_on - timedelta(days=10)).isoformat()}), 201)
    body = {"ref": "F-7", "severity": "critical", "title": "Log4Shell on the reporting servers",
            "job_id": log4j_job["pk"]}
    # A linked finding's fix date cannot be typed in.
    assert officer.post(f"/api/compliance/audits/{a['id']}/findings",
                        json={**body, "fixed_on": fixed_on.isoformat()}).status_code == 400
    ok(officer.post(f"/api/compliance/audits/{a['id']}/findings", json=body), 201)
    assert log4j_job["pk"] in [j["id"] for j in ok(officer.get("/api/compliance/jobs?q=Log4j"))["jobs"]]

    # The exit check: an auditor can see that this critical finding closed within a month, and the proof.
    d = ok(client(env, AUDITOR).get(f"/api/compliance/entities/{e['id']}"))
    item = finding_of(d, "F-7")
    assert item["fixed_on"] == fixed_on.isoformat() and item["fixed_source"] == "rescan"
    assert item["clock"]["state"] == "fixed_on_time" and item["clock"]["closed_on"] == fixed_on.isoformat()
    assert item["clock"]["due_on"] > item["clock"]["closed_on"]
    job = item["job"]
    proof = next(c for c in job["checks"] if c["id"] == job["proof_check"])
    assert proof["outcome"] == "fixed" and proof["still_open"] == 0 and proof["as_of"] == fixed_on.isoformat()


def test_evidence_is_stored_by_hash_linked_and_downloaded_with_an_audit_trail(env):
    officer, auditor = client(env, OFFICER), client(env, AUDITOR)
    e = ok(officer.post("/api/compliance/entities", json={"name": "Evidence Station", "entity_type": "generator",
                                                          "capacity_mw": 75}), 201)
    other = ok(officer.post("/api/compliance/entities", json={"name": "Other Station", "entity_type": "generator",
                                                              "capacity_mw": 75}), 201)
    a = ok(officer.post(f"/api/compliance/entities/{e['id']}/audits", json={
        "ref": "CSA-3", "auditor": "Example LLP", "auditor_status": "mop_designated", "started_on": days(-20),
        "report_submitted_on": days(-3)}), 201)
    content = b"%PDF-1.4\n% audit report for the test\n"
    up = ok(officer.post(f"/api/compliance/entities/{e['id']}/evidence",
                         data={"kind": "audit_report", "title": "CSA-3 audit report", "owner_type": "audit_report",
                               "owner_id": str(a["id"])},
                         files={"file": ("CSA-3 report.pdf", content, "application/pdf")}), 201)
    assert up["sha256"] == hashlib.sha256(content).hexdigest() and up["size"] == len(content)
    assert up["filename"] == "CSA-3_report.pdf"
    app, _ = env
    assert cmp.evidence_path(app.state.settings.workspace, up["sha256"]).read_bytes() == content

    d = ok(auditor.get(f"/api/compliance/entities/{e['id']}"))
    assert [x["id"] for x in d["audits"][0]["report_evidence"]] == [up["id"]]
    r = auditor.get(f"/api/compliance/evidence/{up['id']}/download")
    assert r.status_code == 200 and r.content == content and r.headers["x-evidence-sha256"] == up["sha256"]
    assert "attachment" in r.headers["content-disposition"]

    # Linking to another entity's record, rescan as an uploaded kind and empty files are refused.
    a2 = ok(officer.post(f"/api/compliance/entities/{other['id']}/audits", json={
        "ref": "CSA-9", "auditor": "Example LLP", "auditor_status": "unknown", "started_on": days(-2)}), 201)
    assert officer.post(f"/api/compliance/evidence/{up['id']}/links",
                        json={"owner_type": "audit_report", "owner_id": a2["id"]}).status_code == 400
    for data, payload in (({"kind": "rescan", "title": "x"}, b"x"), ({"kind": "other", "title": "x"}, b"")):
        assert officer.post(f"/api/compliance/entities/{e['id']}/evidence", data=data,
                            files={"file": ("x.txt", payload, "text/plain")}).status_code == 400
    assert auditor.post(f"/api/compliance/entities/{e['id']}/evidence", data={"kind": "other", "title": "x"},
                        files={"file": ("x.txt", b"x", "text/plain")}).status_code == 403

    # Unlinking keeps the file and the trail.
    ok(officer.delete(f"/api/compliance/evidence/{up['id']}/links?owner_type=audit_report&owner_id={a['id']}"))
    d = ok(officer.get(f"/api/compliance/entities/{e['id']}"))
    assert d["audits"][0]["report_evidence"] == [] and d["evidence"][0]["id"] == up["id"]
    with app.state.sessionmaker() as db:
        actions = set(db.scalars(select(AuditEvent.action).where(AuditEvent.target_type == "cmp_evidence")))
    assert {"compliance.evidence_upload", "compliance.evidence_link", "compliance.evidence_download",
            "compliance.evidence_unlink"} <= actions


def test_recurring_activities_feed_the_periodic_checks(env):
    officer = client(env, OFFICER)
    e = ok(officer.post("/api/compliance/entities", json={"name": "Drill Station", "entity_type": "generator",
                                                          "capacity_mw": 300}), 201)
    before = ok(officer.get(f"/api/compliance/entities/{e['id']}"))["assessment"]["periodic"]
    assert next(p for p in before if p["activity"] == "ccmp_drill")["state"] == "no_record"
    assert officer.post(f"/api/compliance/entities/{e['id']}/activities",
                        json={"activity": "backup", "performed_on": days(-1)}).status_code == 400  # per asset
    ok(officer.post(f"/api/compliance/entities/{e['id']}/activities",
                    json={"activity": "ccmp_drill", "performed_on": days(-10), "approved_by": "Station head"}), 201)
    d = ok(officer.get(f"/api/compliance/entities/{e['id']}"))
    drill = next(p for p in d["assessment"]["periodic"] if p["activity"] == "ccmp_drill")
    assert drill["state"] == "current" and drill["last_performed_on"] == days(-10)
    assert d["activities"][0]["title"]


def test_assets_come_from_the_register_and_are_classed_by_a_person(env):
    officer = client(env, OFFICER)
    e = ok(officer.post("/api/compliance/entities", json={"name": "Vindhya Thermal Plant", "entity_type": "generator",
                                                          "capacity_mw": 1320, "site": "Vindhya Thermal Plant"}), 201)
    first = ok(officer.post(f"/api/compliance/entities/{e['id']}/assets/import"))
    assert first["added"] > 0 and first["already"] == 0
    assert ok(officer.post(f"/api/compliance/entities/{e['id']}/assets/import")) == {"added": 0,
                                                                                     "already": first["added"]}
    d = ok(officer.get(f"/api/compliance/entities/{e['id']}"))
    assert len(d["assets"]) == first["added"] and all(x["critical"] is None for x in d["assets"])
    assert all(x["register"]["site"] == "Vindhya Thermal Plant" for x in d["assets"])
    # Unclassed assets are a gap of their own for the backup rule; nothing is classed from the register.
    states = {p["state"] for p in d["assessment"]["periodic"] if p["activity"] == "backup"}
    assert states == {"unclassified_asset"}

    crit, other = d["assets"][0], d["assets"][1]
    ok(officer.put(f"/api/compliance/assets/{crit['id']}", json={"critical": True}))
    ok(officer.put(f"/api/compliance/assets/{other['id']}", json={"critical": False}))
    acts = f"/api/compliance/entities/{e['id']}/activities"
    assert officer.post(acts, json={"activity": "backup", "performed_on": days(-3),
                                    "asset_id": other["asset_id"]}).status_code == 400  # not a critical system
    assert officer.post(acts, json={"activity": "policy_review", "performed_on": days(-3),
                                    "asset_id": crit["asset_id"]}).status_code == 400  # entity-wide activity
    ok(officer.post(acts, json={"activity": "backup", "performed_on": days(-3), "asset_id": crit["asset_id"]}), 201)
    ok(officer.post(acts, json={"activity": "asset_risk_assessment", "performed_on": days(-20),
                                "asset_id": crit["asset_id"]}), 201)
    d = ok(officer.get(f"/api/compliance/entities/{e['id']}"))
    row = next(x for x in d["assets"] if x["id"] == crit["id"])
    assert row["critical"] is True and row["backup"]["state"] == "current"
    assert row["risk_assessment"]["state"] == "current" and row["risk_assessment"]["last_performed_on"] == days(-20)
    assert next(x for x in d["assets"] if x["id"] == other["id"])["backup"] is None
    assert not any("No assets are recorded" in n for n in d["notes"])
    # An asset with activities on record stays.
    assert officer.delete(f"/api/compliance/assets/{crit['id']}").status_code == 400


def test_the_audit_pack_exports_with_its_evidence_and_a_digest(env, log4j_job):
    officer, auditor = client(env, OFFICER), client(env, AUDITOR)
    fixed_on = date.fromisoformat(log4j_job["fixed_on"])
    e = ok(officer.post("/api/compliance/entities", json={"name": "Pack Station", "entity_type": "generator",
                                                          "capacity_mw": 500}), 201)
    a = ok(officer.post(f"/api/compliance/entities/{e['id']}/audits", json={
        "ref": "CSA-P", "auditor": "Example LLP", "auditor_status": "cert_in_empanelled",
        "started_on": (fixed_on - timedelta(days=30)).isoformat(),
        "report_submitted_on": (fixed_on - timedelta(days=10)).isoformat()}), 201)
    ok(officer.post(f"/api/compliance/audits/{a['id']}/findings", json={
        "ref": "P-1", "severity": "critical", "title": "Log4Shell", "job_id": log4j_job["pk"]}), 201)
    manual = ok(officer.post(f"/api/compliance/audits/{a['id']}/findings", json={
        "ref": "P-2", "severity": "high", "title": "Default SNMP community", "fixed_on": days(-1)}), 201)
    content = b"%PDF-1.4\n% report\n"
    up = ok(officer.post(f"/api/compliance/entities/{e['id']}/evidence",
                         data={"kind": "audit_report", "title": "CSA-P report", "owner_type": "audit_report",
                               "owner_id": str(a["id"])}, files={"file": ("report.pdf", content, "application/pdf")}),
            201)

    # The screen lists what an auditor would ask for and not find: P-2 was closed by hand with no evidence.
    d = ok(officer.get(f"/api/compliance/entities/{e['id']}"))
    gaps = {(g["kind"], g["ref"]) for g in d["evidence_gaps"]}
    assert ("no_fix_evidence", "P-2") in gaps and not any(r == "P-1" for _, r in gaps)
    assert manual["fixed_on"] == days(-1)

    r = auditor.get(f"/api/compliance/entities/{e['id']}/audit-pack.json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert verify_audit_pack(r.text)
    pack = json.loads(r.text)
    f1 = next(f for x in pack["audits"] for f in x["findings"] if f["assessment"]["finding_id"] == "P-1")
    assert f1["assessment"]["state"] == "fixed_on_time" and f1["fix_evidence_ids"][0].startswith("RESCAN-")
    assert any(x["evidence_id"] == f"EV-{up['id']}" and x["sha256"] == up["sha256"] for x in pack["evidence"])

    z = zipfile.ZipFile(io.BytesIO(auditor.get(f"/api/compliance/entities/{e['id']}/audit-pack.zip").content))
    names = set(z.namelist())
    assert {"audit-pack.json", "README.txt", f"evidence/EV-{up['id']}-report.pdf"} <= names
    assert z.read(f"evidence/EV-{up['id']}-report.pdf") == content
    assert verify_audit_pack(z.read("audit-pack.json").decode())
    app, _ = env
    with app.state.sessionmaker() as db:
        exports = list(db.scalars(select(AuditEvent).where(AuditEvent.action == "compliance.audit_pack_export",
                                                           AuditEvent.target_id == str(e["id"]))))
    assert {x.detail["format"] for x in exports} == {"json", "zip"}
