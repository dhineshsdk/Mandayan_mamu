from __future__ import annotations

import json
from datetime import date

from conftest import at, audit, finding, records

from sutra_compliance import (
    ActivityRecord,
    Asset,
    CompensatingControl,
    EvidenceItem,
    Incident,
    build_audit_pack,
    verify_audit_pack,
)

SHA = "a" * 64


def sample():
    evidence = (
        EvidenceItem("E-REPORT", "audit_report", "Audit report", at(2027, 5, 10), SHA, "s3://bucket/report.pdf"),
        EvidenceItem("E-FIX1", "rescan", "Rescan after patch", at(2027, 6, 2), SHA),
        EvidenceItem("E-OLD", "rescan", "Scan before the fix", at(2027, 5, 1)),
        EvidenceItem("E-CTL", "firewall_config", "ACL export", at(2027, 6, 5)),
        EvidenceItem("E-RA", "risk_assessment", "PLC-1 risk assessment", at(2027, 5, 1)),
    )
    ctl = CompensatingControl("C1", "Block SMB from corp", date(2027, 6, 5), evidence_ids=("E-CTL",))
    ctl_bare = CompensatingControl("C2", "Extra monitoring", date(2027, 6, 5))
    findings = (
        finding("F1", fixed_on=date(2027, 6, 1), fix_evidence_ids=("E-FIX1",), asset_ids=("PLC-1",)),
        finding("F2", severity="high", compensating_controls=(ctl, ctl_bare), asset_ids=("PLC-1",)),
        finding("F3", severity="medium", fixed_on=date(2027, 6, 3), fix_evidence_ids=("E-OLD",)),
        finding("F4", severity="low", fixed_on=date(2027, 6, 3)),
        finding("F5", severity="high", fix_evidence_ids=("E-GHOST",)),
    )
    return records(
        assets=(Asset("PLC-1", "Boiler PLC", critical=True), Asset("PC-1", "Office PC", critical=False)),
        audits=(audit(report_evidence_ids=("E-REPORT",)),),
        findings=findings,
        incidents=(Incident("I1", "ent-1", "Phishing", at(2027, 6, 1, 9),
                            reported_at={"csirt_power": at(2027, 6, 1, 11), "cert_in": at(2027, 6, 1, 11)}),),
        activities=(ActivityRecord("asset_risk_assessment", date(2027, 5, 1), "PLC-1", evidence_ids=("E-RA",)),
                    ActivityRecord("policy_review", date(2027, 4, 2))),
        evidence=evidence,
    )


def test_pack_digest_verifies_and_detects_tampering(pack):
    ap = build_audit_pack(sample(), pack, at(2027, 6, 15))
    text = ap.to_json()
    assert verify_audit_pack(text)
    data = json.loads(text)
    data["summary"]["status"] = "on_track"
    assert not verify_audit_pack(json.dumps(data))
    data = json.loads(text)
    del data["digest"]
    assert not verify_audit_pack(json.dumps(data))


def test_pack_is_deterministic(pack):
    a = build_audit_pack(sample(), pack, at(2027, 6, 15))
    b = build_audit_pack(sample(), pack, at(2027, 6, 15))
    assert a.digest == b.digest and a.to_json() == b.to_json()


def test_pack_records_rule_pack_version_and_sources(pack):
    c = build_audit_pack(sample(), pack, at(2027, 6, 15)).content
    assert c["format"] == "sutra.compliance.audit_pack/1"
    assert c["rule_pack"]["version"] == pack.version
    assert c["rule_pack"]["verification"] == "unverified_against_gazette"
    assert {s["id"] for s in c["rule_pack"]["sources"]} >= {"cea-gazette", "beacon"}


def test_evidence_gaps(pack):
    c = build_audit_pack(sample(), pack, at(2027, 6, 15)).content
    gaps = {(g["kind"], g["ref"]) for g in c["evidence_gaps"]}
    assert ("missing_reference", "E-GHOST") in gaps
    assert ("fix_evidence_predates_fix", "F3") in gaps
    assert ("no_fix_evidence", "F4") in gaps
    assert ("control_without_evidence", "F2:C2") in gaps
    assert ("activity_without_evidence", "policy_review:entity:2027-04-02") in gaps
    assert ("no_report_evidence", "I1") in gaps
    assert ("no_fix_evidence", "F1") not in gaps
    assert ("control_without_evidence", "F2:C1") not in gaps
    assert c["summary"]["evidence_gap_count"] == len(c["evidence_gaps"])


def test_evidence_index_shows_who_references_each_item(pack):
    c = build_audit_pack(sample(), pack, at(2027, 6, 15)).content
    idx = {e["evidence_id"]: e for e in c["evidence"]}
    assert idx["E-FIX1"]["referenced_by"] == ["finding:F1:fix"]
    assert idx["E-CTL"]["referenced_by"] == ["finding:F2:control:C1"]
    assert idx["E-REPORT"]["sha256"] == SHA


def test_finding_entries_carry_state_timeline_and_citations(pack):
    c = build_audit_pack(sample(), pack, at(2027, 6, 15)).content
    entries = {f["assessment"]["finding_id"]: f for f in c["audits"][0]["findings"]}
    f2 = entries["F2"]
    assert f2["assessment"]["state"] == "overdue_compensated"
    assert f2["assessment"]["citations"][0]["rule_id"] == "CEA-FIX-CRITICAL-HIGH"
    assert [(e["on"], e["event"]) for e in f2["timeline"]] == [
        ("2027-05-10", "audit_report_submitted"),
        ("2027-06-05", "compensating_control_in_place:C1"),
        ("2027-06-05", "compensating_control_in_place:C2"),
        ("2027-06-10", "fix_due"),
    ]
    assert entries["F1"]["assessment"]["state"] == "fixed_on_time"


def test_asset_risk_review_section(pack):
    c = build_audit_pack(sample(), pack, at(2027, 6, 15)).content
    assets = {a["asset_id"]: a for a in c["assets"]}
    plc = assets["PLC-1"]
    assert plc["risk_assessment"]["due_on"] == "2027-11-01"
    assert plc["risk_assessment_evidence_ids"] == ["E-RA"]
    assert plc["open_finding_ids"] == ["F2"]
    assert assets["PC-1"]["risk_assessment"]["state"] == "no_record"


def test_summary_and_incidents(pack):
    c = build_audit_pack(sample(), pack, at(2027, 6, 15)).content
    assert c["summary"]["status"] == "non_compliant"  # F5 is high, overdue, uncompensated
    assert all(o["state"] == "done_on_time" for o in c["incidents"])
