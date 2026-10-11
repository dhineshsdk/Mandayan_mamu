from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from conftest import at, records

from sutra_compliance import (
    ActivityRecord,
    Asset,
    DeliverableState,
    EvidenceItem,
    Incident,
    PeriodicState,
    assess_incident,
    assess_periodic,
)


def by_recipient(obligations):
    return {(o.rule_id, o.recipient): o for o in obligations}


def test_six_hour_report_per_recipient(pack):
    inc = Incident("I1", "ent-1", "Ransomware on historian", at(2027, 6, 1, 10),
                   reported_at={"csirt_power": at(2027, 6, 1, 15), "cert_in": at(2027, 6, 1, 17)})
    got = by_recipient(assess_incident(inc, pack, at(2027, 6, 2)))
    assert got[("CEA-INCIDENT-6H", "csirt_power")].state is DeliverableState.DONE_ON_TIME
    late = got[("CEA-INCIDENT-6H", "cert_in")]
    assert late.state is DeliverableState.DONE_LATE
    assert late.due_at == at(2027, 6, 1, 16)
    assert not any(k[0] == "CEA-SABOTAGE-24H" for k in got)


def test_pending_and_overdue(pack):
    inc = Incident("I1", "ent-1", "x", at(2027, 6, 1, 10))
    pending = by_recipient(assess_incident(inc, pack, at(2027, 6, 1, 14, 30)))[("CEA-INCIDENT-6H", "cert_in")]
    assert pending.state is DeliverableState.PENDING and pending.hours_remaining == 1.5
    overdue = by_recipient(assess_incident(inc, pack, at(2027, 6, 1, 16, 1)))[("CEA-INCIDENT-6H", "cert_in")]
    assert overdue.state is DeliverableState.OVERDUE and overdue.breach is True


def test_clock_works_across_timezones(pack):
    utc_detect = datetime(2027, 6, 1, 4, 30, tzinfo=UTC)  # 10:00 IST
    inc = Incident("I1", "ent-1", "x", utc_detect, reported_at={"cert_in": at(2027, 6, 1, 16)})
    got = by_recipient(assess_incident(inc, pack, at(2027, 6, 2)))
    assert got[("CEA-INCIDENT-6H", "cert_in")].state is DeliverableState.DONE_ON_TIME


def test_sabotage_report(pack):
    evidence = {"R1": EvidenceItem("R1", "root_cause_analysis", "RCA", at(2027, 6, 3, 9))}
    inc = Incident("I1", "ent-1", "x", at(2027, 6, 1, 10), sabotage_concluded_at=at(2027, 6, 2, 12),
                   sabotage_reported_at=at(2027, 6, 3, 8), affects_critical_system=True,
                   sabotage_evidence_ids=("R1",))
    sab = by_recipient(assess_incident(inc, pack, at(2027, 6, 4), evidence))[("CEA-SABOTAGE-24H", None)]
    assert sab.state is DeliverableState.DONE_ON_TIME
    assert sab.due_at == at(2027, 6, 3, 12)
    assert sab.missing_evidence_kinds == ("forensic_summary",)


def test_sabotage_rule_skipped_when_no_critical_system(pack):
    inc = Incident("I1", "ent-1", "x", at(2027, 6, 1, 10), sabotage_concluded_at=at(2027, 6, 2, 12),
                   affects_critical_system=False)
    assert not any(o.rule_id == "CEA-SABOTAGE-24H" for o in assess_incident(inc, pack, at(2027, 6, 4)))


def test_sabotage_unknown_criticality_applies_with_note(pack):
    inc = Incident("I1", "ent-1", "x", at(2027, 6, 1, 10), sabotage_concluded_at=at(2027, 6, 2, 12))
    sab = [o for o in assess_incident(inc, pack, at(2027, 6, 4)) if o.rule_id == "CEA-SABOTAGE-24H"]
    assert sab and sab[0].state is DeliverableState.OVERDUE and "Not recorded" in sab[0].note


def test_incident_input_validation():
    with pytest.raises(ValueError, match="timezone-aware"):
        Incident("I1", "ent-1", "x", datetime(2027, 6, 1, 10))
    with pytest.raises(ValueError, match="unknown recipient"):
        Incident("I1", "ent-1", "x", at(2027, 6, 1), reported_at={"police": at(2027, 6, 1)})
    with pytest.raises(ValueError, match="without a sabotage conclusion"):
        Incident("I1", "ent-1", "x", at(2027, 6, 1), sabotage_reported_at=at(2027, 6, 2))


def test_incident_before_in_force(pack):
    inc = Incident("I1", "ent-1", "x", at(2027, 3, 1, 10))
    assert all(o.in_force is False for o in assess_incident(inc, pack, at(2027, 3, 2)))


def test_naive_now_rejected(pack):
    with pytest.raises(ValueError):
        assess_incident(Incident("I1", "ent-1", "x", at(2027, 6, 1)), pack, datetime(2027, 6, 2))


# ---------------------------------------------------------------- recurring obligations


def _periodic(pack, today, **kw):
    return {(p.activity, p.asset_id): p for p in assess_periodic(records(**kw), pack, today)}


def test_entity_level_cycles(pack):
    acts = (ActivityRecord("policy_review", date(2027, 4, 10)), ActivityRecord("ir_plan_review", date(2027, 4, 10)))
    got = _periodic(pack, date(2027, 10, 1), activities=acts)
    assert got[("policy_review", None)].due_on == date(2028, 4, 10)
    assert got[("policy_review", None)].state is PeriodicState.CURRENT
    assert got[("ir_plan_review", None)].due_on == date(2027, 10, 10)
    assert got[("ir_plan_review", None)].state is PeriodicState.DUE_SOON
    assert got[("ccmp_drill", None)].state is PeriodicState.NO_RECORD
    later = _periodic(pack, date(2027, 10, 11), activities=acts)
    assert later[("ir_plan_review", None)].state is PeriodicState.OVERDUE
    assert later[("ir_plan_review", None)].breach is True


def test_latest_record_wins(pack):
    acts = (ActivityRecord("ir_plan_review", date(2027, 4, 10)), ActivityRecord("ir_plan_review", date(2027, 9, 1)))
    got = _periodic(pack, date(2027, 10, 11), activities=acts)
    assert got[("ir_plan_review", None)].last_performed_on == date(2027, 9, 1)


def test_per_asset_and_critical_asset_scopes(pack):
    assets = (Asset("PLC-1", critical=True), Asset("PC-1", critical=False), Asset("HMI-9", critical=None))
    acts = (ActivityRecord("asset_risk_assessment", date(2027, 5, 1), asset_id="PLC-1"),
            ActivityRecord("backup", date(2027, 5, 20), asset_id="PLC-1"))
    got = _periodic(pack, date(2027, 6, 1), assets=assets, activities=acts)
    assert got[("asset_risk_assessment", "PLC-1")].due_on == date(2027, 11, 1)
    assert got[("asset_risk_assessment", "PC-1")].state is PeriodicState.NO_RECORD
    assert got[("asset_risk_assessment", "HMI-9")].state is PeriodicState.NO_RECORD
    assert got[("backup", "PLC-1")].due_on == date(2027, 6, 20)
    assert ("backup", "PC-1") not in got
    assert got[("backup", "HMI-9")].state is PeriodicState.UNCLASSIFIED_ASSET


def test_future_records_ignored(pack):
    acts = (ActivityRecord("policy_review", date(2027, 12, 1)),)
    assert _periodic(pack, date(2027, 6, 1), activities=acts)[("policy_review", None)].state is PeriodicState.NO_RECORD


def test_due_soon_threshold_is_configurable(pack):
    acts = (ActivityRecord("ir_plan_review", date(2027, 4, 10)),)
    got = {p.activity: p for p in assess_periodic(records(activities=acts), pack, date(2027, 9, 1),
                                                  due_soon_days=60)}
    assert got["ir_plan_review"].state is PeriodicState.DUE_SOON
