from __future__ import annotations

from datetime import date, datetime

from conftest import IST, audit, finding, records

from sutra_compliance import (
    DeliverableState,
    EvidenceItem,
    PriorFindingState,
    WindowState,
    assess_audit,
    assess_audit_cycle,
)
from sutra_compliance.engine import assess_prior_findings


def ev(eid, kind, when=datetime(2027, 10, 1, 10, tzinfo=IST)):
    return EvidenceItem(eid, kind, f"{kind} {eid}", when)


def test_report_and_closure_deadlines(pack):
    a = audit(started=date(2027, 4, 5), report=None)
    r = assess_audit(a, [], pack, date(2027, 5, 1))
    d = {x.deliverable: x for x in r.deliverables}
    assert d["audit_report"].due_on == date(2027, 5, 17)
    assert d["audit_report"].state is DeliverableState.PENDING
    assert d["closure_report"].due_on == date(2027, 10, 5)
    r = assess_audit(a, [], pack, date(2027, 5, 18))
    assert {x.deliverable: x for x in r.deliverables}["audit_report"].state is DeliverableState.OVERDUE


def test_late_report(pack):
    r = assess_audit(audit(report=date(2027, 5, 20)), [], pack, date(2027, 6, 1))
    rep = {x.deliverable: x for x in r.deliverables}["audit_report"]
    assert rep.state is DeliverableState.DONE_LATE and rep.breach is False


def test_closure_report_expects_board_report(pack):
    a = audit(closure=date(2027, 10, 1), closure_evidence_ids=("E1",))
    r = assess_audit(a, [], pack, date(2027, 10, 2), {"E1": ev("E1", "closure_report")})
    closure = {x.deliverable: x for x in r.deliverables}["closure_report"]
    assert closure.state is DeliverableState.DONE_ON_TIME
    assert closure.missing_evidence_kinds == ("board_report",)
    a = audit(closure=date(2027, 10, 1), closure_evidence_ids=("E1", "E2"))
    r = assess_audit(a, [], pack, date(2027, 10, 2), {"E1": ev("E1", "closure_report"), "E2": ev("E2", "board_report")})
    assert {x.deliverable: x for x in r.deliverables}["closure_report"].missing_evidence_kinds == ()


def test_auditor_eligibility(pack):
    assert assess_audit(audit(status="cert_in_empanelled"), [], pack, date(2027, 6, 1)).auditor_eligible is True
    assert assess_audit(audit(status="mop_designated"), [], pack, date(2027, 6, 1)).auditor_eligible is True
    assert assess_audit(audit(status="other"), [], pack, date(2027, 6, 1)).auditor_eligible is False
    assert assess_audit(audit(status="unknown"), [], pack, date(2027, 6, 1)).auditor_eligible is None


def test_audit_only_assesses_its_own_findings(pack):
    r = assess_audit(audit(), [finding("F1"), finding("F2", audit_id="A2")], pack, date(2027, 6, 1))
    assert [f.finding_id for f in r.findings] == ["F1"]


def test_gap_between_audits(pack):
    a1 = audit("A1", started=date(2027, 4, 5))
    ok = assess_audit_cycle([a1, audit("A2", started=date(2028, 4, 3))], pack, date(2028, 5, 1))
    assert ok.gaps[0].gap_ok is True
    short = assess_audit_cycle([a1, audit("A2", started=date(2027, 12, 1))], pack, date(2028, 1, 1))
    assert short.gaps[0].gap_ok is False
    assert short.gaps[0].earliest_allowed == date(2028, 1, 5)
    assert short.breach is True


def test_next_audit_window(pack):
    a1 = audit("A1", started=date(2027, 4, 5))
    c = assess_audit_cycle([a1], pack, date(2027, 12, 1))
    assert (c.next_audit_earliest, c.next_audit_latest) == (date(2028, 1, 5), date(2028, 7, 5))
    assert c.next_audit_state is WindowState.NOT_YET
    assert assess_audit_cycle([a1], pack, date(2028, 3, 1)).next_audit_state is WindowState.OPEN
    missed = assess_audit_cycle([a1], pack, date(2028, 7, 6))
    assert missed.next_audit_state is WindowState.MISSED and missed.breach is True


def test_every_financial_year(pack):
    a1 = audit("A1", started=date(2027, 4, 5))
    c = assess_audit_cycle([a1], pack, date(2028, 5, 1))
    fys = {f.financial_year: f for f in c.financial_years}
    assert fys["FY2027-28"].state is WindowState.MET
    assert fys["FY2028-29"].state is WindowState.OPEN
    assert fys["FY2028-29"].ends_on == date(2029, 3, 31)
    c = assess_audit_cycle([a1], pack, date(2029, 4, 1))
    assert {f.financial_year: f for f in c.financial_years}["FY2028-29"].state is WindowState.MISSED


def test_no_financial_year_checks_before_in_force(pack):
    assert assess_audit_cycle([], pack, date(2027, 3, 31)).financial_years == ()


def test_rotation_not_checked_while_sources_conflict(pack):
    same = [audit(f"A{i}", started=date(2027 + i, 4, 5), auditor="Same Firm") for i in range(3)]
    c = assess_audit_cycle(same, pack, date(2030, 1, 1))
    assert c.rotation_checked is False and c.rotation_ok is None
    assert "CEA-AUDITOR-ROTATION is disabled" in c.rotation_note


def test_rotation_enforced_once_configured(load_modified):
    fixed = load_modified("enabled = false\nmax_consecutive = 0", "enabled = true\nmax_consecutive = 2")
    same = [audit(f"A{i}", started=date(2027 + i, 4, 5), auditor="Same Firm") for i in range(3)]
    c = assess_audit_cycle(same, fixed, date(2030, 1, 1))
    assert c.rotation_checked is True and c.rotation_ok is False and c.breach is True
    mixed = [*same[:2], audit("A2", started=date(2029, 4, 5), auditor="Other Firm")]
    assert assess_audit_cycle(mixed, fixed, date(2030, 1, 1)).rotation_ok is True


def test_prior_findings_rechecked_by_next_audit(pack):
    a1 = audit("A1", started=date(2027, 4, 5))
    a2 = audit("A2", started=date(2028, 4, 3), report=None)
    fs = (
        finding("F1", fixed_on=date(2027, 6, 1), fix_evidence_ids=("E1",)),
        finding("F2", fixed_on=date(2027, 6, 1)),
        finding("F3"),
        finding("F4"),
        finding("F5", audit_id="A2", carried_from_finding_id="F3"),
    )
    recs = records(audits=(a1, a2), findings=fs, evidence=(ev("E1", "rescan"),))
    got = {c.finding_id: c.state for c in assess_prior_findings(recs, pack, date(2028, 5, 1))}
    assert got == {
        "F1": PriorFindingState.CLOSED_WITH_EVIDENCE,
        "F2": PriorFindingState.CLOSED_WITHOUT_EVIDENCE,
        "F3": PriorFindingState.CARRIED_FORWARD,
        "F4": PriorFindingState.NOT_RECHECKED,
    }
