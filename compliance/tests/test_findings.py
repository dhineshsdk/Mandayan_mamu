from __future__ import annotations

from datetime import date

import pytest
from conftest import audit, finding

from sutra_compliance import CompensatingControl, FindingState, ScheduledFix, assess_finding

A = audit(report=date(2027, 5, 10))  # critical/high due 10 Jun 2027, medium/low due 10 Aug 2027


def test_open_critical_within_window(pack):
    r = assess_finding(finding(), A, pack, date(2027, 6, 1))
    assert r.state is FindingState.OPEN
    assert r.clock_starts_on == date(2027, 5, 10)
    assert r.due_on == date(2027, 6, 10)
    assert r.days_remaining == 9
    assert r.breach is False and r.in_force is True


def test_due_date_is_inclusive(pack):
    assert assess_finding(finding(), A, pack, date(2027, 6, 10)).state is FindingState.OPEN
    on_time = assess_finding(finding(fixed_on=date(2027, 6, 10)), A, pack, date(2027, 7, 1))
    assert on_time.state is FindingState.FIXED_ON_TIME
    late = assess_finding(finding(fixed_on=date(2027, 6, 11)), A, pack, date(2027, 7, 1))
    assert late.state is FindingState.FIXED_LATE and late.days_late == 1


@pytest.mark.parametrize("severity, due", [("high", date(2027, 6, 10)), ("medium", date(2027, 8, 10)),
                                           ("low", date(2027, 8, 10))])
def test_windows_by_severity(pack, severity, due):
    assert assess_finding(finding(severity=severity), A, pack, date(2027, 5, 11)).due_on == due


def test_severity_is_case_insensitive(pack):
    assert assess_finding(finding(severity="HIGH"), A, pack, date(2027, 5, 11)).severity == "high"


def test_clock_waits_for_the_audit_report(pack):
    r = assess_finding(finding(), audit(report=None), pack, date(2027, 6, 30))
    assert r.state is FindingState.CLOCK_NOT_STARTED
    assert r.due_on is None and r.breach is False
    # A report dated in the future has not been submitted yet either.
    r = assess_finding(finding(), audit(report=date(2027, 7, 1)), pack, date(2027, 6, 30))
    assert r.state is FindingState.CLOCK_NOT_STARTED


def test_fixed_before_report_is_on_time(pack):
    r = assess_finding(finding(fixed_on=date(2027, 4, 20)), audit(report=None), pack, date(2027, 6, 30))
    assert r.state is FindingState.FIXED_ON_TIME


def test_overdue_critical_without_control_is_a_breach(pack):
    r = assess_finding(finding(), A, pack, date(2027, 6, 15))
    assert r.state is FindingState.OVERDUE_UNCOMPENSATED
    assert r.days_overdue == 5
    assert r.compensating_control_required is True
    assert r.breach is True
    assert "CEA-COMPENSATING-CONTROLS" in {c.rule_id for c in r.citations}


def test_overdue_critical_with_active_control_is_compensated(pack):
    ctl = CompensatingControl("C1", "Firewall rule blocks SMB from corp", date(2027, 6, 1))
    r = assess_finding(finding(compensating_controls=(ctl,)), A, pack, date(2027, 6, 15))
    assert r.state is FindingState.OVERDUE_COMPENSATED
    assert r.compensating_controls_active == ("C1",)
    assert r.breach is False


def test_withdrawn_or_future_control_does_not_count(pack):
    withdrawn = CompensatingControl("C1", "x", date(2027, 6, 1), withdrawn_on=date(2027, 6, 12))
    future = CompensatingControl("C2", "y", date(2027, 6, 20))
    r = assess_finding(finding(compensating_controls=(withdrawn, future)), A, pack, date(2027, 6, 15))
    assert r.state is FindingState.OVERDUE_UNCOMPENSATED


def test_overdue_medium_has_no_compensating_path(pack):
    r = assess_finding(finding(severity="medium"), A, pack, date(2027, 8, 11))
    assert r.state is FindingState.OVERDUE
    assert r.compensating_control_required is False
    assert r.breach is True


def test_info_findings_are_not_covered(pack):
    r = assess_finding(finding(severity="info"), A, pack, date(2028, 1, 1))
    assert r.state is FindingState.NOT_COVERED and r.due_on is None and r.breach is False


def test_future_fix_date_is_ignored(pack):
    r = assess_finding(finding(fixed_on=date(2027, 6, 20)), A, pack, date(2027, 6, 15))
    assert r.state is FindingState.OVERDUE_UNCOMPENSATED and r.closed_on is None


def test_auditor_clearance_closes_a_finding(pack):
    r = assess_finding(finding(auditor_cleared_on=date(2027, 6, 5)), A, pack, date(2027, 6, 15))
    assert r.state is FindingState.FIXED_ON_TIME and r.closed_on == date(2027, 6, 5)


def test_before_in_force_results_are_flagged(pack):
    r = assess_finding(finding(), audit(started=date(2027, 1, 4), report=date(2027, 2, 1)), pack, date(2027, 3, 15))
    assert r.state is FindingState.OVERDUE_UNCOMPENSATED
    assert r.in_force is False
    assert r.breach is True  # the rule is not met; in_force says it does not bind yet


def test_scheduled_fix_shown_but_never_stops_the_clock(pack):
    sched = ScheduledFix(date(2027, 11, 24), "annual shutdown", "SD-2027")
    r = assess_finding(finding(scheduled_fix=sched), A, pack, date(2027, 6, 15))
    assert r.state is FindingState.OVERDUE_UNCOMPENSATED
    assert r.scheduled_fix_on == date(2027, 11, 24)
    assert r.scheduled_fix_after_due is True
    assert "annual shutdown" in r.explanation


def test_critical_fix_needs_pre_deployment_audit(pack):
    crit = assess_finding(finding(), A, pack, date(2027, 5, 20))
    assert crit.fix_needs_pre_deployment_audit is True
    assert "CEA-SECOND-SCHEDULE" in {c.rule_id for c in crit.citations}
    assert assess_finding(finding(severity="high"), A, pack, date(2027, 5, 20)).fix_needs_pre_deployment_audit is False


def test_while_open_trigger_requires_controls_inside_the_window(load_modified):
    strict = load_modified('trigger = "after_fix_deadline"', 'trigger = "while_open"')
    r = assess_finding(finding(), A, strict, date(2027, 5, 20))
    assert r.state is FindingState.OPEN
    assert r.compensating_control_required is True and r.breach is True
    ctl = CompensatingControl("C1", "x", date(2027, 5, 12))
    assert assess_finding(finding(compensating_controls=(ctl,)), A, strict, date(2027, 5, 20)).breach is False


def test_finding_must_match_audit(pack):
    with pytest.raises(ValueError):
        assess_finding(finding(audit_id="A2"), A, pack, date(2027, 5, 20))


def test_every_assessment_is_cited(pack):
    r = assess_finding(finding(), A, pack, date(2027, 5, 20))
    assert r.citations[0].rule_id == "CEA-FIX-CRITICAL-HIGH"
    assert r.citations[0].pack_version == pack.version
