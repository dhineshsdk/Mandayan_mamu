"""Compute deadlines and compliance states from a rule pack and an entity's records.

Every result carries the citation of the rule it came from, so a screen or export can show which rule, which
pack version and which sources a number rests on.

Engine conventions (choices the sources do not settle; each is stated in the README):
- Deadlines are inclusive: work done on the due date is on time.
- An obligation is in force when the event that starts its clock falls on or after the pack's in-force date.
  Results before that are still computed (for readiness) but flagged ``in_force = False`` and kept out of
  ``status``; ``status_if_in_force`` counts them.
- ``breach`` on a result says the rule is not met; ``in_force`` says whether that is binding yet.
- Dates in the future (a fix dated after "now") are ignored as not yet happened.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date, datetime, timedelta
from enum import StrEnum
from typing import Any

from .durations import add_months
from .model import Audit, AuditFinding, Entity, EntityRecords, EvidenceItem, Incident
from .rulepack import (
    ApplicabilityRule,
    AuditDeliverableRule,
    AuditIntervalRule,
    AuditorEligibilityRule,
    AuditorRotationRule,
    ChangePreAuditRule,
    Citation,
    IncidentReportRule,
    PeriodicRule,
    PriorFindingsRule,
    RulePack,
)

DEFAULT_DUE_SOON_DAYS = 14


def to_jsonable(value: Any) -> Any:
    """Convert results (dataclasses, enums, dates, citations) into plain JSON types."""
    if isinstance(value, Citation):
        return value.to_dict()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value) if not f.name.startswith("_")}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value


class _Result:
    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


# --------------------------------------------------------------------------------------------------------------
# Applicability
# --------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Applicability(_Result):
    entity_id: str
    covered: bool
    excluded_topics: tuple[str, ...]
    chapters_determined: bool
    reason: str
    citation: Citation | None


def assess_applicability(entity: Entity, pack: RulePack) -> Applicability:
    rule: ApplicabilityRule | None = next((a for a in pack.applicability if entity.entity_type in a.entity_types),
                                         None)
    if rule is None:
        return Applicability(entity.entity_id, False, (), True,
                             f"No applicability entry in pack {pack.id} covers entity type {entity.entity_type!r}.",
                             None)
    citation = pack.cite(rule)
    if rule.min_capacity_mw is not None:
        if entity.capacity_mw is None:
            return Applicability(entity.entity_id, False, rule.excluded_topics, rule.chapters_determined,
                                 f"Coverage depends on capacity (threshold {rule.min_capacity_mw:g} MW), "
                                 "which is not recorded for this entity.", citation)
        if entity.capacity_mw < rule.min_capacity_mw:
            return Applicability(entity.entity_id, False, (), rule.chapters_determined,
                                 f"{entity.capacity_mw:g} MW is below the {rule.min_capacity_mw:g} MW threshold. "
                                 f"{rule.notes}".strip(), citation)
        reason = f"{entity.capacity_mw:g} MW meets the {rule.min_capacity_mw:g} MW threshold."
    else:
        reason = rule.notes or "Covered."
    if not rule.chapters_determined:
        reason = rule.notes
    return Applicability(entity.entity_id, True, rule.excluded_topics, rule.chapters_determined, reason, citation)


# --------------------------------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------------------------------


class FindingState(StrEnum):
    NOT_COVERED = "not_covered"  # no rule sets a deadline for this severity
    CLOCK_NOT_STARTED = "clock_not_started"  # the audit report has not been submitted
    OPEN = "open"  # open, inside the window
    FIXED_ON_TIME = "fixed_on_time"
    FIXED_LATE = "fixed_late"
    OVERDUE_COMPENSATED = "overdue_compensated"  # past the window, compensating control in place
    OVERDUE_UNCOMPENSATED = "overdue_uncompensated"  # past the window, compensating control required but missing
    OVERDUE = "overdue"  # past the window; no compensating-control rule applies to this severity


OPEN_STATES = {FindingState.CLOCK_NOT_STARTED, FindingState.OPEN, FindingState.OVERDUE_COMPENSATED,
               FindingState.OVERDUE_UNCOMPENSATED, FindingState.OVERDUE}


@dataclass(frozen=True)
class FindingAssessment(_Result):
    finding_id: str
    audit_id: str
    severity: str
    title: str
    state: FindingState
    in_force: bool
    clock_starts_on: date | None
    due_on: date | None
    closed_on: date | None
    days_remaining: int | None
    days_overdue: int | None
    days_late: int | None
    compensating_control_required: bool
    compensating_controls_active: tuple[str, ...]
    scheduled_fix_on: date | None
    scheduled_fix_reason: str | None
    scheduled_fix_after_due: bool | None
    fix_needs_pre_deployment_audit: bool
    breach: bool  # out of compliance under the rule now; binding only when in_force
    explanation: str
    citations: tuple[Citation, ...]


def _closed_by(finding: AuditFinding, today: date) -> date | None:
    closed = finding.closed_on
    return closed if closed is not None and closed <= today else None


def assess_finding(finding: AuditFinding, audit: Audit, pack: RulePack, today: date) -> FindingAssessment:
    if finding.audit_id != audit.audit_id:
        raise ValueError(f"finding {finding.finding_id} belongs to audit {finding.audit_id}, not {audit.audit_id}")
    citations: list[Citation] = []
    fix_rule = pack.fix_rule_for(finding.severity)
    comp_rule = pack.compensating_rule_for(finding.severity)
    closed = _closed_by(finding, today)
    active = tuple(c.control_id for c in finding.compensating_controls if c.active_on(today))
    sched = finding.scheduled_fix

    needs_pre_audit = False
    for rule in pack.rules_of(ChangePreAuditRule):
        if finding.severity == "critical" and any(c.id == "critical_vulnerability_fix" for c in rule.categories):
            needs_pre_audit = True
            citations.append(pack.cite(rule))

    base: dict[str, Any] = dict(
        finding_id=finding.finding_id, audit_id=finding.audit_id, severity=finding.severity, title=finding.title,
        closed_on=closed, compensating_controls_active=active, fix_needs_pre_deployment_audit=needs_pre_audit,
        scheduled_fix_on=sched.planned_on if sched else None, scheduled_fix_reason=sched.reason if sched else None,
        days_remaining=None, days_overdue=None, days_late=None,
    )

    if fix_rule is None:
        return FindingAssessment(
            **base, state=FindingState.NOT_COVERED, in_force=False, clock_starts_on=None, due_on=None,
            compensating_control_required=False, scheduled_fix_after_due=None, breach=False,
            explanation=f"No rule in pack {pack.id} {pack.version} sets a fix deadline for "
                        f"{finding.severity} findings.",
            citations=tuple(citations))

    citations.insert(0, pack.cite(fix_rule))
    start = audit.report_submitted_on
    if start is None or start > today:
        state = FindingState.FIXED_ON_TIME if closed else FindingState.CLOCK_NOT_STARTED
        explanation = ("Fixed before the audit report was submitted." if closed else
                       f"The {fix_rule.duration} clock starts when the audit report is submitted.")
        return FindingAssessment(
            **base, state=state, in_force=False, clock_starts_on=None, due_on=None,
            compensating_control_required=False, scheduled_fix_after_due=None, breach=False,
            explanation=explanation, citations=tuple(citations))

    due = fix_rule.duration.after(start)
    in_force = pack.is_in_force(start)
    required = False
    if comp_rule is not None and closed is None:
        if comp_rule.trigger == "while_open" or today > due:
            required = True
            citations.append(pack.cite(comp_rule))

    if closed is not None:
        late = (closed - due).days
        if late > 0:
            state, base["days_late"] = FindingState.FIXED_LATE, late
            explanation = f"Fixed on {closed}, {late} day(s) after the {fix_rule.duration} deadline of {due}."
        else:
            state = FindingState.FIXED_ON_TIME
            explanation = f"Fixed on {closed}, within the {fix_rule.duration} deadline of {due}."
        breach = False
    elif today <= due:
        state, base["days_remaining"] = FindingState.OPEN, (due - today).days
        explanation = f"Open; due {due} ({fix_rule.duration} from the audit report on {start})."
        breach = required and not active
        if breach:
            explanation += " A compensating control is required while it is open and none is active."
    else:
        base["days_overdue"] = (today - due).days
        if comp_rule is None:
            state = FindingState.OVERDUE
            explanation = f"Past its {fix_rule.duration} deadline of {due}; no compensating-control rule covers " \
                          f"{finding.severity} findings."
            breach = True
        elif active:
            state = FindingState.OVERDUE_COMPENSATED
            explanation = (f"Past its deadline of {due}; compensating control(s) {', '.join(active)} in place "
                           "until the auditor clears it.")
            breach = False
        else:
            state = FindingState.OVERDUE_UNCOMPENSATED
            explanation = f"Past its deadline of {due} with no compensating control in place."
            breach = True
    if sched is not None and closed is None:
        explanation += f" Fix scheduled for {sched.planned_on} ({sched.reason})."

    return FindingAssessment(
        **base, state=state, in_force=in_force, clock_starts_on=start, due_on=due,
        compensating_control_required=required,
        scheduled_fix_after_due=(sched.planned_on > due) if sched and closed is None else None,
        breach=breach, explanation=explanation, citations=tuple(citations))


# --------------------------------------------------------------------------------------------------------------
# Audits
# --------------------------------------------------------------------------------------------------------------


class DeliverableState(StrEnum):
    PENDING = "pending"  # not done, not yet due
    DONE_ON_TIME = "done_on_time"
    DONE_LATE = "done_late"
    OVERDUE = "overdue"


def _deliverable_state(done: date | None, due: date, today: date) -> DeliverableState:
    if done is not None and done <= today:
        return DeliverableState.DONE_ON_TIME if done <= due else DeliverableState.DONE_LATE
    return DeliverableState.PENDING if today <= due else DeliverableState.OVERDUE


@dataclass(frozen=True)
class DeliverableAssessment(_Result):
    deliverable: str
    due_on: date
    done_on: date | None
    state: DeliverableState
    in_force: bool
    breach: bool
    missing_evidence_kinds: tuple[str, ...]
    citation: Citation


@dataclass(frozen=True)
class AuditAssessment(_Result):
    audit_id: str
    auditor: str
    started_on: date
    auditor_eligible: bool | None
    eligibility_citation: Citation | None
    deliverables: tuple[DeliverableAssessment, ...]
    findings: tuple[FindingAssessment, ...]


def assess_audit(audit: Audit, findings: Iterable[AuditFinding], pack: RulePack, today: date,
                 evidence: dict[str, EvidenceItem] | None = None) -> AuditAssessment:
    evidence = evidence or {}
    in_force = pack.is_in_force(audit.started_on)
    deliverables = []
    for rule in pack.rules_of(AuditDeliverableRule):
        due = rule.duration.after(audit.started_on)
        if rule.deliverable == "audit_report":
            done, ev_ids = audit.report_submitted_on, audit.report_evidence_ids
        else:
            done, ev_ids = audit.closure_report_on, audit.closure_evidence_ids
        state = _deliverable_state(done, due, today)
        kinds = {evidence[e].kind for e in ev_ids if e in evidence}
        missing = tuple(k for k in rule.expects_evidence if k not in kinds) if done else ()
        deliverables.append(DeliverableAssessment(
            deliverable=rule.deliverable, due_on=due, done_on=done if done and done <= today else None, state=state,
            in_force=in_force, breach=state is DeliverableState.OVERDUE, missing_evidence_kinds=missing,
            citation=pack.cite(rule)))

    eligible: bool | None = None
    elig_citation = None
    elig_rules = pack.rules_of(AuditorEligibilityRule)
    if elig_rules:
        rule = elig_rules[0]
        elig_citation = pack.cite(rule)
        eligible = None if audit.auditor_status == "unknown" else audit.auditor_status in rule.allowed

    assessed = tuple(sorted((assess_finding(f, audit, pack, today) for f in findings if f.audit_id == audit.audit_id),
                            key=lambda a: a.finding_id))
    return AuditAssessment(audit_id=audit.audit_id, auditor=audit.auditor, started_on=audit.started_on,
                           auditor_eligible=eligible, eligibility_citation=elig_citation,
                           deliverables=tuple(deliverables), findings=assessed)


class WindowState(StrEnum):
    NOT_YET = "not_yet"  # earliest allowed start is in the future
    OPEN = "open"  # inside the allowed window, not yet started
    MET = "met"
    MISSED = "missed"


@dataclass(frozen=True)
class GapCheck(_Result):
    from_audit_id: str
    to_audit_id: str
    gap_ok: bool
    earliest_allowed: date | None
    latest_allowed: date | None
    actual: date


@dataclass(frozen=True)
class FinancialYearCheck(_Result):
    financial_year: str
    starts_on: date
    ends_on: date
    audit_ids: tuple[str, ...]
    state: WindowState


@dataclass(frozen=True)
class AuditCycleAssessment(_Result):
    gaps: tuple[GapCheck, ...]
    financial_years: tuple[FinancialYearCheck, ...]
    next_audit_earliest: date | None
    next_audit_latest: date | None
    next_audit_state: WindowState | None
    rotation_checked: bool
    rotation_ok: bool | None
    rotation_note: str
    breach: bool
    citations: tuple[Citation, ...]


def financial_year_of(day: date, start_month: int) -> tuple[date, date]:
    year = day.year if day.month >= start_month else day.year - 1
    start = date(year, start_month, 1)
    return start, add_months(start, 12) - timedelta(days=1)


def _fy_label(start: date, end: date) -> str:
    return f"FY{start.year}-{str(end.year)[-2:]}" if start.year != end.year else f"FY{start.year}"


def assess_audit_cycle(audits: Iterable[Audit], pack: RulePack, today: date) -> AuditCycleAssessment:
    started = sorted((a for a in audits if a.started_on <= today), key=lambda a: (a.started_on, a.audit_id))
    rules = pack.rules_of(AuditIntervalRule)
    citations = [pack.cite(r) for r in rules]
    gaps: list[GapCheck] = []
    fys: list[FinancialYearCheck] = []
    nxt_early = nxt_late = None
    nxt_state = None
    breach = False
    for rule in rules:
        if rule.min_gap or rule.max_gap:
            for prev, cur in zip(started, started[1:]):
                early = rule.min_gap.after(prev.started_on) if rule.min_gap else None
                late = rule.max_gap.after(prev.started_on) if rule.max_gap else None
                ok = (early is None or cur.started_on >= early) and (late is None or cur.started_on <= late)
                gaps.append(GapCheck(prev.audit_id, cur.audit_id, ok, early, late, cur.started_on))
                if not ok and pack.is_in_force(cur.started_on):
                    breach = True
            if started:
                last = started[-1].started_on
                nxt_early = rule.min_gap.after(last) if rule.min_gap else None
                nxt_late = rule.max_gap.after(last) if rule.max_gap else None
                if nxt_late is not None and today > nxt_late:
                    nxt_state = WindowState.MISSED
                    breach = breach or pack.is_in_force(nxt_late)
                elif nxt_early is not None and today < nxt_early:
                    nxt_state = WindowState.NOT_YET
                else:
                    nxt_state = WindowState.OPEN
        if rule.every_financial_year and today >= pack.in_force_from:
            fy_start, fy_end = financial_year_of(pack.in_force_from, pack.financial_year_start_month)
            while fy_start <= today:
                ids = tuple(a.audit_id for a in started if fy_start <= a.started_on <= fy_end)
                if ids:
                    state = WindowState.MET
                elif today > fy_end:
                    state, breach = WindowState.MISSED, True
                else:
                    state = WindowState.OPEN
                fys.append(FinancialYearCheck(_fy_label(fy_start, fy_end), fy_start, fy_end, ids, state))
                fy_start = fy_end + timedelta(days=1)
                fy_end = add_months(fy_start, 12) - timedelta(days=1)

    rotation_rules = pack.rules_of(AuditorRotationRule, include_disabled=True)
    rotation_checked = False
    rotation_ok: bool | None = None
    rotation_note = "No auditor rotation rule in the pack."
    for rule in rotation_rules:
        citations.append(pack.cite(rule))
        if not rule.enabled:
            rotation_note = f"{rule.id} is disabled ({rule.confidence}): {rule.notes}".strip()
            continue
        rotation_checked = True
        run, longest_ok = 1, True
        for prev, cur in zip(started, started[1:]):
            run = run + 1 if prev.auditor.strip().lower() == cur.auditor.strip().lower() else 1
            if run > rule.max_consecutive:
                longest_ok = False
                breach = breach or pack.is_in_force(cur.started_on)
        rotation_ok = longest_ok
        rotation_note = ("Within the rotation limit." if longest_ok else
                         f"The same auditor ran more than {rule.max_consecutive} consecutive audits.")
    return AuditCycleAssessment(tuple(gaps), tuple(fys), nxt_early, nxt_late, nxt_state, rotation_checked,
                                rotation_ok, rotation_note, breach, tuple(citations))


class PriorFindingState(StrEnum):
    CLOSED_WITH_EVIDENCE = "closed_with_evidence"
    CLOSED_WITHOUT_EVIDENCE = "closed_without_evidence"
    CARRIED_FORWARD = "carried_forward"
    NOT_RECHECKED = "not_rechecked"


@dataclass(frozen=True)
class PriorFindingCheck(_Result):
    finding_id: str
    from_audit_id: str
    checked_in_audit_id: str
    state: PriorFindingState
    citation: Citation


def assess_prior_findings(records: EntityRecords, pack: RulePack, today: date) -> tuple[PriorFindingCheck, ...]:
    rules = pack.rules_of(PriorFindingsRule)
    if not rules:
        return ()
    citation = pack.cite(rules[0])
    audits = sorted((a for a in records.audits if a.started_on <= today), key=lambda a: (a.started_on, a.audit_id))
    nxt = {a.audit_id: b for a, b in zip(audits, audits[1:])}
    carried = {f.carried_from_finding_id: f for f in records.findings if f.carried_from_finding_id}
    known_evidence = {e.evidence_id for e in records.evidence}
    out = []
    for f in sorted(records.findings, key=lambda f: f.finding_id):
        later = nxt.get(f.audit_id)
        if later is None:
            continue
        closed = f.closed_on
        if closed is not None and closed <= later.started_on:
            has_ev = any(e in known_evidence for e in f.fix_evidence_ids)
            state = PriorFindingState.CLOSED_WITH_EVIDENCE if has_ev else PriorFindingState.CLOSED_WITHOUT_EVIDENCE
        elif f.finding_id in carried and carried[f.finding_id].audit_id == later.audit_id:
            state = PriorFindingState.CARRIED_FORWARD
        else:
            state = PriorFindingState.NOT_RECHECKED
        out.append(PriorFindingCheck(f.finding_id, f.audit_id, later.audit_id, state, citation))
    return tuple(out)


# --------------------------------------------------------------------------------------------------------------
# Incidents
# --------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IncidentObligation(_Result):
    incident_id: str
    rule_id: str
    recipient: str | None
    clock_starts_at: datetime
    due_at: datetime
    reported_at: datetime | None
    state: DeliverableState
    in_force: bool
    breach: bool
    hours_remaining: float | None
    missing_evidence_kinds: tuple[str, ...]
    note: str
    citation: Citation


def assess_incident(incident: Incident, pack: RulePack, now: datetime,
                    evidence: dict[str, EvidenceItem] | None = None) -> tuple[IncidentObligation, ...]:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    evidence = evidence or {}
    out = []
    for rule in pack.rules_of(IncidentReportRule):
        note = ""
        if rule.trigger == "incident_detected":
            start = incident.detected_at
            ev_ids = incident.report_evidence_ids
        else:
            if incident.sabotage_concluded_at is None or incident.affects_critical_system is False:
                continue
            start = incident.sabotage_concluded_at
            ev_ids = incident.sabotage_evidence_ids
            if incident.affects_critical_system is None:
                note = "Not recorded whether a critical system was affected; the 24-hour rule is applied."
        due = rule.duration.after_datetime(start)
        in_force = pack.is_in_force(start.astimezone(pack.local_tz).date())
        kinds = {evidence[e].kind for e in ev_ids if e in evidence}
        for recipient in rule.recipients or (None,):
            if rule.trigger == "incident_detected":
                sent = incident.reported_at.get(recipient) if recipient else None
            else:
                sent = incident.sabotage_reported_at
            if sent is not None and sent > now:
                sent = None
            if sent is not None:
                state = DeliverableState.DONE_ON_TIME if sent <= due else DeliverableState.DONE_LATE
            else:
                state = DeliverableState.PENDING if now <= due else DeliverableState.OVERDUE
            remaining = round((due - now).total_seconds() / 3600, 2) if state is DeliverableState.PENDING else None
            missing = tuple(k for k in rule.expects_evidence if k not in kinds) if sent else ()
            out.append(IncidentObligation(
                incident_id=incident.incident_id, rule_id=rule.id, recipient=recipient, clock_starts_at=start,
                due_at=due, reported_at=sent, state=state, in_force=in_force,
                breach=state is DeliverableState.OVERDUE, hours_remaining=remaining,
                missing_evidence_kinds=missing, note=note, citation=pack.cite(rule)))
    return tuple(out)


# --------------------------------------------------------------------------------------------------------------
# Recurring obligations
# --------------------------------------------------------------------------------------------------------------


class PeriodicState(StrEnum):
    NO_RECORD = "no_record"
    CURRENT = "current"
    DUE_SOON = "due_soon"
    OVERDUE = "overdue"
    UNCLASSIFIED_ASSET = "unclassified_asset"  # cannot tell whether the obligation applies


@dataclass(frozen=True)
class PeriodicAssessment(_Result):
    rule_id: str
    activity: str
    asset_id: str | None
    last_performed_on: date | None
    due_on: date | None
    state: PeriodicState
    in_force: bool
    breach: bool
    citation: Citation


def assess_periodic(records: EntityRecords, pack: RulePack, today: date,
                    due_soon_days: int = DEFAULT_DUE_SOON_DAYS) -> tuple[PeriodicAssessment, ...]:
    in_force = pack.is_in_force(today)
    out: list[PeriodicAssessment] = []
    for rule in pack.rules_of(PeriodicRule):
        citation = pack.cite(rule)
        done = [r for r in records.activities if r.activity == rule.activity and r.performed_on <= today]
        targets: list[str | None]
        if rule.scope == "entity":
            targets = [None]
        else:
            targets = []
            for asset in sorted(records.assets, key=lambda a: a.asset_id):
                if rule.scope == "critical_asset" and asset.critical is None:
                    out.append(PeriodicAssessment(rule.id, rule.activity, asset.asset_id, None, None,
                                                  PeriodicState.UNCLASSIFIED_ASSET, in_force, False, citation))
                    continue
                if rule.scope == "critical_asset" and not asset.critical:
                    continue
                targets.append(asset.asset_id)
        for target in targets:
            mine = [r.performed_on for r in done if target is None or r.asset_id == target]
            if not mine:
                out.append(PeriodicAssessment(rule.id, rule.activity, target, None, None, PeriodicState.NO_RECORD,
                                              in_force, False, citation))
                continue
            last = max(mine)
            due = rule.interval.after(last)
            if today > due:
                state = PeriodicState.OVERDUE
            elif (due - today).days <= due_soon_days:
                state = PeriodicState.DUE_SOON
            else:
                state = PeriodicState.CURRENT
            out.append(PeriodicAssessment(rule.id, rule.activity, target, last, due, state, in_force,
                                          state is PeriodicState.OVERDUE, citation))
    return tuple(out)


# --------------------------------------------------------------------------------------------------------------
# Changes
# --------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ChangeCheck(_Result):
    needs_pre_deployment_audit: bool
    matched_categories: tuple[str, ...]
    unknown_categories: tuple[str, ...]
    citations: tuple[Citation, ...]


def check_change(categories: Iterable[str], pack: RulePack) -> ChangeCheck:
    """Does a change in these categories need a cyber security audit before deployment (Second Schedule)?"""
    wanted = list(dict.fromkeys(categories))
    matched: list[str] = []
    known: set[str] = set()
    citations = []
    for rule in pack.rules_of(ChangePreAuditRule):
        ids = {c.id for c in rule.categories}
        known |= ids
        hit = [c for c in wanted if c in ids]
        if hit:
            matched.extend(hit)
            citations.append(pack.cite(rule))
    return ChangeCheck(bool(matched), tuple(dict.fromkeys(matched)), tuple(c for c in wanted if c not in known),
                       tuple(citations))


# --------------------------------------------------------------------------------------------------------------
# Whole entity
# --------------------------------------------------------------------------------------------------------------


class EntityStatus(StrEnum):
    NON_COMPLIANT = "non_compliant"
    ATTENTION = "attention"
    ON_TRACK = "on_track"
    NOT_COVERED = "not_covered"


@dataclass(frozen=True)
class Issue(_Result):
    """One line of the status: a breach or something that needs attention, with the rule behind it."""

    severity: str  # "breach" or "attention"
    subject: str  # "finding", "audit", "audit_cycle", "incident", "periodic", "evidence"
    ref: str
    message: str
    in_force: bool
    rule_id: str | None


@dataclass(frozen=True)
class Deadline(_Result):
    subject: str
    ref: str
    rule_id: str
    due: str  # ISO date or datetime
    days_left: int


@dataclass(frozen=True)
class EntityAssessment(_Result):
    entity_id: str
    entity_name: str
    as_of: datetime
    as_of_date: date
    pack: dict[str, Any]
    regulation_in_force: bool
    applicability: Applicability
    status: EntityStatus
    status_if_in_force: EntityStatus
    issues: tuple[Issue, ...]
    upcoming_deadlines: tuple[Deadline, ...]
    finding_counts: dict[str, int]
    audits: tuple[AuditAssessment, ...]
    audit_cycle: AuditCycleAssessment
    prior_findings: tuple[PriorFindingCheck, ...]
    incidents: tuple[IncidentObligation, ...]
    periodic: tuple[PeriodicAssessment, ...]
    unchecked: tuple[str, ...] = field(default=())


def _status(issues: Iterable[Issue], only_in_force: bool) -> EntityStatus:
    relevant = [i for i in issues if i.in_force or not only_in_force]
    if any(i.severity == "breach" for i in relevant):
        return EntityStatus.NON_COMPLIANT
    if any(i.severity == "attention" for i in relevant):
        return EntityStatus.ATTENTION
    return EntityStatus.ON_TRACK


def evaluate_entity(records: EntityRecords, pack: RulePack, now: datetime,
                    due_soon_days: int = DEFAULT_DUE_SOON_DAYS) -> EntityAssessment:
    """Assess one entity against the pack as of ``now`` (timezone-aware)."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    today = now.astimezone(pack.local_tz).date()
    evidence = {e.evidence_id: e for e in records.evidence}
    applicability = assess_applicability(records.entity, pack)
    excluded = set(applicability.excluded_topics)

    def topic_ok(rule_id: str | None) -> bool:
        return rule_id is None or pack.rule(rule_id).topic not in excluded

    audits = tuple(assess_audit(a, records.findings, pack, today, evidence)
                   for a in sorted(records.audits, key=lambda a: (a.started_on, a.audit_id)))
    cycle = assess_audit_cycle(records.audits, pack, today)
    prior = assess_prior_findings(records, pack, today)
    incidents = tuple(o for i in sorted(records.incidents, key=lambda i: i.detected_at)
                      for o in assess_incident(i, pack, now, evidence))
    periodic = assess_periodic(records, pack, today, due_soon_days)

    issues: list[Issue] = []
    deadlines: list[Deadline] = []
    counts: dict[str, int] = {s.value: 0 for s in FindingState}

    def add(sev: str, subject: str, ref: str, msg: str, in_force: bool, rule_id: str | None) -> None:
        if topic_ok(rule_id):
            issues.append(Issue(sev, subject, ref, msg, in_force, rule_id))

    for aa in audits:
        audit_in_force = pack.is_in_force(aa.started_on)
        if aa.auditor_eligible is False:
            add("breach", "audit", aa.audit_id, f"Auditor {aa.auditor} is not CERT-In empanelled or "
                "Ministry of Power designated.", audit_in_force, aa.eligibility_citation.rule_id)
        elif aa.auditor_eligible is None and aa.eligibility_citation:
            add("attention", "audit", aa.audit_id, f"Empanelment of auditor {aa.auditor} is not recorded.",
                audit_in_force, aa.eligibility_citation.rule_id)
        for d in aa.deliverables:
            rid = d.citation.rule_id
            if d.state is DeliverableState.OVERDUE:
                add("breach", "audit", aa.audit_id, f"{d.deliverable.replace('_', ' ').capitalize()} overdue "
                    f"since {d.due_on}.", d.in_force, rid)
            elif d.state is DeliverableState.PENDING:
                left = (d.due_on - today).days
                deadlines.append(Deadline("audit", f"{aa.audit_id}:{d.deliverable}", rid, d.due_on.isoformat(), left))
                if left <= due_soon_days:
                    add("attention", "audit", aa.audit_id, f"{d.deliverable.replace('_', ' ').capitalize()} due "
                        f"{d.due_on}.", d.in_force, rid)
            for kind in d.missing_evidence_kinds:
                add("attention", "evidence", aa.audit_id, f"No {kind.replace('_', ' ')} on file for the "
                    f"{d.deliverable.replace('_', ' ')}.", d.in_force, rid)
        for fa in aa.findings:
            counts[fa.state.value] += 1
            rid = fa.citations[0].rule_id if fa.citations and fa.state is not FindingState.NOT_COVERED else None
            if fa.breach:
                comp_rid = next((c.rule_id for c in fa.citations
                                 if pack.rule(c.rule_id).kind == "compensating_control"), rid)
                add("breach", "finding", fa.finding_id, fa.explanation, fa.in_force,
                    comp_rid if fa.compensating_control_required else rid)
            elif fa.state is FindingState.OVERDUE_COMPENSATED:
                add("attention", "finding", fa.finding_id, fa.explanation, fa.in_force, rid)
            elif fa.state is FindingState.OPEN and fa.due_on is not None:
                deadlines.append(Deadline("finding", fa.finding_id, rid, fa.due_on.isoformat(), fa.days_remaining))
                if fa.days_remaining is not None and fa.days_remaining <= due_soon_days:
                    add("attention", "finding", fa.finding_id, fa.explanation, fa.in_force, rid)
            if fa.scheduled_fix_after_due and fa.state is FindingState.OPEN:
                add("attention", "finding", fa.finding_id, f"Scheduled fix on {fa.scheduled_fix_on} falls after the "
                    f"deadline of {fa.due_on}.", fa.in_force, rid)

    cycle_rule = cycle.citations[0].rule_id if cycle.citations else None
    for g in cycle.gaps:
        if not g.gap_ok:
            add("breach", "audit_cycle", g.to_audit_id, f"Audit started {g.actual}, outside the allowed window "
                f"{g.earliest_allowed} to {g.latest_allowed} after {g.from_audit_id}.",
                pack.is_in_force(g.actual), cycle_rule)
    if cycle.next_audit_state is WindowState.MISSED:
        add("breach", "audit_cycle", "next", f"Next audit was due to start by {cycle.next_audit_latest}.",
            pack.is_in_force(cycle.next_audit_latest), cycle_rule)
    elif cycle.next_audit_latest is not None:
        deadlines.append(Deadline("audit_cycle", "next_audit", cycle_rule, cycle.next_audit_latest.isoformat(),
                                  (cycle.next_audit_latest - today).days))
    for fy in cycle.financial_years:
        if fy.state is WindowState.MISSED:
            add("breach", "audit_cycle", fy.financial_year, f"No audit started in {fy.financial_year}.", True,
                cycle_rule)
        elif fy.state is WindowState.OPEN:
            deadlines.append(Deadline("audit_cycle", fy.financial_year, cycle_rule, fy.ends_on.isoformat(),
                                      (fy.ends_on - today).days))
            if (fy.ends_on - today).days <= due_soon_days:
                add("attention", "audit_cycle", fy.financial_year, f"No audit started yet in {fy.financial_year}, "
                    f"which ends {fy.ends_on}.", True, cycle_rule)
    if cycle.rotation_ok is False:
        rot = next(c.rule_id for c in cycle.citations if pack.rule(c.rule_id).kind == "auditor_rotation")
        add("breach", "audit_cycle", "rotation", cycle.rotation_note, pack.is_in_force(today), rot)
    if not records.audits:
        add("attention", "audit_cycle", "none", "No audits recorded.", pack.is_in_force(today), cycle_rule)

    for pf in prior:
        if pf.state is PriorFindingState.NOT_RECHECKED:
            add("attention", "finding", pf.finding_id, f"Open finding from {pf.from_audit_id} is not carried into "
                f"{pf.checked_in_audit_id}.", pack.is_in_force(today), pf.citation.rule_id)
        elif pf.state is PriorFindingState.CLOSED_WITHOUT_EVIDENCE:
            add("attention", "evidence", pf.finding_id, f"Finding closed before {pf.checked_in_audit_id} with no "
                "fix evidence on file.", pack.is_in_force(today), pf.citation.rule_id)

    for io in incidents:
        who = io.recipient.replace("_", "-").upper() if io.recipient else "the regulator"
        if io.state is DeliverableState.OVERDUE:
            add("breach", "incident", io.incident_id, f"Report to {who} overdue since {io.due_at.isoformat()}.",
                io.in_force, io.rule_id)
        elif io.state is DeliverableState.PENDING:
            hours = io.hours_remaining or 0.0
            deadlines.append(Deadline("incident", f"{io.incident_id}:{io.recipient or 'report'}", io.rule_id,
                                      io.due_at.isoformat(), (io.due_at.astimezone(pack.local_tz).date() - today).days))
            add("attention", "incident", io.incident_id, f"Report to {who} due by {io.due_at.isoformat()} "
                f"({hours:g} h left).", io.in_force, io.rule_id)
        for kind in io.missing_evidence_kinds:
            add("attention", "evidence", io.incident_id, f"No {kind.replace('_', ' ')} on file for the report.",
                io.in_force, io.rule_id)

    for pa in periodic:
        label = pa.activity.replace("_", " ") + (f" for {pa.asset_id}" if pa.asset_id else "")
        if pa.state is PeriodicState.OVERDUE:
            add("breach", "periodic", pa.asset_id or pa.activity, f"{label.capitalize()} overdue since {pa.due_on}.",
                pa.in_force, pa.rule_id)
        elif pa.state is PeriodicState.NO_RECORD:
            add("attention", "periodic", pa.asset_id or pa.activity, f"No record of {label}.", pa.in_force,
                pa.rule_id)
        elif pa.state is PeriodicState.UNCLASSIFIED_ASSET:
            add("attention", "periodic", pa.asset_id or pa.activity, f"Asset {pa.asset_id} is not classed critical "
                f"or non-critical, so {pa.activity.replace('_', ' ')} cannot be checked.", pa.in_force, pa.rule_id)
        elif pa.due_on is not None:
            deadlines.append(Deadline("periodic", pa.asset_id or pa.activity, pa.rule_id, pa.due_on.isoformat(),
                                      (pa.due_on - today).days))
            if pa.state is PeriodicState.DUE_SOON:
                add("attention", "periodic", pa.asset_id or pa.activity, f"{label.capitalize()} due {pa.due_on}.",
                    pa.in_force, pa.rule_id)

    unchecked = [f"{r.id}: {r.notes}" for r in pack.rules if not r.enabled]
    if not applicability.chapters_determined:
        unchecked.append(f"Applicability: {applicability.reason}")

    if applicability.covered:
        status = _status(issues, only_in_force=True)
        status_if = _status(issues, only_in_force=False)
    else:
        status = status_if = EntityStatus.NOT_COVERED

    deadlines = [d for d in deadlines if topic_ok(d.rule_id)]
    deadlines.sort(key=lambda d: (d.due, d.subject, d.ref))
    order = {"breach": 0, "attention": 1}
    issues.sort(key=lambda i: (order[i.severity], i.subject, i.ref))
    return EntityAssessment(
        entity_id=records.entity.entity_id, entity_name=records.entity.name, as_of=now, as_of_date=today,
        pack=pack.summary(), regulation_in_force=pack.is_in_force(today), applicability=applicability,
        status=status, status_if_in_force=status_if, issues=tuple(issues), upcoming_deadlines=tuple(deadlines),
        finding_counts=counts, audits=audits, audit_cycle=cycle, prior_findings=prior, incidents=incidents,
        periodic=periodic, unchecked=tuple(unchecked))
