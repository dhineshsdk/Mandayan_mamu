"""Input records the engine evaluates. Plain, immutable data with no storage or framework dependencies.

Callers (the app server, an import job, a test) build these from whatever store they use and pass them in.
Dates are Indian calendar dates; datetimes must be timezone-aware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime

from .rulepack import ENTITY_TYPES, RECIPIENTS

FINDING_SEVERITIES = ("critical", "high", "medium", "low", "info")
AUDITOR_STATUSES = ("cert_in_empanelled", "mop_designated", "other", "unknown")


def _aware(value: datetime | None, what: str) -> None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise ValueError(f"{what} must be timezone-aware")


def _plain_date(value: date | None, what: str) -> None:
    if isinstance(value, datetime):
        raise TypeError(f"{what} must be a date, not a datetime")


@dataclass(frozen=True)
class Entity:
    entity_id: str
    name: str
    entity_type: str
    capacity_mw: float | None = None

    def __post_init__(self) -> None:
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(f"entity_type {self.entity_type!r} is not one of {', '.join(ENTITY_TYPES)}")
        if self.capacity_mw is not None and self.capacity_mw < 0:
            raise ValueError("capacity_mw must not be negative")


@dataclass(frozen=True)
class Asset:
    asset_id: str
    name: str = ""
    critical: bool | None = None  # None: not yet classified, which is itself a gap


@dataclass(frozen=True)
class EvidenceItem:
    """A stored piece of proof. The engine checks references to it; it never reads the content."""

    evidence_id: str
    kind: str  # e.g. "rescan", "change_ticket", "screenshot", "board_report", "audit_report"
    title: str
    captured_at: datetime
    sha256: str | None = None
    uri: str | None = None
    captured_by: str | None = None

    def __post_init__(self) -> None:
        _aware(self.captured_at, "captured_at")
        if self.sha256 is not None:
            digest = self.sha256.lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(f"evidence {self.evidence_id}: sha256 must be 64 hex characters")


@dataclass(frozen=True)
class Audit:
    audit_id: str
    entity_id: str
    auditor: str
    auditor_status: str
    started_on: date
    report_submitted_on: date | None = None
    closure_report_on: date | None = None
    report_evidence_ids: tuple[str, ...] = ()
    closure_evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.auditor_status not in AUDITOR_STATUSES:
            raise ValueError(f"auditor_status {self.auditor_status!r} is not one of {', '.join(AUDITOR_STATUSES)}")
        for name in ("started_on", "report_submitted_on", "closure_report_on"):
            _plain_date(getattr(self, name), name)
        if self.report_submitted_on and self.report_submitted_on < self.started_on:
            raise ValueError(f"audit {self.audit_id}: report submitted before the audit started")
        if self.closure_report_on and self.closure_report_on < self.started_on:
            raise ValueError(f"audit {self.audit_id}: closure report dated before the audit started")


@dataclass(frozen=True)
class CompensatingControl:
    control_id: str
    description: str
    implemented_on: date
    withdrawn_on: date | None = None
    approved_by: str | None = None
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _plain_date(self.implemented_on, "implemented_on")
        _plain_date(self.withdrawn_on, "withdrawn_on")
        if self.withdrawn_on and self.withdrawn_on < self.implemented_on:
            raise ValueError(f"control {self.control_id}: withdrawn before it was implemented")

    def active_on(self, day: date) -> bool:
        return self.implemented_on <= day and (self.withdrawn_on is None or day < self.withdrawn_on)


@dataclass(frozen=True)
class ScheduledFix:
    """A planned fix date, such as the next plant shutdown. Shown alongside the clock; it never stops it."""

    planned_on: date
    reason: str
    reference: str | None = None


@dataclass(frozen=True)
class AuditFinding:
    finding_id: str
    audit_id: str
    severity: str
    title: str
    asset_ids: tuple[str, ...] = ()
    fixed_on: date | None = None
    auditor_cleared_on: date | None = None
    fix_evidence_ids: tuple[str, ...] = ()
    compensating_controls: tuple[CompensatingControl, ...] = ()
    scheduled_fix: ScheduledFix | None = None
    # Set when the same issue was raised in an earlier audit, so the next audit can show it was rechecked.
    carried_from_finding_id: str | None = None

    def __post_init__(self) -> None:
        sev = self.severity.lower()
        if sev not in FINDING_SEVERITIES:
            raise ValueError(f"finding {self.finding_id}: severity {self.severity!r} is not one of "
                             f"{', '.join(FINDING_SEVERITIES)}")
        object.__setattr__(self, "severity", sev)
        _plain_date(self.fixed_on, "fixed_on")
        _plain_date(self.auditor_cleared_on, "auditor_cleared_on")
        ids = [c.control_id for c in self.compensating_controls]
        if len(set(ids)) != len(ids):
            raise ValueError(f"finding {self.finding_id}: duplicate compensating control ids")

    @property
    def closed_on(self) -> date | None:
        """When the finding stopped being open: the fix date, else the auditor's clearance date."""
        return self.fixed_on or self.auditor_cleared_on


@dataclass(frozen=True)
class Incident:
    incident_id: str
    entity_id: str
    title: str
    detected_at: datetime
    # Time each report was sent, by recipient ("csirt_power", "cert_in").
    reported_at: dict[str, datetime] = field(default_factory=dict)
    sabotage_concluded_at: datetime | None = None
    sabotage_reported_at: datetime | None = None
    affects_critical_system: bool | None = None
    report_evidence_ids: tuple[str, ...] = ()
    sabotage_evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _aware(self.detected_at, "detected_at")
        _aware(self.sabotage_concluded_at, "sabotage_concluded_at")
        _aware(self.sabotage_reported_at, "sabotage_reported_at")
        for who, when in self.reported_at.items():
            if who not in RECIPIENTS:
                raise ValueError(f"incident {self.incident_id}: unknown recipient {who!r}; "
                                 f"expected one of {', '.join(RECIPIENTS)}")
            _aware(when, f"reported_at[{who}]")
        if self.sabotage_reported_at and not self.sabotage_concluded_at:
            raise ValueError(f"incident {self.incident_id}: sabotage report without a sabotage conclusion")


@dataclass(frozen=True)
class ActivityRecord:
    """One performance of a recurring obligation (a policy review, a drill, a backup)."""

    activity: str
    performed_on: date
    asset_id: str | None = None
    approved_by: str | None = None
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _plain_date(self.performed_on, "performed_on")


@dataclass(frozen=True)
class EntityRecords:
    """Everything known about one regulated entity, as of the evaluation."""

    entity: Entity
    assets: tuple[Asset, ...] = ()
    audits: tuple[Audit, ...] = ()
    findings: tuple[AuditFinding, ...] = ()
    incidents: tuple[Incident, ...] = ()
    activities: tuple[ActivityRecord, ...] = ()
    evidence: tuple[EvidenceItem, ...] = ()

    def __post_init__(self) -> None:
        for label, ids in (
            ("asset", [a.asset_id for a in self.assets]),
            ("audit", [a.audit_id for a in self.audits]),
            ("finding", [f.finding_id for f in self.findings]),
            ("incident", [i.incident_id for i in self.incidents]),
            ("evidence", [e.evidence_id for e in self.evidence]),
        ):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            if dupes:
                raise ValueError(f"duplicate {label} ids: {', '.join(dupes)}")
        audit_ids = {a.audit_id for a in self.audits}
        for a in self.audits:
            if a.entity_id != self.entity.entity_id:
                raise ValueError(f"audit {a.audit_id} belongs to entity {a.entity_id}, not {self.entity.entity_id}")
        for f in self.findings:
            if f.audit_id not in audit_ids:
                raise ValueError(f"finding {f.finding_id} refers to unknown audit {f.audit_id}")
        for i in self.incidents:
            if i.entity_id != self.entity.entity_id:
                raise ValueError(f"incident {i.incident_id} belongs to entity {i.entity_id}, "
                                 f"not {self.entity.entity_id}")
