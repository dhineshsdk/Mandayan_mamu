"""Sutra compliance engine: regulations as versioned, cited rule data, and the clocks and evidence built on them.

Typical use::

    from sutra_compliance import load_rule_pack, evaluate_entity, build_audit_pack

    pack = load_rule_pack()                      # bundled CEA 2026 pack
    result = evaluate_entity(records, pack, now)  # records: EntityRecords, now: timezone-aware datetime
    audit_pack = build_audit_pack(records, pack, now)
"""

from .auditpack import AuditPack, EvidenceGap, build_audit_pack, verify_audit_pack
from .durations import Duration, add_months
from .engine import (
    Applicability,
    AuditAssessment,
    AuditCycleAssessment,
    ChangeCheck,
    Deadline,
    DeliverableState,
    EntityAssessment,
    EntityStatus,
    FindingAssessment,
    FindingState,
    IncidentObligation,
    Issue,
    PeriodicAssessment,
    PeriodicState,
    PriorFindingState,
    WindowState,
    assess_applicability,
    assess_audit,
    assess_audit_cycle,
    assess_finding,
    assess_incident,
    assess_periodic,
    check_change,
    evaluate_entity,
    to_jsonable,
)
from .model import (
    ActivityRecord,
    Asset,
    Audit,
    AuditFinding,
    CompensatingControl,
    Entity,
    EntityRecords,
    EvidenceItem,
    Incident,
    ScheduledFix,
)
from .rulepack import Citation, RulePack, RulePackError, load_rule_pack, parse_rule_pack

__version__ = "0.1.0"

__all__ = [
    "ActivityRecord",
    "Applicability",
    "Asset",
    "Audit",
    "AuditAssessment",
    "AuditCycleAssessment",
    "AuditFinding",
    "AuditPack",
    "ChangeCheck",
    "Citation",
    "CompensatingControl",
    "Deadline",
    "DeliverableState",
    "Duration",
    "Entity",
    "EntityAssessment",
    "EntityRecords",
    "EntityStatus",
    "EvidenceGap",
    "EvidenceItem",
    "FindingAssessment",
    "FindingState",
    "Incident",
    "IncidentObligation",
    "Issue",
    "PeriodicAssessment",
    "PeriodicState",
    "PriorFindingState",
    "RulePack",
    "RulePackError",
    "ScheduledFix",
    "WindowState",
    "add_months",
    "assess_applicability",
    "assess_audit",
    "assess_audit_cycle",
    "assess_finding",
    "assess_incident",
    "assess_periodic",
    "build_audit_pack",
    "check_change",
    "evaluate_entity",
    "load_rule_pack",
    "parse_rule_pack",
    "to_jsonable",
    "verify_audit_pack",
]
