"""Compliance (M-CMP): the CEA fix clock and the records behind it, assessed by ``sutra_compliance``.

The app stores entities, audits, findings, compensating controls, recurring activities and evidence; this module turns
them into the library's ``EntityRecords`` and runs the rule pack over them. The library decides every state and
deadline; nothing here computes a clock of its own.

A finding linked to a patch job takes its fix date from the rescan that verified the job (``Job.fixed_on``), and that
rescan is attached as fix evidence automatically. A finding without a job has its fix date recorded by hand, and the
audit pack lists it as a gap unless a piece of evidence backs it.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from functools import cache
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session
from sutra_compliance import (
    ActivityRecord,
    Audit,
    AuditFinding,
    CompensatingControl,
    Entity,
    EntityRecords,
    EvidenceItem,
    RulePack,
    ScheduledFix,
    evaluate_entity,
    load_rule_pack,
)
from sutra_compliance.model import AUDITOR_STATUSES, FINDING_SEVERITIES
from sutra_compliance.rulepack import ENTITY_TYPES, PeriodicRule

from .models import (
    CmpActivity,
    CmpAudit,
    CmpControl,
    CmpEntity,
    CmpEvidence,
    CmpEvidenceLink,
    CmpFinding,
    Job,
    JobCheck,
)

ENTITY_TYPE_LABELS = {
    "generator": "Generating station", "captive_plant": "Captive power plant", "energy_storage": "Energy storage",
    "transmission_licensee": "Transmission licensee", "distribution_licensee": "Distribution licensee",
    "nldc": "National load despatch centre", "rldc": "Regional load despatch centre",
    "sldc": "State load despatch centre", "power_exchange": "Power exchange", "otc_platform": "OTC platform",
    "vendor": "Vendor",
}
AUDITOR_STATUS_LABELS = {
    "cert_in_empanelled": "CERT-In empanelled", "mop_designated": "Ministry of Power designated",
    "other": "Neither", "unknown": "Not recorded",
}
# Kinds a person can upload. "rescan" is not here: rescan evidence comes only from Sutra's own fix verification.
EVIDENCE_KINDS = {
    "audit_report": "Audit report", "closure_report": "Closure report",
    "board_report": "Report to the head of the entity or the board", "change_ticket": "Change ticket",
    "scan_report": "Scan report", "screenshot": "Screenshot", "config_export": "Configuration export",
    "policy_document": "Policy or plan", "drill_report": "Drill report", "risk_assessment": "Risk assessment",
    "root_cause_analysis": "Root cause analysis", "forensic_summary": "Forensic summary", "other": "Other",
}
# What evidence can be attached to.
OWNER_TYPES = ("audit_report", "audit_closure", "finding", "control", "activity")
APP_NOTES = (
    "Per-asset obligations (risk assessment every six months, backup age for critical systems) are not checked yet: "
    "assets are not passed to the rule pack until each one is classed critical or not.",
    "Incident reporting clocks (6 hours to CSIRT-Power and CERT-In) are not recorded here yet.",
)


@cache
def pack() -> RulePack:
    return load_rule_pack()


def today_local() -> date:
    return datetime.now(UTC).astimezone(pack().local_tz).date()


def entity_activities() -> dict[str, str]:
    """Recurring activities recorded per entity, with the rule title: {activity: title}."""
    return {r.activity: r.title for r in pack().rules_of(PeriodicRule) if r.scope == "entity"}


def check_entity_type(value: str) -> str:
    if value not in ENTITY_TYPES:
        raise ValueError(f"Choose an entity type: {', '.join(ENTITY_TYPES)}.")
    return value


def check_auditor_status(value: str) -> str:
    if value not in AUDITOR_STATUSES:
        raise ValueError(f"Choose the auditor's status: {', '.join(AUDITOR_STATUSES)}.")
    return value


def check_severity(value: str) -> str:
    v = value.strip().lower()
    if v not in FINDING_SEVERITIES:
        raise ValueError(f"Choose a severity: {', '.join(FINDING_SEVERITIES)}.")
    return v


def check_past(value: date | None, what: str) -> date | None:
    """Dates of things that have happened cannot be in the future (Indian calendar date)."""
    if value is not None and value > today_local():
        raise ValueError(f"{what} cannot be in the future.")
    return value


# ---------- evidence files ----------

def evidence_root(workspace: Path) -> Path:
    return workspace / "evidence"


def evidence_path(workspace: Path, sha256: str) -> Path:
    return evidence_root(workspace) / sha256[:2] / sha256


def store_evidence(workspace: Path, staged: Path) -> tuple[str, int]:
    """Move an uploaded file into the evidence store, named by its SHA-256. Returns (sha256, size)."""
    h = hashlib.sha256()
    size = 0
    with staged.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
            size += len(chunk)
    digest = h.hexdigest()
    dest = evidence_path(workspace, digest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        staged.unlink()
    else:
        staged.replace(dest)
    return digest, size


# ---------- records for the engine ----------

def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC)


def _ev_id(ev_id: int) -> str:
    return f"EV-{ev_id}"


def _rescan_id(check: JobCheck) -> str:
    return f"RESCAN-J{check.job_id}-{check.id}"


def entity_ref(e: CmpEntity) -> str:
    return f"E{e.id}"


def control_ref(c: CmpControl) -> str:
    return f"C{c.id}"


def links_by_owner(db: Session, entity_id: int) -> dict[tuple[str, int], list[int]]:
    rows = db.execute(select(CmpEvidenceLink.owner_type, CmpEvidenceLink.owner_id, CmpEvidenceLink.evidence_id)
                      .join(CmpEvidence, CmpEvidence.id == CmpEvidenceLink.evidence_id)
                      .where(CmpEvidence.entity_id == entity_id).order_by(CmpEvidenceLink.id))
    out: dict[tuple[str, int], list[int]] = {}
    for owner_type, owner_id, ev in rows:
        out.setdefault((owner_type, owner_id), []).append(ev)
    return out


def proving_check(db: Session, job: Job) -> JobCheck | None:
    """The rescan that verified ``job`` fixed, if it is verified-fixed now."""
    if job.status != "verified-fixed":
        return None
    return db.scalars(select(JobCheck).where(JobCheck.job_id == job.id, JobCheck.outcome == "fixed")
                      .order_by(JobCheck.id.desc())).first()


class Loaded:
    """One entity's rows, and the ``EntityRecords`` built from them."""

    def __init__(self, db: Session, e: CmpEntity):
        self.entity = e
        self.audits = list(db.scalars(select(CmpAudit).where(CmpAudit.entity_id == e.id)
                                      .order_by(CmpAudit.started_on, CmpAudit.id)))
        self.findings = list(db.scalars(select(CmpFinding).where(CmpFinding.entity_id == e.id)
                                        .order_by(CmpFinding.audit_id, CmpFinding.ref)))
        fids = [f.id for f in self.findings]
        self.controls: dict[int, list[CmpControl]] = {}
        if fids:
            for c in db.scalars(select(CmpControl).where(CmpControl.finding_id.in_(fids)).order_by(CmpControl.id)):
                self.controls.setdefault(c.finding_id, []).append(c)
        self.activities = list(db.scalars(select(CmpActivity).where(CmpActivity.entity_id == e.id)
                                          .order_by(CmpActivity.performed_on.desc(), CmpActivity.id.desc())))
        self.evidence = list(db.scalars(select(CmpEvidence).where(CmpEvidence.entity_id == e.id)
                                        .order_by(CmpEvidence.id)))
        self.links = links_by_owner(db, e.id)
        job_ids = {f.job_id for f in self.findings if f.job_id}
        self.jobs = {j.id: j for j in db.scalars(select(Job).where(Job.id.in_(job_ids)))} if job_ids else {}
        self.checks: dict[int, list[JobCheck]] = {}
        if job_ids:
            for c in db.scalars(select(JobCheck).where(JobCheck.job_id.in_(job_ids)).order_by(JobCheck.id)):
                self.checks.setdefault(c.job_id, []).append(c)
        self.proof = {jid: proving_check(db, j) for jid, j in self.jobs.items()}
        self.records = self._records()

    def evidence_ids(self, owner_type: str, owner_id: int) -> tuple[str, ...]:
        return tuple(_ev_id(i) for i in self.links.get((owner_type, owner_id), []))

    def fixed_on(self, f: CmpFinding) -> tuple[date | None, str]:
        """The fix date and where it came from: "rescan" (the linked job's verifying rescan), "recorded" or ""."""
        if f.job_id:
            job = self.jobs.get(f.job_id)
            if job is not None and job.status == "verified-fixed" and job.fixed_on:
                return job.fixed_on, "rescan"
            return None, ""
        return (f.fixed_on, "recorded") if f.fixed_on else (None, "")

    def _records(self) -> EntityRecords:
        e = self.entity
        eid = entity_ref(e)
        audit_ref = {a.id: a.ref for a in self.audits}
        finding_ref = {f.id: f.ref for f in self.findings}
        items = [EvidenceItem(_ev_id(x.id), x.kind, x.title, _aware(x.captured_at), sha256=x.sha256,
                              uri=f"/api/compliance/evidence/{x.id}/download", captured_by=str(x.captured_by or ""))
                 for x in self.evidence]
        findings = []
        for f in self.findings:
            fixed, source = self.fixed_on(f)
            fix_ev = list(self.evidence_ids("finding", f.id))
            check = self.proof.get(f.job_id) if f.job_id and source == "rescan" else None
            if check is not None:
                items.append(EvidenceItem(
                    _rescan_id(check), "rescan",
                    f"Rescan as of {check.as_of}: {check.fixed} of the job's findings gone, {check.still_open} still "
                    f"open", _aware(check.checked_at), uri=f"/api/jobs/{check.job_id}"))
                fix_ev.insert(0, _rescan_id(check))
            controls = tuple(CompensatingControl(control_ref(c), c.description, c.implemented_on, c.withdrawn_on,
                                                 c.approved_by or None, self.evidence_ids("control", c.id))
                             for c in self.controls.get(f.id, []))
            sched = ScheduledFix(f.planned_on, f.planned_reason or "Scheduled fix",
                                 f.planned_reference or None) if f.planned_on else None
            findings.append(AuditFinding(
                f.ref, audit_ref[f.audit_id], f.severity, f.title, tuple(f.asset_ids or ()), fixed_on=fixed,
                auditor_cleared_on=f.auditor_cleared_on, fix_evidence_ids=tuple(fix_ev),
                compensating_controls=controls, scheduled_fix=sched,
                carried_from_finding_id=finding_ref.get(f.carried_from_id) if f.carried_from_id else None))
        audits = tuple(Audit(a.ref, eid, a.auditor, a.auditor_status, a.started_on, a.report_submitted_on,
                             a.closure_report_on, self.evidence_ids("audit_report", a.id),
                             self.evidence_ids("audit_closure", a.id)) for a in self.audits)
        activities = tuple(ActivityRecord(x.activity, x.performed_on, x.asset_id or None, x.approved_by or None,
                                          self.evidence_ids("activity", x.id)) for x in self.activities)
        return EntityRecords(entity=Entity(eid, e.name, e.entity_type, e.capacity_mw), audits=audits,
                             findings=tuple(findings), activities=activities, evidence=tuple(items))

    def assess(self, now: datetime | None = None):
        return evaluate_entity(self.records, pack(), now or datetime.now(UTC))


# ---------- JSON ----------

def evidence_json(x: CmpEvidence) -> dict:
    return {"id": x.id, "ref": _ev_id(x.id), "kind": x.kind, "kind_label": EVIDENCE_KINDS.get(x.kind, x.kind),
            "title": x.title, "filename": x.filename, "size": x.size, "sha256": x.sha256,
            "captured_at": x.captured_at.isoformat(timespec="seconds"), "captured_by": x.captured_by}


def entity_summary(db: Session, e: CmpEntity) -> dict:
    loaded = Loaded(db, e)
    a = loaded.assess()
    return {"id": e.id, "name": e.name, "entity_type": e.entity_type,
            "entity_type_label": ENTITY_TYPE_LABELS.get(e.entity_type, e.entity_type), "capacity_mw": e.capacity_mw,
            "site": e.site, "status": a.status.value, "status_if_in_force": a.status_if_in_force.value,
            "covered": a.applicability.covered, "audits": len(loaded.audits), "findings": len(loaded.findings),
            "finding_counts": a.finding_counts,
            "breaches": sum(1 for i in a.issues if i.severity == "breach"),
            "next_deadline": a.upcoming_deadlines[0].to_dict() if a.upcoming_deadlines else None}


def job_json(job: Job, checks: list[JobCheck], proof: JobCheck | None) -> dict:
    return {"id": job.id, "title": job.rc_title, "team": job.team, "status": job.status, "mode": job.mode,
            "fixed_on": job.fixed_on.isoformat() if job.fixed_on else None,
            "proof_check": proof.id if proof else None,
            "checks": [{"id": c.id, "as_of": c.as_of.isoformat() if c.as_of else None,
                        "checked_at": c.checked_at.isoformat(timespec="seconds"), "outcome": c.outcome,
                        "fixed": c.fixed, "still_open": c.still_open, "not_rescanned": c.not_rescanned}
                       for c in checks]}


def entity_detail(db: Session, e: CmpEntity, now: datetime | None = None) -> dict:
    loaded = Loaded(db, e)
    a = loaded.assess(now).to_dict()
    ev = {x.id: evidence_json(x) for x in loaded.evidence}

    def linked(owner_type: str, owner_id: int) -> list[dict]:
        return [ev[i] for i in loaded.links.get((owner_type, owner_id), []) if i in ev]

    by_audit = {x["audit_id"]: x for x in a.pop("audits")}
    clocks = {f["finding_id"]: f for x in by_audit.values() for f in x["findings"]}
    ref_of = {f.id: f.ref for f in loaded.findings}
    audits = []
    for au in loaded.audits:
        assessed = by_audit.get(au.ref, {})
        findings = []
        for f in (x for x in loaded.findings if x.audit_id == au.id):
            fixed, source = loaded.fixed_on(f)
            job = loaded.jobs.get(f.job_id) if f.job_id else None
            findings.append({
                "id": f.id, "ref": f.ref, "severity": f.severity, "title": f.title, "asset_ids": f.asset_ids or [],
                "fixed_on": fixed.isoformat() if fixed else None, "fixed_source": source,
                "recorded_fixed_on": f.fixed_on.isoformat() if f.fixed_on else None,
                "auditor_cleared_on": f.auditor_cleared_on.isoformat() if f.auditor_cleared_on else None,
                "planned_on": f.planned_on.isoformat() if f.planned_on else None,
                "planned_reason": f.planned_reason, "planned_reference": f.planned_reference,
                "carried_from": ref_of.get(f.carried_from_id) if f.carried_from_id else None,
                "carried_from_id": f.carried_from_id,
                "job_id": f.job_id,
                "job": job_json(job, loaded.checks.get(job.id, []), loaded.proof.get(job.id)) if job else None,
                "controls": [{"id": c.id, "ref": control_ref(c), "description": c.description,
                              "implemented_on": c.implemented_on.isoformat(),
                              "withdrawn_on": c.withdrawn_on.isoformat() if c.withdrawn_on else None,
                              "approved_by": c.approved_by, "evidence": linked("control", c.id)}
                             for c in loaded.controls.get(f.id, [])],
                "evidence": linked("finding", f.id),
                "clock": clocks.get(f.ref),
            })
        audits.append({
            "id": au.id, "ref": au.ref, "auditor": au.auditor, "auditor_status": au.auditor_status,
            "auditor_status_label": AUDITOR_STATUS_LABELS.get(au.auditor_status, au.auditor_status),
            "started_on": au.started_on.isoformat(),
            "report_submitted_on": au.report_submitted_on.isoformat() if au.report_submitted_on else None,
            "closure_report_on": au.closure_report_on.isoformat() if au.closure_report_on else None,
            "report_evidence": linked("audit_report", au.id), "closure_evidence": linked("audit_closure", au.id),
            "auditor_eligible": assessed.get("auditor_eligible"),
            "eligibility_citation": assessed.get("eligibility_citation"),
            "deliverables": assessed.get("deliverables", []), "findings": findings,
        })
    activity_titles = entity_activities()
    return {
        "entity": {"id": e.id, "name": e.name, "entity_type": e.entity_type,
                   "entity_type_label": ENTITY_TYPE_LABELS.get(e.entity_type, e.entity_type),
                   "capacity_mw": e.capacity_mw, "site": e.site},
        "assessment": a, "audits": audits,
        "activities": [{"id": x.id, "activity": x.activity, "title": activity_titles.get(x.activity, x.activity),
                        "performed_on": x.performed_on.isoformat(), "approved_by": x.approved_by,
                        "evidence": linked("activity", x.id)} for x in loaded.activities],
        "evidence": [{**ev[x.id], "links": [{"owner_type": t, "owner_id": o}
                                            for (t, o), ids in loaded.links.items() if x.id in ids]}
                     for x in loaded.evidence],
        "notes": list(APP_NOTES),
    }


def meta() -> dict:
    p = pack()
    return {"entity_types": ENTITY_TYPE_LABELS, "severities": list(FINDING_SEVERITIES),
            "auditor_statuses": AUDITOR_STATUS_LABELS, "evidence_kinds": EVIDENCE_KINDS,
            "activities": entity_activities(), "pack": p.summary(), "today": today_local().isoformat()}
