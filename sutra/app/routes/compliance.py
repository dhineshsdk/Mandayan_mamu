"""Compliance (M-CMP): regulated entities, their CEA audits and findings, the fix clock and the evidence behind it.

Reading needs M-CMP view (the compliance officer, the CISO and a time-limited auditor); recording audits, findings,
controls, activities and evidence needs M-CMP act. Evidence files are never changed or deleted once uploaded; a
wrong link can be removed, and the audit log keeps both.
"""

from __future__ import annotations

import secrets
from datetime import UTC, date, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import compliance as cmp
from ..access import Principal
from ..deps import client_ip, get_db, require
from ..models import (
    CmpActivity,
    CmpAsset,
    CmpAudit,
    CmpControl,
    CmpEntity,
    CmpEvidence,
    CmpEvidenceLink,
    CmpFinding,
    CmpIncident,
    Job,
    utcnow,
)
from ..security import audit
from .data import safe_name

router = APIRouter(prefix="/api/compliance")
VIEW = require("M-CMP", "view")
ACT = require("M-CMP", "act")
CHUNK = 1024 * 1024
# Served inline-safe types; anything else downloads as a plain byte stream.
SAFE_TYPES = {"application/pdf", "image/png", "image/jpeg", "text/plain", "text/csv"}


def _get(db: Session, model, pk: int, what: str):
    row = db.get(model, pk)
    if row is None:
        raise LookupError(f"No such {what}.")
    return row


def _validate(db: Session, entity: CmpEntity) -> None:
    """Build the engine's records from the pending changes; the library refuses inconsistent data (ValueError)."""
    db.flush()
    cmp.Loaded(db, entity)


def _iso(d: date | None) -> str | None:
    return d.isoformat() if d else None


# ---------- reference data and entities ----------

@router.get("/meta")
def meta(p: Principal = Depends(VIEW)):
    return cmp.meta()


@router.get("/entities")
def list_entities(p: Principal = Depends(VIEW), db: Session = Depends(get_db)):
    return {"entities": [cmp.entity_summary(db, e) for e in db.scalars(select(CmpEntity).order_by(CmpEntity.name))],
            "can_act": p.can("M-CMP", "act")}


class EntityIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    entity_type: str = Field(max_length=40)
    capacity_mw: float | None = Field(default=None, ge=0, le=100000)
    site: str = Field(default="", max_length=120)


@router.post("/entities", status_code=201)
def add_entity(body: EntityIn, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    name = body.name.strip()
    if db.scalars(select(CmpEntity).where(CmpEntity.name == name)).first():
        raise ValueError(f"An entity named {name} already exists.")
    e = CmpEntity(name=name, entity_type=cmp.check_entity_type(body.entity_type), capacity_mw=body.capacity_mw,
                  site=body.site.strip(), created_by=p.user.id)
    db.add(e)
    _validate(db, e)
    audit(db, "compliance.entity_add", p.user, "cmp_entity", e.id, client_ip(request), name=e.name,
          entity_type=e.entity_type, capacity_mw=e.capacity_mw, site=e.site)
    db.commit()
    return cmp.entity_summary(db, e)


@router.get("/entities/{eid}")
def get_entity(eid: int, request: Request, p: Principal = Depends(VIEW), db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    out = cmp.entity_detail(db, e)
    audit(db, "compliance.entity_view", p.user, "cmp_entity", e.id, client_ip(request))
    db.commit()
    return {**out, "can_act": p.can("M-CMP", "act")}


@router.put("/entities/{eid}")
def update_entity(eid: int, body: EntityIn, request: Request, p: Principal = Depends(ACT),
                  db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    name = body.name.strip()
    clash = db.scalars(select(CmpEntity).where(CmpEntity.name == name, CmpEntity.id != e.id)).first()
    if clash:
        raise ValueError(f"An entity named {name} already exists.")
    before = {"name": e.name, "entity_type": e.entity_type, "capacity_mw": e.capacity_mw, "site": e.site}
    e.name, e.entity_type = name, cmp.check_entity_type(body.entity_type)
    e.capacity_mw, e.site, e.updated_at = body.capacity_mw, body.site.strip(), utcnow()
    _validate(db, e)
    audit(db, "compliance.entity_change", p.user, "cmp_entity", e.id, client_ip(request), before=before,
          name=e.name, entity_type=e.entity_type, capacity_mw=e.capacity_mw, site=e.site)
    db.commit()
    return cmp.entity_summary(db, e)


@router.delete("/entities/{eid}")
def delete_entity(eid: int, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    used = (db.scalar(select(func.count(CmpAudit.id)).where(CmpAudit.entity_id == e.id))
            or db.scalar(select(func.count(CmpEvidence.id)).where(CmpEvidence.entity_id == e.id))
            or db.scalar(select(func.count(CmpActivity.id)).where(CmpActivity.entity_id == e.id)))
    if used:
        raise ValueError("This entity has audits, activities or evidence on record, so it cannot be removed.")
    audit(db, "compliance.entity_delete", p.user, "cmp_entity", e.id, client_ip(request), name=e.name)
    for x in db.scalars(select(CmpAsset).where(CmpAsset.entity_id == e.id)):
        db.delete(x)
    db.delete(e)
    db.commit()
    return {"ok": True}


# ---------- audits ----------

class AuditIn(BaseModel):
    ref: str = Field(min_length=1, max_length=60)
    auditor: str = Field(min_length=1, max_length=200)
    auditor_status: str = Field(max_length=24)
    started_on: date
    report_submitted_on: date | None = None
    closure_report_on: date | None = None


def _audit_fields(a: CmpAudit, body: AuditIn) -> None:
    a.ref, a.auditor = body.ref.strip(), body.auditor.strip()
    a.auditor_status = cmp.check_auditor_status(body.auditor_status)
    a.started_on = cmp.check_past(body.started_on, "The audit start date")
    a.report_submitted_on = cmp.check_past(body.report_submitted_on, "The report date")
    a.closure_report_on = cmp.check_past(body.closure_report_on, "The closure report date")


def _audit_json(a: CmpAudit) -> dict:
    return {"id": a.id, "ref": a.ref, "auditor": a.auditor, "auditor_status": a.auditor_status,
            "started_on": _iso(a.started_on), "report_submitted_on": _iso(a.report_submitted_on),
            "closure_report_on": _iso(a.closure_report_on)}


def _unique_audit_ref(db: Session, entity_id: int, ref: str, not_id: int | None = None) -> None:
    q = select(CmpAudit).where(CmpAudit.entity_id == entity_id, CmpAudit.ref == ref)
    if not_id is not None:
        q = q.where(CmpAudit.id != not_id)
    if db.scalars(q).first():
        raise ValueError(f"This entity already has an audit {ref}.")


@router.post("/entities/{eid}/audits", status_code=201)
def add_audit(eid: int, body: AuditIn, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    _unique_audit_ref(db, e.id, body.ref.strip())
    a = CmpAudit(entity_id=e.id, created_by=p.user.id)
    _audit_fields(a, body)
    db.add(a)
    _validate(db, e)
    audit(db, "compliance.audit_add", p.user, "cmp_audit", a.id, client_ip(request), entity=e.id, **_audit_json(a))
    db.commit()
    return _audit_json(a)


@router.put("/audits/{aid}")
def update_audit(aid: int, body: AuditIn, request: Request, p: Principal = Depends(ACT),
                 db: Session = Depends(get_db)):
    a = _get(db, CmpAudit, aid, "audit")
    _unique_audit_ref(db, a.entity_id, body.ref.strip(), a.id)
    before = _audit_json(a)
    _audit_fields(a, body)
    a.updated_at = utcnow()
    _validate(db, db.get(CmpEntity, a.entity_id))
    audit(db, "compliance.audit_change", p.user, "cmp_audit", a.id, client_ip(request), entity=a.entity_id,
          before=before, after=_audit_json(a))
    db.commit()
    return _audit_json(a)


@router.delete("/audits/{aid}")
def delete_audit(aid: int, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    a = _get(db, CmpAudit, aid, "audit")
    if db.scalar(select(func.count(CmpFinding.id)).where(CmpFinding.audit_id == a.id)):
        raise ValueError("Remove this audit's findings first.")
    audit(db, "compliance.audit_delete", p.user, "cmp_audit", a.id, client_ip(request), entity=a.entity_id,
          **_audit_json(a))
    db.execute(CmpEvidenceLink.__table__.delete().where(CmpEvidenceLink.owner_type.in_(("audit_report",
                                                                                           "audit_closure")),
                                                        CmpEvidenceLink.owner_id == a.id))
    db.delete(a)
    db.commit()
    return {"ok": True}


# ---------- findings ----------

class FindingIn(BaseModel):
    ref: str = Field(min_length=1, max_length=60)
    severity: str = Field(max_length=12)
    title: str = Field(min_length=1, max_length=2000)
    asset_ids: list[str] = Field(default_factory=list, max_length=500)
    job_id: int | None = None
    fixed_on: date | None = None
    auditor_cleared_on: date | None = None
    planned_on: date | None = None
    planned_reason: str = Field(default="", max_length=300)
    planned_reference: str = Field(default="", max_length=120)
    carried_from_id: int | None = None


def _finding_json(f: CmpFinding) -> dict:
    return {"id": f.id, "ref": f.ref, "severity": f.severity, "title": f.title, "asset_ids": f.asset_ids,
            "job_id": f.job_id, "fixed_on": _iso(f.fixed_on), "auditor_cleared_on": _iso(f.auditor_cleared_on),
            "planned_on": _iso(f.planned_on), "planned_reason": f.planned_reason,
            "planned_reference": f.planned_reference, "carried_from_id": f.carried_from_id}


def _finding_fields(db: Session, f: CmpFinding, body: FindingIn) -> None:
    ref = body.ref.strip()
    q = select(CmpFinding).where(CmpFinding.entity_id == f.entity_id, CmpFinding.ref == ref)
    if f.id is not None:
        q = q.where(CmpFinding.id != f.id)
    if db.scalars(q).first():
        raise ValueError(f"This entity already has a finding {ref}.")
    if body.job_id is not None:
        if db.get(Job, body.job_id) is None:
            raise ValueError("No such patch job.")
        if body.fixed_on is not None:
            raise ValueError("This finding is linked to a patch job, so its fix date comes from the rescan that "
                             "verifies the job. Clear the fix date or remove the link.")
    if body.planned_on is not None and not body.planned_reason.strip():
        raise ValueError("Say what the scheduled fix date is, for example the shutdown it is planned for.")
    if body.carried_from_id is not None:
        prior = db.get(CmpFinding, body.carried_from_id)
        if prior is None or prior.entity_id != f.entity_id or prior.id == f.id:
            raise ValueError("The earlier finding must be another finding of the same entity.")
        if prior.audit_id == f.audit_id:
            raise ValueError("The earlier finding must come from an earlier audit.")
    f.ref, f.severity, f.title = ref, cmp.check_severity(body.severity), body.title.strip()
    f.asset_ids = list(dict.fromkeys(a.strip() for a in body.asset_ids if a.strip()))
    f.job_id = body.job_id
    f.fixed_on = cmp.check_past(body.fixed_on, "The fix date")
    f.auditor_cleared_on = cmp.check_past(body.auditor_cleared_on, "The auditor's clearance date")
    f.planned_on = body.planned_on
    f.planned_reason = body.planned_reason.strip() if body.planned_on else ""
    f.planned_reference = body.planned_reference.strip() if body.planned_on else ""
    f.carried_from_id = body.carried_from_id


@router.post("/audits/{aid}/findings", status_code=201)
def add_finding(aid: int, body: FindingIn, request: Request, p: Principal = Depends(ACT),
                db: Session = Depends(get_db)):
    a = _get(db, CmpAudit, aid, "audit")
    f = CmpFinding(entity_id=a.entity_id, audit_id=a.id, created_by=p.user.id)
    _finding_fields(db, f, body)
    db.add(f)
    _validate(db, db.get(CmpEntity, a.entity_id))
    audit(db, "compliance.finding_add", p.user, "cmp_finding", f.id, client_ip(request), entity=a.entity_id,
          audit=a.ref, **_finding_json(f))
    db.commit()
    return _finding_json(f)


@router.put("/findings/{fid}")
def update_finding(fid: int, body: FindingIn, request: Request, p: Principal = Depends(ACT),
                   db: Session = Depends(get_db)):
    f = _get(db, CmpFinding, fid, "finding")
    before = _finding_json(f)
    _finding_fields(db, f, body)
    f.updated_at = utcnow()
    _validate(db, db.get(CmpEntity, f.entity_id))
    audit(db, "compliance.finding_change", p.user, "cmp_finding", f.id, client_ip(request), entity=f.entity_id,
          before=before, after=_finding_json(f))
    db.commit()
    return _finding_json(f)


@router.delete("/findings/{fid}")
def delete_finding(fid: int, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    f = _get(db, CmpFinding, fid, "finding")
    if db.scalars(select(CmpFinding).where(CmpFinding.carried_from_id == f.id)).first():
        raise ValueError("A later finding is carried from this one. Remove that link first.")
    controls = list(db.scalars(select(CmpControl).where(CmpControl.finding_id == f.id)))
    audit(db, "compliance.finding_delete", p.user, "cmp_finding", f.id, client_ip(request), entity=f.entity_id,
          controls=[c.description for c in controls], **_finding_json(f))
    db.execute(CmpEvidenceLink.__table__.delete().where(CmpEvidenceLink.owner_type == "control",
                                                        CmpEvidenceLink.owner_id.in_([c.id for c in controls])))
    db.execute(CmpEvidenceLink.__table__.delete().where(CmpEvidenceLink.owner_type == "finding",
                                                        CmpEvidenceLink.owner_id == f.id))
    for c in controls:
        db.delete(c)
    db.delete(f)
    db.commit()
    return {"ok": True}


@router.get("/jobs")
def find_jobs(q: str = "", p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    """Patch jobs to link a finding to, newest first; ``q`` matches the job number, title or team."""
    query = select(Job).order_by(Job.id.desc()).limit(50)
    q = q.strip()[:100]
    if q:
        conds = [Job.rc_title.ilike(f"%{q}%"), Job.team.ilike(f"%{q}%")]
        if q.lstrip("#").isdigit():
            conds.append(Job.id == int(q.lstrip("#")))
        query = query.where(or_(*conds))
    return {"jobs": [{"id": j.id, "title": j.rc_title, "team": j.team, "status": j.status, "mode": j.mode,
                      "fixed_on": _iso(j.fixed_on)} for j in db.scalars(query)]}


# ---------- compensating controls ----------

class ControlIn(BaseModel):
    description: str = Field(min_length=1, max_length=2000)
    implemented_on: date
    withdrawn_on: date | None = None
    approved_by: str = Field(default="", max_length=200)


def _control_json(c: CmpControl) -> dict:
    return {"id": c.id, "description": c.description, "implemented_on": _iso(c.implemented_on),
            "withdrawn_on": _iso(c.withdrawn_on), "approved_by": c.approved_by}


def _control_fields(c: CmpControl, body: ControlIn) -> None:
    c.description = body.description.strip()
    c.implemented_on = cmp.check_past(body.implemented_on, "The date the control was put in place")
    c.withdrawn_on = cmp.check_past(body.withdrawn_on, "The date the control was withdrawn")
    c.approved_by = body.approved_by.strip()


@router.post("/findings/{fid}/controls", status_code=201)
def add_control(fid: int, body: ControlIn, request: Request, p: Principal = Depends(ACT),
                db: Session = Depends(get_db)):
    f = _get(db, CmpFinding, fid, "finding")
    c = CmpControl(finding_id=f.id, created_by=p.user.id)
    _control_fields(c, body)
    db.add(c)
    _validate(db, db.get(CmpEntity, f.entity_id))
    audit(db, "compliance.control_add", p.user, "cmp_control", c.id, client_ip(request), finding=f.ref,
          entity=f.entity_id, **_control_json(c))
    db.commit()
    return _control_json(c)


@router.put("/controls/{cid}")
def update_control(cid: int, body: ControlIn, request: Request, p: Principal = Depends(ACT),
                   db: Session = Depends(get_db)):
    c = _get(db, CmpControl, cid, "compensating control")
    f = db.get(CmpFinding, c.finding_id)
    before = _control_json(c)
    _control_fields(c, body)
    _validate(db, db.get(CmpEntity, f.entity_id))
    audit(db, "compliance.control_change", p.user, "cmp_control", c.id, client_ip(request), finding=f.ref,
          entity=f.entity_id, before=before, after=_control_json(c))
    db.commit()
    return _control_json(c)


# ---------- recurring activities ----------

class ActivityIn(BaseModel):
    activity: str = Field(max_length=40)
    performed_on: date
    asset_id: str = Field(default="", max_length=120)  # required for per-asset activities
    approved_by: str = Field(default="", max_length=200)


@router.post("/entities/{eid}/activities", status_code=201)
def add_activity(eid: int, body: ActivityIn, request: Request, p: Principal = Depends(ACT),
                 db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    acts = cmp.activities()
    if body.activity not in acts:
        raise ValueError(f"Choose an activity: {', '.join(acts)}.")
    asset_id = body.asset_id.strip()
    scope = acts[body.activity]["scope"]
    if scope == "entity":
        if asset_id:
            raise ValueError(f"{acts[body.activity]['title']} is recorded for the whole entity, not one asset.")
    else:
        asset = db.scalars(select(CmpAsset).where(CmpAsset.entity_id == e.id, CmpAsset.asset_id == asset_id)).first()
        if asset is None:
            raise ValueError(f"{acts[body.activity]['title']} is recorded per asset: choose one of this entity's "
                             "assets.")
        if scope == "critical_asset" and asset.critical is not True:
            raise ValueError(f"{acts[body.activity]['title']} applies to critical systems; {asset_id} is not classed "
                             "critical.")
    x = CmpActivity(entity_id=e.id, activity=body.activity, asset_id=asset_id,
                    performed_on=cmp.check_past(body.performed_on, "The date it was done"),
                    approved_by=body.approved_by.strip(), created_by=p.user.id)
    db.add(x)
    _validate(db, e)
    audit(db, "compliance.activity_add", p.user, "cmp_activity", x.id, client_ip(request), entity=e.id,
          activity=x.activity, asset_id=x.asset_id, performed_on=_iso(x.performed_on), approved_by=x.approved_by)
    db.commit()
    return {"id": x.id}


@router.delete("/activities/{xid}")
def delete_activity(xid: int, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    x = _get(db, CmpActivity, xid, "activity record")
    audit(db, "compliance.activity_delete", p.user, "cmp_activity", x.id, client_ip(request), entity=x.entity_id,
          activity=x.activity, performed_on=_iso(x.performed_on))
    db.execute(CmpEvidenceLink.__table__.delete().where(CmpEvidenceLink.owner_type == "activity",
                                                        CmpEvidenceLink.owner_id == x.id))
    db.delete(x)
    db.commit()
    return {"ok": True}


# ---------- incidents ----------

def _utc(dt: datetime | None) -> datetime | None:
    """Naive UTC for storage; a time without an offset is read as Indian time (the people entering it are there)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=cmp.pack().local_tz)
    return dt.astimezone(UTC).replace(tzinfo=None)


class IncidentIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=5000)
    detected_at: datetime
    asset_ids: list[str] = Field(default_factory=list, max_length=500)
    affects_critical_system: bool | None = None
    actions_taken: str = Field(default="", max_length=5000)
    reported_csirt_at: datetime | None = None
    reported_certin_at: datetime | None = None
    sabotage_concluded_at: datetime | None = None
    sabotage_reported_at: datetime | None = None


def _incident_fields(x: CmpIncident, body: IncidentIn) -> None:
    now = utcnow()
    times = {"detected_at": _utc(body.detected_at), "reported_csirt_at": _utc(body.reported_csirt_at),
             "reported_certin_at": _utc(body.reported_certin_at),
             "sabotage_concluded_at": _utc(body.sabotage_concluded_at),
             "sabotage_reported_at": _utc(body.sabotage_reported_at)}
    for v in times.values():
        if v is not None and v > now:
            raise ValueError("Times of things that have happened cannot be in the future.")
    for k in ("reported_csirt_at", "reported_certin_at"):
        if times[k] is not None and times[k] < times["detected_at"]:
            raise ValueError("A report cannot be sent before the incident was detected.")
    if times["sabotage_reported_at"] is not None and times["sabotage_concluded_at"] is None:
        raise ValueError("Record when the incident was concluded to be sabotage before recording its report.")
    if times["sabotage_concluded_at"] is not None and times["sabotage_concluded_at"] < times["detected_at"]:
        raise ValueError("Sabotage cannot be concluded before the incident was detected.")
    x.title, x.description, x.actions_taken = body.title.strip(), body.description.strip(), body.actions_taken.strip()
    x.asset_ids = list(dict.fromkeys(a.strip() for a in body.asset_ids if a.strip()))
    x.affects_critical_system = body.affects_critical_system
    for k, v in times.items():
        setattr(x, k, v)


def _incident_audit(x: CmpIncident) -> dict:
    return {"title": x.title, "detected_at": x.detected_at.isoformat(),
            "reported_csirt_at": x.reported_csirt_at.isoformat() if x.reported_csirt_at else None,
            "reported_certin_at": x.reported_certin_at.isoformat() if x.reported_certin_at else None,
            "sabotage_concluded_at": x.sabotage_concluded_at.isoformat() if x.sabotage_concluded_at else None,
            "sabotage_reported_at": x.sabotage_reported_at.isoformat() if x.sabotage_reported_at else None,
            "affects_critical_system": x.affects_critical_system}


@router.post("/entities/{eid}/incidents", status_code=201)
def add_incident(eid: int, body: IncidentIn, request: Request, p: Principal = Depends(ACT),
                 db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    x = CmpIncident(entity_id=e.id, ref="", created_by=p.user.id, title="", detected_at=utcnow())
    _incident_fields(x, body)
    db.add(x)
    db.flush()
    x.ref = cmp.incident_ref(x)
    _validate(db, e)
    audit(db, "compliance.incident_add", p.user, "cmp_incident", x.id, client_ip(request), entity=e.id,
          **_incident_audit(x))
    db.commit()
    return {"id": x.id, "ref": x.ref}


@router.put("/incidents/{xid}")
def update_incident(xid: int, body: IncidentIn, request: Request, p: Principal = Depends(ACT),
                    db: Session = Depends(get_db)):
    x = _get(db, CmpIncident, xid, "incident")
    before = _incident_audit(x)
    _incident_fields(x, body)
    x.updated_at = utcnow()
    _validate(db, db.get(CmpEntity, x.entity_id))
    audit(db, "compliance.incident_change", p.user, "cmp_incident", x.id, client_ip(request), entity=x.entity_id,
          before=before, after=_incident_audit(x))
    db.commit()
    return {"ok": True}


@router.delete("/incidents/{xid}")
def delete_incident(xid: int, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    x = _get(db, CmpIncident, xid, "incident")
    if x.reported_csirt_at or x.reported_certin_at or x.sabotage_reported_at:
        raise ValueError("A report has been recorded for this incident, so it stays on the record.")
    audit(db, "compliance.incident_delete", p.user, "cmp_incident", x.id, client_ip(request), entity=x.entity_id,
          **_incident_audit(x))
    db.execute(CmpEvidenceLink.__table__.delete().where(CmpEvidenceLink.owner_type.in_(("incident", "sabotage")),
                                                        CmpEvidenceLink.owner_id == x.id))
    db.delete(x)
    db.commit()
    return {"ok": True}


# ---------- assets ----------

class AssetIn(BaseModel):
    asset_id: str = Field(min_length=1, max_length=120)
    name: str = Field(default="", max_length=255)


class ClassIn(BaseModel):
    critical: bool | None  # None clears the classification


@router.post("/entities/{eid}/assets/import")
def import_assets(eid: int, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    added, existing = cmp.import_assets(db, e)
    _validate(db, e)
    audit(db, "compliance.assets_import", p.user, "cmp_entity", e.id, client_ip(request), site=e.site, added=added,
          already=existing)
    db.commit()
    return {"added": added, "already": existing}


@router.post("/entities/{eid}/assets", status_code=201)
def add_asset(eid: int, body: AssetIn, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    aid = body.asset_id.strip()
    if db.scalars(select(CmpAsset).where(CmpAsset.entity_id == e.id, CmpAsset.asset_id == aid)).first():
        raise ValueError(f"{aid} is already recorded for this entity.")
    x = CmpAsset(entity_id=e.id, asset_id=aid, name=body.name.strip())
    db.add(x)
    _validate(db, e)
    audit(db, "compliance.asset_add", p.user, "cmp_asset", x.id, client_ip(request), entity=e.id, asset_id=aid)
    db.commit()
    return {"id": x.id}


@router.put("/assets/{xid}")
def classify_asset(xid: int, body: ClassIn, request: Request, p: Principal = Depends(ACT),
                   db: Session = Depends(get_db)):
    x = _get(db, CmpAsset, xid, "asset")
    before = x.critical
    x.critical, x.classified_by, x.classified_at = body.critical, p.user.id, utcnow()
    _validate(db, db.get(CmpEntity, x.entity_id))
    audit(db, "compliance.asset_classify", p.user, "cmp_asset", x.id, client_ip(request), entity=x.entity_id,
          asset_id=x.asset_id, before=before, critical=x.critical)
    db.commit()
    return {"ok": True}


@router.delete("/assets/{xid}")
def delete_asset(xid: int, request: Request, p: Principal = Depends(ACT), db: Session = Depends(get_db)):
    x = _get(db, CmpAsset, xid, "asset")
    if db.scalars(select(CmpActivity).where(CmpActivity.entity_id == x.entity_id,
                                            CmpActivity.asset_id == x.asset_id)).first():
        raise ValueError("Activities are recorded for this asset, so it cannot be removed.")
    audit(db, "compliance.asset_delete", p.user, "cmp_asset", x.id, client_ip(request), entity=x.entity_id,
          asset_id=x.asset_id)
    db.delete(x)
    db.commit()
    return {"ok": True}


# ---------- audit pack ----------

def _pack_name(e: CmpEntity, ext: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in e.name)[:60].strip("-") or "entity"
    return f"audit-pack-{safe}-{cmp.today_local().isoformat()}.{ext}"


@router.get("/entities/{eid}/audit-pack.json")
def audit_pack_json(eid: int, request: Request, p: Principal = Depends(VIEW), db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    ap = cmp.Loaded(db, e).audit_pack()
    audit(db, "compliance.audit_pack_export", p.user, "cmp_entity", e.id, client_ip(request), format="json",
          digest=ap.digest)
    db.commit()
    return Response(ap.to_json(), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{_pack_name(e, "json")}"'})


@router.get("/entities/{eid}/audit-pack.zip")
def audit_pack_zip(eid: int, request: Request, p: Principal = Depends(VIEW), db: Session = Depends(get_db)):
    """The audit pack with every evidence file it references, for an auditor to keep."""
    e = _get(db, CmpEntity, eid, "entity")
    loaded = cmp.Loaded(db, e)
    ap = loaded.audit_pack()
    data = cmp.pack_zip(request.app.state.settings.workspace, ap, loaded.evidence)
    audit(db, "compliance.audit_pack_export", p.user, "cmp_entity", e.id, client_ip(request), format="zip",
          digest=ap.digest, files=len(loaded.evidence))
    db.commit()
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{_pack_name(e, "zip")}"'})


# ---------- evidence ----------

def _owner_entity(db: Session, owner_type: str, owner_id: int) -> int:
    """The entity an evidence link's owner belongs to."""
    if owner_type in ("audit_report", "audit_closure"):
        return _get(db, CmpAudit, owner_id, "audit").entity_id
    if owner_type == "finding":
        return _get(db, CmpFinding, owner_id, "finding").entity_id
    if owner_type == "control":
        c = _get(db, CmpControl, owner_id, "compensating control")
        return db.get(CmpFinding, c.finding_id).entity_id
    if owner_type == "activity":
        return _get(db, CmpActivity, owner_id, "activity record").entity_id
    if owner_type in ("incident", "sabotage"):
        return _get(db, CmpIncident, owner_id, "incident").entity_id
    raise ValueError(f"Evidence can be attached to: {', '.join(cmp.OWNER_TYPES)}.")


def _link(db: Session, p: Principal, request: Request, x: CmpEvidence, owner_type: str, owner_id: int) -> None:
    if _owner_entity(db, owner_type, owner_id) != x.entity_id:
        raise ValueError("That record belongs to another entity.")
    exists = db.scalars(select(CmpEvidenceLink).where(CmpEvidenceLink.evidence_id == x.id,
                                                      CmpEvidenceLink.owner_type == owner_type,
                                                      CmpEvidenceLink.owner_id == owner_id)).first()
    if exists:
        return
    db.add(CmpEvidenceLink(evidence_id=x.id, owner_type=owner_type, owner_id=owner_id, linked_by=p.user.id))
    audit(db, "compliance.evidence_link", p.user, "cmp_evidence", x.id, client_ip(request), entity=x.entity_id,
          owner_type=owner_type, owner_id=owner_id)


@router.post("/entities/{eid}/evidence", status_code=201)
async def upload_evidence(eid: int, request: Request, file: UploadFile, kind: str = Form(...),
                          title: str = Form(..., min_length=1, max_length=300), owner_type: str = Form(""),
                          owner_id: int | None = Form(None), p: Principal = Depends(ACT),
                          db: Session = Depends(get_db)):
    e = _get(db, CmpEntity, eid, "entity")
    if kind not in cmp.EVIDENCE_KINDS:
        raise ValueError(f"Choose what the file is: {', '.join(cmp.EVIDENCE_KINDS)}.")
    if owner_type and owner_id is None:
        raise ValueError("Say which record the file is evidence for.")
    workspace = request.app.state.settings.workspace
    limit = request.app.state.settings.max_upload_bytes
    tmp = cmp.evidence_root(workspace) / ".incoming"
    tmp.mkdir(parents=True, exist_ok=True)
    staged = tmp / secrets.token_hex(16)
    size = 0
    try:
        with staged.open("wb") as out:
            while chunk := await file.read(CHUNK):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"The file is larger than {limit // (1024 * 1024)} MB.")
                out.write(chunk)
        if size == 0:
            raise ValueError("The file is empty.")
        digest, size = cmp.store_evidence(workspace, staged)
    finally:
        staged.unlink(missing_ok=True)
    x = CmpEvidence(entity_id=e.id, kind=kind, title=title.strip(), filename=safe_name(file.filename or "evidence"),
                    content_type=(file.content_type or "application/octet-stream")[:100], size=size, sha256=digest,
                    captured_by=p.user.id)
    db.add(x)
    db.flush()
    audit(db, "compliance.evidence_upload", p.user, "cmp_evidence", x.id, client_ip(request), entity=e.id,
          kind=kind, title=x.title, filename=x.filename, size=size, sha256=digest)
    if owner_type:
        _link(db, p, request, x, owner_type, owner_id)
    db.commit()
    return cmp.evidence_json(x)


class LinkIn(BaseModel):
    owner_type: str = Field(max_length=16)
    owner_id: int


@router.post("/evidence/{xid}/links", status_code=201)
def link_evidence(xid: int, body: LinkIn, request: Request, p: Principal = Depends(ACT),
                  db: Session = Depends(get_db)):
    x = _get(db, CmpEvidence, xid, "evidence")
    _link(db, p, request, x, body.owner_type, body.owner_id)
    db.commit()
    return {"ok": True}


@router.delete("/evidence/{xid}/links")
def unlink_evidence(xid: int, owner_type: str, owner_id: int, request: Request, p: Principal = Depends(ACT),
                    db: Session = Depends(get_db)):
    x = _get(db, CmpEvidence, xid, "evidence")
    link = db.scalars(select(CmpEvidenceLink).where(CmpEvidenceLink.evidence_id == x.id,
                                                    CmpEvidenceLink.owner_type == owner_type,
                                                    CmpEvidenceLink.owner_id == owner_id)).first()
    if link is None:
        raise LookupError("That file is not attached there.")
    audit(db, "compliance.evidence_unlink", p.user, "cmp_evidence", x.id, client_ip(request), entity=x.entity_id,
          owner_type=owner_type, owner_id=owner_id)
    db.delete(link)
    db.commit()
    return {"ok": True}


@router.get("/evidence/{xid}/download")
def download_evidence(xid: int, request: Request, p: Principal = Depends(VIEW), db: Session = Depends(get_db)):
    x = _get(db, CmpEvidence, xid, "evidence")
    path = cmp.evidence_path(request.app.state.settings.workspace, x.sha256)
    if not path.exists():
        raise LookupError("The stored file is missing from the evidence store.")
    audit(db, "compliance.evidence_download", p.user, "cmp_evidence", x.id, client_ip(request), entity=x.entity_id,
          sha256=x.sha256)
    db.commit()
    media = x.content_type if x.content_type in SAFE_TYPES else "application/octet-stream"
    return FileResponse(path, media_type=media, filename=x.filename,
                        headers={"X-Evidence-SHA256": x.sha256})
