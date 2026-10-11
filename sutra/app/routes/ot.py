"""OT plans (M-OT): the plant engineer's list, and the records they keep on each plan."""

from __future__ import annotations

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import closure, otplans
from .. import jobs as J
from ..access import Principal
from ..deps import client_ip, get_db, require
from ..models import AuditEvent, Job
from ..security import audit

router = APIRouter(prefix="/api/ot")


class OemIn(BaseModel):
    state: Literal["requested", "approved", "refused"]
    on: date
    reference: str = Field(default="", max_length=120)
    note: str = Field(default="", max_length=1000)


class ControlIn(BaseModel):
    control: str = Field(max_length=1000)
    on: date


class SlotIn(BaseModel):
    on: date
    start: str = Field(max_length=5)
    hours: int
    confirmed_with: str = Field(max_length=120)


class ExecutionIn(BaseModel):
    on: date
    result: Literal["applied", "partly-applied", "rolled-back", "not-applied"]
    hosts: list[str] = Field(default_factory=list, max_length=5000)
    note: str = Field(default="", max_length=2000)


def _plans(request: Request, db: Session, p: Principal):
    res = request.app.state.analysis.result
    out = []
    for job in db.scalars(select(Job).where(Job.is_ot.is_(True), Job.mode != "exception").order_by(Job.id.desc())):
        plan = otplans.plan_for(db, job, res)
        if otplans.visible(p, plan, job):
            out.append((plan, job))
    db.commit()  # plans created for jobs raised before this module existed
    return out


def _get(request: Request, db: Session, p: Principal, pk: int):
    job = db.get(Job, pk)
    plan = otplans.plan_for(db, job, request.app.state.analysis.result) if job else None
    if plan is not None and not otplans.visible(p, plan, job):
        audit(db, "ot.access_denied", p.user, "job", job.id, client_ip(request), path=request.url.path)
        db.commit()
        plan = None  # reported as missing, so a plan at another plant does not reveal itself
    if plan is None:
        raise LookupError("No such OT plan.")
    db.commit()
    return plan, job


def _summary(db: Session, plan, job: Job) -> dict:
    return {"pk": job.id, "id": f"J-{job.id:03d}", "rc_title": job.rc_title, "team": job.team, "ssvc": job.ssvc,
            "status": job.status, "mode": job.mode, "hosts": len(job.hosts), "sites": plan.sites,
            "due_on": job.due_on.isoformat() if job.due_on else None, "sla_breached": job.sla_breached_at is not None,
            "stage": otplans.stage(db, plan, job), "slot_on": plan.slot_on.isoformat() if plan.slot_on else None,
            "oem": plan.oem_state}


@router.get("")
def list_plans(request: Request, p: Principal = Depends(require("M-OT", "view")), db: Session = Depends(get_db)):
    return {"plans": [_summary(db, plan, job) for plan, job in _plans(request, db, p)], "stages": otplans.STAGES}


def _detail(request: Request, db: Session, p: Principal, plan, job: Job) -> dict:
    out = J.job_json(db, job, None, request.app.state.analysis.result)
    out.pop("can_decide"), out.pop("waiting_reason")
    out["checks"] = closure.checks_json(db, job)
    out["plan"] = otplans.plan_json(db, plan, job, p)
    events = db.scalars(select(AuditEvent).where(AuditEvent.target_type == "job", AuditEvent.target_id == str(job.id))
                        .order_by(AuditEvent.id))
    out["audit"] = [{"at": e.at.isoformat(timespec="seconds"), "actor": e.actor_email, "action": e.action,
                     "comment": (e.detail or {}).get("comment") or (e.detail or {}).get("reason") or ""}
                    for e in events]
    return out


@router.get("/{pk}")
def get_plan(pk: int, request: Request, p: Principal = Depends(require("M-OT", "view")),
             db: Session = Depends(get_db)):
    plan, job = _get(request, db, p, pk)
    return _detail(request, db, p, plan, job)


@router.post("/{pk}/oem")
def oem(pk: int, body: OemIn, request: Request, p: Principal = Depends(require("M-OT", "act")),
        db: Session = Depends(get_db)):
    plan, job = _get(request, db, p, pk)
    otplans.record_oem(db, p, plan, job, body.state, body.on, body.reference, body.note, client_ip(request))
    return _detail(request, db, p, plan, job)


@router.post("/{pk}/control")
def control(pk: int, body: ControlIn, request: Request, p: Principal = Depends(require("M-OT", "act")),
            db: Session = Depends(get_db)):
    plan, job = _get(request, db, p, pk)
    otplans.record_control(db, p, plan, job, body.control, body.on, client_ip(request))
    return _detail(request, db, p, plan, job)


@router.post("/{pk}/slot")
def slot(pk: int, body: SlotIn, request: Request, p: Principal = Depends(require("M-OT", "act")),
         db: Session = Depends(get_db)):
    plan, job = _get(request, db, p, pk)
    otplans.confirm_slot(db, p, plan, job, body.on, body.start, body.hours, body.confirmed_with, client_ip(request))
    return _detail(request, db, p, plan, job)


@router.post("/{pk}/execution")
def execution(pk: int, body: ExecutionIn, request: Request, p: Principal = Depends(require("M-OT", "act")),
              db: Session = Depends(get_db)):
    plan, job = _get(request, db, p, pk)
    otplans.record_execution(db, p, plan, job, body.on, body.result, body.hosts, body.note, client_ip(request))
    return _detail(request, db, p, plan, job)
