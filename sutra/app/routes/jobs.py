"""Patch jobs: list, raise, decide. The acting person always comes from the session."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import jobs as J
from ..access import Principal
from ..deps import client_ip, get_db, require
from ..models import AuditEvent, Job
from ..security import audit

router = APIRouter(prefix="/api/jobs")


class RaiseIn(BaseModel):
    rc_id: str = Field(max_length=16)
    team: str = Field(max_length=120)
    mode: Literal["patch", "manual"] = "patch"
    ticket: str = Field(default="", max_length=80)


class DecisionIn(BaseModel):
    action: Literal["approve", "reject", "sendback"]
    comment: str = Field(default="", max_length=500)


def _current(request: Request, db: Session) -> list[Job]:
    store = request.app.state.analysis
    if store.dataset_id is None:
        return []
    return list(db.scalars(select(Job).where(Job.dataset_id == store.dataset_id).order_by(Job.id.desc())))


def _get(request: Request, db: Session, p: Principal, pk: int) -> Job:
    job = db.get(Job, pk)
    if job is not None and not J.job_visible(p, job, request.app.state.analysis.result):
        audit(db, "job.access_denied", p.user, "job", job.id, client_ip(request), path=request.url.path)
        db.commit()
        job = None  # reported as missing, so a job outside the person's scope does not reveal itself
    if job is None:
        raise LookupError("No such job.")
    return job


@router.get("")
def list_jobs(request: Request, p: Principal = Depends(require("M-PJ", "view")), db: Session = Depends(get_db)):
    res = request.app.state.analysis.result
    jobs = [j for j in _current(request, db) if J.job_visible(p, j, res)]
    waiting = []
    if p.can("M-PJ", "approve"):
        for j in _current(request, db):
            cur = next((s for s in j.steps if s.state == "current"), None)
            if cur and J.can_sign(p, j, cur) is None:
                waiting.append(j)
    return {"jobs": [J.job_json(db, j, p) for j in jobs], "waiting_for_me": [J.job_json(db, j, p) for j in waiting]}


@router.get("/{pk}")
def get_job(pk: int, request: Request, p: Principal = Depends(require("M-PJ", "view")),
            db: Session = Depends(get_db)):
    job = _get(request, db, p, pk)
    out = J.job_json(db, job, p)
    events = db.scalars(select(AuditEvent).where(AuditEvent.target_type == "job", AuditEvent.target_id == str(job.id))
                        .order_by(AuditEvent.id))
    out["audit"] = [{"at": e.at.isoformat(timespec="seconds"), "actor": e.actor_email, "action": e.action,
                     "comment": (e.detail or {}).get("comment") or (e.detail or {}).get("reason") or ""}
                    for e in events]
    return out


@router.post("", status_code=201)
def raise_job(body: RaiseIn, request: Request, p: Principal = Depends(require("M-PJ", "act")),
              db: Session = Depends(get_db)):
    store = request.app.state.analysis
    if store.result is None:
        raise LookupError("No data has been imported yet.")
    job = J.raise_job(db, p, store.result, body.rc_id, body.team, body.mode, body.ticket.strip(), store.dataset_id,
                      client_ip(request))
    return J.job_json(db, job, p)


@router.post("/{pk}/decision")
def decide(pk: int, body: DecisionIn, request: Request, p: Principal = Depends(require("M-PJ", "approve")),
           db: Session = Depends(get_db)):
    job = _get(request, db, p, pk)
    J.decide(db, p, job, body.action, body.comment.strip(), client_ip(request))
    return J.job_json(db, job, p)
