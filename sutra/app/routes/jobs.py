"""Patch jobs: list, raise, decide. The acting person always comes from the session."""

from __future__ import annotations

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import closure, otplans
from .. import compliance as cmp
from .. import jobs as J
from ..access import Principal
from ..deps import client_ip, get_db, require, require_any
from ..models import AuditEvent, Job, utcnow
from ..security import audit

router = APIRouter(prefix="/api/jobs")


class RaiseIn(BaseModel):
    rc_id: str = Field(max_length=16)
    team: str = Field(max_length=120)
    mode: Literal["patch", "manual", "exception"] = "patch"
    ticket: str = Field(default="", max_length=80)
    # Risk acceptance (mode "exception") only.
    justification: str = Field(default="", max_length=2000)
    control: str = Field(default="", max_length=1000)
    expires_on: date | None = None


class DecisionIn(BaseModel):
    action: Literal["approve", "reject", "sendback"]
    comment: str = Field(default="", max_length=500)


def _all(db: Session) -> list[Job]:
    """Jobs from every import: a job stays open until it is closed, whatever has been imported since."""
    return list(db.scalars(select(Job).order_by(Job.id.desc())))


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
    jobs = [j for j in _all(db) if J.job_visible(p, j, res)]
    waiting = []
    if p.can("M-PJ", "approve"):
        for j in _all(db):
            cur = next((s for s in j.steps if s.state == "current"), None)
            if cur and J.can_sign(p, j, cur) is None:
                waiting.append(j)
    return {"jobs": [J.job_json(db, j, p, res) for j in jobs],
            "waiting_for_me": [J.job_json(db, j, p, res) for j in waiting],
            "escalated_to_me": [J.job_json(db, j, p, res) for j in jobs if J.escalated_to_me(p, j)]}


@router.get("/{pk}")
def get_job(pk: int, request: Request, p: Principal = Depends(require("M-PJ", "view")),
            db: Session = Depends(get_db)):
    job = _get(request, db, p, pk)
    out = J.job_json(db, job, p, request.app.state.analysis.result)
    out["checks"] = closure.checks_json(db, job)
    plan = otplans.plan_for(db, job, request.app.state.analysis.result)
    out["ot_plan"] = otplans.plan_json(db, plan, job, p) if plan else None
    out["second_schedule"] = cmp.second_schedule(db, job)
    db.commit()
    s = request.app.state.settings
    out["jira_url"] = f"{s.jira_url}/browse/{job.jira_key}" if job.jira_key and s.jira_url else None
    out["servicenow_url"] = (f"{s.servicenow_url}/{s.servicenow_table}.do?sys_id={job.servicenow_sys_id}"
                             if job.servicenow_sys_id and s.servicenow_url else None)
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
                      client_ip(request), request.app.state.drafts, justification=body.justification,
                      control=body.control, expires_on=body.expires_on)
    return J.job_json(db, job, p, store.result)


@router.post("/{pk}/decision")
def decide(pk: int, body: DecisionIn, request: Request, p: Principal = Depends(require("M-PJ", "approve")),
           db: Session = Depends(get_db)):
    job = _get(request, db, p, pk)
    if body.action == "approve" and job.status == "pending" and \
            sum(1 for s in job.steps if s.state in ("current", "waiting")) == 1 and \
            cmp.second_schedule(db, job)["blocks_final_approval"]:
        raise J.Conflict("This change needs a cyber security audit before deployment (CEA Second Schedule). Record "
                         "the pre-deployment audit on the job, then approve.")
    J.decide(db, p, job, body.action, body.comment.strip(), client_ip(request))
    return J.job_json(db, job, p, request.app.state.analysis.result)


CHANGE_EDITORS = require_any(("M-PJ", "act"), ("M-PJ", "approve"))


class CategoriesIn(BaseModel):
    categories: list[str] = Field(default_factory=list, max_length=20)


@router.put("/{pk}/change-categories")
def set_change_categories(pk: int, body: CategoriesIn, request: Request, p: Principal = Depends(CHANGE_EDITORS),
                          db: Session = Depends(get_db)):
    """What kind of change the fix is, for the CEA Second Schedule. Sutra adds the critical-fix category itself."""
    job = _get(request, db, p, pk)
    if job.status not in J.OPEN:
        raise J.Conflict("This job is closed.")
    before = list(job.change_categories or [])
    job.change_categories = cmp.check_categories(body.categories)
    audit(db, "job.change_categories", p.user, "job", job.id, client_ip(request), before=before,
          after=job.change_categories)
    db.commit()
    return cmp.second_schedule(db, job)


class PreAuditIn(BaseModel):
    reference: str = Field(min_length=1, max_length=120)
    audited_on: date
    auditor: str = Field(min_length=1, max_length=200)


@router.post("/{pk}/pre-deployment-audit")
def record_pre_audit(pk: int, body: PreAuditIn, request: Request, p: Principal = Depends(CHANGE_EDITORS),
                     db: Session = Depends(get_db)):
    job = _get(request, db, p, pk)
    if not cmp.second_schedule(db, job)["needs_pre_deployment_audit"]:
        raise ValueError("This change does not need a pre-deployment audit under the Second Schedule.")
    cmp.check_past(body.audited_on, "The audit date")
    job.pre_audit = {"reference": body.reference.strip(), "audited_on": body.audited_on.isoformat(),
                     "auditor": body.auditor.strip(), "by": p.user.display_name,
                     "at": utcnow().isoformat(timespec="seconds")}
    audit(db, "job.pre_deployment_audit", p.user, "job", job.id, client_ip(request), **job.pre_audit)
    db.commit()
    return cmp.second_schedule(db, job)
