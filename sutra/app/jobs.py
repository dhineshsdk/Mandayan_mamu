"""Patch jobs: raise, route, approve. Every rule here is enforced on the server."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import patch
from ..pipeline import Result
from .access import Principal
from .models import Job, JobStep, OwnershipTeam, Setting, User, utcnow
from .security import audit

PJ = "M-PJ"
OPEN = ("pending", "approved", "fixing-manually")


class Forbidden(Exception):
    """The person is signed in but may not do this."""


class Conflict(Exception):
    """The request clashes with the job's current state."""


def approval_rules(db: Session) -> dict:
    s = db.get(Setting, "approval_rules")
    return dict(s.value) if s else {}


def job_visible(p: Principal, job: Job, res: Result | None) -> bool:
    if p.is_org_wide(PJ):
        return True
    if p.team_allowed(job.team, PJ, "view"):
        return True
    if res is not None:  # a site-scoped viewer sees jobs on hosts at their site
        return any(h in res.assets and p.asset_allowed(res.assets[h], PJ) for h in job.hosts)
    return False


def raise_job(db: Session, p: Principal, res: Result, rc_id: str, team: str, mode: str, ticket: str,
              dataset_id: int, ip: str) -> Job:
    if not p.team_allowed(team, PJ, "act"):
        raise Forbidden("You can raise jobs only for your own team.")
    rc = next((r for r in res.root_causes if r.rc_id == rc_id), None)
    if rc is None:
        raise LookupError("Unknown root cause.")
    hosts = [res.assets[a] for a in rc.asset_ids if patch.team_of(res.assets[a]) == team]
    if not hosts:
        raise Conflict(f"{team} owns no hosts in {rc_id}.")
    # One open job per team per root cause, across imports (root-cause IDs are renumbered each import; keys are not).
    existing = db.scalars(select(Job).where(Job.rc_key == rc.key, Job.team == team, Job.status.in_(OPEN))).first()
    if existing:
        raise Conflict(f"{team} already has job J-{existing.id:03d} open for {rc_id}.")
    chart = db.get(OwnershipTeam, team)
    findings = {f.finding_id: f for f in res.findings}
    mine = [findings[f] for f in rc.finding_ids if patch.team_of(res.assets[findings[f].asset_id]) == team]
    job = Job(dataset_id=dataset_id, rc_id=rc.rc_id, rc_key=rc.key, rc_title=rc.title, team=team,
              vertical=chart.vertical if chart else "", mode=mode, ssvc=rc.ssvc, is_ot=rc.is_ot,
              ticket=ticket, hosts=[h.asset_id for h in hosts], findings=[f.finding_id for f in mine],
              raised_by=p.user.id)
    if mode == "manual":
        job.status = "fixing-manually"
    else:
        if chart is None:
            raise Conflict(f"{team} is not in the ownership chart, so nobody can approve its jobs. "
                           "Ask an admin to upload the chart.")
        r = patch.route(rc, hosts, approval_rules(db))
        who = {"manager": (chart.manager_email, chart.manager_name),
               "vm_analyst": (chart.vm_analyst_email, chart.vm_analyst_name),
               "vertical_head": (chart.vertical_head_email, chart.vertical_head_name)}
        missing = [patch.ROLE_LABEL[s] for s in r["steps"] if s != "vm_analyst" and not who[s][0]]
        if missing:
            raise Conflict(f"The ownership chart has no {', '.join(missing).lower()} for {team}.")
        job.status, job.route = "pending", r
        job.draft = patch.draft_job(rc, hosts, mine, res.as_of)
        job.steps = [JobStep(position=i, role=s, expected_email=who[s][0], expected_name=who[s][1],
                             state="current" if i == 0 else "waiting") for i, s in enumerate(r["steps"])]
    db.add(job)
    db.flush()
    job.jira_key = f"{(chart.jira_project if chart and chart.jira_project else 'SEC')}-{job.id}"
    audit(db, "job.raise" if mode == "patch" else "job.manual", p.user, "job", job.id, ip, rc=rc_id, team=team,
          route=job.route["reason"] if job.route else None, ticket=ticket or None)
    db.commit()
    return job


def can_sign(p: Principal, job: Job, step: JobStep) -> str | None:
    """None if this person may sign this step now, otherwise the reason they may not."""
    if job.status != "pending" or step.state != "current":
        return "This step is not waiting for a decision."
    if job.raised_by == p.user.id:
        return "You raised this job, so you cannot approve any step of it."
    if any(s.decided_by == p.user.id for s in job.steps if s.id != step.id):
        return "You already signed another step of this job."
    if not p.can(PJ, "approve"):
        return "Your role does not approve patch jobs."
    email = p.user.email.lower()
    if step.role == "manager":
        if "team_manager" not in p.role_keys or not p.team_allowed(job.team, PJ, "approve"):
            return f"Only the manager of {job.team} can sign this step."
        if email != step.expected_email.lower():
            return f"The ownership chart names {step.expected_name or step.expected_email} as manager of {job.team}."
    elif step.role == "vm_analyst":
        if "vm_analyst" not in p.role_keys or not p.is_org_wide(PJ, "approve"):
            return "Only a VM analyst can sign this step."
    elif step.role == "vertical_head":
        if "vertical_head" not in p.role_keys or not p.team_allowed(job.team, PJ, "approve"):
            return f"Only the head of {job.vertical or 'this vertical'} can sign this step."
        if email != step.expected_email.lower():
            return f"The ownership chart names {step.expected_name or step.expected_email} as head of {job.vertical}."
    else:
        return "Unknown step."
    return None


def decide(db: Session, p: Principal, job: Job, action: str, comment: str, ip: str) -> Job:
    if action not in ("approve", "reject", "sendback"):
        raise ValueError("Action must be approve, reject or sendback.")
    step = next((s for s in job.steps if s.state == "current"), None)
    if step is None or job.status != "pending":
        raise Conflict("This job is not waiting for an approval.")
    why = can_sign(p, job, step)
    if why:
        audit(db, "job.decision_denied", p.user, "job", job.id, ip, step=step.role, reason=why)
        db.commit()
        raise Forbidden(why)
    step.decided_by, step.decided_at, step.comment = p.user.id, utcnow(), comment
    if action == "approve":
        step.state = "approved"
        nxt = next((s for s in job.steps if s.state == "waiting"), None)
        if nxt:
            nxt.state = "current"
        else:
            job.status = "approved"
    elif action == "reject":
        step.state, job.status = "rejected", "rejected"
    else:
        step.state, job.status = "sent-back", "sent-back"
    emergency = bool(action == "approve" and job.route and job.route.get("emergency") and
                     step.role == "vertical_head")
    audit(db, f"job.{action}", p.user, "job", job.id, ip, step=step.role, comment=comment or None,
          emergency=emergency or None)
    db.commit()
    return job


def job_json(db: Session, job: Job, p: Principal | None = None, res: Result | None = None) -> dict:
    """``res`` (the current analysis) maps the job's root cause to its ID in the latest import, if still there."""
    users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(
        {job.raised_by} | {s.decided_by for s in job.steps if s.decided_by})))}
    cur = next((s for s in job.steps if s.state == "current"), None)
    return {
        "id": f"J-{job.id:03d}", "pk": job.id, "rc_id": job.rc_id, "rc_title": job.rc_title, "team": job.team,
        "vertical": job.vertical, "mode": job.mode, "status": job.status, "ssvc": job.ssvc, "is_ot": job.is_ot,
        "jira": job.jira_key, "ticket": job.ticket, "hosts": job.hosts, "findings": job.findings,
        "route": job.route, "draft": job.draft, "created": job.created_at.isoformat(timespec="seconds"),
        "raised_by": users[job.raised_by].display_name if job.raised_by in users else "",
        "steps": [{"role": s.role, "label": patch.ROLE_LABEL[s.role], "who": s.expected_name or s.expected_email,
                   "state": s.state, "comment": s.comment,
                   "decided_by": users[s.decided_by].display_name if s.decided_by in users else None,
                   "at": s.decided_at.isoformat(timespec="seconds") if s.decided_at else None} for s in job.steps],
        "rc_current_id": next((r.rc_id for r in res.root_causes if r.key == job.rc_key), None) if res else None,
        "can_decide": bool(p and cur and can_sign(p, job, cur) is None),
        "waiting_reason": (can_sign(p, job, cur) if p and cur else None),
    }
