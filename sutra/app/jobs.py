"""Patch jobs: raise, route, approve. Every rule here is enforced on the server."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import ingest, patch
from ..pipeline import Result
from . import drafting
from .access import Principal
from .drafting import DraftService
from .models import Job, JobStep, OwnershipTeam, Setting, User, utcnow
from .security import audit

PJ = "M-PJ"
OPEN = ("drafting", "pending", "approved", "fixing-manually", "reopened")  # a fix in progress
EXCEPTION_OPEN = ("pending", "accepted")  # a risk-acceptance request or one in force


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
              dataset_id: int, ip: str, drafts: DraftService | None = None, *, justification: str = "",
              control: str = "", expires_on: date | None = None) -> Job:
    """mode: patch (drafted job, routed for approval), manual (the team fixes it by hand under a change ticket) or
    exception (accept the risk until ``expires_on``, routed for approval)."""
    if not p.team_allowed(team, PJ, "act"):
        raise Forbidden("You can raise jobs only for your own team.")
    rc = next((r for r in res.root_causes if r.rc_id == rc_id), None)
    if rc is None:
        raise LookupError("Unknown root cause.")
    hosts = [res.assets[a] for a in rc.asset_ids if patch.team_of(res.assets[a]) == team]
    if not hosts:
        raise Conflict(f"{team} owns no hosts in {rc_id}.")
    if mode == "exception":
        if len(justification.strip()) < 20:
            raise ValueError("Explain why the risk should be accepted (at least 20 characters).")
        if not control.strip():
            raise ValueError("Name the compensating control that stays in place until the exception expires.")
        today = drafting.today()
        if expires_on is None or not today < expires_on <= today + timedelta(days=patch.MAX_EXCEPTION_DAYS):
            raise ValueError(f"The exception must expire after today and within {patch.MAX_EXCEPTION_DAYS} days.")
    # One open job per team per root cause, across imports (root-cause IDs are renumbered each import; keys are not).
    # A risk acceptance is tracked separately: a team may still fix what it has accepted for now.
    is_exc = Job.mode == "exception"
    clash = (is_exc & Job.status.in_(EXCEPTION_OPEN)) if mode == "exception" else (~is_exc & Job.status.in_(OPEN))
    existing = db.scalars(select(Job).where(Job.rc_key == rc.key, Job.team == team, clash)).first()
    if existing:
        what = "a risk acceptance" if mode == "exception" else "job"
        raise Conflict(f"{team} already has {what} J-{existing.id:03d} open for {rc_id}.")
    chart = db.get(OwnershipTeam, team)
    findings = {f.finding_id: f for f in res.findings}
    mine = [findings[f] for f in rc.finding_ids if patch.team_of(res.assets[findings[f].asset_id]) == team]
    job = Job(dataset_id=dataset_id, rc_id=rc.rc_id, rc_key=rc.key, rc_title=rc.title, team=team,
              vertical=chart.vertical if chart else "", mode=mode, ssvc=rc.ssvc, is_ot=rc.is_ot,
              ticket=ticket, hosts=[h.asset_id for h in hosts], findings=[f.finding_id for f in mine],
              targets=sorted({(f.asset_id, ingest.fingerprint(f)[:400]) for f in mine}),
              raised_by=p.user.id)
    if mode == "manual":
        job.status = "fixing-manually"
    elif mode == "exception":
        if chart is None:
            raise Conflict(f"{team} is not in the ownership chart, so nobody can approve its requests.")
        r = patch.exception_route(rc)
        who = _approvers(chart)
        missing = [patch.ROLE_LABEL[s] for s in r["steps"] if s in ("manager", "vertical_head") and not who[s][0]]
        if missing:
            raise Conflict(f"The ownership chart has no {', '.join(missing).lower()} for {team}.")
        job.status, job.route = "pending", r
        job.justification, job.compensating_control, job.expires_on = justification.strip(), control.strip(), expires_on
        job.steps = [JobStep(position=i, role=s, expected_email=who[s][0], expected_name=who[s][1],
                             state="current" if i == 0 else "waiting") for i, s in enumerate(r["steps"])]
    else:
        if chart is None:
            raise Conflict(f"{team} is not in the ownership chart, so nobody can approve its jobs. "
                           "Ask an admin to upload the chart.")
        r = patch.route(rc, hosts, approval_rules(db))
        who = _approvers(chart)
        missing = [patch.ROLE_LABEL[s] for s in r["steps"] if s != "vm_analyst" and not who[s][0]]
        if missing:
            raise Conflict(f"The ownership chart has no {', '.join(missing).lower()} for {team}.")
        inp = drafting.build_input(db, rc, hosts, mine)
        job.status, job.route = "drafting", r
        job.steps = [JobStep(position=i, role=s, expected_email=who[s][0], expected_name=who[s][1],
                             state="waiting") for i, s in enumerate(r["steps"])]
    db.add(job)
    db.flush()
    job.jira_key = f"{(chart.jira_project if chart and chart.jira_project else 'SEC')}-{job.id}"
    event = {"patch": "job.raise", "manual": "job.manual", "exception": "job.exception_request"}[mode]
    audit(db, event, p.user, "job", job.id, ip, rc=rc_id, team=team,
          route=job.route["reason"] if job.route else None, ticket=ticket or None,
          expires_on=expires_on.isoformat() if mode == "exception" else None)
    drafts = drafts or drafting.DraftService(drafter=drafting.template_only())
    if job.status == "drafting" and not drafts.background:
        drafting.apply_draft(db, job, drafts.draft_now(inp))
    db.commit()
    if job.status == "drafting":  # the first approval step opens when the draft is written
        drafts.submit(job.id, inp)
    return job


def _approvers(chart: OwnershipTeam) -> dict[str, tuple[str, str]]:
    """Expected signer per step. The VM analyst and CISO steps can be signed by anyone holding that role."""
    return {"manager": (chart.manager_email, chart.manager_name),
            "vm_analyst": (chart.vm_analyst_email, chart.vm_analyst_name),
            "vertical_head": (chart.vertical_head_email, chart.vertical_head_name),
            "ciso": ("", "")}


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
    elif step.role == "ciso":
        if "ciso" not in p.role_keys or not p.is_org_wide(PJ, "approve"):
            return "Only the CISO can give the final sign-off on accepting this risk."
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
            job.status = "accepted" if job.mode == "exception" else "approved"
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
        "fixed_on": job.fixed_on.isoformat() if job.fixed_on else None,
        "closed_at": job.closed_at.isoformat(timespec="seconds") if job.closed_at else None,
        "targets": len(job.targets),
        "exception": {"justification": job.justification, "control": job.compensating_control,
                      "expires_on": job.expires_on.isoformat() if job.expires_on else None}
        if job.mode == "exception" else None,
    }
