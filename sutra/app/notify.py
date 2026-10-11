"""Who hears about what, and the outbox that delivers it.

Job events queue rows in the ``outbox`` table in the same transaction as the change that caused them, so nothing is
announced that did not happen and nothing that happened is lost. A background dispatcher sends them and retries
failures with growing waits. Integrations that are not configured are marked "skipped", which the admin page shows.

Events and recipients:

- a step needs a decision: the person the ownership chart names for it (manager, vertical head), or everyone holding
  the role (VM analyst, CISO);
- approved, accepted, rejected or sent back: whoever raised the job;
- a step escalated: the person it was escalated to, plus the Teams channel;
- fix SLA missed: the team's manager, plus the Teams channel;
- fixed or reopened by a rescan, risk acceptance expired, and each OT plan record (OEM approval, control, shutdown
  slot, execution): whoever raised it and the team's manager;
- a job raised: a Jira issue in the team's project and a ServiceNow record, if those are configured. Later events
  are added to them as comments or work notes, and a proved fix moves the Jira issue to the configured status.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .integrations import NotConfigured, Senders
from .models import Job, Outbox, OwnershipTeam, User, UserRole, utcnow
from .security import audit

log = logging.getLogger("sutra.notify")
MAX_ATTEMPTS = 6
INTERVAL_SECONDS = 30
TEXT = {
    "step": ("Approval needed: {id} {title}", "{team} needs your decision as {role} on {id}: {title}."),
    "approved": ("Approved: {id} {title}", "{id} for {team} has every approval it needs."),
    "accepted": ("Risk accepted: {id} {title}", "The risk on {id} is accepted until {expires}."),
    "rejected": ("Rejected: {id} {title}", "{id} was rejected at the {role} step."),
    "sent-back": ("Sent back: {id} {title}", "{id} was sent back at the {role} step."),
    "escalated": ("Escalated to you: {id} {title}",
                  "The {role} step of {id} for {team} has waited longer than agreed. You cannot sign it; please "
                  "chase {who}."),
    "breached": ("Fix date missed: {id} {title}", "{id} for {team} was due by {due} and no rescan has proved it."),
    "fixed": ("Fixed: {id} {title}", "The scan of {as_of} no longer reports the findings of {id}. It is closed."),
    "reopened": ("Reopened: {id} {title}", "The scan of {as_of} reports the findings of {id} again. It is open."),
    "expired": ("Risk acceptance expired: {id} {title}",
                "The risk acceptance {id} for {team} ended on {expires}. Fix it or ask again."),
    "ot": ("OT plan: {id} {title}", "{what}"),
}


def _link(settings: Settings, job: Job) -> str:
    return f"{settings.base_url}/#/job/{job.id}" if settings.base_url else ""


def _holders(db: Session, role: str) -> list[str]:
    return sorted({u.email for u in db.scalars(select(User).join(UserRole).where(UserRole.role_key == role,
                                                                                 User.is_active.is_(True)))})


def _people(db: Session, job: Job, who: str) -> list[str]:
    chart = db.get(OwnershipTeam, job.team)
    if who == "raiser":
        u = db.get(User, job.raised_by)
        return [u.email] if u and u.is_active else []
    if who == "manager":
        return [chart.manager_email] if chart and chart.manager_email else []
    if who == "vertical_head":
        return [chart.vertical_head_email] if chart and chart.vertical_head_email else []
    return _holders(db, who)  # vm_analyst, ciso: anyone holding the role


def _add(db: Session, kind: str, job: Job, event: str, recipient: str = "", subject: str = "", body: str = ""):
    db.add(Outbox(kind=kind, job_id=job.id, event=event, recipient=recipient, subject=subject[:300], body=body))


def job_event(db: Session, job: Job, event: str, *, role: str = "", to: list[str] | None = None,
              teams: bool = False, **facts) -> None:
    """Queue the messages for one job event. The caller commits."""
    from .. import patch

    label = patch.ROLE_LABEL.get(role, role)
    values = {"id": f"J-{job.id:03d}", "title": job.rc_title, "team": job.team, "role": label,
              "expires": job.expires_on.isoformat() if job.expires_on else "", "due": job.due_on or "", **facts}
    subject, text = (str(t.format(**values)) for t in TEXT[event])
    for addr in sorted(set(to or [])):
        _add(db, "email", job, event, addr, subject, text)
    if teams:
        _add(db, "teams", job, event, "", subject, text)
    if event in ("step",):
        return  # tickets get decisions, not every request for one
    _add(db, "jira.comment", job, event, "", subject, text)
    _add(db, "servicenow.note", job, event, "", subject, text)
    if event == "fixed":
        _add(db, "jira.done", job, event, "", subject, text)


def step_opened(db: Session, job: Job) -> None:
    step = next((s for s in job.steps if s.state == "current"), None)
    if step is not None:
        job_event(db, job, "step", role=step.role, to=_people(db, job, step.role))


def job_raised(db: Session, job: Job) -> None:
    kind = {"patch": "Patch job", "manual": "Manual fix", "exception": "Risk acceptance"}[job.mode]
    desc = (f"{kind} raised in Sutra for {job.team}.\nRoot cause: {job.rc_title}\nSSVC: {job.ssvc}\n"
            f"Hosts: {len(job.hosts)}, findings: {len(job.targets)}\n"
            + (f"Fix due: {job.due_on.isoformat()}\n" if job.due_on else "")
            + "Sutra closes this only when a rescan shows the findings gone.")
    summary = f"[Sutra J-{job.id:03d}] {kind}: {job.rc_title}"
    _add(db, "jira.create", job, "raised", "", summary, desc)
    _add(db, "servicenow.create", job, "raised", "", summary, desc)


def decided(db: Session, job: Job, role: str) -> None:
    if job.status in ("approved", "accepted", "rejected", "sent-back"):
        job_event(db, job, job.status, role=role, to=_people(db, job, "raiser"))
    else:
        step_opened(db, job)


def escalated(db: Session, job: Job, step) -> None:
    who = step.expected_name or step.expected_email or ("the CISO" if step.role == "ciso" else "the VM analyst")
    job_event(db, job, "escalated", role=step.role, to=_people(db, job, step.escalated_to), teams=True,
              who=who)


def breached(db: Session, job: Job) -> None:
    job_event(db, job, "breached", to=_people(db, job, "manager"), teams=True)


def rescan(db: Session, job: Job, outcome: str, as_of) -> None:
    if outcome in ("fixed", "reopened"):
        job_event(db, job, outcome, to=_people(db, job, "raiser") + _people(db, job, "manager"),
                  as_of=as_of.isoformat() if as_of else "")


def ot(db: Session, job: Job, what: str) -> None:
    """A plant engineer recorded something on the job's OT plan."""
    job_event(db, job, "ot", to=_people(db, job, "raiser") + _people(db, job, "manager"), what=what)


def expired(db: Session, job: Job) -> None:
    job_event(db, job, "expired", to=_people(db, job, "raiser") + _people(db, job, "manager"))


# ---------- delivery ----------

def _deliver(db: Session, senders: Senders, row: Outbox) -> bool:
    """Send one row. Returns False if it must wait for another row (a comment before its ticket exists)."""
    job = db.get(Job, row.job_id) if row.job_id else None
    link = _link(senders.s, job) if job else ""
    body = row.body + (f"\n\nOpen in Sutra: {link}" if link else "")
    if row.kind == "email":
        senders.email(row.recipient, row.subject, body + "\n\nSent by Sutra.")
    elif row.kind == "teams":
        senders.teams(row.subject, row.body, link)
    elif row.kind == "jira.create":
        if job.jira_key:
            return True
        chart = db.get(OwnershipTeam, job.team)
        if not senders.s.jira_enabled:
            raise NotConfigured("Jira is not configured")
        if not chart or not chart.jira_project:
            raise NotConfigured(f"the ownership chart has no Jira project for {job.team}")
        job.jira_key = senders.jira_create(chart.jira_project, row.subject, body)
        audit(db, "job.jira_created", None, "job", job.id, issue=job.jira_key)
    elif row.kind in ("jira.comment", "jira.done"):
        if not senders.s.jira_enabled:
            raise NotConfigured("Jira is not configured")
        if not job.jira_key:
            return _wait_for(db, job, "jira.create")
        senders.jira_comment(job.jira_key, row.body)
        if row.kind == "jira.done" and senders.s.jira_done_status:
            if not senders.jira_transition(job.jira_key, senders.s.jira_done_status):
                row.last_error = f"no transition to {senders.s.jira_done_status!r}; commented only"
    elif row.kind == "servicenow.create":
        if job.servicenow_sys_id:
            return True
        job.servicenow_sys_id, job.servicenow_number = senders.servicenow_create(row.subject, body)
        audit(db, "job.servicenow_created", None, "job", job.id, number=job.servicenow_number)
    elif row.kind == "servicenow.note":
        if not senders.s.servicenow_enabled:
            raise NotConfigured("ServiceNow is not configured")
        if not job.servicenow_sys_id:
            return _wait_for(db, job, "servicenow.create")
        senders.servicenow_note(job.servicenow_sys_id, row.body)
    else:
        raise NotConfigured(f"unknown kind {row.kind}")
    return True


def _wait_for(db: Session, job: Job, kind: str) -> bool:
    """A comment waits while its ticket is still queued; if the ticket gave up or was skipped, so does it."""
    create = db.scalars(select(Outbox).where(Outbox.job_id == job.id, Outbox.kind == kind)).first()
    if create is None or create.status in ("failed", "skipped"):
        raise NotConfigured(f"no {kind.split('.')[0]} record exists for this job")
    return False


def dispatch(sessions: sessionmaker, senders: Senders, now: datetime | None = None, limit: int = 100) -> dict:
    now = now or utcnow()
    counts = {"sent": 0, "failed": 0, "skipped": 0, "retry": 0}
    with sessions() as db:
        rows = db.scalars(select(Outbox).where(Outbox.status == "queued", Outbox.next_attempt_at <= now)
                          .order_by(Outbox.id).limit(limit)).all()
        for row in rows:
            try:
                if not _deliver(db, senders, row):
                    row.next_attempt_at = now + timedelta(minutes=1)
                    continue
                row.status, row.sent_at = "sent", now
                counts["sent"] += 1
            except NotConfigured as e:
                row.status, row.last_error = "skipped", str(e)
                counts["skipped"] += 1
            except Exception as e:  # network, auth, a 4xx/5xx: retry, then give up
                row.attempts += 1
                row.last_error = f"{type(e).__name__}: {e}"[:2000]
                if row.attempts >= MAX_ATTEMPTS:
                    row.status = "failed"
                    counts["failed"] += 1
                    log.warning("outbox %s (%s) gave up: %s", row.id, row.kind, row.last_error)
                else:
                    row.next_attempt_at = now + timedelta(minutes=2 ** row.attempts)
                    counts["retry"] += 1
            db.commit()
    return counts


class Dispatcher:
    def __init__(self, sessions: sessionmaker, senders: Senders):
        self.sessions, self.senders = sessions, senders
        self._stop = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._loop, name="sutra-notify", daemon=True).start()

    def _loop(self) -> None:
        while not self._stop.wait(INTERVAL_SECONDS):
            try:
                dispatch(self.sessions, self.senders)
            except Exception:
                log.exception("dispatch failed")

    def stop(self) -> None:
        self._stop.set()
