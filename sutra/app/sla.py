"""Service levels for jobs: how long each approval step may wait, and how long a fix may take.

These are product defaults that each customer sets for itself under Administration; they are not regulatory
values. The CEA fix clock (one month for critical and high, three for medium and low) is computed separately from
the findings and is never relaxed by these settings.

- A step that waits longer than its limit is escalated once: the next approver in the chain is told it has stalled
  (the CISO, for the last step). Escalation never lets anyone sign a step that is not theirs.
- A fix that is not proved by a rescan before its due date is recorded as an SLA breach. The job stays open.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify
from .models import Job, Setting
from .security import audit

DEFAULT_SLA = {
    "step_hours": {"manager": 48, "vm_analyst": 48, "vertical_head": 72, "ciso": 72},
    "fix_days": {"Act": 14, "Attend": 30, "Track*": 90, "Track": 180},
}
FIX_OPEN = ("drafting", "pending", "approved", "fixing-manually", "reopened")
STEP_LIMITS = (1, 24 * 30)  # hours
FIX_LIMITS = (1, 730)  # days


def settings(db: Session) -> dict:
    s = db.get(Setting, "sla")
    value = dict(s.value) if s else {}
    return {k: {**DEFAULT_SLA[k], **value.get(k, {})} for k in DEFAULT_SLA}


def due_on(db: Session, ssvc: str, raised: date) -> date:
    return raised + timedelta(days=int(settings(db)["fix_days"].get(ssvc, DEFAULT_SLA["fix_days"]["Track"])))


def escalate_to(job: Job, position: int) -> str:
    """The next approver after this step, or the CISO for the last one."""
    later = [s.role for s in job.steps if s.position > position]
    return later[0] if later else "ciso"


def step_due(job: Job, step, cfg: dict) -> datetime:
    opened = step.opened_at or job.created_at
    return opened + timedelta(hours=int(cfg["step_hours"].get(step.role, 48)))


def escalate_stalled(db: Session, now: datetime) -> int:
    """Escalate each current step that has waited past its limit, once. The caller commits."""
    cfg = settings(db)
    n = 0
    for job in db.scalars(select(Job).where(Job.status == "pending")):
        step = next((s for s in job.steps if s.state == "current"), None)
        if step is None or step.escalated_at is not None or now <= step_due(job, step, cfg):
            continue
        step.escalated_at, step.escalated_to = now, escalate_to(job, step.position)
        audit(db, "job.step_escalated", None, "job", job.id, step=step.role, escalated_to=step.escalated_to,
              waited_hours=round((now - (step.opened_at or job.created_at)).total_seconds() / 3600, 1))
        notify.escalated(db, job, step)
        n += 1
    return n


def record_breaches(db: Session, now: datetime, today: date) -> int:
    """Mark open fixes past their due date as breached, once. The caller commits."""
    n = 0
    for job in db.scalars(select(Job).where(Job.mode != "exception", Job.status.in_(FIX_OPEN),
                                            Job.due_on < today, Job.sla_breached_at.is_(None))):
        job.sla_breached_at = now
        audit(db, "job.sla_breached", None, "job", job.id, due_on=job.due_on.isoformat())
        notify.breached(db, job)
        n += 1
    return n
