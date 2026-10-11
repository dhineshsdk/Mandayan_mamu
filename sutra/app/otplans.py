"""OT plans: the plant engineer's side of a fix on OT assets.

An OT job is approved like any other (manager, VM analyst, vertical head), but nothing is pushed to a controller.
A plant engineer carries the staged plan out by hand, and records here what happened at each stage:

- OEM approval: requested, then approved or refused, with the OEM's own reference;
- the compensating control held until the shutdown;
- the shutdown slot, confirmed with operations;
- each attempt to apply the fix, with its result.

Recording an execution never closes the job: as for IT jobs, only a rescan that no longer reports the findings does
(``sutra.app.closure``). Execution can be recorded only once the job is approved, the OEM has approved the change
and a shutdown slot is confirmed.

Who may act: a plant engineer whose M-OT "act" scope covers every plant the job's OT hosts are at. One plant's
engineer cannot confirm another plant's shutdown.
"""

from __future__ import annotations

import re
from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..pipeline import Result
from . import drafting, jobs, notify
from .access import Principal
from .jobs import Conflict, Forbidden
from .models import AssetSnapshot, Job, JobCheck, OtPlan, User, utcnow
from .security import audit

OT = "M-OT"
OEM_STATES = {"requested": "Requested", "approved": "Approved", "refused": "Refused"}
RESULTS = {"applied": "Applied on the hosts listed", "partly-applied": "Partly applied",
           "rolled-back": "Applied, then rolled back", "not-applied": "Not applied"}
STAGES = {
    "approvals": "Waiting for approvals",
    "oem": "Needs OEM approval",
    "oem-refused": "OEM refused the change",
    "slot": "Needs a shutdown slot",
    "ready": "Ready for the shutdown",
    "executed": "Carried out; waiting for a rescan",
    "fixed": "Fixed (proved by rescan)",
    "closed": "Closed without a fix",
}
CLOCK = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def applies_to(job: Job) -> bool:
    return job.is_ot and job.mode != "exception"


def _sites(db: Session, job: Job, res: Result | None) -> list[str]:
    """Plants of the job's OT hosts, as they stood in the import the job was raised from."""
    rows = db.execute(select(AssetSnapshot.site, AssetSnapshot.is_ot)
                      .where(AssetSnapshot.dataset_id == job.dataset_id, AssetSnapshot.asset_id.in_(job.hosts))).all()
    if rows:
        ot = {s for s, is_ot in rows if is_ot and s}
        return sorted(ot or {s for s, _ in rows if s})
    if res is not None:  # imports from before snapshots were kept
        assets = [res.assets[h] for h in job.hosts if h in res.assets]
        return sorted({a.site for a in assets if a.is_ot and a.site} or {a.site for a in assets if a.site})
    return []


def plan_for(db: Session, job: Job, res: Result | None = None) -> OtPlan | None:
    """The job's plan, created on first use (jobs raised before this module existed get one too)."""
    if not applies_to(job):
        return None
    plan = db.scalars(select(OtPlan).where(OtPlan.job_id == job.id)).first()
    if plan is None:
        plan = OtPlan(job_id=job.id, sites=_sites(db, job, res), executions=[])
        db.add(plan)
        db.flush()
    return plan


def visible(p: Principal, plan: OtPlan, job: Job) -> bool:
    return any(p.allowed(OT, "view", job.team, s) for s in plan.sites)


def _outside_scope(p: Principal, plan: OtPlan, job: Job) -> str | None:
    if not plan.sites:
        return "The job's hosts have no plant recorded, so no plant engineer is responsible for it."
    if not all(p.allowed(OT, "act", job.team, s) for s in plan.sites):
        return f"Only a plant engineer for {', '.join(plan.sites)} can record on this plan."
    return None


def may_act(p: Principal, plan: OtPlan, job: Job) -> str | None:
    """None if this person may record on the plan now, otherwise why not."""
    why = _outside_scope(p, plan, job)
    if why is None and job.status not in jobs.OPEN:
        why = "The job is closed."
    return why


def _reopened_at(db: Session, job: Job):
    return db.scalars(select(JobCheck.checked_at).where(JobCheck.job_id == job.id, JobCheck.outcome == "reopened")
                      .order_by(JobCheck.checked_at.desc())).first()


def stage(db: Session, plan: OtPlan, job: Job) -> str:
    if job.status == "verified-fixed":
        return "fixed"
    if job.status not in jobs.OPEN:
        return "closed"
    if job.status in ("drafting", "pending"):
        return "approvals"
    if plan.oem_state == "refused":
        return "oem-refused"
    if plan.oem_state != "approved":
        return "oem"
    done = [e for e in plan.executions if e["result"] in ("applied", "partly-applied")]
    if done:
        reopened = _reopened_at(db, job)
        if reopened is None or done[-1]["at"] > reopened.isoformat(timespec="seconds"):
            return "executed"
    return "slot" if plan.slot_on is None else "ready"


def _check(db: Session, p: Principal, plan: OtPlan, job: Job, ip: str) -> None:
    why = _outside_scope(p, plan, job)
    if why:
        audit(db, "ot.denied", p.user, "job", job.id, ip, reason=why)
        db.commit()
        raise Forbidden(why)
    if job.status not in jobs.OPEN:
        raise Conflict("The job is closed.")


def _past(on: date, what: str) -> None:
    if on > drafting.today():
        raise ValueError(f"The {what} date cannot be in the future.")


def _done(db: Session, p: Principal, plan: OtPlan, job: Job, ip: str, action: str, what: str, **detail) -> None:
    plan.updated_at = utcnow()
    audit(db, action, p.user, "job", job.id, ip, **detail)
    notify.ot(db, job, what)
    db.commit()


def record_oem(db: Session, p: Principal, plan: OtPlan, job: Job, state: str, on: date, reference: str, note: str,
               ip: str) -> None:
    _check(db, p, plan, job, ip)
    if state not in OEM_STATES:
        raise ValueError("State must be requested, approved or refused.")
    _past(on, "OEM")
    reference, note = reference.strip(), note.strip()
    if state == "approved" and not (reference or plan.oem_reference):
        raise ValueError("Give the OEM's reference for the approval (their case number or letter).")
    if state == "refused" and not note:
        raise ValueError("Say what the OEM said when refusing.")
    if state == "requested":
        plan.oem_requested_on, plan.oem_decided_on = on, None
    else:
        if plan.oem_requested_on and on < plan.oem_requested_on:
            raise ValueError("The OEM cannot have decided before it was asked.")
        plan.oem_decided_on = on
    plan.oem_state, plan.oem_note = state, note
    plan.oem_reference = reference or plan.oem_reference
    label = OEM_STATES[state].lower()
    _done(db, p, plan, job, ip, "ot.oem_" + state, f"OEM approval {label} on {on.isoformat()}"
          + (f" (reference {plan.oem_reference})" if plan.oem_reference else "") + (f": {note}" if note else "."),
          on=on.isoformat(), reference=plan.oem_reference or None, comment=note or None)


def record_control(db: Session, p: Principal, plan: OtPlan, job: Job, control: str, on: date, ip: str) -> None:
    _check(db, p, plan, job, ip)
    control = control.strip()
    if len(control) < 10:
        raise ValueError("Describe the compensating control in place (at least 10 characters).")
    _past(on, "control")
    plan.control, plan.control_on = control, on
    _done(db, p, plan, job, ip, "ot.control", f"Compensating control in place since {on.isoformat()}: {control}",
          on=on.isoformat(), comment=control)


def confirm_slot(db: Session, p: Principal, plan: OtPlan, job: Job, on: date, start: str, hours: int, with_: str,
                 ip: str) -> None:
    _check(db, p, plan, job, ip)
    if on < drafting.today():
        raise ValueError("The shutdown slot must be today or later.")
    if not CLOCK.match(start):
        raise ValueError("Start time must be HH:MM.")
    if not 1 <= hours <= 240:
        raise ValueError("The slot must last between 1 and 240 hours.")
    if not with_.strip():
        raise ValueError("Name who in operations confirmed the slot.")
    moved = plan.slot_on is not None
    plan.slot_on, plan.slot_start, plan.slot_hours, plan.slot_with = on, start, hours, with_.strip()
    _done(db, p, plan, job, ip, "ot.slot_moved" if moved else "ot.slot_confirmed",
          f"Shutdown slot {'moved to' if moved else 'confirmed for'} {on.isoformat()} {start}, {hours} h, "
          f"with {plan.slot_with}.", on=on.isoformat(), start=start, hours=hours, comment=f"with {plan.slot_with}")


def record_execution(db: Session, p: Principal, plan: OtPlan, job: Job, on: date, result: str, hosts: list[str],
                     note: str, ip: str) -> None:
    _check(db, p, plan, job, ip)
    if job.status not in ("approved", "reopened"):
        raise Conflict("The job must be approved before the change is carried out.")
    if plan.oem_state != "approved":
        raise Conflict("Record the OEM's approval before carrying out the change.")
    if plan.slot_on is None:
        raise Conflict("Confirm a shutdown slot before carrying out the change.")
    if result not in RESULTS:
        raise ValueError(f"Result must be one of: {', '.join(RESULTS)}.")
    _past(on, "execution")
    if on < job.created_at.date():
        raise ValueError("The change cannot have been carried out before the job was raised.")
    hosts = list(dict.fromkeys(hosts)) or list(job.hosts)
    unknown = [h for h in hosts if h not in job.hosts]
    if unknown:
        raise ValueError(f"Not in this job: {', '.join(unknown[:5])}.")
    note = note.strip()
    if result != "applied" and not note:
        raise ValueError("Say what happened when the change was not fully applied.")
    plan.executions = [*plan.executions, {"on": on.isoformat(), "result": result, "hosts": hosts, "note": note,
                                          "by": p.user.id, "at": utcnow().isoformat(timespec="seconds")}]
    _done(db, p, plan, job, ip, "ot.executed", f"Carried out on {on.isoformat()}: {RESULTS[result].lower()} "
          f"({len(hosts)} host{'s' if len(hosts) != 1 else ''}){': ' + note if note else '.'} "
          "The job closes when a rescan proves the fix.", on=on.isoformat(), result=result, hosts=len(hosts),
          comment=note or None)


def plan_json(db: Session, plan: OtPlan, job: Job, p: Principal | None = None) -> dict:
    by = {e["by"] for e in plan.executions}
    users = {u.id: u.display_name for u in db.scalars(select(User).where(User.id.in_(by)))} if by else {}
    key = stage(db, plan, job)
    named = drafting.maintenance(db)["ot_shutdowns"]
    return {
        "job_pk": job.id, "sites": plan.sites, "stage": key, "stage_label": STAGES[key],
        "oem": {"state": plan.oem_state, "reference": plan.oem_reference, "note": plan.oem_note,
                "requested_on": plan.oem_requested_on.isoformat() if plan.oem_requested_on else None,
                "decided_on": plan.oem_decided_on.isoformat() if plan.oem_decided_on else None},
        "control": {"text": plan.control, "on": plan.control_on.isoformat() if plan.control_on else None},
        "slot": {"on": plan.slot_on.isoformat() if plan.slot_on else None, "start": plan.slot_start,
                 "hours": plan.slot_hours, "with": plan.slot_with},
        # The plant's next named shutdown from the maintenance policy, offered as a suggestion only.
        "named_shutdowns": {s: named[s] for s in plan.sites if s in named},
        "executions": [{**e, "by": users.get(e["by"], ""), "result_label": RESULTS[e["result"]]}
                       for e in plan.executions],
        "can_act": bool(p and may_act(p, plan, job) is None),
        "why_not": may_act(p, plan, job) if p else None,
        "updated": plan.updated_at.isoformat(timespec="seconds"),
    }
