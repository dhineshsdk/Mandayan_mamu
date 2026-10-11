"""Verified closure: a job closes only when a later scan proves its findings are gone, and reopens if they return.

Nobody sets "fixed" by hand. After each import, every open job (and every job closed by an earlier rescan) is
checked against that import's findings:

- a target (asset, finding fingerprint) still reported is still open;
- a target missing from the import counts as fixed only if its host was scanned in that import, otherwise it is
  "not rescanned", because absence of evidence is not a fix;
- when every target is fixed, the job becomes verified-fixed, with the scan date that proved it;
- when a verified-fixed job's findings are reported again, it reopens.

An import whose scans are older than the last check of a job is ignored for that job: an old file uploaded late
cannot reopen or close anything.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AssetSnapshot, Dataset, Job, JobCheck, Observation, utcnow
from .security import audit

CHECKED = ("drafting", "pending", "approved", "fixing-manually", "reopened", "verified-fixed", "accepted", "expired")
MAX_ITEMS = 200


def targets_of(db: Session, job: Job) -> list[tuple[str, str]]:
    """The job's targets; for jobs raised before targets were recorded, rebuilt from the import it came from."""
    if job.targets:
        return [(a, fp) for a, fp in job.targets]
    rows = db.execute(select(Observation.asset_id, Observation.fingerprint)
                      .where(Observation.dataset_id == job.dataset_id, Observation.rc_key == job.rc_key,
                             Observation.asset_id.in_(job.hosts))).all()
    return sorted({(a, fp) for a, fp in rows})


def _last_as_of(db: Session, job: Job):
    return db.scalars(select(JobCheck.as_of).where(JobCheck.job_id == job.id)
                      .order_by(JobCheck.as_of.desc())).first()


def verify(db: Session, ds: Dataset) -> dict[str, int]:
    """Check every relevant job against import ``ds``. The caller commits. Returns counts by outcome."""
    present = {(a, fp) for a, fp in db.execute(select(Observation.asset_id, Observation.fingerprint)
                                               .where(Observation.dataset_id == ds.id))}
    scanned = set(db.scalars(select(AssetSnapshot.asset_id)
                             .where(AssetSnapshot.dataset_id == ds.id, AssetSnapshot.scanned.is_(True))))
    counts: dict[str, int] = {}
    for job in db.scalars(select(Job).where(Job.status.in_(CHECKED), Job.dataset_id != ds.id).order_by(Job.id)):
        last = _last_as_of(db, job)
        if last and ds.as_of and ds.as_of < last:
            continue
        targets = targets_of(db, job)
        if not targets:
            continue
        still = [t for t in targets if t in present]
        fixed = [t for t in targets if t not in present and t[0] in scanned]
        unknown = len(targets) - len(still) - len(fixed)
        if job.status == "verified-fixed":
            if not still:
                continue  # stays closed; nothing new to record
            outcome = "reopened"
            job.status, job.fixed_on, job.closed_at = "reopened", None, None
        elif not still and not unknown:
            outcome = "fixed"
            job.status, job.fixed_on, job.closed_at = "verified-fixed", ds.as_of, utcnow()
        elif not still:
            outcome = "not-rescanned"
        elif fixed:
            outcome = "partly-fixed"
        else:
            outcome = "not-fixed"
        db.add(JobCheck(job_id=job.id, dataset_id=ds.id, as_of=ds.as_of, fixed=len(fixed), still_open=len(still),
                        not_rescanned=unknown, outcome=outcome, still_open_items=[list(t) for t in still[:MAX_ITEMS]]))
        audit(db, f"job.rescan_{outcome.replace('-', '_')}", None, "job", job.id, dataset=ds.id,
              as_of=ds.as_of.isoformat() if ds.as_of else None, fixed=len(fixed), still_open=len(still),
              not_rescanned=unknown)
        counts[outcome] = counts.get(outcome, 0) + 1
    db.flush()
    return counts


def checks_json(db: Session, job: Job) -> list[dict]:
    rows = db.scalars(select(JobCheck).where(JobCheck.job_id == job.id).order_by(JobCheck.id))
    return [{"as_of": c.as_of.isoformat() if c.as_of else None,
             "checked_at": c.checked_at.isoformat(timespec="seconds"),
             "fixed": c.fixed, "still_open": c.still_open, "not_rescanned": c.not_rescanned, "outcome": c.outcome}
            for c in rows]
