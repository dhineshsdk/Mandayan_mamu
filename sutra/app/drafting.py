"""Patch-job drafts from the sutra_patchdraft library, with the customer's maintenance policy.

With an Anthropic API key the draft comes from Claude and can take minutes, so the job waits in "drafting" and a
single background worker writes the draft; nobody can approve a job before its draft exists. Without a key the
template draft is written at once. Who approves never depends on the draft (``sutra.patch.route``).
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from sutra_patchdraft import DraftInput, InputError, MaintenancePolicy, PatchDrafter, from_sutra, template_only

from .models import Job, Setting, utcnow
from .security import audit

log = logging.getLogger("sutra.drafting")
IST = timezone(timedelta(hours=5, minutes=30))
DEFAULT_MAINTENANCE = {"weekday": 5, "start": "22:00", "duration_hours": 4, "timezone_label": "IST",
                       "ot_shutdowns": {}}


def today() -> date:
    """Today's date in India, which is what maintenance windows are counted from."""
    return datetime.now(IST).date()


def maintenance(db: Session) -> dict:
    s = db.get(Setting, "maintenance")
    return {**DEFAULT_MAINTENANCE, **(dict(s.value) if s else {})}


def policy_for(db: Session, sites: set[str]) -> MaintenancePolicy:
    """The weekly IT window, and the plant shutdown when every host in the job is at one site that has one named.

    A job spanning two plants gets no shutdown date: one slot cannot cover both, so the draft says it is not set.
    """
    m = maintenance(db)
    hh, mm = (int(x) for x in m["start"].split(":"))
    shutdown = None
    if len(sites) == 1:
        named = m["ot_shutdowns"].get(next(iter(sites)))
        shutdown = date.fromisoformat(named) if named else None
    return MaintenancePolicy(weekday=int(m["weekday"]), start=time(hh, mm), duration_hours=int(m["duration_hours"]),
                             timezone_label=m["timezone_label"], ot_shutdown=shutdown)


def build_input(db: Session, rc, hosts: list, findings: list) -> DraftInput:
    return from_sutra(rc, hosts, findings, today(), policy=policy_for(db, {h.site for h in hosts}))


def apply_draft(db: Session, job: Job, draft) -> None:
    """Store a finished draft and open the first approval step. The caller commits."""
    job.draft = draft.to_dict()
    job.status = "pending"
    for s in job.steps:
        s.state = "current" if s.position == 0 else "waiting"
        s.opened_at = utcnow() if s.position == 0 else None
    audit(db, "job.drafted", None, "job", job.id, source=draft.source, model=draft.model,
          fallback_reason=draft.fallback_reason)


class DraftService:
    """Writes drafts. ``drafter.ai_available`` decides whether drafting happens now or in the background."""

    def __init__(self, sessions: sessionmaker | None = None, drafter: PatchDrafter | None = None):
        self.sessions = sessions
        self.drafter = drafter if drafter is not None else PatchDrafter()
        self._pool: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()
        self._pending: set[Future] = set()

    @property
    def background(self) -> bool:
        return self.drafter.ai_available

    def draft_now(self, inp: DraftInput):
        return self.drafter.draft(inp)

    def submit(self, job_id: int, inp: DraftInput) -> None:
        with self._lock:
            if self._pool is None:  # one at a time: drafts are rare and API rate limits are per organisation
                self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sutra-draft")
            fut = self._pool.submit(self._run, self.sessions, job_id, inp)
            self._pending.add(fut)
            fut.add_done_callback(self._pending.discard)

    def _run(self, sessions: sessionmaker, job_id: int, inp: DraftInput) -> None:
        try:
            draft = self.drafter.draft(inp)  # never raises for model trouble; it falls back to the template
        except Exception as e:  # a bug, not bad model output: the job must not wait forever
            log.exception("drafting job %s failed", job_id)
            with sessions() as db:
                job = db.get(Job, job_id)
                if job is not None and job.status == "drafting":
                    job.status = "draft-failed"
                    audit(db, "job.draft_failed", None, "job", job_id, error=type(e).__name__)
                    db.commit()
            return
        with sessions() as db:
            job = db.get(Job, job_id)
            if job is not None and job.status == "drafting":
                apply_draft(db, job, draft)
                db.commit()

    def wait(self, timeout: float | None = None) -> None:
        """Block until queued drafts are written (tests, shutdown)."""
        for fut in list(self._pending):
            fut.result(timeout=timeout)

    def shutdown(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)


def resume(service: DraftService, res) -> None:
    """Re-queue jobs left in "drafting" by a restart, rebuilding their input from the current import."""
    if res is None:
        return
    from .. import patch  # local: avoid an import cycle with jobs.py

    queued = []
    with service.sessions() as db:
        for job in db.scalars(select(Job).where(Job.status == "drafting")):
            rc = next((r for r in res.root_causes if r.key == job.rc_key), None)
            hosts = [res.assets[a] for a in job.hosts if a in res.assets]
            findings = {f.finding_id: f for f in res.findings}
            mine = [f for f in (findings.get(i) for i in (rc.finding_ids if rc else []))
                    if f is not None and f.asset_id in job.hosts and patch.team_of(res.assets[f.asset_id]) == job.team]
            try:
                if rc is None or not hosts:
                    raise InputError("the root cause is not in the current import")
                inp = build_input(db, rc, hosts, mine)
            except InputError as e:
                job.status = "draft-failed"
                audit(db, "job.draft_failed", None, "job", job.id, error=str(e))
                continue
            if service.background:
                queued.append((job.id, inp))
            else:
                apply_draft(db, job, service.draft_now(inp))
        db.commit()
    for job_id, inp in queued:
        service.submit(job_id, inp)


__all__ = ["DraftService", "IST", "apply_draft", "build_input", "maintenance", "policy_for", "resume",
           "template_only", "today"]
