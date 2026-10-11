"""Time-based work: risk acceptances that run out, stalled approvals and missed fix dates.

Runs at start-up, after every import and once an hour. Each task is idempotent and takes the time as an argument,
so tests can move the clock.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from . import drafting, notify, sla
from .models import Job, utcnow
from .security import audit

log = logging.getLogger("sutra.sweeper")
INTERVAL_SECONDS = 3600


def expire_exceptions(db: Session, today: date) -> int:
    """An accepted risk whose expiry date has passed is back on the team's list. The caller commits."""
    n = 0
    for job in db.scalars(select(Job).where(Job.mode == "exception", Job.status == "accepted",
                                            Job.expires_on < today)):
        job.status = "expired"
        audit(db, "job.exception_expired", None, "job", job.id, expires_on=job.expires_on.isoformat())
        notify.expired(db, job)
        n += 1
    return n


def run(db: Session, now: datetime) -> dict[str, int]:
    """``now`` is naive UTC like every stored timestamp; "today" is the date in India. The caller commits."""
    today = now.replace(tzinfo=UTC).astimezone(drafting.IST).date()
    return {"expired": expire_exceptions(db, today), "escalated": sla.escalate_stalled(db, now),
            "breached": sla.record_breaches(db, now, today)}


def sweep(sessions: sessionmaker, now: datetime | None = None) -> dict[str, int]:
    with sessions() as db:
        out = run(db, now or utcnow())
        db.commit()
    return out


class Sweeper:
    def __init__(self, sessions: sessionmaker):
        self.sessions = sessions
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="sutra-sweeper", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(INTERVAL_SECONDS):
            try:
                sweep(self.sessions)
            except Exception:  # keep the loop alive; the next run retries
                log.exception("sweep failed")

    def stop(self) -> None:
        self._stop.set()
