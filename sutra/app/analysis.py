"""The current analysis, and the same analysis restricted to what one person may see."""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import ingest, pipeline, risk, views
from ..pipeline import Result
from . import closure, history, sweeper
from .models import Dataset, OwnershipTeam, utcnow


class AnalysisStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.dataset_id: int | None = None
        self.result: Result | None = None
        self.intel = risk.load_intel()
        self._scoped: dict[str, tuple[Result, dict]] = {}

    def load_current(self, db: Session) -> None:
        ds = db.scalars(select(Dataset).where(Dataset.is_current.is_(True)).order_by(Dataset.id.desc())).first()
        if ds is None:
            self.dataset_id, self.result, self._scoped = None, None, {}
            return
        files = [Path(f["path"]) for f in ds.files if Path(f["path"]).exists()]
        cmdb = next((Path(f["path"]) for f in ds.files if f["format"] == "cmdb"), None)
        scans = [p for p in files if ingest.detect_format(p) in ingest.LOADERS]
        if not scans:
            self.dataset_id, self.result, self._scoped = None, None, {}
            return
        res = pipeline.run(scans, cmdb, org=ds.org_name, known_first_seen=history.first_seen_hints(db, ds.id))
        with self.lock:
            self.dataset_id, self.result, self._scoped = ds.id, res, {}

    def activate(self, db: Session, files: list[dict], org: str, kind: str, user_id: int | None) -> Dataset:
        """Analyse a new import, load its ownership chart if it has one, store its snapshot and make it current."""
        scans = [Path(f["path"]) for f in files if f["format"] in ingest.LOADERS]
        if not scans:
            raise ValueError("Include at least one Qualys CSV, Tenable CSV or .nessus file.")
        cmdb = next((Path(f["path"]) for f in files if f["format"] == "cmdb"), None)
        # Fails before anything is stored if the files are bad.
        res = pipeline.run(scans, cmdb, org=org, known_first_seen=history.first_seen_hints(db))
        teams = next((Path(f["path"]) for f in files if f["format"] == "teams"), None)
        if teams:
            replace_ownership(db, ingest.load_teams(teams))
        db.execute(update(Dataset).values(is_current=False))
        ds = Dataset(org_name=org, kind=kind, files=files, is_current=True, created_by=user_id)
        db.add(ds)
        db.flush()
        history.record(db, ds, res)
        closure.verify(db, ds)
        sweeper.run(db, utcnow())
        db.commit()
        with self.lock:
            self.dataset_id, self.result, self._scoped = ds.id, res, {}
        return ds

    def scoped(self, asset_ids: set[str]) -> tuple[Result, dict]:
        """The restricted result and its JSON payload, cached per scope."""
        res = self.result
        if res is None:
            raise LookupError("No data has been imported yet.")
        key = hashlib.sha256("\n".join(sorted(asset_ids)).encode()).hexdigest()
        with self.lock:
            hit = self._scoped.get(key)
        if hit:
            return hit
        sub = pipeline.restrict(res, asset_ids, self.intel)
        value = (sub, views.payload(sub, self.intel))
        with self.lock:
            if len(self._scoped) > 64:
                self._scoped.clear()
            self._scoped[key] = value
        return value


def replace_ownership(db: Session, rows: list[dict]) -> int:
    """Replace the ownership chart. The caller audits and commits."""
    db.query(OwnershipTeam).delete()
    for r in rows:
        db.add(OwnershipTeam(**r))
    db.flush()
    return len(rows)
