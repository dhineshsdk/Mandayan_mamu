"""Import history: the list of imports and what changed between two of them, cut to the person's scope."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import history
from ..access import Principal
from ..deps import get_db, require_any
from ..models import Dataset

router = APIRouter(prefix="/api/history")
DETAIL = ("M-RC", "M-TP")  # modules that show host-level findings
SUMMARY = ("M-BRD",)  # the board sees totals per team, not hosts
READERS = require_any(*((m, "view") for m in DETAIL + SUMMARY))


@router.get("/imports")
def imports(p: Principal = Depends(READERS), db: Session = Depends(get_db)):
    return [history.dataset_json(d) for d in db.scalars(select(Dataset).order_by(Dataset.id.desc()).limit(100))]


@router.get("/changes")
def changes(from_id: int | None = None, to_id: int | None = None, p: Principal = Depends(READERS),
            db: Session = Depends(get_db)):
    new = db.get(Dataset, to_id) if to_id else db.scalars(select(Dataset).where(Dataset.is_current.is_(True))
                                                         .order_by(Dataset.id.desc())).first()
    if new is None:
        raise LookupError("No import found.")
    old = db.get(Dataset, from_id) if from_id else history.previous(db, new)
    if old is None:
        raise LookupError("There is no earlier import to compare with yet.")
    if old.id == new.id:
        raise ValueError("Choose two different imports.")
    if old.id > new.id:
        old, new = new, old
    detail = any(p.can(m, "view") for m in DETAIL)
    modules = DETAIL if detail else SUMMARY
    out = history.compare(db, old, new, lambda team, site: any(p.allowed(m, "view", team, site) for m in modules))
    if not detail:
        for t in out["teams"]:
            t.pop("items")
    out["detail"] = detail
    return out
