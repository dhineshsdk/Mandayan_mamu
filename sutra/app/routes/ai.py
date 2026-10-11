"""AI explanations and the board briefing. Each runs with the asker's own scope, so a plant head's explanation is
written from that plant's data only. The model only ever sees typed facts (see ``sutra_explain``)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..access import Principal
from ..deps import client_ip, get_db, require, require_any
from . import views

router = APIRouter(prefix="/api")


@router.get("/root-causes/{rc_id}/explanation")
def explanation(rc_id: str, request: Request, p: Principal = Depends(require("M-RC", "view")),
                db: Session = Depends(get_db)):
    _, payload = views.scoped(request, p, "M-RC")
    if not any(r["id"] == rc_id for r in payload["root_causes"]):
        raise LookupError(f"No root cause {rc_id} in your scope.")
    scope = views.scope_of(request, p, "M-RC")
    return request.app.state.ai.root_cause(db, payload, rc_id, scope, p.user, client_ip(request))


@router.get("/board/briefing")
def briefing(request: Request, p: Principal = Depends(require("M-BRD", "view")), db: Session = Depends(get_db)):
    res, payload = views.scoped(request, p, "M-BRD")
    return request.app.state.ai.briefing(db, payload, len(views.unowned(db, res)), views.scope_of(request, p, "M-BRD"),
                                         p.user, client_ip(request))


@router.get("/admin/ai")
def ai_status(request: Request, p: Principal = Depends(require_any(("M-ADM", "act"), ("M-ADM", "admin")))):
    return request.app.state.ai.status(request.app.state.drafts.background)
