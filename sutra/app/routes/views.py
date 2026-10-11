"""Read-only analysis screens. Each one is restricted to the scope the person holds for that module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import report
from ... import views as shapes
from .. import scorecard
from ..access import Principal
from ..deps import client_ip, current_principal, get_db, require
from ..models import Dataset, OwnershipTeam
from ..security import audit

router = APIRouter(prefix="/api")

DOWNLOADS = {"receipts.json": "application/json", "root_causes.csv": "text/csv", "findings.csv": "text/csv"}
BOARD_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'; base-uri 'none'"


def scoped(request: Request, p: Principal, module: str):
    store = request.app.state.analysis
    if store.result is None:
        raise LookupError("No data has been imported yet.")
    return store.scoped(p.asset_ids(store.result.assets, module, "view"))


RC_SUMMARY = ("id", "kind", "title", "fix", "is_ot", "hosts", "findings", "max_severity", "ssvc", "ale", "ale_p10",
              "ale_p90", "ale_label", "cea_overdue", "earliest_due", "owners", "sites")


def _summary(rc: dict) -> dict:
    return {k: rc[k] for k in RC_SUMMARY}


def _board(payload: dict) -> dict:
    """The board needs totals and the ranked fixes, not host lists or scanner evidence."""
    cov = payload["coverage"]
    return {**{k: payload[k] for k in ("org", "as_of", "sources", "raw_rows", "portfolio", "portfolio_labels",
                                       "headline", "risk_by_process", "risk_by_site")},
            "coverage": {"cmdb_assets": cov["cmdb_assets"], "scanned_assets": cov["scanned_assets"],
                         "unscanned": len(cov["unscanned"]), "unknown": len(cov["unknown"]),
                         "inferred_images": len(cov["inferred_images"]),
                         "multi_scanner_findings": cov["multi_scanner_findings"]},
            "root_causes": [_summary(r) for r in payload["root_causes"]]}


@router.get("/status")
def status(request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    store = request.app.state.analysis
    ds = db.get(Dataset, store.dataset_id) if store.dataset_id else None
    return {"loaded": store.result is not None, "org": store.result.org if store.result else "",
            "as_of": store.result.as_of.isoformat() if store.result else None,
            "synthetic": bool(ds and ds.kind == "demo")}


def unowned(db: Session, res) -> list[str]:
    """Assets with no owning team in the ownership chart: nobody will be asked to fix them."""
    chart = {t.team for t in db.scalars(select(OwnershipTeam))}
    return sorted(a.asset_id for a in res.assets.values() if not (a.in_cmdb and a.owner in chart))


@router.get("/board")
def board(request: Request, p: Principal = Depends(require("M-BRD", "view")), db: Session = Depends(get_db)):
    res, payload = scoped(request, p, "M-BRD")
    out = _board(payload)
    out["coverage"]["unowned"] = len(unowned(db, res))
    return out


@router.get("/board/pack")
def board_pack(request: Request, p: Principal = Depends(require("M-BRD", "view")), db: Session = Depends(get_db)):
    res, _ = scoped(request, p, "M-BRD")
    audit(db, "board.pack", p.user, "board", res.org, client_ip(request))
    db.commit()
    return HTMLResponse(report.render_board_html(res), headers={"Content-Security-Policy": BOARD_CSP})


@router.get("/root-causes")
def root_causes(request: Request, p: Principal = Depends(require("M-RC", "view"))):
    return scoped(request, p, "M-RC")[1]


@router.get("/downloads/{name}")
def download(name: str, request: Request, p: Principal = Depends(require("M-RC", "view")),
             db: Session = Depends(get_db)):
    if name not in DOWNLOADS:
        raise LookupError("No such download.")
    res, _ = scoped(request, p, "M-RC")
    with tempfile.TemporaryDirectory() as tmp:
        report.write_receipts(res, Path(tmp))
        body = (Path(tmp) / name).read_bytes()
    audit(db, "export.download", p.user, "export", name, client_ip(request))
    db.commit()
    return Response(body, media_type=DOWNLOADS[name],
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/assets")
def assets(request: Request, p: Principal = Depends(require("M-AST", "view")), db: Session = Depends(get_db)):
    res, payload = scoped(request, p, "M-AST")
    out = {k: payload[k] for k in ("org", "as_of", "coverage", "assets", "findings")}
    out["coverage"] = {**out["coverage"], "unowned": unowned(db, res)}
    return out


class HeadlineIn(BaseModel):
    query: str = Field(min_length=1, max_length=120)


@router.post("/headline")
def headline(body: HeadlineIn, request: Request, p: Principal = Depends(require("M-HC", "view"))):
    store = request.app.state.analysis
    res, payload = scoped(request, p, "M-HC")
    out = shapes.headline_check(res, body.query, store.intel)
    rcs = {r["id"]: r for r in payload["root_causes"]}
    out["root_causes"] = [_summary(rcs[i]) for i in out["root_causes"]]
    out["hosts_list"] = [{"id": a, "hostname": res.assets[a].hostname, "ip": res.assets[a].ip}
                         for a in out["asset_ids"]]
    return out


@router.get("/portal")
def portal(request: Request, p: Principal = Depends(require("M-TP", "view")), db: Session = Depends(get_db)):
    payload = scoped(request, p, "M-TP")[1]
    chart = {t.team: t for t in db.scalars(select(OwnershipTeam))}
    teams = []
    for o in payload["owners"]:
        t = chart.get(o["owner"])
        teams.append({**o, "jira": t.jira_project if t else "", "manager": t.manager_name if t else "",
                      "vertical": t.vertical if t else "", "vertical_head": t.vertical_head_name if t else "",
                      "in_chart": t is not None})
    return {**{k: payload[k] for k in ("org", "as_of", "root_causes", "assets", "findings")}, "teams": teams}


@router.get("/scorecards")
def scorecards(request: Request, p: Principal = Depends(require("M-CSO", "view")), db: Session = Depends(get_db)):
    """Team scorecards; for the CISO, the whole organisation's dashboard."""
    return scorecard.build(db, p, request.app.state.analysis.result)
