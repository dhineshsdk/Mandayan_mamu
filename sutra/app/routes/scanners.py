"""Scanner API connections and pulls, and the threat-intel feeds (part of Data and connectors, M-DAT).

Seeing connections and pulls needs M-DAT view; starting a pull needs act; adding or changing a connection, its
credentials or the schedule needs admin. Secrets are write-only: no response ever contains one.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import scanpull, vault
from ..access import Principal
from ..deps import client_ip, get_db, require
from ..jobs import Conflict
from ..models import ScannerConnection, ScanPull, Setting, utcnow
from ..security import audit

router = APIRouter(prefix="/api/data")


class ConnectionIn(BaseModel):
    kind: Literal["qualys", "tenable_vm", "tenable_sc", "crowdstrike"]
    name: str = Field(min_length=1, max_length=80)
    base_url: str = Field(default="", max_length=300)
    username: str = Field(min_length=1, max_length=200)
    secret: str = Field(default="", max_length=500)  # empty on an update keeps the stored one
    ca_bundle: str = Field(default="", max_length=500)
    enabled: bool = True


class ScheduleIn(BaseModel):
    enabled: bool
    hour: int = Field(ge=0, le=23)


def _check_url(kind: str, url: str) -> str:
    url = (url.strip() or scanpull.KINDS[kind]["default_url"]).rstrip("/")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/") or parts.query:
        raise ValueError("The address must be an https:// URL with no path, for example "
                         f"{scanpull.KINDS[kind]['url_hint']}.")
    return url


@router.get("/connections")
def list_connections(p: Principal = Depends(require("M-DAT", "view")), db: Session = Depends(get_db)):
    conns = db.scalars(select(ScannerConnection).order_by(ScannerConnection.id))
    pulls = db.scalars(select(ScanPull).order_by(ScanPull.id.desc()).limit(20))
    return {"connections": [scanpull.connection_json(c) for c in conns],
            "pulls": [scanpull.pull_json(x) for x in pulls], "schedule": scanpull.schedule(db),
            "kinds": scanpull.KINDS}


@router.post("/connections", status_code=201)
def add_connection(body: ConnectionIn, request: Request, p: Principal = Depends(require("M-DAT", "admin")),
                   db: Session = Depends(get_db)):
    if not body.secret:
        raise ValueError(f"Enter the {scanpull.KINDS[body.kind]['secret'].lower()}.")
    key = request.app.state.settings.secret_key
    c = ScannerConnection(kind=body.kind, name=body.name.strip(), base_url=_check_url(body.kind, body.base_url),
                          username=body.username.strip(), secret=vault.seal(key, body.secret),
                          ca_bundle=body.ca_bundle.strip(), enabled=body.enabled, created_by=p.user.id)
    db.add(c)
    db.flush()
    audit(db, "data.connection_add", p.user, "scanner_connection", c.id, client_ip(request), kind=c.kind,
          name=c.name, base_url=c.base_url)
    db.commit()
    return scanpull.connection_json(c)


@router.put("/connections/{cid}")
def update_connection(cid: int, body: ConnectionIn, request: Request,
                      p: Principal = Depends(require("M-DAT", "admin")), db: Session = Depends(get_db)):
    c = db.get(ScannerConnection, cid)
    if c is None:
        raise LookupError("No such connection.")
    if body.kind != c.kind:
        raise ValueError("The scanner type of a connection cannot change. Add a new connection instead.")
    c.name, c.base_url, c.username = body.name.strip(), _check_url(c.kind, body.base_url), body.username.strip()
    c.ca_bundle, c.enabled, c.updated_at = body.ca_bundle.strip(), body.enabled, utcnow()
    if body.secret:
        c.secret = vault.seal(request.app.state.settings.secret_key, body.secret)
    audit(db, "data.connection_change", p.user, "scanner_connection", c.id, client_ip(request), name=c.name,
          base_url=c.base_url, enabled=c.enabled, secret_changed=bool(body.secret))
    db.commit()
    return scanpull.connection_json(c)


@router.delete("/connections/{cid}")
def delete_connection(cid: int, request: Request, p: Principal = Depends(require("M-DAT", "admin")),
                      db: Session = Depends(get_db)):
    c = db.get(ScannerConnection, cid)
    if c is None:
        raise LookupError("No such connection.")
    audit(db, "data.connection_delete", p.user, "scanner_connection", c.id, client_ip(request), name=c.name)
    db.delete(c)
    db.commit()
    return {"ok": True}


@router.put("/connections-schedule")
def set_schedule(body: ScheduleIn, request: Request, p: Principal = Depends(require("M-DAT", "admin")),
                 db: Session = Depends(get_db)):
    s = db.get(Setting, "scan_schedule")
    value = body.model_dump()
    if s is None:
        db.add(Setting(key="scan_schedule", value=value))
    else:
        s.value = value
    audit(db, "data.pull_schedule", p.user, "setting", "scan_schedule", client_ip(request), **value)
    db.commit()
    return {"schedule": scanpull.schedule(db)}


@router.post("/pulls", status_code=202)
def start_pull(request: Request, p: Principal = Depends(require("M-DAT", "act")), db: Session = Depends(get_db)):
    try:
        pull_id = request.app.state.puller.start("manual", p.user.id)
    except RuntimeError as e:
        raise Conflict(str(e)) from e
    audit(db, "data.pull_start", p.user, "scan_pull", pull_id, client_ip(request))
    db.commit()
    return {"pull": pull_id}


@router.get("/pulls/{pid}")
def get_pull(pid: int, p: Principal = Depends(require("M-DAT", "view")), db: Session = Depends(get_db)):
    x = db.get(ScanPull, pid)
    if x is None:
        raise LookupError("No such pull.")
    return scanpull.pull_json(x)


# ---------- threat intelligence (CISA KEV and EPSS) ----------

@router.get("/intel")
def intel_status(request: Request, p: Principal = Depends(require("M-DAT", "view"))):
    store = request.app.state.intel
    current = request.app.state.analysis.intel
    return {**store.status(), "refreshing": request.app.state.intel_updater.busy(),
            "known_exploited": sum(1 for v in current.values() if v.get("exploitation") == "active"),
            "with_epss": sum(1 for v in current.values() if "epss" in v)}


@router.post("/intel/refresh")
def intel_refresh(request: Request, p: Principal = Depends(require("M-DAT", "act")), db: Session = Depends(get_db)):
    try:
        out = request.app.state.intel_updater.refresh()
    except RuntimeError as e:
        raise Conflict(str(e)) from e
    audit(db, "data.intel_refresh", p.user, "setting", "threat_intel", client_ip(request), **out)
    db.commit()
    return {"results": out, **intel_status(request, p)}
