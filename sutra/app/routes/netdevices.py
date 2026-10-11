"""Firewall and switch configuration collection (part of Data and connectors, M-DAT).

Seeing devices, stored configurations and their changes needs M-DAT view; collecting now needs act; adding or
changing a device, its credentials or its pinned host key needs admin. Secrets are write-only: no response ever
contains one, and stored configurations were masked before they were saved.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import netconfig, vault
from ..access import Principal
from ..deps import client_ip, get_db, require
from ..jobs import Conflict
from ..models import ConfigSnapshot, NetworkDevice, utcnow
from ..security import audit

router = APIRouter(prefix="/api/data")


class DeviceIn(BaseModel):
    kind: Literal["fortigate", "panos", "cisco_ios"]
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(min_length=1, max_length=300)
    username: str = Field(default="", max_length=200)
    secret: str = Field(default="", max_length=2000)  # empty on an update keeps the stored one
    ca_bundle: str = Field(default="", max_length=500)
    site: str = Field(default="", max_length=80)
    host_key: str = Field(default="", max_length=100)  # an SSH fingerprint to pin up front; empty pins on first use
    clear_host_key: bool = False
    enabled: bool = True


def _check(body: DeviceIn) -> tuple[str, str, str]:
    """(address, username, host_key) checked for the device kind."""
    kind = netconfig.KINDS[body.kind]
    address = netconfig.check_address(body.kind, body.address)
    username = body.username.strip()
    if kind["transport"] == "ssh":
        if not username:
            raise ValueError("Enter the SSH user name.")
        host_key = body.host_key.strip()
        if host_key and not host_key.startswith("SHA256:"):
            raise ValueError("The host key must be an SSH SHA256 fingerprint, as ssh-keygen -l shows it "
                             "(SHA256:...).")
        return address, username, host_key
    return address, "", ""


def _device(db: Session, did: int) -> NetworkDevice:
    d = db.get(NetworkDevice, did)
    if d is None:
        raise LookupError("No such device.")
    return d


@router.get("/devices")
def list_devices(request: Request, p: Principal = Depends(require("M-DAT", "view")), db: Session = Depends(get_db)):
    devices = db.scalars(select(NetworkDevice).order_by(NetworkDevice.site, NetworkDevice.name))
    return {"devices": [netconfig.device_json(db, d) for d in devices], "kinds": netconfig.KINDS,
            "collecting": request.app.state.collector.busy()}


@router.post("/devices", status_code=201)
def add_device(body: DeviceIn, request: Request, p: Principal = Depends(require("M-DAT", "admin")),
               db: Session = Depends(get_db)):
    if not body.secret:
        raise ValueError(f"Enter the {netconfig.KINDS[body.kind]['secret'].lower()}.")
    address, username, host_key = _check(body)
    d = NetworkDevice(kind=body.kind, name=body.name.strip(), address=address, username=username,
                      secret=vault.seal(request.app.state.settings.secret_key, body.secret),
                      ca_bundle=body.ca_bundle.strip(), host_key=host_key, site=body.site.strip(),
                      enabled=body.enabled, created_by=p.user.id)
    db.add(d)
    db.flush()
    audit(db, "data.device_add", p.user, "network_device", d.id, client_ip(request), kind=d.kind, name=d.name,
          address=d.address, site=d.site, host_key=d.host_key)
    db.commit()
    return netconfig.device_json(db, d)


@router.put("/devices/{did}")
def update_device(did: int, body: DeviceIn, request: Request, p: Principal = Depends(require("M-DAT", "admin")),
                  db: Session = Depends(get_db)):
    d = _device(db, did)
    if body.kind != d.kind:
        raise ValueError("The type of a device cannot change. Add a new device instead.")
    address, username, host_key = _check(body)
    old_key = d.host_key
    d.name, d.address, d.username, d.site = body.name.strip(), address, username, body.site.strip()
    d.ca_bundle, d.enabled, d.updated_at = body.ca_bundle.strip(), body.enabled, utcnow()
    if body.clear_host_key:
        d.host_key = ""
    elif host_key:
        d.host_key = host_key
    if body.secret:
        d.secret = vault.seal(request.app.state.settings.secret_key, body.secret)
    audit(db, "data.device_change", p.user, "network_device", d.id, client_ip(request), name=d.name,
          address=d.address, site=d.site, enabled=d.enabled, secret_changed=bool(body.secret),
          host_key_before=old_key, host_key=d.host_key)
    db.commit()
    return netconfig.device_json(db, d)


@router.delete("/devices/{did}")
def delete_device(did: int, request: Request, p: Principal = Depends(require("M-DAT", "admin")),
                  db: Session = Depends(get_db)):
    d = _device(db, did)
    n = len(db.scalars(select(ConfigSnapshot.id).where(ConfigSnapshot.device_id == d.id)).all())
    audit(db, "data.device_delete", p.user, "network_device", d.id, client_ip(request), name=d.name, snapshots=n)
    for s in db.scalars(select(ConfigSnapshot).where(ConfigSnapshot.device_id == d.id)):
        db.delete(s)
    db.delete(d)
    db.commit()
    return {"ok": True}


class CollectIn(BaseModel):
    device: int | None = None  # one device, or every enabled one


@router.post("/devices/collect", status_code=202)
def collect(body: CollectIn, request: Request, p: Principal = Depends(require("M-DAT", "act")),
            db: Session = Depends(get_db)):
    try:
        ids = request.app.state.collector.start("manual", p.user.id, body.device)
    except RuntimeError as e:
        raise Conflict(str(e)) from e
    audit(db, "data.config_collect_start", p.user, "network_device", ",".join(str(i) for i in ids),
          client_ip(request))
    db.commit()
    return {"devices": ids}


@router.get("/devices/{did}/snapshots")
def list_snapshots(did: int, p: Principal = Depends(require("M-DAT", "view")), db: Session = Depends(get_db)):
    d = _device(db, did)
    snaps = db.scalars(select(ConfigSnapshot).where(ConfigSnapshot.device_id == d.id)
                       .order_by(ConfigSnapshot.id.desc()).limit(200))
    return {"device": netconfig.device_json(db, d), "snapshots": [netconfig.snapshot_json(s) for s in snaps]}


def _snapshot(db: Session, sid: int) -> ConfigSnapshot:
    s = db.get(ConfigSnapshot, sid)
    if s is None:
        raise LookupError("No such configuration.")
    return s


@router.get("/snapshots/{sid}")
def get_snapshot(sid: int, request: Request, p: Principal = Depends(require("M-DAT", "view")),
                 db: Session = Depends(get_db)):
    s = _snapshot(db, sid)
    audit(db, "data.config_view", p.user, "config_snapshot", s.id, client_ip(request), device=s.device_id)
    db.commit()
    return {**netconfig.snapshot_json(s), "config": s.config, "arp_table": s.arp, "mac_entries": s.mac_table}


@router.get("/snapshots/{sid}/download")
def download_snapshot(sid: int, request: Request, p: Principal = Depends(require("M-DAT", "view")),
                      db: Session = Depends(get_db)):
    s = _snapshot(db, sid)
    d = db.get(NetworkDevice, s.device_id)
    audit(db, "data.config_download", p.user, "config_snapshot", s.id, client_ip(request), device=s.device_id)
    db.commit()
    ext = "xml" if s.config_format == "panos-xml" else "conf"
    stamp = s.collected_at.strftime("%Y%m%d-%H%M")
    safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in (d.name if d else "device"))[:60]
    return PlainTextResponse(s.config, headers={
        "Content-Disposition": f'attachment; filename="{safe}-{stamp}.{ext}"'})


@router.get("/snapshots/{sid}/diff")
def snapshot_diff(sid: int, p: Principal = Depends(require("M-DAT", "view")), db: Session = Depends(get_db)):
    """What changed from the device's previous stored configuration to this one."""
    s = _snapshot(db, sid)
    prev = db.scalars(select(ConfigSnapshot).where(ConfigSnapshot.device_id == s.device_id,
                                                   ConfigSnapshot.id < s.id).order_by(ConfigSnapshot.id.desc())).first()
    return netconfig.diff(prev, s)
