"""Attack surface (M-ATK): the paths into OT and the rule findings. Seeing them needs M-ATK view; defining zones and
loading hit counts needs M-ATK act (the CISO and the VM analyst)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import attack
from ..access import Principal
from ..deps import client_ip, get_db, require
from ..models import AttackHits, AttackZone, NetworkDevice, utcnow
from ..security import audit

router = APIRouter(prefix="/api/attack")
MAX_UPLOAD = 5_000_000


class ZoneIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["internet", "it", "dmz", "ot"]
    cidrs: list[str] = Field(default_factory=list, max_length=200)


class ZonesIn(BaseModel):
    zones: list[ZoneIn] = Field(max_length=100)


class HitsIn(BaseModel):
    format: Literal["csv", "panos_xml", "ios_access_lists", "fortios_json"]
    text: str = Field(min_length=1, max_length=MAX_UPLOAD)
    since: datetime | None = None  # when the device's counters were last reset, if the format does not say


@router.get("")
def overview(p: Principal = Depends(require("M-ATK", "view")), db: Session = Depends(get_db)):
    return {**attack.report(db), "can_act": p.can("M-ATK", "act")}


@router.put("/zones")
def set_zones(body: ZonesIn, request: Request, p: Principal = Depends(require("M-ATK", "act")),
              db: Session = Depends(get_db)):
    names = [z.name.strip() for z in body.zones]
    if len(set(n.lower() for n in names)) != len(names):
        raise ValueError("Zone names must be different from each other.")
    checked = [(z.name.strip(), z.kind, attack.check_zone(z.name, z.kind, z.cidrs)) for z in body.zones]
    for old in db.scalars(select(AttackZone)):
        db.delete(old)
    db.flush()
    for name, kind, cidrs in checked:
        db.add(AttackZone(name=name, kind=kind, cidrs=cidrs, updated_by=p.user.id))
    audit(db, "attack.zones_set", p.user, "attack_zones", "", client_ip(request),
          zones=[{"name": n, "kind": k, "cidrs": c} for n, k, c in checked])
    db.commit()
    return {"zones": len(checked)}


@router.post("/hits/{device_id}")
def load_hits(device_id: int, body: HitsIn, request: Request, p: Principal = Depends(require("M-ATK", "act")),
              db: Session = Depends(get_db)):
    n = attack.store_hits(db, device_id, body.format, body.text, body.since, p.user.id)
    audit(db, "attack.hits_loaded", p.user, "network_device", device_id, client_ip(request), format=body.format,
          rules=n)
    db.commit()
    return {"rules": n}


@router.delete("/hits/{device_id}")
def clear_hits(device_id: int, request: Request, p: Principal = Depends(require("M-ATK", "act")),
               db: Session = Depends(get_db)):
    row = db.scalars(select(AttackHits).where(AttackHits.device_id == device_id)).first()
    if row is None or db.get(NetworkDevice, device_id) is None:
        raise LookupError("No hit counts are loaded for that device.")
    db.delete(row)
    audit(db, "attack.hits_cleared", p.user, "network_device", device_id, client_ip(request))
    db.commit()
    return {"cleared": True, "at": utcnow().isoformat(timespec="seconds")}
