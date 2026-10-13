"""Attack surface (M-ATK): paths from the internet, IT and the DMZ into OT, and the rules behind them, read from the
latest stored configuration of each network device (``sutra.app.netconfig``) by the ``sutra.attack`` library.

* **Zones** are named groups of networks of a kind (internet, IT, DMZ, OT) that an admin defines. Without an OT zone
  there is nothing to look for. The internet zone defaults to every public address.
* **Hit counts** are uploaded per device (configurations do not carry them) and replace the previous upload. Without
  them no rule is called unused, and the page says which devices have none.
* The analysis runs when a person opens the page; nothing is cached, so it always reflects the stored configurations.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from sutra.attack import analyze as A
from sutra.attack import boxes as bx
from sutra.attack import fortios, hits, ios, panos
from sutra.attack.model import Device

from .models import AttackHits, AttackZone, ConfigSnapshot, NetworkDevice, utcnow

KINDS = A.KINDS
UNUSED_DAYS = A.__dict__.get("UNUSED_DAYS", 90)
LIMITS = [
    "IPv4 only.",
    "Routing is read from connected networks and static routes; OSPF, EIGRP and BGP are not read.",
    "NAT, application and user identity, and IPS profiles are not modelled; a rule that depends on them is shown "
    "as the addresses and ports it names.",
    "A path shows what the configurations allow, not what has been used. Use the hit counts for that.",
]


def check_zone(name: str, kind: str, cidrs: list[str]) -> list[str]:
    """The zone's CIDRs in canonical form. Raises ValueError with a message for the person editing."""
    if kind not in KINDS:
        raise ValueError(f"A zone kind is one of: {', '.join(KINDS)}.")
    if not name.strip():
        raise ValueError("Every zone needs a name.")
    out = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
        except ValueError:
            raise ValueError(f"{c!r} is not a network such as 10.50.0.0/16.") from None
        if net.version != 4:
            raise ValueError("Only IPv4 networks can be used.")
        out.append(str(net))
    if kind != "internet" and not out:
        raise ValueError(f"Zone {name!r} needs at least one network.")
    return out


def zones(db: Session) -> list[A.Zone]:
    return [A.Zone(z.name, z.kind, list(z.cidrs)) for z in db.scalars(select(AttackZone).order_by(AttackZone.id))]


def load_devices(db: Session) -> tuple[list[Device], dict[str, int], list[dict]]:
    """(parsed devices, device name -> network device id, per-device problems)."""
    devices: list[Device] = []
    ids: dict[str, int] = {}
    problems: list[dict] = []
    for nd in db.scalars(select(NetworkDevice).where(NetworkDevice.enabled.is_(True)).order_by(NetworkDevice.id)):
        snap = db.scalars(select(ConfigSnapshot).where(ConfigSnapshot.device_id == nd.id)
                          .order_by(ConfigSnapshot.id.desc())).first()
        if snap is None:
            problems.append({"device": nd.name, "problem": "No configuration has been collected yet."})
            continue
        try:
            if nd.kind == "fortigate":
                parsed = fortios.parse(snap.config, nd.name)
            elif nd.kind == "panos":
                parsed = [panos.parse(snap.config, nd.name)]
            else:
                parsed = [ios.parse(snap.config, nd.name)]
        except Exception as e:  # a parser meeting syntax it does not know must not hide the other devices
            problems.append({"device": nd.name, "problem": f"The configuration could not be read: {e}"})
            continue
        for dev in parsed:
            if len(parsed) == 1:
                dev.name = nd.name
            elif not dev.name.startswith(nd.name):
                dev.name = f"{nd.name}/{dev.name.rpartition('/')[2]}"
            dev.site = nd.site
            devices.append(dev)
            ids[dev.name] = nd.id
    return devices, ids, problems


def stored_hits(db: Session, ids: dict[str, int]) -> dict[str, hits.HitMap]:
    by_id = {h.device_id: h for h in db.scalars(select(AttackHits))}
    out: dict[str, hits.HitMap] = {}
    for name, did in ids.items():
        h = by_id.get(did)
        if h:
            out[name] = {k: hits.RuleHits(v["hits"], _t(v.get("last_hit")), _t(v.get("since")))
                         for k, v in h.rules.items()}
    return out


def _t(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


def store_hits(db: Session, device_id: int, fmt: str, text: str, since: datetime | None, user_id: int | None) -> int:
    """Parse and keep an upload for a device, replacing any earlier one. Raises ValueError for bad input."""
    if db.get(NetworkDevice, device_id) is None:
        raise LookupError("No such device.")
    parsed = hits.parse(fmt, text, since)
    rules = {k: {"hits": v.hits, "last_hit": _iso(v.last_hit), "since": _iso(v.since)} for k, v in parsed.items()}
    row = db.scalars(select(AttackHits).where(AttackHits.device_id == device_id)).first()
    if row is None:
        row = AttackHits(device_id=device_id, source_format=fmt, rules=rules, loaded_by=user_id)
        db.add(row)
    row.source_format, row.rules, row.loaded_at, row.loaded_by = fmt, rules, utcnow(), user_id
    return len(rules)


def report(db: Session, now: datetime | None = None) -> dict:
    devices, ids, problems = load_devices(db)
    zs = zones(db)
    hit_maps = stored_hits(db, ids)
    r = A.analyze(devices, zs, hit_maps, now or utcnow(), UNUSED_DAYS)
    by_dev = {d.name: d for d in devices}
    loaded = {h.device_id: h for h in db.scalars(select(AttackHits))}

    def rule_ref(device: str, key: str) -> dict:
        rule = next((x for x in by_dev[device].rules if x.key == key), None)
        return {"key": key, "name": rule.name if rule else "", "summary": A.rule_summary(rule) if rule else "",
                "action": rule.action if rule else ""}

    paths = []
    for f in r.path_findings:
        p = f.path
        paths.append({"severity": f.severity, "title": f.title, "detail": f.detail, "src_zone": p.src_zone,
                      "dst_zone": p.dst_zone, "src_kind": p.src_kind, "dst_kind": p.dst_kind,
                      "sources": p.sources(), "destinations": p.destinations(), "services": p.services,
                      "broad": p.broad(), "complete": p.complete, "approximate": f.approximate,
                      "hops": [{"device": h.device, "ingress": h.ingress, "egress": h.egress,
                                "rules": [rule_ref(h.device, k) for k in h.rules]} for h in p.hops]})
    cover = []
    for c in r.coverage:
        h = loaded.get(ids.get(c["device"], -1))
        cover.append({**c, "hits_loaded": _iso(h.loaded_at) if h else None,
                      "hits_format": h.source_format if h else None, "device_id": ids.get(c["device"])})
    return {
        "generated": _iso(now or utcnow()), "unused_days": UNUSED_DAYS, "summary": r.counts(),
        "kinds": KINDS, "hit_formats": hits.FORMATS, "limits": LIMITS,
        "zones": [{"name": z.name, "kind": z.kind, "kind_label": KINDS[z.kind], "cidrs": z.cidrs,
                   "ranges": [f"{bx.ip_text(a)}-{bx.ip_text(b)}" for a, b in z.intervals()] if not z.cidrs else []}
                  for z in zs],
        "paths": paths,
        "findings": [{"kind": f.kind, "severity": f.severity, "title": f.title, "detail": f.detail,
                      "device": f.device, "rule": rule_ref(f.device, f.rule) if f.rule else None,
                      "approximate": f.approximate, "on_risky_path": f.on_risky_path} for f in r.findings],
        "chokepoints": [{"device": c.device, "rule": rule_ref(c.device, c.rule), "paths": c.paths, "sole": c.sole,
                         "unused": c.unused, "approximate": c.approximate} for c in r.chokepoints],
        "coverage": cover, "problems": problems, "notes": r.notes,
        "devices_without_hits": [c["device"] for c in cover if not c["hit_counts"]],
    }
