"""Import history: every import is stored as a snapshot of its assets and findings, so Sutra can say what was
fixed, what is new and what is still open between any two imports, and keep a finding's age across imports."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import date, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import ingest
from ..pipeline import Result
from .models import AssetSnapshot, Dataset, Observation, OwnershipTeam

NO_TEAM = "(no owning team)"


def first_seen_hints(db: Session, before_id: int | None = None) -> dict[tuple[str, str], date]:
    """Earliest scanner first-seen date of each finding in earlier imports."""
    q = (select(Observation.asset_id, Observation.fingerprint, func.min(Observation.first_seen))
         .group_by(Observation.asset_id, Observation.fingerprint))
    if before_id is not None:
        q = q.where(Observation.dataset_id < before_id)
    return {(a, fp): d for a, fp, d in db.execute(q) if d is not None}


def _first_imported(db: Session, before_id: int) -> dict[tuple[str, str], datetime]:
    q = (select(Observation.asset_id, Observation.fingerprint, func.min(Observation.first_imported_at))
         .where(Observation.dataset_id < before_id).group_by(Observation.asset_id, Observation.fingerprint))
    return {(a, fp): t for a, fp, t in db.execute(q)}


def record(db: Session, ds: Dataset, res: Result) -> dict:
    """Store the import's assets and findings. The caller commits."""
    chart = {t.team for t in db.scalars(select(OwnershipTeam))}
    for a in res.assets.values():
        db.add(AssetSnapshot(dataset_id=ds.id, asset_id=a.asset_id, hostname=a.hostname, ip=a.ip, site=a.site,
                             team=a.owner if a.in_cmdb else "", owned=a.in_cmdb and a.owner in chart,
                             in_cmdb=a.in_cmdb, scanned=bool(a.scanned_by), is_ot=a.is_ot,
                             criticality=a.criticality))
    rc_by_id = {r.rc_id: r for r in res.root_causes}
    earlier = _first_imported(db, ds.id)
    for f in res.findings:
        a = res.assets[f.asset_id]
        fp = ingest.fingerprint(f)
        rc = rc_by_id.get(f.root_cause_id)
        db.add(Observation(dataset_id=ds.id, asset_id=f.asset_id, fingerprint=fp[:400],
                           team=a.owner if a.in_cmdb else "", site=a.site, title=f.title, severity=f.severity,
                           cves=list(f.cves), rc_key=(rc.key if rc else "")[:400], rc_title=rc.title if rc else "",
                           first_seen=f.first_seen, last_seen=f.last_seen,
                           first_imported_at=earlier.get((f.asset_id, fp[:400]), ds.created_at)))
    unowned = sum(1 for a in res.assets.values() if not (a.in_cmdb and a.owner in chart))
    summary = {"assets": len(res.assets), "scanned": sum(1 for a in res.assets.values() if a.scanned_by),
               "findings": len(res.findings), "root_causes": len(res.root_causes), "unowned_assets": unowned,
               "ale_mean": round(res.portfolio.get("ale_mean", 0.0))}
    ds.as_of, ds.summary = res.as_of, summary
    db.flush()
    return summary


def previous(db: Session, ds: Dataset) -> Dataset | None:
    return db.scalars(select(Dataset).where(Dataset.id < ds.id).order_by(Dataset.id.desc())).first()


def compare(db: Session, old: Dataset, new: Dataset, allowed: Callable[[str, str], bool]) -> dict:
    """What changed from ``old`` to ``new``, per team, for the teams and sites ``allowed(team, site)`` admits.

    A finding missing from the newer import counts as fixed only if its host was scanned in the newer import;
    otherwise it is "not rescanned", because absence of evidence is not a fix.
    """
    def rows(ds):
        return {(o.asset_id, o.fingerprint): o for o in db.scalars(select(Observation)
                                                                    .where(Observation.dataset_id == ds.id))}

    before, after = rows(old), rows(new)
    snaps = {s.asset_id: s for s in db.scalars(select(AssetSnapshot).where(AssetSnapshot.dataset_id == new.id))}
    teams: dict[str, dict[str, list]] = defaultdict(lambda: {"fixed": [], "new": [], "still_open": [],
                                                               "not_rescanned": []})

    def item(o: Observation, host: str) -> dict:
        return {"asset_id": o.asset_id, "host": host, "title": o.title, "severity": o.severity, "cves": o.cves,
                "root_cause": o.rc_title, "first_seen": o.first_seen.isoformat() if o.first_seen else None,
                "first_imported_at": o.first_imported_at.isoformat(timespec="seconds")}

    old_hosts = {s.asset_id: s.hostname for s in db.scalars(select(AssetSnapshot)
                                                           .where(AssetSnapshot.dataset_id == old.id))}
    for key in before.keys() | after.keys():
        o_new, o_old = after.get(key), before.get(key)
        o = o_new or o_old
        snap = snaps.get(o.asset_id)
        team = (snap.team if snap else o.team) or NO_TEAM
        site = snap.site if snap else o.site
        if not allowed("" if team == NO_TEAM else team, site):
            continue
        host = (snap.hostname if snap else old_hosts.get(o.asset_id, "")) or o.asset_id
        if o_new and o_old:
            teams[team]["still_open"].append(item(o_new, host))
        elif o_new:
            teams[team]["new"].append(item(o_new, host))
        elif snap is not None and snap.scanned:
            teams[team]["fixed"].append(item(o_old, host))
        else:
            teams[team]["not_rescanned"].append(item(o_old, host))

    out = []
    for team in sorted(teams, key=lambda t: (t == NO_TEAM, t)):
        groups = teams[team]
        for v in groups.values():
            v.sort(key=lambda x: (x["host"], x["title"]))
        out.append({"team": team, **{k: len(v) for k, v in groups.items()}, "items": groups})
    totals = {k: sum(t[k] for t in out) for k in ("fixed", "new", "still_open", "not_rescanned")}
    return {"from": dataset_json(old), "to": dataset_json(new), "totals": totals, "teams": out}


def dataset_json(ds: Dataset) -> dict:
    return {"id": ds.id, "org": ds.org_name, "kind": ds.kind, "current": ds.is_current,
            "as_of": ds.as_of.isoformat() if ds.as_of else None,
            "imported_at": ds.created_at.isoformat(timespec="seconds"), "summary": ds.summary or {}}
