"""Team scorecards and the CISO dashboard (M-CSO): backlog, time to fix and SLA breaches, by team and by plant.

Every number is counted from the current import and from jobs; nothing is estimated.

- Backlog: findings in the current import on the team's assets, by SSVC, and how many have no job open for them
  (no fix in progress and no risk acceptance in force).
- Oldest open finding: days from the scanner first reporting it to the current import's scan date.
- Time to fix: for jobs a rescan proved fixed, the days from the scanner first reporting the job's findings to the
  scan that no longer reported them (median). It measures exposure, not how fast Sutra's approvals ran.
- On time: of the jobs proved fixed, how many were proved by their fix due date.
- SLA breaches: jobs that missed their fix due date without a rescan proving the fix (``sutra.app.sla``).

What a person sees is limited to their M-CSO scope: a team manager their own teams, a vertical head their
vertical, the CISO the whole organisation.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date
from statistics import median

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import patch
from ..pipeline import Result
from . import drafting
from .access import Principal
from .jobs import OPEN
from .models import AssetSnapshot, Dataset, Job, Observation, OwnershipTeam

CSO = "M-CSO"
SSVC = ("Act", "Attend", "Track*", "Track")


def _job_first_seen(db: Session, jobs: list[Job]) -> dict[int, date]:
    """Earliest scanner first-seen date of each job's findings, from the import the job was raised from."""
    out: dict[int, date] = {}
    for job in jobs:
        d = db.scalar(select(func.min(Observation.first_seen))
                      .where(Observation.dataset_id == job.dataset_id, Observation.rc_key == job.rc_key,
                             Observation.asset_id.in_(job.hosts)))
        if d is not None:
            out[job.id] = d
    return out


def _job_sites(db: Session, jobs: list[Job]) -> dict[int, set[str]]:
    by_ds: dict[int, list[Job]] = defaultdict(list)
    for j in jobs:
        by_ds[j.dataset_id].append(j)
    out: dict[int, set[str]] = {}
    for ds, js in by_ds.items():
        site = dict(db.execute(select(AssetSnapshot.asset_id, AssetSnapshot.site)
                               .where(AssetSnapshot.dataset_id == ds)).all())
        for j in js:
            out[j.id] = {site[h] for h in j.hosts if site.get(h)}
    return out


def _blank() -> dict:
    return {"open_findings": 0, "by_ssvc": dict.fromkeys(SSVC, 0), "without_job": 0, "oldest_days": None,
            "jobs_open": 0, "awaiting_approval": 0, "overdue": 0, "breaches": 0, "accepted": 0, "fixed": 0,
            "fixed_on_time": 0, "_ttf": []}


def _finish(row: dict) -> dict:
    ttf = row.pop("_ttf")
    row["median_days_to_fix"] = round(median(ttf)) if ttf else None
    row["on_time_pct"] = round(100 * row["fixed_on_time"] / row["fixed"]) if row["fixed"] else None
    return row


def build(db: Session, p: Principal, res: Result | None) -> dict:
    today = drafting.today()
    chart = {t.team: t for t in db.scalars(select(OwnershipTeam))}
    teams: dict[str, dict] = defaultdict(_blank)
    plants: dict[str, dict] = defaultdict(_blank)
    org = _blank()

    def in_scope(team: str, site: str = "") -> bool:
        return p.allowed(CSO, "view", team, site)

    jobs = [j for j in db.scalars(select(Job)) if in_scope(j.team)]
    sites = _job_sites(db, jobs)
    covered: set[tuple[str, str]] = set()  # (rc_key, team) with a fix in progress or a risk acceptance in force
    for j in jobs:
        if (j.mode != "exception" and j.status in OPEN) or (j.mode == "exception" and j.status == "accepted"):
            covered.add((j.rc_key, j.team))

    if res is not None:
        rc_by_id = {r.rc_id: r for r in res.root_causes}
        for f in res.findings:
            a = res.assets[f.asset_id]
            team = patch.team_of(a)
            if not in_scope(team, a.site):
                continue
            rc = rc_by_id.get(f.root_cause_id)
            age = (res.as_of - f.first_seen).days if f.first_seen and res.as_of else None
            rows = [teams[team], org] + ([plants[a.site]] if a.site else [])
            for row in rows:
                row["open_findings"] += 1
                if rc is not None:
                    row["by_ssvc"][rc.ssvc] = row["by_ssvc"].get(rc.ssvc, 0) + 1
                if rc is None or (rc.key, team) not in covered:
                    row["without_job"] += 1
                if age is not None and (row["oldest_days"] is None or age > row["oldest_days"]):
                    row["oldest_days"] = age

    fixed = [j for j in jobs if j.status == "verified-fixed" and j.fixed_on]
    first = _job_first_seen(db, fixed)
    for j in jobs:
        rows = [teams[j.team], org] + [plants[s] for s in sorted(sites.get(j.id, ()))]
        for row in rows:
            if j.mode == "exception":
                row["accepted"] += j.status == "accepted"
                continue
            if j.status in OPEN:
                row["jobs_open"] += 1
                row["awaiting_approval"] += j.status in ("drafting", "pending")
                row["overdue"] += bool(j.due_on and j.due_on < today)
            row["breaches"] += j.sla_breached_at is not None
            if j.status == "verified-fixed" and j.fixed_on:
                row["fixed"] += 1
                row["fixed_on_time"] += bool(j.due_on and j.fixed_on <= j.due_on)
                if j.id in first:
                    row["_ttf"].append((j.fixed_on - first[j.id]).days)

    team_rows = []
    for name in sorted(teams):
        t = chart.get(name)
        team_rows.append({"team": name, "vertical": t.vertical if t else "", "manager": t.manager_name if t else "",
                          **_finish(teams[name])})
    return {
        "as_of": res.as_of.isoformat() if res and res.as_of else None,
        "org_wide": p.is_org_wide(CSO),
        "totals": _finish(org),
        "teams": team_rows,
        "plants": [{"site": s, **_finish(plants[s])} for s in sorted(plants)],
        "trend": trend(db, p, res),
    }


def trend(db: Session, p: Principal, res: Result | None, limit: int = 12) -> list[dict]:
    """Open findings in scope at each import of this organisation, oldest first."""
    if res is None:
        return []
    current = db.scalars(select(Dataset).where(Dataset.is_current.is_(True))).first()
    if current is None:
        return []
    ds = list(db.scalars(select(Dataset).where(Dataset.org_name == current.org_name)
                         .order_by(Dataset.as_of.desc(), Dataset.id.desc()).limit(limit)))
    out = []
    for d in reversed(ds):
        rows = db.execute(select(Observation.team, Observation.site, func.count())
                          .where(Observation.dataset_id == d.id).group_by(Observation.team, Observation.site)).all()
        n = sum(c for team, site, c in rows if p.allowed(CSO, "view", team or patch.UNOWNED, site))
        out.append({"dataset": d.id, "as_of": d.as_of.isoformat() if d.as_of else None, "open_findings": n})
    return out
