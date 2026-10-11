"""End-to-end run: ingest -> resolve assets -> dedupe -> group by root cause -> SSVC + rupee risk."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path

from . import ingest, risk, rootcause
from .model import SEVERITY_ORDER, Asset, Finding, RootCause


@dataclass
class Result:
    org: str
    as_of: date
    sources: dict[str, int]
    raw_rows: int
    assets: dict[str, Asset]
    findings: list[Finding]
    root_causes: list[RootCause]
    portfolio: dict
    coverage: dict = field(default_factory=dict)


def run(files: list[Path], cmdb: Path | None = None, org: str = "", intel_path: Path | None = None,
        known_first_seen: dict[tuple[str, str], date] | None = None, intel: dict | None = None) -> Result:
    """Analyse any mix of Qualys CSV, Tenable CSV and .nessus files; the format is detected from content.

    A CMDB or ownership chart among ``files`` is recognised too, so a whole export folder can be passed.
    ``known_first_seen`` maps (asset_id, fingerprint) to the earliest first-seen date from earlier imports, so a
    finding's age (and its CEA clock) does not reset when a scanner export lacks history.
    ``intel`` (CVE -> exploitation details) overrides the file at ``intel_path``; the server passes its live feeds.
    """
    cmdb_assets = ingest.load_cmdb(cmdb) if cmdb else []
    raws, sources = [], {}
    for p in files:
        fmt = ingest.detect_format(p)
        if fmt not in ingest.LOADERS:
            if fmt == "cmdb" and not cmdb_assets:
                cmdb_assets = ingest.load_cmdb(p)
            continue  # ownership charts and duplicate CMDBs are not scanner findings
        rows = ingest.LOADERS[fmt](p)
        sources[p.name] = sum(1 for r in rows if r["kind"] != "info")
        raws += rows
    if not raws:
        raise SystemExit("No findings found in the given exports.")

    assets = ingest.resolve_assets(cmdb_assets, raws)
    findings = ingest.dedupe(raws)
    for f in findings if known_first_seen else ():
        earlier = known_first_seen.get((f.asset_id, ingest.fingerprint(f)))
        if earlier and (f.first_seen is None or earlier < f.first_seen):
            f.first_seen = earlier
    as_of = max(f.last_seen for f in findings if f.last_seen) if any(f.last_seen for f in findings) else date.today()

    rcs = rootcause.group(assets, findings)
    portfolio = risk.assess(rcs, assets, findings, intel if intel is not None else risk.load_intel(intel_path), as_of)

    rcs.sort(key=lambda r: (-r.ale_mean, risk.SSVC_ORDER[r.ssvc]))
    for i, rc in enumerate(rcs, start=1):
        rc.rc_id = f"RC-{i:03d}"
    by_id = {f.finding_id: f for f in findings}
    for rc in rcs:
        for fid in rc.finding_ids:
            by_id[fid].root_cause_id = rc.rc_id

    in_cmdb = [a for a in assets.values() if a.in_cmdb]
    unscanned = [a for a in in_cmdb if not a.scanned_by]
    coverage = {
        "cmdb_assets": len(in_cmdb),
        "scanned_assets": sum(1 for a in assets.values() if a.scanned_by),
        "unscanned": sorted(unscanned, key=lambda a: (-a.criticality, a.hostname)),
        "unknown": sorted((a for a in assets.values() if not a.in_cmdb), key=lambda a: a.hostname),
        "inferred_images": sorted((a for a in assets.values() if a.image_source.startswith("inferred")),
                                  key=lambda a: a.hostname),
        "multi_scanner_findings": sum(1 for f in findings if len(f.scanners) > 1),
    }
    return Result(org=org, as_of=as_of, sources=sources, raw_rows=sum(sources.values()), assets=assets,
                  findings=findings, root_causes=rcs, portfolio=portfolio, coverage=coverage)


def restrict(res: Result, asset_ids: set[str], intel: dict) -> Result:
    """The same analysis seen through a scope: only these assets, with risk re-computed for them.

    Root causes keep their IDs and titles; their hosts, findings and rupee risk shrink to the scope.
    """
    if asset_ids >= set(res.assets):
        return res
    assets = {k: a for k, a in res.assets.items() if k in asset_ids}
    findings = [f for f in res.findings if f.asset_id in asset_ids]
    kept = {f.finding_id for f in findings}
    by_id = {f.finding_id: f for f in findings}
    rcs = []
    for rc in res.root_causes:
        fids = [f for f in rc.finding_ids if f in kept]
        if not fids:
            continue
        members = [by_id[f] for f in fids]
        sub = replace(rc, finding_ids=fids, asset_ids=sorted({f.asset_id for f in members}),
                      cves=sorted({c for f in members for c in f.cves}),
                      max_severity=max((f.severity for f in members), key=SEVERITY_ORDER.get),
                      max_cvss=max((f.cvss or 0.0 for f in members), default=0.0),
                      risk_inputs={})
        sub.is_ot = any(assets[a].is_ot for a in sub.asset_ids)
        rcs.append(sub)
    portfolio = risk.assess(rcs, assets, findings, intel, res.as_of) if rcs else {
        "ale_mean": 0.0, "ale_p10": 0.0, "ale_p90": 0.0, "iterations": 0}
    rcs.sort(key=lambda r: (-r.ale_mean, risk.SSVC_ORDER[r.ssvc]))
    cov = res.coverage
    coverage = {
        "cmdb_assets": sum(1 for a in assets.values() if a.in_cmdb),
        "scanned_assets": sum(1 for a in assets.values() if a.scanned_by),
        "unscanned": [a for a in cov["unscanned"] if a.asset_id in asset_ids],
        "unknown": [a for a in cov["unknown"] if a.asset_id in asset_ids],
        "inferred_images": [a for a in cov["inferred_images"] if a.asset_id in asset_ids],
        "multi_scanner_findings": sum(1 for f in findings if len(f.scanners) > 1),
    }
    sources = dict(res.sources)
    return Result(org=res.org, as_of=res.as_of, sources=sources, raw_rows=sum(len(f.sources) for f in findings),
                  assets=assets, findings=findings, root_causes=rcs, portfolio=portfolio, coverage=coverage)
