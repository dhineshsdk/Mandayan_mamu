"""End-to-end run: ingest -> resolve assets -> dedupe -> group by root cause -> SSVC + rupee risk."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from . import ingest, risk, rootcause
from .model import Asset, Finding, RootCause


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


def run(files: list[Path], cmdb: Path | None = None, org: str = "", intel_path: Path | None = None) -> Result:
    """Analyse any mix of Qualys CSV, Tenable CSV and .nessus files; the format is detected from content.

    A CMDB or ownership chart among ``files`` is recognised too, so a whole export folder can be passed.
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
    as_of = max(f.last_seen for f in findings if f.last_seen) if any(f.last_seen for f in findings) else date.today()

    rcs = rootcause.group(assets, findings)
    portfolio = risk.assess(rcs, assets, findings, risk.load_intel(intel_path), as_of)

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
