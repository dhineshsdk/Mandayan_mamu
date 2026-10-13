"""Detections as a Sutra rows file (``sutra-rows`` version 1, JSON lines), which Sutra's Import data page reads like
any scanner export. The keys and their meaning are those of ``sutra/ingest`` (``ROW_KEYS``); the importer rejects a
file that lacks one, and ``tests/test_rows.py`` checks the same list here."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from .inventory import Inventory
from .match import Detection, MatchResult

HEADER = "sutra-rows"
SCANNER = "Sutra Scan"
ROW_KEYS = ("scanner", "ref", "file", "row", "ip", "host", "os", "title", "severity", "cvss", "cves", "port",
            "evidence", "solution", "first", "last", "package", "installed", "fixed", "control",
            "credential_fp", "kind")


def _evidence(d: Detection, result: MatchResult) -> str:
    f = result.feed
    how = f"CVSS {d.cvss}" if d.rated_by == "cvss" else d.rated_by
    fix = f"fixed in {d.fixed}" if d.fixed else "no fixed version published"
    src = f" (source package {d.source})" if d.source else ""
    return (f"{d.package}{src} {d.installed} is affected by {d.advisory}; {fix}. Severity {d.severity} ({how}). "
            f"Matched against {d.ecosystem} advisories from OSV, newest advisory in the snapshot "
            f"{f['data_as_of'][:10]}, snapshot digest {f['digest'][:12]}. {d.url}")


def to_rows(inv: Inventory, result: MatchResult, *, source: str = "") -> list[dict]:
    """One info row proving the host was scanned, then one package row per detection."""
    source = source or f"sutra-scan:{inv.hostname or 'host'}"
    last = None
    if inv.collected_at:
        last = datetime.fromisoformat(inv.collected_at.replace("Z", "+00:00")).date().isoformat()
    common = dict(scanner=SCANNER, file=source, ip=(inv.ips[0] if inv.ips else ""), host=inv.hostname,
                  os=inv.os.pretty_name or inv.os.id, port="", first=None, last=last, control="", credential_fp="")
    rows = [dict(common, ref="host", row="host", title=f"Host assessed by {SCANNER}", severity="info", cvss=None,
                 cves=[], evidence=f"{len(inv.packages)} installed packages checked", solution="", package="",
                 installed="", fixed="", kind="info")]
    for d in result.detections:
        rows.append(dict(common, ref=d.advisory, row=f"{d.advisory}:{d.package}:{d.installed}",
                         title=f"{d.package} {d.installed}: {d.summary or d.advisory}", severity=d.severity,
                         cvss=d.cvss, cves=list(d.cves), evidence=_evidence(d, result),
                         solution=(f"Upgrade {d.package} to {d.fixed} or later." if d.fixed
                                   else f"No fixed version of {d.package} is published yet. Mitigate or remove it."),
                         package=d.package, installed=d.installed, fixed=d.fixed, kind="package"))
    return rows


def write(path: str | Path, rows: Iterable[dict], source: str) -> int:
    n = 0
    with Path(path).open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"format": HEADER, "version": 1, "source": source}) + "\n")
        for r in rows:
            fh.write(json.dumps({k: r[k] for k in ROW_KEYS}) + "\n")
            n += 1
    return n
