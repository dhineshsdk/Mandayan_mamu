"""Turn connector findings into the row dicts Sutra's ingest pipeline consumes.

The file importers in ``sutra/ingest/__init__.py`` build each row with ``_raw()``: classify the finding as a
package, config or credential problem with ``sutra.ingest.normalize``, then pack the fields into a dict. This module
builds the same dict from a :class:`ScannerFinding`, so ``resolve_assets``, ``dedupe`` and root-cause grouping treat
API data exactly like an exported file. ``tests/test_sutra_rows.py`` checks the two stay identical whenever the
``sutra`` package is importable.

The receipt fields map as: ``file`` is the connector source (for example ``qualys-api:<host>``) and ``row`` is the
detection's ``record_id``. Two keys the file importers do not set are added: ``state`` (open, reopened, fixed) and
``last_fixed``, which fix verification will need.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from importlib import import_module
from types import ModuleType

from .models import STATE_FIXED, ScannerFinding

_PACKAGE_PARSERS = {"Qualys": "package_from_qualys", "Tenable": "package_from_tenable"}


def _normalize() -> ModuleType:
    try:
        return import_module("sutra.ingest.normalize")
    except ImportError as exc:  # pragma: no cover - depends on how the app is installed
        raise ImportError("sutra_connectors.sutra_rows needs the sutra application package on the import path") from exc


def _short(hostname: str) -> str:
    return (hostname or "").split(".")[0].strip().lower()


def to_sutra_row(f: ScannerFinding, nz: ModuleType | None = None) -> dict:
    """One finding as a Sutra ingest row (same keys and values as ``sutra.ingest._raw``)."""
    nz = nz or _normalize()
    fields = {"kind": "info"} if f.severity == "info" else nz.classify(f.title, f.evidence)
    pkg = inst = fixed = ""
    if fields["kind"] == "other":
        pkg, inst, fixed = getattr(nz, _PACKAGE_PARSERS[f.scanner])(f.title, f.evidence)
        if pkg:
            fields["kind"] = "package"
    return dict(scanner=f.scanner, ref=f.scanner_ref, file=f.source, row=f.record_id, ip=f.ip.strip(),
                host=_short(f.hostname), os=f.os, title=f.title, severity=f.severity, cvss=f.cvss,
                cves=nz.cves(" ".join(f.cves)), port=f.port, evidence=f.evidence.strip(), solution=f.solution,
                first=f.first_seen.date() if f.first_seen else None,
                last=f.last_seen.date() if f.last_seen else None, package=pkg, installed=inst, fixed=fixed,
                control=fields.get("control", ""), credential_fp=fields.get("credential_fp", ""),
                kind=fields["kind"], state=f.state, last_fixed=f.last_fixed.date() if f.last_fixed else None)


def to_sutra_rows(findings: Iterable[ScannerFinding], *, include_fixed: bool = False) -> Iterator[dict]:
    """Rows for the ingest pipeline. Fixed detections are left out unless ``include_fixed`` is set, because the
    current pipeline treats every row as an open finding."""
    nz = _normalize()
    for f in findings:
        if f.state == STATE_FIXED and not include_fixed:
            continue
        yield to_sutra_row(f, nz)
