"""Readers for image and filesystem scan reports: Trivy JSON (``trivy image|fs|rootfs|vm --format json``) and
Grype JSON (``grype <target> -o json``).

These scanners look at one artifact (a container or VM image, a directory, an SBOM) rather than a host on the
network. Each report becomes one asset named after the artifact (its first repository tag when it has one), with
no IP address. The asset's image is set to the same name, so when the CMDB lists hosts built from that image under
the same name, the scanned image joins them in base-image root-cause grouping. A CMDB row whose ``hostname`` is the
artifact name gives the image an owner, criticality and rupee value.

Field names follow the scanners' own output models: Trivy's ``pkg/types/report.go`` and
``pkg/types/vulnerability.go`` (report ``SchemaVersion`` 2) and Grype's ``grype/presenter/models``
(``document.go``, ``match.go``, ``vulnerability.go``, ``vulnerability_metadata.go``, ``source.go``).

Both scanners report every vulnerability as a flaw in a named package at an installed version, so every row is a
package finding. Severities map one to one, except Trivy ``UNKNOWN`` and Grype ``Unknown`` and ``Negligible``,
which become ``low`` (they are real matches, so they are kept rather than dropped as informational).
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from . import normalize as nz

TRIVY_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}
GRYPE_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "low",
                  "unknown": "low"}
# Trivy marks a vulnerability "not_affected" only when a VEX statement says the package is not affected.
TRIVY_SKIP_STATUS = {"not_affected"}


def _day(value) -> date | None:
    """The date part of an RFC 3339 timestamp. Go writes up to nine fractional digits, so only the date is parsed."""
    try:
        return date.fromisoformat(str(value or "")[:10])
    except ValueError:
        return None


def artifact_key(name: str) -> str:
    """How an artifact is named on its asset: lower case, kept whole (``ingest._short`` keeps image names whole)."""
    return (name or "").strip().lower()


def _row(scanner, ref, path, row, artifact, os_name, title, severity, cvss, cves, evidence, solution, last,
         pkg, installed, fixed) -> dict:
    host = artifact_key(artifact)
    return dict(scanner=scanner, ref=ref, file=path.name, row=row, ip="", host=host, os=os_name, title=title,
                severity=severity, cvss=cvss, cves=cves, port="", evidence=evidence, solution=solution, first=None,
                last=last, package=pkg, installed=nz.strip_epoch(installed), fixed=nz.strip_epoch(fixed), control="",
                credential_fp="", kind="package", image=host)


def _solution(pkg: str, fixed: str, state: str) -> str:
    if fixed:
        return f"Upgrade {pkg} to {fixed} or later and rebuild the image."
    return f"No fixed version of {pkg} is published yet ({state or 'no fix'}). Remove the package or mitigate."


def _load_json(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name}: not valid JSON ({exc})") from exc
    if not isinstance(doc, dict):
        raise ValueError(f"{path.name}: expected a JSON object")
    return doc


def _trivy_cvss(v: dict) -> float | None:
    """The score from the source Trivy took the severity from, else NVD, else any source; CVSS v3 first."""
    scores = v.get("CVSS") or {}
    order = [v.get("SeveritySource"), "nvd", *sorted(scores)]
    for key in ("V3Score", "V40Score", "V2Score"):
        for src in order:
            s = (scores.get(src) or {}).get(key) if src else None
            if s:
                return float(s)
    return None


def trivy_artifact(doc: dict) -> str:
    meta = doc.get("Metadata") or {}
    tags = meta.get("RepoTags") or []
    return tags[0] if tags else doc.get("ArtifactName", "")


def load_trivy(path: Path) -> list[dict]:
    doc = _load_json(path)
    if doc.get("SchemaVersion") != 2:
        raise ValueError(f"{path.name}: Trivy report schema version {doc.get('SchemaVersion')!r}; Sutra reads "
                         "version 2")
    artifact = trivy_artifact(doc)
    if not artifact:
        raise ValueError(f"{path.name}: Trivy report without an ArtifactName")
    os_info = (doc.get("Metadata") or {}).get("OS") or {}
    os_name = " ".join(x for x in (os_info.get("Family", ""), os_info.get("Name", "")) if x)
    scanned = _day(doc.get("CreatedAt"))
    out = []
    for result in doc.get("Results") or []:
        target = result.get("Target", "")
        for n, v in enumerate(result.get("Vulnerabilities") or [], start=1):
            if v.get("Status") in TRIVY_SKIP_STATUS:
                continue
            vid, pkg = v.get("VulnerabilityID", ""), v.get("PkgName", "")
            inst, fixed = v.get("InstalledVersion", ""), v.get("FixedVersion") or ""
            title = f"{vid} in {pkg} {inst}" + (f": {v['Title']}" if v.get("Title") else "")
            evidence = "\n".join(x for x in (
                f"Target: {target}", f"Package: {pkg} {inst}" + (f" ({v['PkgPath']})" if v.get("PkgPath") else ""),
                f"Fixed version: {fixed or 'none published'}", f"Status: {v.get('Status', '')}",
                f"Layer: {(v.get('Layer') or {}).get('DiffID', '')}" if v.get("Layer") else "") if x)
            out.append(_row("Trivy", vid, path, f"{target} #{n}", artifact, os_name, title,
                            TRIVY_SEVERITY.get(str(v.get("Severity", "")).upper(), "low"), _trivy_cvss(v),
                            nz.cves(" ".join([vid, *(v.get("VendorIDs") or [])])), evidence,
                            _solution(pkg, fixed, v.get("Status", "")), scanned, pkg, inst, fixed))
    return out


def _grype_cvss(meta: list[dict]) -> float | None:
    """Highest CVSS v3 base score across the vulnerability and its related records, else the highest of any."""
    best: dict[bool, float] = {}
    for m in meta:
        for c in m.get("cvss") or []:
            score = (c.get("metrics") or {}).get("baseScore")
            if score:
                v3 = str(c.get("version", "")).startswith("3")
                best[v3] = max(best.get(v3, 0.0), float(score))
    return best.get(True) or best.get(False)


def grype_artifact(doc: dict) -> str:
    src = doc.get("source") or {}
    target = src.get("target")
    if isinstance(target, dict):
        tags = target.get("tags") or []
        return target.get("userInput") or (tags[0] if tags else "") or target.get("imageID", "")
    return str(target or "")


def load_grype(path: Path) -> list[dict]:
    doc = _load_json(path)
    if not isinstance(doc.get("matches"), list):
        raise ValueError(f"{path.name}: Grype report without a matches list")
    artifact = grype_artifact(doc)
    if not artifact:
        raise ValueError(f"{path.name}: Grype report without a source target")
    distro = doc.get("distro") or {}
    os_name = " ".join(x for x in (distro.get("name", ""), distro.get("version", "")) if x)
    scanned = _day((doc.get("descriptor") or {}).get("timestamp"))
    out = []
    for n, m in enumerate(doc["matches"], start=1):
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        vid, pkg, inst = v.get("id", ""), a.get("name", ""), a.get("version", "")
        fix = v.get("fix") or {}
        suggested = [d.get("fix", {}).get("suggestedVersion") for d in m.get("matchDetails") or [] if d.get("fix")]
        fixed = next((s for s in suggested if s), "") or next(iter(fix.get("versions") or []), "")
        where = ", ".join(loc.get("path", "") for loc in a.get("locations") or [] if loc.get("path"))
        evidence = "\n".join(x for x in (
            f"Package: {pkg} {inst} ({a.get('type', '')})", f"Location: {where}" if where else "",
            f"Fixed version: {fixed or 'none published'}", f"Fix state: {fix.get('state', '')}") if x)
        title = f"{vid} in {pkg} {inst}"
        desc = v.get("description") or next((r.get("description") for r in related if r.get("description")), "")
        if desc:
            evidence += f"\n{desc}"
        out.append(_row("Grype", vid, path, f"match {n}", artifact, os_name, title,
                        GRYPE_SEVERITY.get(str(v.get("severity", "")).lower(), "low"), _grype_cvss([v, *related]),
                        nz.cves(" ".join([vid, *(r.get("id", "") for r in related)])), evidence,
                        _solution(pkg, fixed, fix.get("state", "")), scanned, pkg, inst, fixed))
    return out
