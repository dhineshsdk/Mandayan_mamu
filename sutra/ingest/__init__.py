"""Readers for Qualys and Tenable exports and the CMDB, plus asset resolution and dedupe."""

from __future__ import annotations

import csv
import xml.etree.ElementTree as ET
from datetime import date, datetime
from pathlib import Path

from ..model import SEVERITY_ORDER, Asset, Finding, SourceRef
from . import normalize as nz


def _short(hostname: str) -> str:
    return (hostname or "").split(".")[0].strip().lower()


def load_cmdb(path: Path) -> list[Asset]:
    assets = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            assets.append(Asset(
                asset_id=r["asset_id"], hostname=_short(r["hostname"]), ip=r["ip"].strip(), site=r.get("site", ""),
                zone=r.get("zone", "corp") or "corp", os=r.get("os", ""), owner=r.get("owner", ""),
                business_process=r.get("business_process", ""), inr_per_hour=float(r.get("inr_per_hour") or 0),
                criticality=int(r.get("criticality") or 3), image=r.get("image", ""),
                image_source="cmdb" if r.get("image") else "", config_template=r.get("config_template", ""),
                is_ot=r.get("is_ot") == "1", safety_critical=r.get("safety_critical") == "1",
                personal_data=r.get("personal_data") == "1"))
    return assets


def _parse_date(value: str, fmts: list[str]) -> date | None:
    value = (value or "").replace(" UTC", "").strip()
    for fmt in fmts:
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def _raw(scanner, ref, path, row_no, ip, host, os_name, title, severity, cvss, cve_text, port, text, solution,
         first, last, package_fn) -> dict:
    fields = {"kind": "info"} if severity == "info" else nz.classify(title, text)
    pkg = inst = fixed = ""
    if fields["kind"] == "other":
        pkg, inst, fixed = package_fn(title, text)
        if pkg:
            fields["kind"] = "package"
    return dict(scanner=scanner, ref=str(ref), file=path.name, row=row_no, ip=ip.strip(), host=_short(host),
                os=os_name, title=title, severity=severity, cvss=float(cvss) if cvss else None,
                cves=nz.cves(cve_text), port=str(port), evidence=text.strip(), solution=solution, first=first,
                last=last, package=pkg, installed=inst, fixed=fixed, control=fields.get("control", ""),
                credential_fp=fields.get("credential_fp", ""), kind=fields["kind"])


def load_qualys(path: Path) -> list[dict]:
    """Qualys VM report CSV. Skips Qualys' preamble lines until the header row."""
    out = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = None
        for line_no, row in enumerate(reader, start=1):
            if header is None:
                if row[:1] == ["IP"] and "QID" in row:
                    header = row
                continue
            if not row or not any(row):
                continue
            r = dict(zip(header, row))
            fmts = ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d"]
            out.append(_raw("Qualys", f"QID {r['QID']}", path, line_no, r["IP"], r.get("DNS") or r.get("NetBIOS", ""),
                            r.get("OS", ""), r["Title"], nz.severity_from_qualys(r["Severity"]),
                            r.get("CVSS3.1 Base") or r.get("CVSS Base"), r.get("CVE ID", ""), r.get("Port", ""),
                            r.get("Results", ""), r.get("Solution", ""), _parse_date(r.get("First Detected"), fmts),
                            _parse_date(r.get("Last Detected"), fmts), nz.package_from_qualys))
    if not out and header is None:
        raise ValueError(f"{path}: no Qualys header row (expected a row starting with \"IP\" and containing \"QID\")")
    return out


def _pick(r: dict, *names: str) -> str:
    for n in names:
        if r.get(n):
            return r[n]
    return ""


def load_tenable(path: Path) -> list[dict]:
    """Tenable.sc, Tenable.io or Nessus vulnerability CSV export (column names differ slightly between them)."""
    out = []
    fmts = ["%b %d, %Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"]
    with path.open(newline="", encoding="utf-8-sig") as f:
        for line_no, r in enumerate(csv.DictReader(f), start=2):
            sev = _pick(r, "Severity", "Risk") or "Info"
            sev = "info" if sev.strip().lower() in ("none", "") else sev
            out.append(_raw("Tenable", f"Plugin {_pick(r, 'Plugin', 'Plugin ID')}", path, line_no,
                            _pick(r, "IP Address", "Host", "IP"), _pick(r, "DNS Name", "FQDN", "NetBIOS Name", "Host"),
                            "", _pick(r, "Plugin Name", "Name"), nz.severity_from_tenable(sev),
                            _pick(r, "CVSS V3 Base Score", "CVSS v3.0 Base Score", "CVSS v2.0 Base Score"),
                            _pick(r, "CVE"), _pick(r, "Port"), _pick(r, "Plugin Output", "Plugin Text"),
                            _pick(r, "Solution"), _parse_date(_pick(r, "First Discovered", "First Seen"), fmts),
                            _parse_date(_pick(r, "Last Observed", "Last Seen"), fmts), nz.package_from_tenable))
    return out


NESSUS_SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def load_nessus(path: Path) -> list[dict]:
    """Nessus / Tenable .nessus XML (NessusClientData_v2). It carries no first-seen date per finding."""
    out = []
    tree = ET.parse(path)
    for host in tree.iter("ReportHost"):
        tags = {t.get("name"): (t.text or "") for t in host.iter("tag")}
        ip = tags.get("host-ip") or host.get("name", "")
        name = tags.get("host-fqdn") or tags.get("netbios-name") or tags.get("hostname") or ""
        scanned = _parse_date(tags.get("HOST_START", "").replace("  ", " "), ["%a %b %d %H:%M:%S %Y"])
        for n, item in enumerate(host.iter("ReportItem"), start=1):
            text = lambda tag: (item.findtext(tag) or "")
            out.append(_raw("Tenable", f"Plugin {item.get('pluginID')}", path, n, ip, name,
                            tags.get("operating-system", ""), item.get("pluginName", ""),
                            NESSUS_SEVERITY.get(item.get("severity", "0"), "info"),
                            text("cvss3_base_score") or text("cvss_base_score"),
                            " ".join(c.text or "" for c in item.findall("cve")), item.get("port", ""),
                            text("plugin_output"), text("solution"), None, scanned, nz.package_from_tenable))
            out[-1]["row"] = f"{ip} item {n}"
    return out


def detect_format(path: Path) -> str:
    """qualys | tenable | nessus | cmdb, from the file's first bytes."""
    head = path.read_bytes()[:20000].decode("utf-8", "ignore")
    if "NessusClientData_v2" in head:
        return "nessus"
    first_lines = head.splitlines()[:30]
    for line in first_lines:
        cols = [c.strip().strip('"') for c in line.split(",")]
        if cols[:1] == ["IP"] and "QID" in cols:
            return "qualys"
        if "Plugin" in cols or "Plugin ID" in cols:
            return "tenable"
        if "asset_id" in cols and "hostname" in cols:
            return "cmdb"
    raise ValueError(f"{path.name}: not a Qualys CSV, Tenable CSV, .nessus file or CMDB CSV")


LOADERS = {"qualys": load_qualys, "tenable": load_tenable, "nessus": load_nessus}


def resolve_assets(cmdb: list[Asset], raws: list[dict]) -> dict[str, Asset]:
    """Match each scanner row to a CMDB asset by IP, then hostname; unknown hosts become new assets."""
    by_id = {a.asset_id: a for a in cmdb}
    by_ip = {a.ip: a for a in cmdb}
    by_host = {a.hostname: a for a in cmdb if a.hostname}
    unknown = 0
    for r in raws:
        a = by_ip.get(r["ip"]) or by_host.get(r["host"])
        if a is None:
            unknown += 1
            a = Asset(asset_id=f"UNK-{unknown:04d}", hostname=r["host"], ip=r["ip"], os=r.get("os", ""),
                      in_cmdb=False, owner="(unknown: not in CMDB)")
            by_id[a.asset_id] = a
            by_ip[a.ip] = a
            if a.hostname:
                by_host[a.hostname] = a
        if not a.os and r.get("os"):
            a.os = r["os"]
        a.scanned_by.add(r["scanner"])
        r["asset_id"] = a.asset_id
    return by_id


def _dedupe_key(r: dict) -> tuple:
    if r["kind"] == "credential":
        return ("cred", r["credential_fp"])
    if r["kind"] == "config":
        return ("config", r["control"])
    if r["kind"] == "package":
        return ("pkg", r["package"].lower(), nz.strip_epoch(r["fixed"]))
    return ("other", tuple(r["cves"]) or r["title"].lower())


def dedupe(raws: list[dict]) -> list[Finding]:
    """Collapse rows that describe the same problem on the same asset, across scanners.

    Informational rows are dropped here, after resolve_assets has used them to mark hosts as scanned.

    Two rows merge when they share an asset and either the same normalized key or an overlapping CVE.
    """
    raws = [r for r in raws if r["kind"] != "info"]  # scan-information rows only prove a host was scanned
    findings: list[Finding] = []
    by_key: dict[tuple, Finding] = {}
    by_cve: dict[tuple, Finding] = {}
    for r in raws:
        key = (r["asset_id"],) + _dedupe_key(r)
        f = by_key.get(key)
        if f is None:
            for c in r["cves"]:
                f = by_cve.get((r["asset_id"], c))
                if f:
                    break
        src = SourceRef(r["scanner"], r["ref"], r["file"], r["row"])
        if f is None:
            f = Finding(finding_id=f"F-{len(findings) + 1:05d}", asset_id=r["asset_id"], title=r["title"],
                        severity=r["severity"], cvss=r["cvss"], cves=list(r["cves"]), port=r["port"], kind=r["kind"],
                        package=r["package"], installed=r["installed"], fixed=nz.strip_epoch(r["fixed"]),
                        control=r["control"], credential_fp=r["credential_fp"], first_seen=r["first"] or r["last"],
                        last_seen=r["last"], evidence=r["evidence"], solution=r["solution"], sources=[src])
            findings.append(f)
        else:
            f.sources.append(src)
            f.cves = sorted(set(f.cves) | set(r["cves"]))
            if SEVERITY_ORDER[r["severity"]] > SEVERITY_ORDER[f.severity]:
                f.severity = r["severity"]
            if r["cvss"] and (f.cvss is None or r["cvss"] > f.cvss):
                f.cvss = r["cvss"]
            first = r["first"] or r["last"]
            if first and (f.first_seen is None or first < f.first_seen):
                f.first_seen = first
            if r["last"] and (f.last_seen is None or r["last"] > f.last_seen):
                f.last_seen = r["last"]
        by_key[key] = f
        for c in r["cves"]:
            by_cve[(r["asset_id"], c)] = f
    return findings
