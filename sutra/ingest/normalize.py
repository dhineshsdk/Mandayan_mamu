"""Turn scanner-specific text into the common fields root-cause grouping needs.

Qualys and Tenable describe the same problem in different words. These helpers pull out
the package and versions, the misconfigured control, or the reused credential, so that
a finding from either scanner lands in the same shape.
"""

from __future__ import annotations

import re

# Misconfigurations, keyed by a stable control name. First match wins.
CONFIG_RULES = [
    (re.compile(r"\bSMBv1\b|\bSMB\)? Protocol Version 1\b", re.I), "SMBv1 enabled"),
    (re.compile(r"\bTLS (Protocol )?Version 1\.0|\bTLS 1\.0\b", re.I), "TLS 1.0/1.1 enabled"),
    (re.compile(r"SNMP.*(default community|\(public\))", re.I), "SNMP default community 'public'"),
    (re.compile(r"self-signed", re.I), "Self-signed TLS certificate"),
    (re.compile(r"HTTP TRACE", re.I), "HTTP TRACE enabled"),
]
CRED_TITLE = re.compile(r"default (vendor )?(credential|password)|password reuse|password reused", re.I)
CRED_FP = re.compile(r"Credential fingerprint\s*:\s*(\S+)", re.I)
ACCOUNT = re.compile(r"Account\s*:\s*(\S+)", re.I)

# "7-Zip Prior to 23.01 Multiple..." (Qualys) and "7-Zip < 23.01 Multiple..." (Tenable)
TITLE_PRIOR = re.compile(r"^(?P<pkg>.+?)\s+(?:Prior to|<)\s+(?P<fixed>[\w.\-:]+)")
QUALYS_PKG_TABLE = re.compile(r"^(?P<pkg>[\w.+\-]+)\t(?P<inst>\S+)\t(?P<fixed>\S+)$", re.M)
QUALYS_VERSION_IS = re.compile(r"Version is\s+(?P<inst>[\w.\-]+)")
TENABLE_PKG = re.compile(r"Remote package installed\s*:\s*(?P<inst>\S+)\s+Should be\s*:\s*(?P<fixed>\S+)")
TENABLE_INSTALLED = re.compile(r"Installed (?:version|firmware)\s*:\s*(?P<inst>\S+)", re.I)
TENABLE_FIXED = re.compile(r"Fixed (?:version|firmware)\s*:\s*(?P<fixed>\S+)", re.I)
KB = re.compile(r"\bKB\d{6,7}\b")
CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def strip_epoch(version: str) -> str:
    return re.sub(r"^\d+:", "", version)


def split_nevra(s: str) -> tuple[str, str]:
    """openssl-1.1.1k-7.el8_6 -> (openssl, 1.1.1k-7.el8_6); runc_1.1.4-0ubuntu1 -> (runc, 1.1.4-0ubuntu1)."""
    m = re.match(r"^(?P<name>.+?)[-_](?P<ver>\d.*)$", s)
    return (m["name"], m["ver"]) if m else (s, "")


def classify(title: str, text: str) -> dict:
    """Return kind plus whichever of control / credential_fp / package fields apply."""
    if CRED_TITLE.search(title):
        fp = CRED_FP.search(text)
        acct = ACCOUNT.search(text)
        return {"kind": "credential",
                "credential_fp": fp[1] if fp else f"account:{acct[1] if acct else 'unknown'}"}
    for rx, control in CONFIG_RULES:
        if rx.search(title):
            return {"kind": "config", "control": control}
    return {"kind": "other"}


def package_from_qualys(title: str, results: str) -> tuple[str, str, str]:
    m = QUALYS_PKG_TABLE.search(results)
    if m and m["pkg"] != "Package":
        return m["pkg"], strip_epoch(m["inst"]), strip_epoch(m["fixed"])
    kb = KB.search(results) or KB.search(title)
    if kb:
        return "Microsoft Windows OS patch", "missing", kb[0]
    t = TITLE_PRIOR.match(title)
    if t:
        inst = QUALYS_VERSION_IS.search(results)
        return t["pkg"], inst["inst"] if inst else "", t["fixed"]
    return "", "", ""


def package_from_tenable(title: str, output: str) -> tuple[str, str, str]:
    m = TENABLE_PKG.search(output)
    if m:
        name, inst = split_nevra(m["inst"])
        _, fixed = split_nevra(m["fixed"])
        return name, inst, fixed
    kb = KB.search(output) or KB.search(title)
    if kb:
        return "Microsoft Windows OS patch", "missing", kb[0]
    t = TITLE_PRIOR.match(title)
    if t:
        inst = TENABLE_INSTALLED.search(output)
        fixed = TENABLE_FIXED.search(output)
        return t["pkg"], inst["inst"] if inst else "", fixed["fixed"] if fixed else t["fixed"]
    return "", "", ""


def cves(text: str) -> list[str]:
    return sorted(set(CVE.findall(text or "")))


def severity_from_qualys(level: str) -> str:
    return {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}.get(str(level).strip(), "info")


def severity_from_tenable(label: str) -> str:
    return (label or "info").strip().lower()
