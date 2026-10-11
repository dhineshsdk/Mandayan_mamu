"""The fact table: every host, finding and change in the input, under a short ID the draft must cite.

The model never writes a host name, package version or KB number into a step on its own. It points at ``H3`` or
``C1``, and the renderer fills in the real value from this table, so a draft can only target hosts and apply changes
that the scan data contains.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .inputs import DraftInput, FindingInput, HostInput

WINDOWS_PATCH = "Microsoft Windows OS patch"  # the package name the ingest layer gives a missing Windows update

ROOT_CAUSE_REF = "R1"

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]")


def clean(text: str, limit: int) -> str:
    """Untrusted text made safe to quote: no control or bidi characters, one line, at most ``limit`` characters."""
    text = unicodedata.normalize("NFKC", str(text))
    text = _CONTROL_CHARS.sub(" ", text)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True)
class Change:
    ref: str
    kind: str  # package | windows-update | config | credential | other
    text: str  # what the change does, built only from input fields
    package: str
    fixed: str
    installed: tuple[str, ...]
    finding_refs: tuple[str, ...]
    host_refs: tuple[str, ...]


@dataclass(frozen=True)
class Facts:
    """Fact IDs for one draft input. Lookups go both ways so drafts can be rendered and cited."""

    hosts: dict[str, HostInput]  # "H1" -> host
    findings: dict[str, FindingInput]  # "F1" -> finding
    changes: dict[str, Change]  # "C1" -> change

    @property
    def all_refs(self) -> set[str]:
        return {ROOT_CAUSE_REF} | set(self.hosts) | set(self.findings) | set(self.changes)

    def host_ref(self, asset_id: str) -> str:
        for ref, h in self.hosts.items():
            if h.asset_id == asset_id:
                return ref
        raise KeyError(asset_id)


def _change_key(f: FindingInput) -> tuple:
    if f.kind == "package" and f.package:
        return ("package", f.package, f.fixed)
    if f.kind == "config" and f.control:
        return ("config", f.control)
    if f.kind == "credential":
        return ("credential", f.title)
    return ("other", f.package or f.title)


def _change_text(key: tuple, members: list[FindingInput]) -> tuple[str, str]:
    kind = key[0]
    if kind == "package":
        package, fixed = key[1], key[2]
        if package == WINDOWS_PATCH:
            return "windows-update", f"Install {fixed}" if fixed else "Install the missing Windows update"
        if fixed:
            return "package", f"Update {package} to {fixed} or later"
        return "package", f"Update {package} (the scan data names no fixed version)"
    if kind == "config":
        return "config", f"Correct the setting: {key[1]}"
    if kind == "credential":
        return "credential", f"Retire the shared credential: {key[1]}"
    solution = next((m.solution for m in members if m.solution), "")
    return "other", f"{key[1]}: {solution}" if solution else f"Remediate: {key[1]}"


def build_facts(inp: DraftInput) -> Facts:
    hosts_sorted = sorted(inp.hosts, key=lambda h: h.asset_id)
    hosts = {f"H{i}": h for i, h in enumerate(hosts_sorted, 1)}
    host_ref = {h.asset_id: ref for ref, h in hosts.items()}
    findings_sorted = sorted(inp.findings, key=lambda f: f.finding_id)
    findings = {f"F{i}": f for i, f in enumerate(findings_sorted, 1)}

    groups: dict[tuple, list[tuple[str, FindingInput]]] = {}
    for ref, f in findings.items():
        groups.setdefault(_change_key(f), []).append((ref, f))
    changes: dict[str, Change] = {}
    for i, key in enumerate(sorted(groups, key=lambda k: tuple(str(x) for x in k)), 1):
        members = [f for _, f in groups[key]]
        kind, text = _change_text(key, members)
        changes[f"C{i}"] = Change(
            ref=f"C{i}", kind=kind, text=clean(text, 300),
            package=members[0].package if key[0] == "package" else "",
            fixed=members[0].fixed if key[0] == "package" else "",
            installed=tuple(sorted({m.installed for m in members if m.installed})),
            finding_refs=tuple(r for r, _ in groups[key]),
            host_refs=tuple(sorted({host_ref[m.asset_id] for m in members}, key=lambda r: int(r[1:]))),
        )
    return Facts(hosts=hosts, findings=findings, changes=changes)


def corpus(inp: DraftInput) -> str:
    """All input text in one lower-cased string, for checking that a draft's versions and IDs came from the input."""
    parts: list[str] = [inp.root_cause.title, inp.root_cause.fix, inp.root_cause.key, *inp.root_cause.cves]
    for h in inp.hosts:
        parts += [h.asset_id, h.hostname, h.os, h.zone, h.site, h.image, h.config_template, h.business_process]
    for f in inp.findings:
        parts += [f.finding_id, f.title, f.package, f.installed, f.fixed, f.control, f.solution, *f.cves,
                  *f.scanner_refs]
    return "\n".join(clean(p, 4000) for p in parts if p).lower()
