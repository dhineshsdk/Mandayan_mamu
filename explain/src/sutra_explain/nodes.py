"""The facts a model may see: nodes with typed fields and no free text.

Scanner titles, hostnames, banners and ticket comments are attacker-writable, so none of them is ever a field here.
A node carries a short ref the model uses (``R1``, ``F3``), the real ID people know (``RC-004``), a display label
that is only ever shown to people, and fields whose values are numbers, booleans, members of a fixed vocabulary, or
strings that match a strict pattern (a CVE ID, a date, a rupee label). ``Node`` refuses anything else when it is
built, so the guarantee does not depend on the builders being careful.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

RC_KINDS = frozenset({"base-image", "package", "config-template", "shared-credential", "fleet-config", "fleet",
                      "single"})
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
CATEGORIES = frozenset({"remote-code-execution", "privilege-escalation", "information-disclosure",
                        "denial-of-service", "weak-credential", "misconfiguration", "outdated-component", "other"})

ENUM_FIELDS: dict[str, frozenset[str]] = {
    "kind": RC_KINDS,
    "ssvc": frozenset({"Act", "Attend", "Track*", "Track"}),
    "exploitation": frozenset({"none", "poc", "active"}),
    "exposure": frozenset({"open", "controlled", "small"}),
    "human_impact": frozenset({"low", "medium", "high", "very high"}),
    "max_severity": SEVERITIES,
    "severity": SEVERITIES,
    "finding_kind": frozenset({"package", "config", "credential", "other"}),
    "category": CATEGORIES,
    "zone": frozenset({"internet", "dmz", "corp", "ot-l3", "ot-l2", "ot-l1"}),
}
PATTERN_FIELDS: dict[str, re.Pattern] = {
    "cve": re.compile(r"CVE-\d{4}-\d{4,7}"),
    "earliest_due": re.compile(r"\d{4}-\d{2}-\d{2}"),
    "ale_label": re.compile(r"₹[0-9][0-9,.]*( lakh| crore)?"),
    "ale_p10_label": re.compile(r"₹[0-9][0-9,.]*( lakh| crore)?"),
    "ale_p90_label": re.compile(r"₹[0-9][0-9,.]*( lakh| crore)?"),
}
NUMBER_FIELDS = frozenset({
    "hosts", "findings", "hosts_total", "findings_total", "cea_overdue", "criticality", "cvss", "epss",
    "cve_count", "cves_active", "cves_poc", "injection_suspects", "scanned_by_count", "root_causes", "top_n",
    "top_findings_share", "top_risk_share", "ssvc_act", "ssvc_attend", "ssvc_track_star", "ssvc_track",
    "cea_overdue_closed_by_top", "cmdb_assets", "scanned_assets", "unscanned", "unknown", "inferred_images",
    "unowned", "rank"})
BOOL_FIELDS = frozenset({"is_ot", "safety_critical", "in_cmdb"})
NODE_KINDS = frozenset({"root_cause", "asset", "finding", "cve", "portfolio", "coverage", "site", "process"})
REF = re.compile(r"[A-Z][0-9]{1,3}")

_NUM = re.compile(r"\d[\d,]*(?:\.\d+)?")


class UnsafeField(ValueError):
    """A field value that is not allowed to reach a model."""


def normalise_number(token: str) -> str:
    """``1,234.50`` -> ``1234.5``; ``007`` -> ``7``. The form claims are compared in."""
    t = token.replace(",", "")
    if "." in t:
        whole, frac = t.split(".", 1)
        frac = frac.rstrip("0")
        t = (whole.lstrip("0") or "0") + ("." + frac if frac else "")
    else:
        t = t.lstrip("0") or "0"
    return t


def numbers_in(text: str) -> list[str]:
    return [normalise_number(m) for m in _NUM.findall(text)]


def _check(key: str, value: Any) -> Any:
    if key in BOOL_FIELDS:
        if not isinstance(value, bool):
            raise UnsafeField(f"{key} must be true or false")
        return value
    if key in NUMBER_FIELDS:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise UnsafeField(f"{key} must be a number")
        return value
    if key in ENUM_FIELDS:
        if value not in ENUM_FIELDS[key]:
            raise UnsafeField(f"{key} is not one of {sorted(ENUM_FIELDS[key])}")
        return value
    if key in PATTERN_FIELDS:
        if not isinstance(value, str) or not PATTERN_FIELDS[key].fullmatch(value):
            raise UnsafeField(f"{key} does not have the expected form")
        return value
    raise UnsafeField(f"{key} is not a field a model may see")


@dataclass(frozen=True)
class Node:
    ref: str
    node_id: str  # the real ID people see, e.g. RC-004 or a finding ID; never sent to the model
    kind: str
    label: str = ""  # display name for people (a title or hostname); never sent to the model
    fields: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not REF.fullmatch(self.ref):
            raise UnsafeField(f"bad ref {self.ref!r}")
        if self.kind not in NODE_KINDS:
            raise UnsafeField(f"bad node kind {self.kind!r}")
        for k, v in self.fields.items():
            _check(k, v)

    def allowed_numbers(self) -> set[str]:
        """Every number a claim citing this node may state, in normalised form."""
        out: set[str] = set()
        for k, v in self.fields.items():
            if isinstance(v, bool):
                continue
            if isinstance(v, (int, float)):
                out.add(normalise_number(f"{v:.6f}".rstrip("0").rstrip(".")))
                out.add(normalise_number(f"{v:.1f}"))
                out.add(normalise_number(f"{v:.2f}"))
                out.add(normalise_number(f"{round(v):,}"))
            elif isinstance(v, str) and k in PATTERN_FIELDS:
                out.update(numbers_in(v))
                if k == "earliest_due":  # a date can be said as a day, a month or a year
                    out.update(normalise_number(p) for p in v.split("-"))
        return out

    def for_model(self) -> dict[str, Any]:
        return {"ref": self.ref, "type": self.kind, **self.fields}

    def public(self) -> dict[str, str]:
        return {"ref": self.ref, "id": self.node_id, "type": self.kind, "label": self.label}


class FactSet:
    """The nodes one explanation is allowed to talk about."""

    def __init__(self, subject: str):
        self.subject = subject
        self.nodes: dict[str, Node] = {}

    def add(self, node: Node) -> Node:
        if node.ref in self.nodes:
            raise ValueError(f"duplicate ref {node.ref}")
        self.nodes[node.ref] = node
        return node

    def get(self, ref: str) -> Node | None:
        return self.nodes.get(ref)

    def __contains__(self, ref: str) -> bool:
        return ref in self.nodes

    def refs(self, kind: str | None = None) -> list[str]:
        return [r for r, n in self.nodes.items() if kind is None or n.kind == kind]

    def for_model(self) -> list[dict[str, Any]]:
        return [n.for_model() for n in self.nodes.values()]
