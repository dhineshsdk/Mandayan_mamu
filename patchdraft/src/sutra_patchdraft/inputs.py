"""What a patch-job draft is built from: one root cause, the hosts it touches and their findings.

Everything here comes from scanners, the CMDB or the ownership chart, so every text field is untrusted: it can carry
an instruction aimed at the model as easily as a package name. The inputs are kept as plain, frozen data; the prompt
builder escapes them and the grounding check measures the draft against them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, time
from typing import Any, Iterable

SSVC_DECISIONS = ("Act", "Attend", "Track*", "Track")


class InputError(ValueError):
    """The draft input is inconsistent (a finding on an unknown host, no hosts, a bad window)."""


@dataclass(frozen=True)
class HostInput:
    asset_id: str
    hostname: str
    os: str = ""
    zone: str = ""
    site: str = ""
    criticality: int = 3  # 1 (low) .. 5 (crown jewel)
    image: str = ""
    config_template: str = ""
    business_process: str = ""
    is_ot: bool = False
    safety_critical: bool = False
    in_cmdb: bool = True


@dataclass(frozen=True)
class FindingInput:
    finding_id: str
    asset_id: str
    title: str
    severity: str
    kind: str  # package | config | credential | other
    cves: tuple[str, ...] = ()
    package: str = ""
    installed: str = ""
    fixed: str = ""
    control: str = ""
    solution: str = ""
    scanner_refs: tuple[str, ...] = ()  # e.g. "Qualys QID 242051", "Tenable plugin 181234"


@dataclass(frozen=True)
class RootCauseInput:
    rc_id: str
    kind: str  # base-image | package | config-template | shared-credential | fleet-config | fleet | single
    key: str
    title: str
    fix: str
    ssvc: str = "Track"
    is_ot: bool = False
    cves: tuple[str, ...] = ()


@dataclass(frozen=True)
class MaintenancePolicy:
    """The customer's change windows. Rings go into consecutive IT windows; OT waits for a named shutdown."""

    weekday: int = 5  # Monday = 0, so 5 is Saturday
    start: time = time(22, 0)
    duration_hours: int = 4
    timezone_label: str = "IST"
    ot_shutdown: date | None = None  # the next planned plant shutdown, if operations has named one

    def __post_init__(self):
        if not 0 <= self.weekday <= 6:
            raise InputError(f"weekday must be 0..6, got {self.weekday}")
        if not 1 <= self.duration_hours <= 24:
            raise InputError(f"duration_hours must be 1..24, got {self.duration_hours}")


@dataclass(frozen=True)
class DraftInput:
    root_cause: RootCauseInput
    hosts: tuple[HostInput, ...]
    findings: tuple[FindingInput, ...]
    as_of: date
    policy: MaintenancePolicy = field(default_factory=MaintenancePolicy)

    def __post_init__(self):
        if not self.hosts:
            raise InputError(f"{self.root_cause.rc_id}: a patch job needs at least one host")
        ids = [h.asset_id for h in self.hosts]
        if len(set(ids)) != len(ids):
            raise InputError(f"{self.root_cause.rc_id}: duplicate host asset_id")
        known = set(ids)
        stray = sorted({f.asset_id for f in self.findings} - known)
        if stray:
            raise InputError(f"{self.root_cause.rc_id}: findings on hosts not in the job: {', '.join(stray)}")
        if self.root_cause.ssvc not in SSVC_DECISIONS:
            raise InputError(f"{self.root_cause.rc_id}: unknown SSVC decision {self.root_cause.ssvc!r}")

    @property
    def is_ot(self) -> bool:
        """OT if the root cause or any host is OT. One OT host makes the whole job a staged, human-run plan."""
        return self.root_cause.is_ot or any(h.is_ot for h in self.hosts)


def _get(obj: Any, name: str, default: Any = "") -> Any:
    value = getattr(obj, name, default)
    return default if value is None else value


def _scanner_refs(finding: Any) -> tuple[str, ...]:
    refs = []
    for s in _get(finding, "sources", []) or []:
        scanner, ref = str(_get(s, "scanner")), str(_get(s, "scanner_ref"))
        if scanner or ref:
            refs.append(f"{scanner} {ref}".strip())
    return tuple(dict.fromkeys(refs))


def from_sutra(rc: Any, hosts: Iterable[Any], findings: Iterable[Any], as_of: date,
               policy: MaintenancePolicy | None = None) -> DraftInput:
    """Build a DraftInput from the analysis objects (``RootCause``, ``Asset``, ``Finding``) by attribute name.

    The caller passes only the hosts and findings in the job's scope (for example, one team's share of a root
    cause). Duck-typed so this package does not import the app.
    """
    host_inputs = tuple(HostInput(
        asset_id=str(_get(h, "asset_id")), hostname=str(_get(h, "hostname")), os=str(_get(h, "os")),
        zone=str(_get(h, "zone")), site=str(_get(h, "site")), criticality=int(_get(h, "criticality", 3)),
        image=str(_get(h, "image")), config_template=str(_get(h, "config_template")),
        business_process=str(_get(h, "business_process")), is_ot=bool(_get(h, "is_ot", False)),
        safety_critical=bool(_get(h, "safety_critical", False)), in_cmdb=bool(_get(h, "in_cmdb", True)),
    ) for h in hosts)
    finding_inputs = tuple(FindingInput(
        finding_id=str(_get(f, "finding_id")), asset_id=str(_get(f, "asset_id")), title=str(_get(f, "title")),
        severity=str(_get(f, "severity")), kind=str(_get(f, "kind", "other")),
        cves=tuple(str(c) for c in _get(f, "cves", ()) or ()), package=str(_get(f, "package")),
        installed=str(_get(f, "installed")), fixed=str(_get(f, "fixed")), control=str(_get(f, "control")),
        solution=str(_get(f, "solution")), scanner_refs=_scanner_refs(f),
    ) for f in findings)
    rc_input = RootCauseInput(
        rc_id=str(_get(rc, "rc_id")), kind=str(_get(rc, "kind")), key=str(_get(rc, "key")),
        title=str(_get(rc, "title")), fix=str(_get(rc, "fix")), ssvc=str(_get(rc, "ssvc", "Track")),
        is_ot=bool(_get(rc, "is_ot", False)), cves=tuple(str(c) for c in _get(rc, "cves", ()) or ()),
    )
    return DraftInput(root_cause=rc_input, hosts=host_inputs, findings=finding_inputs, as_of=as_of,
                      policy=policy or MaintenancePolicy())
