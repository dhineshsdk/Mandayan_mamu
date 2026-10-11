"""Core data shapes shared by ingest, root-cause grouping, risk and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Asset:
    asset_id: str
    hostname: str
    ip: str
    site: str = ""
    zone: str = "corp"  # internet | dmz | corp | ot-l3 | ot-l2 | ot-l1
    os: str = ""
    owner: str = ""
    business_process: str = ""
    inr_per_hour: float = 0.0
    criticality: int = 3  # 1 (low) .. 5 (crown jewel)
    image: str = ""
    image_source: str = ""  # "cmdb" or "inferred (jaccard 0.92)"
    config_template: str = ""
    is_ot: bool = False
    safety_critical: bool = False
    personal_data: bool = False
    in_cmdb: bool = True
    scanned_by: set[str] = field(default_factory=set)


@dataclass
class SourceRef:
    """Where a finding came from: the receipt behind every number."""

    scanner: str
    scanner_ref: str  # Qualys QID or Tenable plugin ID
    source_file: str
    source_row: int


@dataclass
class Finding:
    finding_id: str
    asset_id: str
    title: str
    severity: str
    cvss: float | None
    cves: list[str]
    port: str
    kind: str  # package | config | credential | other
    package: str = ""
    installed: str = ""
    fixed: str = ""
    control: str = ""
    credential_fp: str = ""
    first_seen: date | None = None
    last_seen: date | None = None
    evidence: str = ""
    solution: str = ""
    sources: list[SourceRef] = field(default_factory=list)
    root_cause_id: str = ""

    @property
    def scanners(self) -> list[str]:
        return sorted({s.scanner for s in self.sources})


@dataclass
class RootCause:
    rc_id: str
    kind: str  # base-image | package | config-template | shared-credential | fleet-config | single
    key: str
    title: str
    fix: str
    finding_ids: list[str] = field(default_factory=list)
    asset_ids: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    max_severity: str = "info"
    max_cvss: float = 0.0
    is_ot: bool = False
    # Filled in by risk.py
    exploitation: str = "none"
    exposure: str = "small"
    human_impact: str = "low"
    ssvc: str = "Track"
    ale_mean: float = 0.0
    ale_p10: float = 0.0
    ale_p90: float = 0.0
    risk_inputs: dict = field(default_factory=dict)
    cea_overdue: int = 0
    executor: str = ""
