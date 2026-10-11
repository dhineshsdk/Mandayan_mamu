"""The records every connector yields, whatever the scanner.

A :class:`ScannerFinding` carries the same fields Sutra's file importers read from a Qualys CSV, a Tenable CSV or a
``.nessus`` file (see ``sutra/ingest``), plus what only an API gives: the vendor's own IDs and the detection state.
:mod:`sutra_connectors.sutra_rows` turns findings into the row dicts the ingest pipeline consumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ("info", "low", "medium", "high", "critical")

# Detection state, normalised across vendors. Each connector documents its own mapping.
STATE_OPEN = "open"
STATE_REOPENED = "reopened"
STATE_FIXED = "fixed"
STATES = (STATE_OPEN, STATE_REOPENED, STATE_FIXED)


@dataclass(frozen=True)
class ScannerFinding:
    """One vulnerability detection on one host, as one scanner reports it."""

    scanner: str  # "Qualys" or "Tenable": the same labels the file importers use
    scanner_ref: str  # "QID 38173" or "Plugin 19506": the receipt Sutra shows next to every finding
    source: str  # where it was pulled from, e.g. "qualys-api:qualysapi.qg1.apps.qualys.in"
    record_id: str  # stable ID of this detection inside ``source``, the API equivalent of a file row
    ip: str
    hostname: str  # FQDN when the scanner has one, else DNS or NetBIOS name; the importers shorten it
    os: str
    title: str
    severity: str  # one of SEVERITIES
    cvss: float | None  # CVSS v3 base score when present, else v2
    cves: tuple[str, ...]
    port: str
    protocol: str
    evidence: str  # Qualys RESULTS or Tenable plugin output
    solution: str
    state: str  # one of STATES
    first_seen: datetime | None
    last_seen: datetime | None
    last_fixed: datetime | None = None
    vendor_ids: dict[str, str] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class ScannerHost:
    """A host the scanner knows about, with or without findings. Feeds the coverage view."""

    scanner: str
    source: str
    host_id: str  # the vendor's asset or host ID
    ips: tuple[str, ...]
    hostnames: tuple[str, ...]  # FQDNs first, then DNS and NetBIOS names, de-duplicated
    os: str
    first_seen: datetime | None
    last_seen: datetime | None  # the last time the scanner assessed or saw the host
    vendor_ids: dict[str, str] = field(default_factory=dict, compare=False)

    @property
    def ip(self) -> str:
        return self.ips[0] if self.ips else ""

    @property
    def hostname(self) -> str:
        return self.hostnames[0] if self.hostnames else ""
