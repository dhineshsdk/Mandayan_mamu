"""Tenable Security Center (formerly Tenable.sc / SecurityCenter) connector, using ``POST /rest/analysis``.

API references (checked 2026-10-11; notes with quotes in ``docs/api-notes/tenable-sc.md``):

- API keys: https://docs.tenable.com/security-center/api/index.htm and
  https://docs.tenable.com/security-center/best-practices/api/Content/APIKeyAuthorization.htm
  (``x-apikey: accesskey=...; secretkey=...;``; Security Center 5.13 or later, with "Allow API Keys" turned on)
- Analysis: https://docs.tenable.com/security-center/api/Analysis.htm
- Query objects and filters: https://docs.tenable.com/security-center/api/Query.htm
- Integration guide (paging, sumip, unique finding key): https://developer.tenable.com/docs/sc-integrations
- Time-range pulls: https://docs.tenable.com/security-center/best-practices/api/Content/
  RetrieveVulnerabilityDataForSpecificTimeRange.htm
- Large deployments ("does not recommend multi-threading API calls"):
  https://docs.tenable.com/security-center/best-practices/large-enterprise-deployment/Content/API.htm

How it pulls:

- Findings: tool ``vulndetails``, paged with ``startOffset`` (inclusive) and ``endOffset`` (exclusive) inside the
  ``query`` object, one page at a time. ``sourceType: cumulative`` holds open findings; an incremental pull also
  reads ``sourceType: patched`` (the mitigated database) for findings fixed since the last pull.
- Hosts: tool ``sumip``, which Tenable's integration guide recommends for asset export.

DOC GAPs, handled conservatively:

- Offsets: Analysis.htm shows ``startOffset``/``endOffset`` at the body root, while Query.htm, the integration guide
  and the official pyTenable SDK put them inside ``query`` ("Must be explicitly supplied for tools vulndetails and
  listvuln"). This connector follows the latter.
- Time filters: Query.htm documents only day ranges (``"<minDaysBack>:<maxDaysBack>"``). The integration guide also
  mentions a Unix-timestamp range form that no example uses, so this connector sends day ranges, rounded up to whole
  days. Overlap is harmless because records carry stable IDs.
- ``totalRecords`` "isn't always returned" (pyTenable), so paging stops on the first short page.
- Offset paging over live data has no documented snapshot guarantee; a finding that moves between pages while a
  pull runs can be missed or repeated. The next incremental pull covers a miss.
- ``cve`` with several CVEs: the format is not documented; it is split on commas and whitespace.
- ``lastMitigated`` is documented as a filter, not as a result field; it is read when present.
- No rate limits are documented for Security Center. Retries follow the shared policy (429 and 5xx).

Read-only: ``POST /rest/analysis`` is a query. ``GET /rest/currentUser`` checks the credentials.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from ._parse import epoch_datetime, score, unique
from .errors import ApiError, ConfigurationError
from .http import Allow, HttpSession, RetryPolicy
from .models import SEVERITIES, STATE_FIXED, STATE_OPEN, STATE_REOPENED, ScannerFinding, ScannerHost

log = logging.getLogger("sutra_connectors.tenable_sc")

ALLOW = (
    Allow("POST", r"/rest/analysis"),
    Allow("GET", r"/rest/currentUser"),
)

# Severity ids, from Query.htm and pyTenable: "from 0 (informational) to 4 (critical)".
SEVERITY_BY_ID = dict(enumerate(SEVERITIES))
PAGE_SIZE_RANGE = (100, 10000)  # Tenable "recommends a page size between 2000 to 10000"

_PLUGIN_OUTPUT = re.compile(r"^\s*<plugin_output>(.*)</plugin_output>\s*$", re.S)


class TenableSCConnector:
    """Pull vulnerabilities and hosts from a Tenable Security Center instance.

    ``base_url`` is the console address, for example ``https://sc.plant.example.in``; ``/rest`` is added here.
    On-premises consoles often use certificates from an internal CA: pass that CA bundle's path as ``verify``.
    ``verify=False`` turns verification off and is logged as a warning on every connector start.
    """

    scanner = "Tenable"

    def __init__(
        self,
        base_url: str,
        access_key: str,
        secret_key: str,
        *,
        severities: tuple[str, ...] = ("low", "medium", "high", "critical"),
        page_size: int = 2000,
        timeout: float = 300.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if not access_key or not secret_key:
            raise ConfigurationError("Tenable SC: access_key and secret_key are required")
        if not severities or any(s not in SEVERITIES for s in severities):
            raise ConfigurationError(f"Tenable SC: severities must be a non-empty subset of {SEVERITIES}")
        if not PAGE_SIZE_RANGE[0] <= page_size <= PAGE_SIZE_RANGE[1]:
            raise ConfigurationError(f"Tenable SC: page_size must be within {PAGE_SIZE_RANGE}")
        if verify is False:
            log.warning("Tenable SC: TLS certificate verification is OFF for %s", base_url)
        self.severities = tuple(severities)
        self.page_size = page_size
        self._clock = clock
        extra = {"sleep": sleep} if sleep else {}
        self.http = HttpSession(
            name="Tenable SC",
            base_url=base_url,
            headers={"x-apikey": f"accesskey={access_key}; secretkey={secret_key};", "Accept": "application/json"},
            allow=ALLOW,
            timeout=timeout,
            verify=verify,
            retry=retry,
            transport=transport,
            **extra,
        )
        self.source = f"tenable-sc:{urlsplit(self.http.base_url).hostname}"

    def __repr__(self) -> str:
        return f"TenableSCConnector(base_url={self.http.base_url!r})"

    @property
    def checkpoint_key(self) -> str:
        return self.source

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> TenableSCConnector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def check(self) -> dict:
        """Confirm the keys work. Returns the ``response`` of ``GET /rest/currentUser``."""
        return _envelope(self.http.request("GET", "/rest/currentUser"))

    # Queries

    def days_back(self, since: datetime) -> int:
        """Whole days between ``since`` and now, rounded up, at least 1 (filters take day ranges)."""
        delta = (self._clock() - since).total_seconds()
        return max(1, math.ceil(delta / 86400))

    def _severity_filter(self) -> dict:
        ids = ",".join(str(i) for i, name in SEVERITY_BY_ID.items() if name in self.severities)
        return {"filterName": "severity", "operator": "=", "value": ids}

    def analysis_body(self, tool: str, source_type: str, filters: list[dict], offset: int) -> dict:
        return {
            "type": "vuln",
            "sourceType": source_type,
            "query": {"type": "vuln", "tool": tool, "filters": filters, "startOffset": offset,
                      "endOffset": offset + self.page_size},
        }

    def _pages(self, tool: str, source_type: str, filters: list[dict]) -> Iterator[dict]:
        offset = 0
        while True:
            body = self.analysis_body(tool, source_type, filters, offset)
            response = _envelope(self.http.request("POST", "/rest/analysis", json=body))
            results = response.get("results")
            if not isinstance(results, list):
                raise ApiError("Tenable SC: /analysis response has no results list")
            yield from results
            if len(results) < self.page_size:
                return
            offset += self.page_size

    # Vulnerabilities

    def finding_queries(self, since: datetime | None) -> list[tuple[str, list[dict]]]:
        """(sourceType, filters) pairs for one pull. Full: every open finding. Incremental: open findings last seen
        within the window, plus findings mitigated within it."""
        sev = self._severity_filter()
        if since is None:
            return [("cumulative", [sev])]
        window = f"0:{self.days_back(since)}"
        return [
            ("cumulative", [sev, {"filterName": "lastSeen", "operator": "=", "value": window}]),
            ("patched", [sev, {"filterName": "lastMitigated", "operator": "=", "value": window}]),
        ]

    def iter_findings(self, since: datetime | None = None) -> Iterator[ScannerFinding]:
        for source_type, filters in self.finding_queries(since):
            for r in self._pages("vulndetails", source_type, filters):
                f = self.finding_from_record(r, patched=source_type == "patched")
                if f is not None:
                    yield f

    def finding_from_record(self, r: dict, *, patched: bool = False) -> ScannerFinding | None:
        sev = r.get("severity")
        sev_id = sev.get("id") if isinstance(sev, dict) else sev
        try:
            severity = SEVERITY_BY_ID[int(sev_id)]
        except (TypeError, ValueError, KeyError):
            log.warning("Tenable SC: skipping record with unknown severity %r (plugin %s, ip %s)",
                        sev, r.get("pluginID"), r.get("ip"))
            return None
        if patched:
            state = STATE_FIXED
        elif str(r.get("hasBeenMitigated", "")).strip() == "1":
            # "Indicates whether the vulnerability was previously fixed in the past and then reopened (1) or not (0)"
            state = STATE_REOPENED
        else:
            state = STATE_OPEN
        text = str(r.get("pluginText") or "")
        m = _PLUGIN_OUTPUT.match(text)
        cvss = score(r.get("cvssV3BaseScore"))
        plugin_id = str(r.get("pluginID") or "")
        return ScannerFinding(
            scanner=self.scanner,
            scanner_ref=f"Plugin {plugin_id}",
            source=self.source,
            record_id=self.record_id(r),
            ip=str(r.get("ip") or ""),
            hostname=str(r.get("dnsName") or "") or _netbios_host(r.get("netbiosName")),
            os=str(r.get("operatingSystem") or ""),
            title=str(r.get("pluginName") or ""),
            severity=severity,
            cvss=cvss if cvss is not None else score(r.get("baseScore")),
            cves=unique(c.upper() for c in re.split(r"[,\s]+", str(r.get("cve") or ""))),
            port=str(r.get("port") or ""),
            protocol=str(r.get("protocol") or ""),
            evidence=m[1] if m else text,
            solution=str(r.get("solution") or ""),
            state=state,
            first_seen=epoch_datetime(r.get("firstSeen")),
            last_seen=epoch_datetime(r.get("lastSeen")),
            last_fixed=epoch_datetime(r.get("lastMitigated")) if patched else None,
            vendor_ids={k: str(v) for k, v in (("plugin_id", plugin_id), ("host_uuid", r.get("hostUUID")),
                                               ("repository_id", _repo_id(r))) if v},
        )

    @staticmethod
    def record_id(r: dict) -> str:
        """Tenable: "The attributes from hostUniqueness in combination with the port, protocol, and pluginID
        attributes define a unique finding." ``hostUniqueness`` names fields, e.g. ``repositoryID,ip,dnsName``."""
        names = [n.strip() for n in str(r.get("hostUniqueness") or "").split(",") if n.strip()]
        names = names or ["repositoryID", "ip", "dnsName"]
        host = [_repo_id(r) if n == "repositoryID" else str(r.get(n) or "") for n in names]
        return "|".join(host + [str(r.get("port") or ""), str(r.get("protocol") or ""), str(r.get("pluginID") or "")])

    # Hosts

    def iter_hosts(self, since: datetime | None = None) -> Iterator[ScannerHost]:
        """Hosts from the ``sumip`` tool. Incremental pulls keep hosts with a finding last seen in the window.

        DOC GAP: sumip has no plain OS name or first/last seen fields. ``os`` carries ``osCPE``, and ``last_seen`` is
        the later of ``lastAuthRun`` and ``lastUnauthRun`` (documented as scan run times).
        """
        filters = [] if since is None else [{"filterName": "lastSeen", "operator": "=",
                                             "value": f"0:{self.days_back(since)}"}]
        for r in self._pages("sumip", "cumulative", filters):
            yield self.host_from_record(r)

    def host_from_record(self, r: dict) -> ScannerHost:
        runs = [d for d in (epoch_datetime(r.get("lastAuthRun")), epoch_datetime(r.get("lastUnauthRun"))) if d]
        ip = str(r.get("ip") or "")
        host_id = str(r.get("hostUUID") or r.get("uuid") or "") or f"{_repo_id(r)}|{ip}"
        return ScannerHost(
            scanner=self.scanner,
            source=self.source,
            host_id=host_id,
            ips=unique([ip]),
            hostnames=unique([r.get("dnsName"), _netbios_host(r.get("netbiosName"))]),
            os=str(r.get("osCPE") or ""),
            first_seen=None,
            last_seen=max(runs) if runs else None,
            vendor_ids={k: v for k, v in (("host_uuid", str(r.get("hostUUID") or "")),
                                          ("repository_id", _repo_id(r))) if v},
        )


def _repo_id(r: dict) -> str:
    repo = r.get("repository")
    return str(repo.get("id") or "") if isinstance(repo, dict) else str(r.get("repositoryID") or "")


def _netbios_host(value: object) -> str:
    """``WORKGROUP\\HOST`` -> ``HOST``."""
    return str(value or "").rsplit("\\", 1)[-1]


def _envelope(resp: httpx.Response) -> dict:
    """The ``response`` of a Security Center reply, after checking ``error_code`` (non-zero means failure)."""
    try:
        data = resp.json()
    except ValueError as exc:
        raise ApiError(f"Tenable SC: {resp.request.url.path} returned a body that is not JSON",
                       status=resp.status_code) from exc
    if not isinstance(data, dict):
        raise ApiError(f"Tenable SC: {resp.request.url.path} returned unexpected JSON", status=resp.status_code)
    if data.get("error_code"):
        raise ApiError(f"Tenable SC: {resp.request.url.path} error {data.get('error_code')}: "
                       f"{data.get('error_msg', '')}", status=resp.status_code, code=str(data.get("error_code")))
    response = data.get("response")
    if not isinstance(response, dict):
        raise ApiError(f"Tenable SC: {resp.request.url.path} reply has no response object", status=resp.status_code)
    return response
