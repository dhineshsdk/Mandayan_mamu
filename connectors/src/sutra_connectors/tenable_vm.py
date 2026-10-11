"""Tenable Vulnerability Management (formerly Tenable.io) connector, using the bulk export APIs.

API references (checked 2026-10-11; notes with quotes in ``docs/api-notes/tenable-vm.md``):

- Authorization: https://developer.tenable.com/docs/authorization (``X-ApiKeys: accessKey=...; secretKey=...;``)
- User-Agent: https://developer.tenable.com/docs/user-agent-header
  (``Integration/1.0 (VENDOR; PRODUCT; Build/VERSION)``)
- Vulnerability export: https://developer.tenable.com/reference/exports-vulns-request-export,
  https://developer.tenable.com/docs/retrieve-vulnerability-data-from-tenableio,
  https://developer.tenable.com/docs/refine-vulnerability-export-requests
- Export status and chunks: https://developer.tenable.com/reference/exports-vulns-export-status,
  https://developer.tenable.com/reference/exports-vulns-download-chunk
- Asset export: https://developer.tenable.com/docs/vm-retrieve-data,
  https://developer.tenable.com/reference/exports-assets-download-chunk
- Rate and concurrency limits: https://developer.tenable.com/docs/rate-limiting,
  https://developer.tenable.com/docs/concurrency-limiting

Several reference pages refuse automated fetching, so request and record schemas were also checked against the
official pyTenable SDK (tenable/io/exports) and a published copy of Tenable's OpenAPI specification. Points where the
sources disagree or say nothing are marked ``DOC GAP`` below.

Flow: ``POST /vulns/export`` returns an ``export_uuid``; ``GET /vulns/export/{uuid}/status`` lists
``chunks_available`` while the job runs; each chunk is downloaded once from
``GET /vulns/export/{uuid}/chunks/{chunk_id}``. Chunks finish out of order and may be downloaded while the job is
still ``PROCESSING``. Assets follow the same pattern under ``/assets/export``.

Read-only: the only POSTs are export requests (which read data into a temporary export file) and cancelling an
export job this connector started, when it times out.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx

from . import __version__
from ._parse import iso_datetime, score, to_epoch, unique
from .errors import ApiError, ConfigurationError, ExportFailed
from .http import Allow, HttpSession, RetryPolicy
from .models import SEVERITIES, STATE_FIXED, STATE_OPEN, STATE_REOPENED, ScannerFinding, ScannerHost

log = logging.getLogger("sutra_connectors.tenable_vm")

DEFAULT_BASE_URL = "https://cloud.tenable.com"

_UUID = r"[A-Za-z0-9-]+"
ALLOW = (
    Allow("POST", r"/vulns/export"),
    Allow("GET", rf"/vulns/export/{_UUID}/status"),
    Allow("GET", rf"/vulns/export/{_UUID}/chunks/\d+"),
    Allow("POST", rf"/vulns/export/{_UUID}/cancel"),
    Allow("POST", r"/assets/export"),
    Allow("GET", rf"/assets/export/{_UUID}/status"),
    Allow("GET", rf"/assets/export/{_UUID}/chunks/\d+"),
    Allow("POST", rf"/assets/export/{_UUID}/cancel"),
)

# Export "state" values in the API ("The API uses different terms for vulnerability states than the user
# interface": OPEN, REOPENED, FIXED). DOC GAP: the case used inside records is not stated, so compare uppercased.
_STATES = {"OPEN": STATE_OPEN, "REOPENED": STATE_REOPENED, "FIXED": STATE_FIXED}

# Job status values documented for GET .../status.
_RUNNING = {"QUEUED", "PROCESSING"}

# num_assets: "default 50, range 50-5000"; Tenable "does not recommend using a chunk size larger than 5000".
# chunk_size (assets): required, "The range is 100-10000"; same 5000 recommendation.
NUM_ASSETS_RANGE = (50, 5000)
CHUNK_SIZE_RANGE = (100, 5000)


class TenableVMConnector:
    """Pull vulnerabilities and assets from Tenable Vulnerability Management.

    ``full_lookback`` bounds a first (full) pull. Without a time filter Tenable exports only what was "found or
    fixed within the last 30 days", so a full pull sends ``since`` = now minus ``full_lookback`` instead. Open
    vulnerabilities last seen before that window are not pulled.

    ``severities`` defaults to low and above: informational plugins are numerous and Sutra drops them after using
    them to mark a host as scanned, which the asset export already covers.
    """

    scanner = "Tenable"

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        severities: tuple[str, ...] = ("low", "medium", "high", "critical"),
        include_unlicensed: bool = False,
        num_assets: int = 500,
        asset_chunk_size: int = 1000,
        full_lookback: timedelta = timedelta(days=365),
        poll_interval: float = 5.0,
        poll_interval_max: float = 30.0,
        export_timeout: timedelta = timedelta(hours=6),
        timeout: float = 120.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not access_key or not secret_key:
            raise ConfigurationError("Tenable VM: access_key and secret_key are required")
        bad = [s for s in severities if s not in SEVERITIES]
        if bad or not severities:
            raise ConfigurationError(f"Tenable VM: severities must be a non-empty subset of {SEVERITIES}")
        if not NUM_ASSETS_RANGE[0] <= num_assets <= NUM_ASSETS_RANGE[1]:
            raise ConfigurationError(f"Tenable VM: num_assets must be within {NUM_ASSETS_RANGE}")
        if not CHUNK_SIZE_RANGE[0] <= asset_chunk_size <= CHUNK_SIZE_RANGE[1]:
            raise ConfigurationError(f"Tenable VM: asset_chunk_size must be within {CHUNK_SIZE_RANGE}")
        self.severities = tuple(severities)
        self.include_unlicensed = include_unlicensed
        self.num_assets = num_assets
        self.asset_chunk_size = asset_chunk_size
        self.full_lookback = full_lookback
        self.poll_interval = poll_interval
        self.poll_interval_max = poll_interval_max
        self.export_timeout = export_timeout
        self._sleep = sleep
        self._clock = clock
        self._monotonic = monotonic
        self.http = HttpSession(
            name="Tenable VM",
            base_url=base_url,
            headers={
                "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key};",
                "User-Agent": f"Integration/1.0 (Sutra; Sutra Connectors; Build/{__version__})",
                "Accept": "application/json",
            },
            allow=ALLOW,
            timeout=timeout,
            verify=verify,
            retry=retry,
            transport=transport,
            sleep=sleep,
        )
        self.source = f"tenable-vm:{urlsplit(self.http.base_url).hostname}"

    def __repr__(self) -> str:
        return f"TenableVMConnector(base_url={self.http.base_url!r})"

    @property
    def checkpoint_key(self) -> str:
        return self.source

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> TenableVMConnector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # Vulnerabilities

    def vuln_export_request(self, since: datetime | None) -> dict:
        """The body for ``POST /vulns/export``.

        Incremental (``since`` given): ``since`` with state OPEN, REOPENED and FIXED. Tenable reads ``since`` as
        last-seen time for open and reopened findings and fix time for fixed ones, so one export returns new,
        still-open and newly fixed detections. ``since`` "cannot be combined" with first_found, last_found or
        last_fixed, so none of those are sent.

        Full: ``since`` = now minus ``full_lookback``, state OPEN and REOPENED only.
        """
        if since is None:
            start, states = self._clock() - self.full_lookback, ["OPEN", "REOPENED"]
        else:
            start, states = since, ["OPEN", "REOPENED", "FIXED"]
        return {
            "num_assets": self.num_assets,
            "include_unlicensed": self.include_unlicensed,
            "filters": {"since": to_epoch(start), "state": states, "severity": list(self.severities)},
        }

    def iter_findings(self, since: datetime | None = None) -> Iterator[ScannerFinding]:
        body = self.vuln_export_request(since)
        for record in self._export("/vulns/export", body):
            finding = self.finding_from_record(record)
            if finding is not None:
                yield finding

    def finding_from_record(self, r: dict) -> ScannerFinding | None:
        """Map one vulnerability export record. Field names follow the export chunk schema; all are optional."""
        asset = r.get("asset") or {}
        plugin = r.get("plugin") or {}
        port = r.get("port") or {}
        severity = str(r.get("severity") or "").strip().lower()
        if severity not in SEVERITIES:
            log.warning("Tenable VM: skipping record with unknown severity %r (plugin %s, asset %s)",
                        r.get("severity"), plugin.get("id"), asset.get("uuid"))
            return None
        raw_state = str(r.get("state") or "").strip().upper()
        state = _STATES.get(raw_state)
        if state is None:
            log.warning("Tenable VM: unknown state %r (plugin %s, asset %s); treating as open",
                        r.get("state"), plugin.get("id"), asset.get("uuid"))
            state = STATE_OPEN
        os_names = asset.get("operating_system") or []
        if isinstance(os_names, str):
            os_names = [os_names]
        cves = plugin.get("cve") or []
        if isinstance(cves, str):
            cves = cves.replace(",", " ").split()
        plugin_id = str(plugin.get("id", ""))
        port_no = port.get("port")
        protocol = str(port.get("protocol") or "")
        record_id = str(r.get("finding_id") or "") or f"{asset.get('uuid', '')}:{plugin_id}:{port_no}:{protocol}"
        cvss = score(plugin.get("cvss3_base_score"))
        return ScannerFinding(
            scanner=self.scanner,
            scanner_ref=f"Plugin {plugin_id}",
            source=self.source,
            record_id=record_id,
            ip=str(asset.get("ipv4") or asset.get("ipv6") or ""),
            hostname=str(asset.get("fqdn") or asset.get("hostname") or asset.get("netbios_name") or ""),
            os="; ".join(unique(os_names)),
            title=str(plugin.get("name") or ""),
            severity=severity,
            cvss=cvss if cvss is not None else score(plugin.get("cvss_base_score")),
            cves=unique(c.upper() for c in cves),
            port="" if port_no is None else str(port_no),
            protocol=protocol,
            evidence=str(r.get("output") or ""),
            solution=str(plugin.get("solution") or ""),
            state=state,
            first_seen=iso_datetime(r.get("first_found")),
            last_seen=iso_datetime(r.get("last_found")),
            last_fixed=iso_datetime(r.get("last_fixed")),
            vendor_ids={k: str(v) for k, v in (("asset_uuid", asset.get("uuid")), ("plugin_id", plugin.get("id")),
                                               ("finding_id", r.get("finding_id"))) if v},
        )

    # Assets

    def asset_export_request(self, since: datetime | None) -> dict:
        """The body for ``POST /assets/export`` (v1). Incremental pulls filter on ``updated_at`` (Unix seconds,
        "later than" the given time); a full pull sends no filter, which returns all current assets.

        DOC GAP: ``/assets/v2/export`` supersedes v1 and uses a nested record model; v1 is still documented and is
        used here because its record fields were verifiable. Deleted and terminated assets are not pulled.
        """
        body: dict = {"chunk_size": self.asset_chunk_size}
        if since is not None:
            body["filters"] = {"updated_at": to_epoch(since)}
        return body

    def iter_hosts(self, since: datetime | None = None) -> Iterator[ScannerHost]:
        for a in self._export("/assets/export", self.asset_export_request(since)):
            yield self.host_from_record(a)

    def host_from_record(self, a: dict) -> ScannerHost:
        def strings(key: str) -> list[str]:
            v = a.get(key) or []
            return [v] if isinstance(v, str) else list(v)

        return ScannerHost(
            scanner=self.scanner,
            source=self.source,
            host_id=str(a.get("id") or ""),
            ips=unique(strings("ipv4s") + strings("ipv6s")),
            hostnames=unique(strings("fqdns") + strings("hostnames") + strings("netbios_names")),
            os="; ".join(unique(strings("operating_systems"))),
            first_seen=iso_datetime(a.get("first_seen")),
            last_seen=iso_datetime(a.get("last_seen")),
            vendor_ids={"asset_id": str(a.get("id") or "")},
        )

    # Export jobs

    def _start_export(self, path: str, body: dict) -> str:
        resp = self.http.request("POST", path, json=body, ok_statuses=[409])
        data = _json(resp)
        if resp.status_code == 409:
            # An identical export from this account is still running. The documented 409 body names it in
            # active_job_id; reuse it, as the official SDK does. DOC GAP: the asset export guide also says a
            # duplicate may instead cancel the old job and start a new one, which needs no special handling.
            job = data.get("active_job_id")
            if not job:
                raise ApiError(f"Tenable VM: {path} returned 409 without active_job_id: "
                               f"{data.get('failure_reason', '')}", status=409)
            log.info("Tenable VM: reusing running export %s (%s)", job, data.get("failure_reason", ""))
            return str(job)
        job = data.get("export_uuid")
        if not job:
            raise ApiError(f"Tenable VM: {path} response has no export_uuid", status=resp.status_code)
        return str(job)

    def _export(self, path: str, body: dict) -> Iterator[dict]:
        job = self._start_export(path, body)
        deadline = self._monotonic() + self.export_timeout.total_seconds()
        done: set[int] = set()
        wait = self.poll_interval
        while True:
            status = _json(self.http.request("GET", f"{path}/{job}/status"))
            state = str(status.get("status", "")).upper()
            for chunk in sorted(set(status.get("chunks_available") or []) - done):
                resp = self.http.request("GET", f"{path}/{job}/chunks/{chunk}")
                records = _json(resp, expect=list)
                done.add(chunk)
                yield from records
            if state == "FINISHED":
                failed = status.get("chunks_failed") or []
                if failed:
                    # Partial data would let a later pull skip findings for good, so fail the pull instead.
                    raise ExportFailed(f"Tenable VM: export {job} finished with failed chunks {failed}: "
                                       f"{status.get('reason', '')}")
                return
            if state not in _RUNNING:
                raise ExportFailed(f"Tenable VM: export {job} ended with status {state or '(none)'}: "
                                   f"{status.get('reason', '')}")
            if self._monotonic() > deadline:
                self._cancel(path, job)
                raise ExportFailed(f"Tenable VM: export {job} still {state} after {self.export_timeout}")
            self._sleep(wait)
            wait = min(self.poll_interval_max, wait + self.poll_interval)

    def _cancel(self, path: str, job: str) -> None:
        try:
            self.http.request("POST", f"{path}/{job}/cancel")
        except Exception as exc:  # noqa: BLE001 - cancelling is best effort; the timeout error matters more
            log.warning("Tenable VM: could not cancel export %s: %s", job, exc)


def _json(resp: httpx.Response, expect: type = dict):
    try:
        data = resp.json()
    except ValueError as exc:
        raise ApiError(f"Tenable VM: {resp.request.url.path} returned a body that is not JSON",
                       status=resp.status_code) from exc
    if not isinstance(data, expect):
        raise ApiError(f"Tenable VM: {resp.request.url.path} returned JSON {type(data).__name__}, "
                       f"expected {expect.__name__}", status=resp.status_code)
    return data
