"""CrowdStrike Falcon Spotlight connector: vulnerabilities the Falcon sensor finds on each host, and the hosts.

Sources (checked 2026-10-11; notes in ``docs/api-notes/crowdstrike.md``). CrowdStrike's own API reference sits
behind a Falcon login, so this module follows two public sources that are generated from or tested against it:

- CrowdStrike's official Python SDK, FalconPy 1.6.6 (``src/falconpy/_endpoint/``), for every path, method and query
  parameter: ``POST /oauth2/token`` (form ``client_id``, ``client_secret``, optional ``member_cid``; tokens have "a
  standard 30-minute lifespan"), ``GET /spotlight/combined/vulnerabilities/v1`` (``filter`` required, ``limit`` 1-5000,
  ``after`` paging token, ``sort`` such as ``updated_timestamp|asc``, ``facet`` = host_info, remediation, cve,
  evaluation_logic), ``GET /devices/queries/devices/v1`` and ``POST /devices/entities/devices/v2``. Cloud base URLs
  are FalconPy's ``BaseURL`` enum.
- Elastic's CrowdStrike integration (``packages/crowdstrike/data_stream/{vulnerability,host}``), for record fields
  and paging: ``resources``, ``errors``, ``meta.pagination.after`` (vulnerabilities) and ``meta.pagination.total``
  with ``offset`` (device IDs), and the field names read below.

DOC GAP: neither source lists the values of a vulnerability's ``status``. The samples show ``open``; ``reopen``,
``closed`` and ``expired`` are the other values CrowdStrike's Spotlight documentation uses. A full pull asks for
``status:['open','reopen']``; confirm both against a live tenant before relying on them.

Read-only: the only POSTs are the token request and the device-details lookup, which is a read that takes its IDs in
the body.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx

from ._parse import iso_datetime, score, unique
from .errors import ApiError, AuthenticationError, ConfigurationError
from .http import Allow, HttpSession, RetryPolicy, require_https
from .models import STATE_FIXED, STATE_OPEN, STATE_REOPENED, ScannerFinding, ScannerHost

log = logging.getLogger("sutra_connectors.crowdstrike")

DEFAULT_BASE_URL = "https://api.crowdstrike.com"
# FalconPy BaseURL: US1, US2, US3, EU1, USGOV1.
CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "us-3": "https://api.us-3.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}

ALLOW = (
    Allow("POST", r"/oauth2/token"),
    Allow("GET", r"/spotlight/combined/vulnerabilities/v1"),
    Allow("GET", r"/devices/queries/devices/v1"),
    Allow("POST", r"/devices/entities/devices/v2"),
)

_STATES = {"open": STATE_OPEN, "reopen": STATE_REOPENED, "closed": STATE_FIXED}
OPEN_FILTER = "status:['open','reopen']"
FACETS = ("cve", "host_info", "remediation")
PAGE_LIMIT = (1, 5000)  # FalconPy: "default: 100, max: 5000"
DEVICE_PAGE = 5000
DEVICE_DETAILS_BATCH = 100  # DOC GAP: the body limit is not stated; 100 IDs per request stays well inside it
# CVSS v3.1 qualitative severity rating scale (FIRST, section 5), used only when Spotlight gives no rating.
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def _severity(rating: object, base: float | None) -> str:
    r = str(rating or "").strip().lower()
    if r in ("critical", "high", "medium", "low"):
        return r
    for floor, name in _CVSS_BANDS:
        if base is not None and base >= floor:
            return name
    return "medium"  # no rating and no score: kept visible rather than dropped as informational


class _Token(httpx.Auth):
    """Bearer token from ``POST /oauth2/token``, renewed a minute before it expires and once after a 401."""

    def __init__(self, session: HttpSession, form: dict[str, str], clock: Callable[[], float]):
        self._session = session
        self._form = form
        self._clock = clock
        self._lock = threading.Lock()
        self._token = ""
        self._expires = 0.0

    def _fetch(self) -> str:
        resp = self._session.request("POST", "/oauth2/token", data=self._form)
        try:
            body = resp.json()
            token = body["access_token"]
            ttl = float(body.get("expires_in") or 1800)
        except (ValueError, KeyError, TypeError) as exc:
            raise ApiError("CrowdStrike: the token response has no access_token") from exc
        self._token, self._expires = token, self._clock() + max(60.0, ttl - 60)
        return token

    def token(self, renew: bool = False) -> str:
        with self._lock:
            if renew or not self._token or self._clock() >= self._expires:
                return self._fetch()
            return self._token

    def auth_flow(self, request: httpx.Request):
        request.headers["Authorization"] = f"Bearer {self.token()}"
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = f"Bearer {self.token(renew=True)}"
            yield request


class CrowdStrikeConnector:
    """Pull Spotlight vulnerabilities and Falcon hosts.

    The API client needs read scope for Vulnerabilities (Spotlight) and Hosts. ``member_cid`` locks the token to one
    child CID for MSSP parent tenants. Hosts the sensor has not reported from within ``host_window`` are not
    returned, so an offline laptop cannot count as freshly assessed.
    """

    scanner = "CrowdStrike"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        member_cid: str = "",
        page_size: int = 5000,
        host_window: timedelta = timedelta(days=30),
        timeout: float = 120.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not client_id or not client_secret:
            raise ConfigurationError("CrowdStrike: client_id and client_secret are required")
        if not PAGE_LIMIT[0] <= page_size <= PAGE_LIMIT[1]:
            raise ConfigurationError(f"CrowdStrike: page_size must be within {PAGE_LIMIT}")
        base_url = require_https(base_url or DEFAULT_BASE_URL, "base_url")
        self.page_size = page_size
        self.host_window = host_window
        self._clock = clock
        common = dict(name="CrowdStrike", base_url=base_url, allow=ALLOW, timeout=timeout, verify=verify,
                      retry=retry, error_hook=_error_detail, transport=transport, sleep=sleep)
        form = {"client_id": client_id, "client_secret": client_secret}
        if member_cid:
            form["member_cid"] = member_cid
        self._token_http = HttpSession(headers={"Accept": "application/json"}, **common)
        self.http = HttpSession(headers={"Accept": "application/json"},
                                auth=_Token(self._token_http, form, monotonic), **common)
        self.source = f"crowdstrike-api:{urlsplit(base_url).hostname}"

    def close(self) -> None:
        self.http.close()
        self._token_http.close()

    def __enter__(self) -> CrowdStrikeConnector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------- vulnerabilities ----------

    def iter_findings(self, since: datetime | None = None) -> Iterator[ScannerFinding]:
        """Open and reopened vulnerabilities; with ``since``, everything updated since then, closed ones included."""
        if since is None:
            flt = OPEN_FILTER
        else:
            stamp = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            flt = f"updated_timestamp:>='{stamp}'"
        after = ""
        while True:
            params: list[tuple[str, str]] = [("filter", flt), ("limit", str(self.page_size)),
                                             ("sort", "updated_timestamp|asc")]
            params += [("facet", f) for f in FACETS]
            if after:
                params.append(("after", after))
            body = _json(self.http.request("GET", "/spotlight/combined/vulnerabilities/v1", params=params))
            for rec in body.get("resources") or []:
                finding = self._finding(rec)
                if finding is not None:
                    yield finding
            after = ((body.get("meta") or {}).get("pagination") or {}).get("after") or ""
            if not after:
                return

    def _finding(self, rec: dict) -> ScannerFinding | None:
        status = str(rec.get("status") or "").lower()
        state = _STATES.get(status)
        if state is None:
            log.info("CrowdStrike: skipping vulnerability %s with status %r", rec.get("id"), status)
            return None
        cve = rec.get("cve") or {}
        cve_id = str(cve.get("id") or rec.get("vulnerability_id") or "").strip()
        host = rec.get("host_info") or {}
        app = rec.get("app") or next(iter(rec.get("apps") or []), {}) or {}
        product = str(app.get("product_name_normalized") or "").strip()
        name_version = str(app.get("product_name_version") or "").strip()
        installed = name_version[len(product):].strip() if product and name_version.startswith(product) else ""
        remediation = (rec.get("remediation") or {}).get("entities") or []
        recommended = (app.get("remediation_info") or {}).get("recommended_id")
        fix = next((r for r in remediation if r.get("id") == recommended), remediation[0] if remediation else {})
        base = score(cve.get("base_score"))
        domain = str(host.get("machine_domain") or "").strip()
        hostname = str(host.get("hostname") or "").strip()
        fqdn = f"{hostname}.{domain}" if hostname and domain and "." not in hostname else hostname
        ports = sorted({str(p) for d in rec.get("data_providers") or [] for p in d.get("ports") or []})
        return ScannerFinding(
            scanner=self.scanner,
            scanner_ref=f"Spotlight {cve_id}" if cve_id else "Spotlight",
            source=self.source,
            record_id=str(rec.get("id") or ""),
            ip=str(host.get("local_ip") or "").strip(),
            hostname=fqdn,
            os=str(host.get("os_version") or "").strip(),
            title=f"{cve_id} in {name_version}" if name_version else cve_id or "Spotlight vulnerability",
            severity=_severity(cve.get("severity"), base),
            cvss=base,
            cves=(cve_id,) if cve_id.upper().startswith("CVE-") else (),
            port=",".join(ports),
            protocol="",
            evidence=f"Installed: {name_version}" if name_version else "",
            solution="\n".join(unique(r.get("action") for r in remediation)),
            state=state,
            first_seen=iso_datetime(rec.get("created_timestamp")),
            last_seen=iso_datetime(host.get("host_last_seen_timestamp")) or iso_datetime(rec.get("updated_timestamp")),
            last_fixed=iso_datetime(rec.get("closed_timestamp")) if state == STATE_FIXED else None,
            package=product,
            installed=installed,
            fixed_version=str(fix.get("reference") or "").strip(),
            vendor_ids={"aid": str(rec.get("aid") or ""), "id": str(rec.get("id") or "")},
        )

    # ---------- hosts ----------

    def iter_hosts(self, since: datetime | None = None) -> Iterator[ScannerHost]:
        """Hosts whose sensor reported within ``host_window`` (and, with ``since``, after ``since``)."""
        cutoff = self._clock() - self.host_window
        if since is not None:
            cutoff = max(cutoff, since.astimezone(timezone.utc))
        for batch in self._device_id_batches():
            body = _json(self.http.request("POST", "/devices/entities/devices/v2", json={"ids": batch}))
            for d in body.get("resources") or []:
                last = iso_datetime(d.get("last_seen"))
                if last is None or last < cutoff:
                    continue
                yield ScannerHost(
                    scanner=self.scanner, source=self.source, host_id=str(d.get("device_id") or ""),
                    ips=unique([d.get("local_ip")]), hostnames=unique([d.get("hostname")]),
                    os=str(d.get("os_version") or "").strip(), first_seen=iso_datetime(d.get("first_seen")),
                    last_seen=last, vendor_ids={"device_id": str(d.get("device_id") or "")})

    def _device_id_batches(self) -> Iterator[list[str]]:
        offset = 0
        while True:
            body = _json(self.http.request("GET", "/devices/queries/devices/v1",
                                           params={"offset": str(offset), "limit": str(DEVICE_PAGE)}))
            ids = [str(i) for i in body.get("resources") or []]
            for i in range(0, len(ids), DEVICE_DETAILS_BATCH):
                yield ids[i:i + DEVICE_DETAILS_BATCH]
            offset += len(ids)
            total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
            if not ids or total is None or offset >= int(total):
                return


def _json(resp: httpx.Response) -> dict:
    try:
        body = resp.json()
    except ValueError as exc:
        raise ApiError(f"CrowdStrike: {resp.request.url.path} returned a body that is not JSON",
                       status=resp.status_code) from exc
    errors = body.get("errors") or []
    if errors:
        first = errors[0] if isinstance(errors[0], dict) else {"message": str(errors[0])}
        if str(first.get("code")) in ("401", "403"):
            raise AuthenticationError(f"CrowdStrike: {first.get('message', 'access denied')}; check the API "
                                      "client's scopes (Vulnerabilities and Hosts: read)")
        raise ApiError(f"CrowdStrike: {first.get('message', 'error')}", status=resp.status_code,
                       code=str(first.get("code", "")) or None)
    return body


def _error_detail(resp: httpx.Response) -> tuple[str, str | None]:
    try:
        errors = resp.json().get("errors") or []
        first = errors[0]
        return str(first.get("message", "")), str(first.get("code", "")) or None
    except (ValueError, AttributeError, IndexError, TypeError):
        text = " ".join(resp.text.split())
        return text[:300], None
