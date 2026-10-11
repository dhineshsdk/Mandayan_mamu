"""Microsoft Defender for Cloud connector: software vulnerabilities that Defender Vulnerability Management finds on
Azure virtual machines (and Arc-connected servers), and the machines it has assessed.

Sources (checked 2026-10-11; notes in ``docs/api-notes/azure-defender.md``):

- Microsoft's Azure SDK for Python, ``azure-mgmt-security`` 7.0.0 (PyPI wheel), generated from the Azure REST API
  specifications: sub-assessments are listed with ``GET /{scope}/providers/Microsoft.Security/subAssessments``
  (api-version ``2019-01-01-preview``, "Get security sub-assessments on all your scanned resources inside a
  subscription scope"), assessments with ``GET /{scope}/providers/Microsoft.Security/assessments`` (api-version
  ``2021-06-01``). ``scope`` is ``/subscriptions/{id}`` or
  ``/providers/Microsoft.Management/managementGroups/{name}``. Pages follow ``nextLink``.
- Elastic's Microsoft Defender for Cloud integration (``packages/microsoft_defender_cloud/data_stream/assessment``),
  which calls the same two operations, and whose pipeline test records show the sub-assessment fields read below:
  ``additionalData.assessedResourceType`` ``ServerVulnerabilityTvm`` with ``softwareVendor``, ``softwareName``,
  ``softwareVersion``, ``recommendedVersion``, ``cvssV30Score`` and ``cve[]`` (``title``, ``cvssScore``,
  ``severity``).
- Tokens: Entra ID client credentials at ``{login}/{tenant}/oauth2/v2.0/token`` with scope
  ``https://management.azure.com/.default``, as for Microsoft Graph in ``sutra.app.directory``.

The SDK's models predate ``ServerVulnerabilityTvm`` (they list ``ServerVulnerability``, the retired Qualys-based
scanner); only the Elastic records show it. Container image and AKS node findings
(``AzureRuntimeImageVulnerability``, ``ManagedAggregatedServerVulnerabilityTvm``) are not read yet.

Read-only: every call is a GET, and the only POST is the token request. The app registration needs read access to
Defender for Cloud on each scope (the Security Reader role, as remembered from Azure's built-in roles; see the notes).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlsplit

import httpx

from ._parse import iso_datetime, score, unique
from .errors import ApiError, ConfigurationError
from .http import Allow, HttpSession, RetryPolicy, require_https
from .models import STATE_FIXED, STATE_OPEN, ScannerFinding, ScannerHost

log = logging.getLogger("sutra_connectors.azure_defender")

MANAGEMENT_URL = "https://management.azure.com"
LOGIN_URL = "https://login.microsoftonline.com"
SUB_ASSESSMENTS_API = "2019-01-01-preview"
ASSESSMENTS_API = "2021-06-01"
SERVER_TYPE = "ServerVulnerabilityTvm"
# DOC GAP: the built-in assessment's key is not in the sources (the Elastic records edit it), so machines are found by
# the assessment's display name.
VA_ASSESSMENT = "Machines should have vulnerability findings resolved"
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SCOPE = r"/(?:subscriptions/[0-9a-fA-F-]{36}|providers/Microsoft\.Management/managementGroups/[\w.()-]{1,90})"
ALLOW_ARM = (Allow("GET", _SCOPE + r"/providers/Microsoft\.Security/(?:subAssessments|assessments)"),)
ALLOW_LOGIN = (Allow("POST", r"/[\w.-]+/oauth2/v2\.0/token"),)
_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))  # CVSS v3.1 rating scale


def scope_path(value: str) -> str:
    """A subscription ID becomes ``/subscriptions/{id}``; anything else is read as a management group name."""
    v = value.strip().strip("/")
    if _GUID.match(v):
        return f"/subscriptions/{v.lower()}"
    if v.lower().startswith("subscriptions/") and _GUID.match(v.split("/", 1)[1]):
        return "/" + v.lower()
    if not re.fullmatch(r"[\w.()-]{1,90}", v):
        raise ConfigurationError(f"Defender for Cloud: {value!r} is neither a subscription ID nor a management "
                                 "group name")
    return f"/providers/Microsoft.Management/managementGroups/{v}"


def _resource_name(resource_id: str) -> str:
    """The last segment of an Azure resource ID: a virtual machine's name."""
    return resource_id.rstrip("/").rsplit("/", 1)[-1]


class _Token(httpx.Auth):
    """Client-credentials token for Azure Resource Manager, renewed a minute early and once after a 401."""

    def __init__(self, session: HttpSession, path: str, form: dict[str, str], clock: Callable[[], float]):
        self._session, self._path, self._form, self._clock = session, path, form, clock
        self._lock = threading.Lock()
        self._token, self._expires = "", 0.0

    def token(self, renew: bool = False) -> str:
        with self._lock:
            if renew or not self._token or self._clock() >= self._expires:
                resp = self._session.request("POST", self._path, data=self._form)
                try:
                    body = resp.json()
                    self._token = body["access_token"]
                    ttl = float(body.get("expires_in") or 3600)
                except (ValueError, KeyError, TypeError) as exc:
                    raise ApiError("Defender for Cloud: the token response has no access_token") from exc
                self._expires = self._clock() + max(60.0, ttl - 60)
            return self._token

    def auth_flow(self, request: httpx.Request):
        request.headers["Authorization"] = f"Bearer {self.token()}"
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = f"Bearer {self.token(renew=True)}"
            yield request


class AzureDefenderConnector:
    """Pull Defender for Cloud server vulnerabilities and assessed machines for one or more scopes.

    ``scopes`` are subscription IDs or management group names.
    """

    scanner = "Defender for Cloud"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scopes: list[str] | tuple[str, ...],
        *,
        base_url: str = MANAGEMENT_URL,
        login_url: str = LOGIN_URL,
        timeout: float = 120.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not tenant_id or not client_id or not client_secret:
            raise ConfigurationError("Defender for Cloud: tenant ID, client ID and client secret are required")
        if not _GUID.match(tenant_id.strip()) and not re.fullmatch(r"[\w-]+(\.[\w-]+)+", tenant_id.strip()):
            raise ConfigurationError("Defender for Cloud: the tenant ID must be a GUID or a domain name")
        self.scopes = [scope_path(s) for s in scopes if s.strip()]
        if not self.scopes:
            raise ConfigurationError("Defender for Cloud: give at least one subscription ID or management group")
        base_url = require_https(base_url or MANAGEMENT_URL, "base_url").rstrip("/")
        login_url = require_https(login_url or LOGIN_URL, "login_url").rstrip("/")
        self._clock = clock
        self._host = urlsplit(base_url).hostname
        common = dict(timeout=timeout, verify=verify, retry=retry, error_hook=_error_detail, transport=transport,
                      sleep=sleep)
        self._login = HttpSession(name="Entra ID", base_url=login_url, headers={"Accept": "application/json"},
                                  allow=ALLOW_LOGIN, **common)
        form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret,
                "scope": f"{base_url}/.default"}
        token = _Token(self._login, f"/{quote(tenant_id.strip(), safe='')}/oauth2/v2.0/token", form, monotonic)
        self.http = HttpSession(name="Defender for Cloud", base_url=base_url,
                                headers={"Accept": "application/json"}, allow=ALLOW_ARM, auth=token, **common)
        self.source = f"defender-for-cloud:{tenant_id.strip().lower()}"

    def close(self) -> None:
        self.http.close()
        self._login.close()

    def __enter__(self) -> AzureDefenderConnector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _pages(self, path: str, api_version: str) -> Iterator[dict]:
        params: list[tuple[str, str]] = [("api-version", api_version)]
        while True:
            body = _json(self.http.request("GET", path, params=params))
            yield from body.get("value") or []
            nxt = body.get("nextLink")
            if not nxt:
                return
            parts = urlsplit(nxt)
            if parts.scheme != "https" or parts.hostname != self._host:
                raise ApiError(f"Defender for Cloud: a nextLink points to another host ({parts.hostname})")
            path, params = parts.path, parse_qsl(parts.query, keep_blank_values=True)

    # ---------- findings ----------

    def iter_findings(self, since: datetime | None = None) -> Iterator[ScannerFinding]:
        """Server vulnerabilities in every scope. The API has no change filter, so ``since`` keeps only those
        generated after it."""
        for scope in self.scopes:
            for rec in self._pages(f"{scope}/providers/Microsoft.Security/subAssessments", SUB_ASSESSMENTS_API):
                f = self._finding(rec)
                if f is not None and (since is None or (f.last_seen and f.last_seen >= since)):
                    yield f

    def _finding(self, rec: dict) -> ScannerFinding | None:
        p = rec.get("properties") or {}
        data = p.get("additionalData") or {}
        if data.get("assessedResourceType") != SERVER_TYPE:
            return None
        status = p.get("status") or {}
        state = {"unhealthy": STATE_OPEN, "healthy": STATE_FIXED}.get(str(status.get("code") or "").lower())
        if state is None:
            return None
        resource_id = str((p.get("resourceDetails") or {}).get("id") or
                          (data.get("resourceIdAsTargetNodeId") or {}).get("azureResourceId") or "")
        cves_raw = data.get("cve") or []
        cves_raw = [cves_raw] if isinstance(cves_raw, dict) else cves_raw
        cves = tuple(c for c in unique(str(c.get("title") or "") for c in cves_raw) if c.upper().startswith("CVE-"))
        scores = [s for s in (score(c.get("cvssScore")) for c in cves_raw) if s is not None]
        base = score(data.get("cvssV30Score")) or (max(scores) if scores else None)
        severity = _SEVERITY.get(str(status.get("severity") or "").lower())
        if severity is None:
            severity = next((name for floor, name in _CVSS_BANDS if base is not None and base >= floor), "medium")
        name, version = str(data.get("softwareName") or ""), str(data.get("softwareVersion") or "")
        fixed = str(data.get("recommendedVersion") or "")
        title = str(p.get("displayName") or "") or f"{name} {version}".strip()
        evidence = "\n".join(x for x in (
            f"Software: {data.get('softwareVendor', '')} {name} {version}".replace("  ", " ").strip() if name else "",
            f"Recommended version: {fixed}" if fixed else "", f"CVEs: {', '.join(cves)}" if cves else "",
            f"Source: {data['source']}" if data.get("source") else "") if x)
        when = iso_datetime(p.get("timeGenerated"))
        return ScannerFinding(
            scanner=self.scanner,
            scanner_ref=f"Defender {p.get('id')}" if p.get("id") else "Defender",
            source=self.source,
            record_id=str(rec.get("id") or ""),
            ip="",
            hostname=_resource_name(resource_id),
            os="",
            title=title,
            severity=severity,
            cvss=base,
            cves=cves,
            port="",
            protocol="",
            evidence=evidence,
            solution=str(p.get("remediation") or "") or (f"Update {name} to {fixed}." if fixed else title),
            state=state,
            first_seen=None,
            last_seen=when,
            last_fixed=when if state == STATE_FIXED else None,
            package=name,
            installed=version,
            fixed_version=fixed,
            vendor_ids={"resource_id": resource_id, "sub_assessment": str(rec.get("name") or "")},
        )

    # ---------- hosts ----------

    def iter_hosts(self, since: datetime | None = None) -> Iterator[ScannerHost]:
        """Machines with a current vulnerability assessment result, healthy or not.

        An assessment is Defender's current verdict, so a machine listed now counts as assessed now. Its
        ``statusChangeDate`` is when the verdict last changed, not when the machine was last scanned, so it is not
        used as the scan date. ``since`` is accepted for the common interface and changes nothing."""
        now = self._clock()
        seen: set[str] = set()
        for scope in self.scopes:
            for rec in self._pages(f"{scope}/providers/Microsoft.Security/assessments", ASSESSMENTS_API):
                p = rec.get("properties") or {}
                status = p.get("status") or {}
                if p.get("displayName") != VA_ASSESSMENT:
                    continue
                if str(status.get("code") or "").lower() not in ("healthy", "unhealthy"):
                    continue
                details = p.get("resourceDetails") or {}
                rid = str(details.get("Id") or details.get("id") or "")
                if not rid or rid.lower() in seen:
                    continue
                seen.add(rid.lower())
                yield ScannerHost(scanner=self.scanner, source=self.source, host_id=rid, ips=(),
                                  hostnames=unique([details.get("ResourceName") or _resource_name(rid)]), os="",
                                  first_seen=iso_datetime(status.get("firstEvaluationDate")), last_seen=now,
                                  vendor_ids={"resource_id": rid})


def _json(resp: httpx.Response) -> dict:
    try:
        body = resp.json()
    except ValueError as exc:
        raise ApiError(f"Defender for Cloud: {resp.request.url.path} returned a body that is not JSON",
                       status=resp.status_code) from exc
    if not isinstance(body, dict):
        raise ApiError(f"Defender for Cloud: {resp.request.url.path} returned an unexpected body")
    return body


def _error_detail(resp: httpx.Response) -> tuple[str, str | None]:
    """Azure Resource Manager errors: ``{"error": {"code", "message"}}``; Entra ID: ``error_description``."""
    try:
        body = resp.json()
        err = body.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or ""), str(err.get("code") or "") or None
        return str(body.get("error_description") or err or "")[:300], str(err or "") or None
    except (ValueError, AttributeError):
        return " ".join(resp.text.split())[:300], None
