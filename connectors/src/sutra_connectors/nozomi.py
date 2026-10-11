"""Nozomi Networks connector: vulnerabilities that Guardian or CMC matches to OT and IoT assets it sees on the
network, and the assets it has seen.

Source (checked 2026-10-11; notes in ``docs/api-notes/nozomi.md``): Elastic's Nozomi Networks integration
(``packages/nozomi_networks/data_stream/{node_cve,asset}``). Its pollers call the Open API query endpoint
``GET /api/open/query/do`` with Basic authentication and the parameters ``query`` (an N2QL query such as
``node_cves | where time > <ms> | sort time asc``), ``page``, ``count``, ``skip_total_count=true`` and
``default_filters=false``; the response carries ``result`` (a list) and, when the query is rejected, ``error``. A page
shorter than ``count`` is the last one. The record fields read below come from its pipeline test records and sample
events. Nozomi's own API documentation is not public, so nothing else was used.

Nozomi identifies assets passively, from traffic, so a vulnerability is a match of the asset's identified product
and firmware against the CVE database (``probability`` and ``likelihood`` say how sure the match is). Firmware has no
package version to upgrade to, so a finding is grouped by product and firmware; ``minimum_hotfix``, when Nozomi gives
one, is the fix.

Read-only: one GET endpoint, and every query is a read.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx

from ._parse import score, unique
from .errors import ApiError, ConfigurationError
from .http import Allow, HttpSession, RetryPolicy, require_https
from .models import STATE_FIXED, STATE_OPEN, ScannerFinding, ScannerHost

log = logging.getLogger("sutra_connectors.nozomi")

QUERY_PATH = "/api/open/query/do"
ALLOW = (Allow("GET", QUERY_PATH),)
PAGE = (1, 1000)
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))  # CVSS v3.1 rating scale


def _ms(value: object) -> datetime | None:
    """Nozomi times are Unix milliseconds."""
    try:
        ms = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc) if ms > 0 else None


def _ips(values) -> tuple[str, ...]:
    """Real addresses from a ``nodes`` or ``ip`` list ("localhost" and 0.0.0.0 left out)."""
    out = []
    for v in values or []:
        try:
            ip = ipaddress.ip_address(str(v).strip())
        except ValueError:
            continue
        if not ip.is_unspecified and not ip.is_loopback:
            out.append(str(ip))
    return unique(out)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _first(rec: dict, *names: str) -> str:
    for n in names:
        v = rec.get(n)
        if v not in (None, ""):
            return str(v).strip()
    return ""


class NozomiConnector:
    """Pull vulnerabilities and assets from a Nozomi Networks Guardian or CMC.

    ``username`` and ``password`` are a local user with read access to the Open API. Assets not active within
    ``host_window`` do not count as assessed.
    """

    scanner = "Nozomi"

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        page_size: int = 500,
        host_window: timedelta = timedelta(days=30),
        timeout: float = 120.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if not base_url:
            raise ConfigurationError("Nozomi: the Guardian or CMC address is required")
        if not username or not password:
            raise ConfigurationError("Nozomi: user name and password are required")
        if not PAGE[0] <= page_size <= PAGE[1]:
            raise ConfigurationError(f"Nozomi: page_size must be within {PAGE}")
        base_url = require_https(base_url, "base_url")
        self.page_size, self.host_window, self._clock = page_size, host_window, clock
        self.http = HttpSession(name="Nozomi", base_url=base_url, headers={"Accept": "application/json"},
                                allow=ALLOW, auth=httpx.BasicAuth(username, password), timeout=timeout,
                                verify=verify, retry=retry, transport=transport, sleep=sleep)
        self.source = f"nozomi-api:{urlsplit(base_url).hostname}"

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> NozomiConnector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def query(self, n2ql: str) -> Iterator[dict]:
        page = 1
        while True:
            resp = self.http.request("GET", QUERY_PATH, params={
                "query": n2ql, "page": str(page), "count": str(self.page_size), "skip_total_count": "true",
                "default_filters": "false"})
            try:
                body = resp.json()
            except ValueError as exc:
                raise ApiError("Nozomi: the query endpoint returned a body that is not JSON",
                               status=resp.status_code) from exc
            if body.get("error"):
                raise ApiError(f"Nozomi: query rejected: {body['error']}")
            rows = body.get("result") or []
            yield from rows
            if len(rows) < self.page_size:
                return
            page += 1

    # ---------- vulnerabilities ----------

    def iter_findings(self, since: datetime | None = None) -> Iterator[ScannerFinding]:
        """Unresolved vulnerabilities; with ``since``, every one recorded since then, resolved ones included."""
        if since is None:
            n2ql = "node_cves | sort time asc"
        else:
            n2ql = f"node_cves | where time > {int(since.timestamp() * 1000)} | sort time asc"
        for rec in self.query(n2ql):
            resolved = bool(rec.get("resolved"))
            if resolved and since is None:
                continue
            yield self._finding(rec, STATE_FIXED if resolved else STATE_OPEN)

    def _finding(self, rec: dict, state: str) -> ScannerFinding:
        cve = _first(rec, "cve")
        base = score(rec.get("cve_score"))
        severity = next((name for floor, name in _CVSS_BANDS if base is not None and base >= floor), "medium")
        product = _first(rec, "product_name", "node_product_name")
        firmware = _first(rec, "firmware_version", "node_firmware_version")
        vendor = _first(rec, "vendor", "node_vendor")
        name = _first(rec, "name", "node_label")
        hotfix = _first(rec, "minimum_hotfix")
        os_name = _first(rec, "os", "node_os")
        when = _ms(rec.get("time"))
        evidence = "\n".join(x for x in (
            f"Asset: {name}" + (f" ({_first(rec, 'type', 'node_type')})" if _first(rec, "type", "node_type") else ""),
            f"Product: {vendor} {product}".strip() if product or vendor else "",
            f"Firmware: {firmware}" if firmware else "", f"OS: {os_name}" if os_name else "",
            f"Match: {rec['probability']} (likelihood {rec.get('likelihood')})" if rec.get("probability") else "",
            f"Zones: {', '.join(rec.get('zones') or [])}" if rec.get("zones") else "",
            f"Weakness: {rec['cwe_name']}" if rec.get("cwe_name") else "",
            str(rec.get("cve_summary") or "")) if x)
        solution = (f"Install {hotfix} or later." if hotfix else
                    "Check the vendor advisory for fixed firmware; plan the update with the OEM for the next outage.")
        return ScannerFinding(
            scanner=self.scanner,
            scanner_ref=f"Nozomi {cve}" if cve else "Nozomi",
            source=self.source,
            record_id=_first(rec, "id"),
            ip=next(iter(_ips(rec.get("nodes"))), ""),
            hostname=name,
            os=os_name,
            title=f"{cve} in {vendor} {product} {firmware}".replace("  ", " ").strip() if product else cve,
            severity=severity,
            cvss=base,
            cves=(cve,) if cve.upper().startswith("CVE-") and cve[4:5].isdigit() else (),
            port="",
            protocol="",
            evidence=evidence,
            solution=solution,
            state=state,
            first_seen=_ms(rec.get("record_created_at")) or when,
            last_seen=when,
            last_fixed=when if state == STATE_FIXED else None,
            package=f"{vendor} {product}".strip() if product else "",
            installed=firmware,
            fixed_version=hotfix,
            vendor_ids={"asset_id": _first(rec, "asset_id", "node_id"), "id": _first(rec, "id")},
        )

    # ---------- assets ----------

    def iter_hosts(self, since: datetime | None = None) -> Iterator[ScannerHost]:
        """Assets active within ``host_window`` (and after ``since``)."""
        cutoff = self._clock() - self.host_window
        if since is not None:
            cutoff = max(cutoff, since.astimezone(timezone.utc))
        n2ql = f"assets | where last_activity_time > {int(cutoff.timestamp() * 1000)} | sort last_activity_time asc"
        for a in self.query(n2ql):
            last = _ms(a.get("last_activity_time"))
            ips = _ips(a.get("ip"))
            name = _first(a, "name")
            names = () if _is_ip(name) else unique([name])
            if last is None or last < cutoff or not (ips or names):
                continue
            yield ScannerHost(scanner=self.scanner, source=self.source, host_id=_first(a, "id"), ips=ips,
                              hostnames=names, os=_first(a, "os"),
                              first_seen=_ms(a.get("created_at")), last_seen=last,
                              vendor_ids={"id": _first(a, "id"), "type": _first(a, "type"),
                                          "level": _first(a, "level")})
