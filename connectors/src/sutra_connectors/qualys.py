"""Qualys VMDR connector: Host List Detection for findings, KnowledgeBase for titles and CVEs, Host List for hosts.

API references (checked 2026-10-11; notes with quotes in ``docs/api-notes/qualys.md``):

- API server per platform (India is IN1, ``https://qualysapi.qg1.apps.qualys.in``):
  https://www.qualys.com/platform-identification/
- Authentication (Basic over HTTPS; "The "X-Requested-With" header parameter must be included"):
  https://docs.qualys.com/en/vm/qweb-all-api/get_started/authentication.htm
- Versions and retirement dates: https://docs.qualys.com/en/vm/qweb-all-api/get_started/api_versioning_standards.htm
- Host List Detection: https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm
- Host List: https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_list.htm
- KnowledgeBase: https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase.htm
- Limits: https://cdn2.qualys.com/docs/qualys-api-limits.pdf and
  https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/get_started/get_started.htm
- Error codes: https://docs.qualys.com/en/vm/qweb-all-api/appendix/appendix_d.htm

API versions: Qualys' versioning page names ``/api/6.0`` as the recommended path for Host List Detection and Host
List (2.0 to 4.0 Host List reach end of life in December 2026) and ``/api/4.0`` for the KnowledgeBase. Those are the
defaults here and can be changed per connector.

DOC GAPs, handled conservatively:

- The 6.0 response schema could not be read; the element names used here are the ones in the published 2.0 samples
  and Qualys' own sample output, and the release notes say later versions add elements. Tag names are matched
  case-insensitively and unknown elements are ignored.
- The exact ``STATUS`` output strings for fixed and reopened detections are not given; ``New``/``Active`` map to
  open, ``Re-Opened`` (any case, with or without the hyphen) to reopened, ``Fixed`` to fixed.
- KnowledgeBase paging is not documented; QIDs are requested in batches with ``ids=``.
- Error code 1981 (HTTP 202, "Please try this same request again later") gives no wait time; this connector waits
  ``busy_wait`` seconds.
- Appendix D lists rate-limit code 1965 as "400 Conflict", the limits guide says 409. Both are treated as limits.

Paging: when a response stops at ``truncation_limit`` hosts, Qualys adds ``<WARNING><CODE>1980</CODE>`` with a URL
for the next batch. This connector reads ``id_min`` from that URL and repeats its own request with it, rather than
calling the URL as given.

Read-only: every request is ``POST`` with ``action=list``, which the allowlist enforces; other actions on the same
paths (for example host updates) are refused before they leave the process.
"""

from __future__ import annotations

import html
import logging
import re
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit
from xml.etree.ElementTree import Element

import httpx
from defusedxml import ElementTree as SafeET

from ._parse import iso_datetime, score, unique
from .errors import ApiError, ConfigurationError, RateLimitError
from .http import Allow, HttpSession, RetryPolicy
from .models import STATE_FIXED, STATE_OPEN, STATE_REOPENED, ScannerFinding, ScannerHost

log = logging.getLogger("sutra_connectors.qualys")

_VER = r"\d+\.\d+"
ALLOW = (
    Allow("POST", rf"/api/{_VER}/fo/asset/host/vm/detection/", require=(("action", "list"),)),
    Allow("POST", rf"/api/{_VER}/fo/asset/host/", require=(("action", "list"),)),
    Allow("POST", rf"/api/{_VER}/fo/knowledge_base/vuln/", require=(("action", "list"),)),
)

# Detection SEVERITY 1-5, the same scale Sutra's Qualys CSV importer uses (severity_from_qualys).
SEVERITY = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
_STATUS = {"NEW": STATE_OPEN, "ACTIVE": STATE_OPEN, "REOPENED": STATE_REOPENED, "FIXED": STATE_FIXED}
OPEN_STATUSES = "New,Active,Re-Opened"
ALL_STATUSES = "New,Active,Re-Opened,Fixed"

# Error codes from Appendix D and the limits guide.
CODE_TRUNCATED = "1980"
CODE_CONCURRENCY = "1960"
CODE_RATE = "1965"
CODE_BLOCKED_LEGACY = "1920"
CODE_BUSY = "1981"
CONCURRENCY_WAIT = 30.0  # no wait time is published for 1960; the widely used qualysapi client waits 30 s

_TAG = re.compile(r"<[^>]+>")


def _upper_tags(root: Element) -> Element:
    for el in root.iter():
        if isinstance(el.tag, str):
            el.tag = el.tag.upper()
    return root


def parse_xml(text: str | bytes) -> Element:
    """Parse a Qualys XML reply safely (no entity expansion, no external DTD fetch) with upper-cased tags."""
    try:
        return _upper_tags(SafeET.fromstring(text))
    except Exception as exc:  # defusedxml raises several types for hostile or broken XML
        raise ApiError(f"Qualys: reply is not well-formed XML ({type(exc).__name__})") from exc


def simple_return(resp: httpx.Response) -> tuple[str, str | None]:
    """Readable detail and code from a ``SIMPLE_RETURN`` error body; falls back to the raw text."""
    try:
        root = parse_xml(resp.content)
        code = root.findtext("RESPONSE/CODE")
        text = " ".join((root.findtext("RESPONSE/TEXT") or "").split())
        if code or text:
            return f"{code or ''} {text}".strip(), code
    except ApiError:
        pass
    return " ".join(resp.text.split())[:300], None


def _to_wait(resp: httpx.Response) -> float | None:
    value = resp.headers.get("X-RateLimit-ToWait-Sec")
    try:
        return float(value) if value not in (None, "") else None
    except ValueError:
        return None


def retry_wait(resp: httpx.Response) -> float | None:
    """How long to wait before retrying a refused call: rate limit (1965) uses ``X-RateLimit-ToWait-Sec``,
    concurrency (1960) waits 30 s. Other 409s, such as 2003 (registration) or 2011 (SecureID), are not retried."""
    if resp.status_code not in (400, 409):
        return None
    _, code = simple_return(resp)
    if code == CODE_RATE or (resp.status_code == 409 and code == CODE_BLOCKED_LEGACY):
        wait = _to_wait(resp)
        return wait if wait is not None else CONCURRENCY_WAIT
    if code == CODE_CONCURRENCY:
        return CONCURRENCY_WAIT
    if resp.status_code == 409 and code is None:
        return _to_wait(resp)
    return None


def _text(el: Element | None, path: str) -> str:
    if el is None:
        return ""
    return (el.findtext(path) or "").strip()


def _plain(markup: str) -> str:
    """KnowledgeBase SOLUTION is HTML in CDATA; Sutra shows plain text."""
    text = _TAG.sub(" ", markup.replace("<br>", "\n").replace("<BR>", "\n"))
    return "\n".join(" ".join(line.split()) for line in html.unescape(text).splitlines()).strip()


class KbEntry:
    __slots__ = ("title", "cves", "cvss", "solution")

    def __init__(self, title: str, cves: tuple[str, ...], cvss: float | None, solution: str):
        self.title, self.cves, self.cvss, self.solution = title, cves, cvss, solution


class QualysConnector:
    """Pull detections and hosts from a Qualys VMDR subscription.

    ``base_url`` is the API server for the subscription's platform, e.g. ``https://qualysapi.qg1.apps.qualys.in``.
    Use an account limited to reading VM data. ``include_vuln_type`` may be ``"confirmed"`` or ``"potential"`` to
    narrow the pull; by default both are pulled, like the detection CSV export.
    """

    scanner = "Qualys"

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        detection_api_version: str = "6.0",
        host_api_version: str = "6.0",
        kb_api_version: str = "4.0",
        truncation_limit: int = 1000,
        kb_batch_size: int = 500,
        include_vuln_type: str | None = None,
        busy_wait: float = 60.0,
        timeout: float = 300.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not username or not password:
            raise ConfigurationError("Qualys: username and password are required")
        for name, v in (("detection_api_version", detection_api_version), ("host_api_version", host_api_version),
                        ("kb_api_version", kb_api_version)):
            if not re.fullmatch(_VER, v):
                raise ConfigurationError(f"Qualys: {name} must look like '6.0', got {v!r}")
        if not 1 <= truncation_limit <= 1_000_000:
            raise ConfigurationError("Qualys: truncation_limit must be within 1-1000000")
        if not 1 <= kb_batch_size <= 5000:
            raise ConfigurationError("Qualys: kb_batch_size must be within 1-5000")
        if include_vuln_type not in (None, "confirmed", "potential"):
            raise ConfigurationError("Qualys: include_vuln_type must be None, 'confirmed' or 'potential'")
        self.detection_path = f"/api/{detection_api_version}/fo/asset/host/vm/detection/"
        self.host_path = f"/api/{host_api_version}/fo/asset/host/"
        self.kb_path = f"/api/{kb_api_version}/fo/knowledge_base/vuln/"
        self.truncation_limit = truncation_limit
        self.kb_batch_size = kb_batch_size
        self.include_vuln_type = include_vuln_type
        self.busy_wait = busy_wait
        self._sleep = sleep
        self._kb: dict[str, KbEntry] = {}
        self.http = HttpSession(
            name="Qualys",
            base_url=base_url,
            headers={"X-Requested-With": "Sutra Connectors"},
            auth=httpx.BasicAuth(username, password),
            allow=ALLOW,
            timeout=timeout,
            verify=verify,
            retry=retry,
            retry_hook=retry_wait,
            error_hook=simple_return,
            transport=transport,
            sleep=sleep,
        )
        self.source = f"qualys-api:{urlsplit(self.http.base_url).hostname}"

    def __repr__(self) -> str:
        return f"QualysConnector(base_url={self.http.base_url!r})"

    @property
    def checkpoint_key(self) -> str:
        return self.source

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> QualysConnector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # Transport

    def _post(self, path: str, data: dict[str, str]) -> Element:
        """One list call. Handles 1981 ("try this same request again later") and waits out an exhausted rate
        window reported by ``X-RateLimit-Remaining: 0`` before the next call."""
        for _ in range(6):
            resp = self.http.request("POST", path, data=data)
            root = parse_xml(resp.content)
            if root.tag == "SIMPLE_RETURN":
                code = _text(root, "RESPONSE/CODE")
                if code == CODE_BUSY:
                    log.info("Qualys: %s busy (1981); retrying in %.0fs", path, self.busy_wait)
                    self._sleep(self.busy_wait)
                    continue
                raise ApiError(f"Qualys: {path}: {code} {_text(root, 'RESPONSE/TEXT')}".strip(),
                               status=resp.status_code, code=code or None)
            if resp.headers.get("X-RateLimit-Remaining") == "0":
                wait = _to_wait(resp)
                if wait:
                    log.info("Qualys: rate window used up; waiting %.0fs", wait)
                    self._sleep(wait)
            return root
        raise RateLimitError(f"Qualys: {path} still busy (1981) after 6 attempts")

    def _paged(self, path: str, data: dict[str, str], list_tag: str) -> Iterator[Element]:
        """Yield HOST elements across truncated pages (WARNING code 1980 carries the next ``id_min``)."""
        data = dict(data)
        seen_id_min = set()
        while True:
            root = self._post(path, data)
            yield from root.iterfind(f"RESPONSE/{list_tag}/HOST")
            next_id = None
            for w in root.iterfind("RESPONSE/WARNING"):
                if _text(w, "CODE") == CODE_TRUNCATED:
                    query = parse_qs(urlsplit(_text(w, "URL")).query)
                    next_id = (query.get("id_min") or [None])[0]
                elif _text(w, "CODE") or _text(w, "TEXT"):
                    log.warning("Qualys: %s warning %s %s", path, _text(w, "CODE"), _text(w, "TEXT"))
            if not next_id:
                return
            if next_id in seen_id_min:
                raise ApiError(f"Qualys: {path} paging repeated id_min={next_id}")
            seen_id_min.add(next_id)
            data["id_min"] = next_id

    # Findings

    def detection_request(self, since: datetime | None) -> dict[str, str]:
        """Form fields for Host List Detection.

        Full: detections with the default open statuses. Incremental: hosts whose VM scan results were processed
        after ``since`` (``vm_processed_after``, the approach Qualys' best-practice guide recommends), with Fixed
        added so fixes arrive too.
        """
        data = {"action": "list", "truncation_limit": str(self.truncation_limit), "show_results": "1",
                "output_format": "XML", "status": OPEN_STATUSES}
        if self.include_vuln_type:
            data["include_vuln_type"] = self.include_vuln_type
        if since is not None:
            data["vm_processed_after"] = _qualys_time(since)
            data["status"] = ALL_STATUSES
        return data

    def iter_findings(self, since: datetime | None = None) -> Iterator[ScannerFinding]:
        batch: list[tuple[Element, Element]] = []
        for host in self._paged(self.detection_path, self.detection_request(since), "HOST_LIST"):
            for det in host.iterfind("DETECTION_LIST/DETECTION"):
                batch.append((host, det))
            if len(batch) >= 5000:
                yield from self._resolve(batch)
                batch = []
        yield from self._resolve(batch)

    def _resolve(self, batch: list[tuple[Element, Element]]) -> Iterator[ScannerFinding]:
        self._load_kb({_text(d, "QID") for _, d in batch})
        for host, det in batch:
            f = self.finding_from_xml(host, det)
            if f is not None:
                yield f

    def _load_kb(self, qids: Iterable[str]) -> None:
        missing = sorted((q for q in qids if q and q not in self._kb), key=int)
        for i in range(0, len(missing), self.kb_batch_size):
            ids = missing[i:i + self.kb_batch_size]
            root = self._post(self.kb_path, {"action": "list", "details": "All", "ids": ",".join(ids)})
            for v in root.iterfind("RESPONSE/VULN_LIST/VULN"):
                qid = _text(v, "QID")
                cvss = score(_text(v, "CVSS_V3/BASE"))
                self._kb[qid] = KbEntry(
                    title=_text(v, "TITLE"),
                    cves=unique(_text(c, "ID").upper() for c in v.iterfind("CVE_LIST/CVE")),
                    cvss=cvss if cvss is not None else score(_text(v, "CVSS/BASE")),
                    solution=_plain(_text(v, "SOLUTION")),
                )
            for q in ids:
                if q not in self._kb:
                    log.warning("Qualys: QID %s is not in the KnowledgeBase reply", q)
                    self._kb[q] = KbEntry("", (), None, "")

    def finding_from_xml(self, host: Element, det: Element) -> ScannerFinding | None:
        qid = _text(det, "QID")
        severity = SEVERITY.get(_text(det, "SEVERITY"))
        if severity is None:
            log.warning("Qualys: skipping QID %s with unknown severity %r", qid, _text(det, "SEVERITY"))
            return None
        raw_status = _text(det, "STATUS")
        state = _STATUS.get(raw_status.upper().replace("-", "").replace(" ", ""))
        if state is None:
            log.warning("Qualys: unknown STATUS %r on QID %s; treating as open", raw_status, qid)
            state = STATE_OPEN
        kb = self._kb.get(qid) or KbEntry("", (), None, "")
        host_id = _text(host, "ID")
        port, protocol = _text(det, "PORT"), _text(det, "PROTOCOL")
        record_id = _text(det, "UNIQUE_VULN_ID") or f"{host_id}:{qid}:{port}:{protocol}"
        return ScannerFinding(
            scanner=self.scanner,
            scanner_ref=f"QID {qid}",
            source=self.source,
            record_id=record_id,
            ip=_text(host, "IP") or _text(host, "IPV6"),
            hostname=_text(host, "DNS_DATA/FQDN") or _text(host, "DNS") or _text(host, "NETBIOS"),
            os=_text(host, "OS"),
            title=kb.title,
            severity=severity,
            cvss=kb.cvss,
            cves=kb.cves,
            port=port,
            protocol=protocol,
            evidence=_text(det, "RESULTS"),
            solution=kb.solution,
            state=state,
            first_seen=iso_datetime(_text(det, "FIRST_FOUND_DATETIME")),
            last_seen=iso_datetime(_text(det, "LAST_FOUND_DATETIME")),
            last_fixed=iso_datetime(_text(det, "LAST_FIXED_DATETIME")),
            vendor_ids={k: v for k, v in (("host_id", host_id), ("qid", qid),
                                          ("unique_vuln_id", _text(det, "UNIQUE_VULN_ID")),
                                          ("type", _text(det, "TYPE"))) if v},
        )

    # Hosts

    def host_request(self, since: datetime | None) -> dict[str, str]:
        data = {"action": "list", "details": "All", "truncation_limit": str(self.truncation_limit)}
        if since is not None:
            data["vm_processed_after"] = _qualys_time(since)
        return data

    def iter_hosts(self, since: datetime | None = None) -> Iterator[ScannerHost]:
        for h in self._paged(self.host_path, self.host_request(since), "HOST_LIST"):
            yield self.host_from_xml(h)

    def host_from_xml(self, h: Element) -> ScannerHost:
        """DOC GAP: the full list of last-scan fields is not confirmed; the latest of the documented
        ``LAST_VULN_SCAN_DATETIME``, ``LAST_VM_SCANNED_DATE`` and ``LAST_ACTIVITY`` is used as last seen."""
        seen = [d for d in (iso_datetime(_text(h, t)) for t in ("LAST_VULN_SCAN_DATETIME", "LAST_VM_SCANNED_DATE",
                                                                  "LAST_ACTIVITY")) if d]
        return ScannerHost(
            scanner=self.scanner,
            source=self.source,
            host_id=_text(h, "ID"),
            ips=unique([_text(h, "IP"), _text(h, "IPV6")]),
            hostnames=unique([_text(h, "DNS_DATA/FQDN"), _text(h, "DNS"), _text(h, "DNS_DATA/HOSTNAME"),
                              _text(h, "NETBIOS")]),
            os=_text(h, "OS"),
            first_seen=iso_datetime(_text(h, "FIRST_FOUND_DATE")),
            last_seen=max(seen) if seen else None,
            vendor_ids={k: v for k, v in (("host_id", _text(h, "ID")), ("asset_id", _text(h, "ASSET_ID")),
                                          ("qg_hostid", _text(h, "QG_HOSTID"))) if v},
        )


def _qualys_time(dt: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` in UTC, the documented date-time parameter format."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
