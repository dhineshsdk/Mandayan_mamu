"""Amazon Inspector connector: package vulnerabilities on EC2 instances, ECR container images and Lambda functions,
and the resources Inspector is actively scanning.

Sources (checked 2026-10-11; notes in ``docs/api-notes/aws-inspector.md``):

- The Inspector2 service model that ships in botocore 1.43.111 (``botocore/data/inspector2/2020-06-08/
  service-2.json``), which AWS generates its SDKs from: ``ListFindings`` is ``POST /findings/list`` (``maxResults``
  1-100, ``nextToken``, ``filterCriteria``, ``sortCriteria``), ``ListCoverage`` is ``POST /coverage/list``
  (``maxResults`` 1-200), the protocol is ``rest-json``, requests are signed with Signature Version 4 under the
  signing name ``inspector2``, and the endpoint is ``https://inspector2.{region}.amazonaws.com``. Field names and enum
  values below come from the same model.
- Elastic's AWS integration (``packages/aws/data_stream/inspector``), for how a poller uses the API and for the
  pipeline test records the fixtures are built from. Those records show timestamps as Unix seconds with a fraction
  (``1749795895.486``), which is how rest-json services send timestamps.

Signature Version 4 is implemented here (``_sign``) so the connector needs no AWS SDK; the tests check it against
botocore's own signer.

Read-only: both operations are reads that take their filters in a POST body. The IAM policy needs only
``inspector2:ListFindings`` and ``inspector2:ListCoverage``. DOC GAP: reading every account of an AWS Organization
through Inspector's delegated administrator account is from AWS's documentation as remembered; see the notes.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlsplit

import httpx

from ._parse import score, unique
from .errors import ApiError, ConfigurationError
from .http import Allow, HttpSession, RetryPolicy, require_https
from .models import STATE_FIXED, STATE_OPEN, ScannerFinding, ScannerHost

log = logging.getLogger("sutra_connectors.aws_inspector")

DEFAULT_REGION = "ap-south-1"
SERVICE = "inspector2"
_ENDPOINT = re.compile(r"^inspector2(?:-fips)?\.([a-z]{2}(?:-[a-z]+)+-\d+)\.(amazonaws\.com(?:\.cn)?|api\.aws)$")
ALLOW = (Allow("POST", r"/findings/list"), Allow("POST", r"/coverage/list"))
FINDINGS_PAGE = 100  # ListFindingsMaxResults: 1-100
COVERAGE_PAGE = 200  # ListCoverageMaxResults: 1-200
_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
             # Inspector's lowest rating. Kept as low, like Trivy's UNKNOWN and Grype's Negligible, so a real
             # package match is not dropped as scan information.
             "INFORMATIONAL": "low"}
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))  # CVSS v3.1 rating scale
_NO_FIX = {"", "notavailable"}


def endpoint(region: str) -> str:
    return f"https://inspector2.{region}.amazonaws.com"


def region_of(base_url: str) -> str:
    """The region in an Inspector endpoint such as ``https://inspector2.ap-south-1.amazonaws.com``."""
    host = urlsplit(base_url).hostname or ""
    m = _ENDPOINT.match(host)
    if not m:
        raise ConfigurationError(f"AWS Inspector: {base_url!r} is not an Inspector endpoint; use "
                                 f"{endpoint(DEFAULT_REGION)} with your region")
    return m[1]


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _sign(request: httpx.Request, *, access_key: str, secret_key: str, session_token: str, region: str,
          now: datetime) -> None:
    """Add Signature Version 4 headers. Signs host, content-type, x-amz-date and, with temporary credentials,
    x-amz-security-token."""
    stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day = stamp[:8]
    request.headers["X-Amz-Date"] = stamp
    if session_token:
        request.headers["X-Amz-Security-Token"] = session_token
    names = sorted(n for n in ("host", "content-type", "x-amz-date", "x-amz-security-token") if n in request.headers)
    canonical_headers = "".join(f"{n}:{' '.join(request.headers[n].split())}\n" for n in names)
    signed = ";".join(names)
    query = "&".join(sorted(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
                            for k, v in request.url.params.multi_items()))
    canonical = "\n".join([request.method, quote(request.url.path or "/", safe="/-_.~"), query, canonical_headers,
                           signed, hashlib.sha256(request.content).hexdigest()])
    scope = f"{day}/{region}/{SERVICE}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(f"AWS4{secret_key}".encode(), day), region), SERVICE), "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    request.headers["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, "
                                        f"Signature={signature}")


class _SigV4(httpx.Auth):
    requires_request_body = True

    def __init__(self, access_key: str, secret_key: str, session_token: str, region: str,
                 clock: Callable[[], datetime]):
        self._args = dict(access_key=access_key, secret_key=secret_key, session_token=session_token, region=region)
        self._clock = clock

    def auth_flow(self, request: httpx.Request):
        _sign(request, now=self._clock(), **self._args)
        yield request


def _epoch(value: object) -> datetime | None:
    """Unix seconds with an optional fraction, as rest-json sends timestamps."""
    if value in (None, ""):
        return None
    try:
        seconds = float(str(value).strip())
    except ValueError:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc) if seconds > 0 else None


def _severity(rating: object, base: float | None) -> str:
    r = _SEVERITY.get(str(rating or "").upper())
    if r:
        return r
    for floor, name in _CVSS_BANDS:  # UNTRIAGED: rate by the score
        if base is not None and base >= floor:
            return name
    return "medium"


def _cvss(details: dict) -> float | None:
    """The highest CVSS v3 base score Inspector lists for the vulnerability, else the highest of any version."""
    best: dict[bool, float] = {}
    for c in details.get("cvss") or []:
        s = score(c.get("baseScore"))
        if s is not None:
            v3 = str(c.get("version", "")).startswith("3")
            best[v3] = max(best.get(v3, 0.0), s)
    return best.get(True) or best.get(False)


def _installed(pkg: dict) -> str:
    """``epoch:version-release`` as Inspector writes ``fixedInVersion`` for OS packages."""
    version, release, epoch = str(pkg.get("version") or ""), str(pkg.get("release") or ""), pkg.get("epoch")
    text = f"{version}-{release}" if release else version
    return f"{epoch}:{text}" if epoch not in (None, "") and release else text


def _resource_name(res: dict) -> tuple[str, str, str]:
    """(hostname, ip, os) for a finding's resource."""
    details = res.get("details") or {}
    tags = res.get("tags") or {}
    rid = str(res.get("id") or "")
    if "awsEc2Instance" in details:
        ec2 = details["awsEc2Instance"]
        ips = ec2.get("ipV4Addresses") or []
        return tags.get("Name") or rid, ips[0] if ips else "", str(ec2.get("platform") or "")
    if "awsEcrContainerImage" in details:
        ecr = details["awsEcrContainerImage"]
        tag = next(iter(ecr.get("imageTags") or []), "") or ecr.get("imageHash", "")
        sep = "@" if str(tag).startswith("sha256:") else ":"
        # The image URI as ``docker pull`` takes it: <registry>.dkr.ecr.<region>.amazonaws.com/<repository>.
        uri = f"{ecr.get('registry')}.dkr.ecr.{res.get('region')}.amazonaws.com/{ecr.get('repositoryName')}"
        return f"{uri}{sep}{tag}", "", str(ecr.get("platform") or "")
    if "vm" in details:  # Inspector's resources in other clouds, such as Azure virtual machines
        vm = details["vm"]
        ips = vm.get("ipV4Addresses") or []
        return vm.get("vmName") or tags.get("Name") or rid, ips[0] if ips else "", str(vm.get("platform") or "")
    return rid, "", ""


class AwsInspectorConnector:
    """Pull Amazon Inspector package vulnerability findings and the resources it scans, for one region.

    Findings of type ``NETWORK_REACHABILITY`` (an open port, not a flaw in software) and ``CODE_VULNERABILITY``
    (Lambda source code) are not read. Suppressed findings are left out: a suppression rule is the account's own
    decision to accept them.
    """

    scanner = "AWS Inspector"

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        *,
        base_url: str = "",
        session_token: str = "",
        host_window: timedelta = timedelta(days=30),
        timeout: float = 120.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if not access_key_id or not secret_access_key:
            raise ConfigurationError("AWS Inspector: an access key ID and secret access key are required")
        base_url = require_https(base_url or endpoint(DEFAULT_REGION), "base_url")
        self.region = region_of(base_url)
        self.host_window = host_window
        self._clock = clock
        self._seen: dict[str, tuple[str, str]] = {}  # resource ID -> (hostname, ip) from findings already read
        self.http = HttpSession(
            name="AWS Inspector", base_url=base_url, headers={"Accept": "application/json"}, allow=ALLOW,
            auth=_SigV4(access_key_id, secret_access_key, session_token, self.region, clock), timeout=timeout,
            verify=verify, retry=retry, error_hook=_error_detail, transport=transport, sleep=sleep)
        self.source = f"aws-inspector:{self.region}"

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> AwsInspectorConnector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _pages(self, path: str, body: dict, key: str) -> Iterator[dict]:
        token = ""
        while True:
            req = {**body, **({"nextToken": token} if token else {})}
            data = _json(self.http.request("POST", path, json=req))
            yield from data.get(key) or []
            token = data.get("nextToken") or ""
            if not token:
                return

    # ---------- findings ----------

    def iter_findings(self, since: datetime | None = None) -> Iterator[ScannerFinding]:
        """Active package vulnerabilities; with ``since``, every one updated since then, closed ones included."""
        criteria: dict = {"findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}]}
        if since is None:
            criteria["findingStatus"] = [{"comparison": "EQUALS", "value": "ACTIVE"}]
        else:
            criteria["updatedAt"] = [{"startInclusive": int(since.timestamp())}]
        body = {"maxResults": FINDINGS_PAGE, "filterCriteria": criteria,
                "sortCriteria": {"field": "LAST_OBSERVED_AT", "sortOrder": "ASC"}}
        for rec in self._pages("/findings/list", body, "findings"):
            yield from self._findings(rec)

    def _findings(self, rec: dict) -> Iterator[ScannerFinding]:
        status = str(rec.get("status") or "").upper()
        state = {"ACTIVE": STATE_OPEN, "CLOSED": STATE_FIXED}.get(status)
        if state is None or rec.get("type") != "PACKAGE_VULNERABILITY":
            return
        res = next(iter(rec.get("resources") or []), {}) or {}
        hostname, ip, os_name = _resource_name(res)
        if res.get("id"):
            self._seen.setdefault(str(res["id"]), (hostname, ip))
        details = rec.get("packageVulnerabilityDetails") or {}
        vid = str(details.get("vulnerabilityId") or "").strip()
        cves = tuple(c for c in unique([vid, *(details.get("relatedVulnerabilities") or [])])
                     if c.upper().startswith("CVE-"))
        base = _cvss(details)
        recommendation = ((rec.get("remediation") or {}).get("recommendation") or {}).get("text") or ""
        packages = details.get("vulnerablePackages") or [{}]
        arn = str(rec.get("findingArn") or "")
        for pkg in packages:
            name, installed = str(pkg.get("name") or ""), _installed(pkg)
            fixed = str(pkg.get("fixedInVersion") or "").strip()
            fixed = "" if fixed.lower() in _NO_FIX else fixed
            evidence = "\n".join(x for x in (
                f"Installed: {name} {installed}" if name else "", f"Fixed in: {fixed or 'no fix published'}",
                f"Path: {pkg['filePath']}" if pkg.get("filePath") else "", str(rec.get("description") or "")) if x)
            solution = str(pkg.get("remediation") or "")
            if recommendation and recommendation != "None Provided":
                solution = "\n".join(x for x in (solution, recommendation) if x)
            yield ScannerFinding(
                scanner=self.scanner,
                scanner_ref=f"Inspector {vid}" if vid else "Inspector",
                source=self.source,
                record_id=arn if len(packages) == 1 else f"{arn}#{name}",
                ip=ip,
                hostname=hostname,
                os=os_name,
                title=f"{vid} in {name} {installed}".strip() if name else str(rec.get("title") or vid),
                severity=_severity(rec.get("severity"), base),
                cvss=base,
                cves=cves,
                port="",
                protocol="",
                evidence=evidence,
                solution=solution or (f"Upgrade {name} to {fixed}." if fixed else ""),
                state=state,
                first_seen=_epoch(rec.get("firstObservedAt")),
                last_seen=_epoch(rec.get("lastObservedAt")),
                last_fixed=_epoch(rec.get("updatedAt")) if state == STATE_FIXED else None,
                package=name,
                installed=installed,
                fixed_version=fixed,
                vendor_ids={"finding_arn": arn, "resource_id": str(res.get("id") or ""),
                            "account": str(rec.get("awsAccountId") or "")},
            )

    # ---------- coverage ----------

    def iter_hosts(self, since: datetime | None = None) -> Iterator[ScannerHost]:
        """Resources under active package scanning, scanned within ``host_window`` (and after ``since``).

        Coverage records carry no IP address. A resource that already appeared in :meth:`iter_findings` on this
        connector gets the name and address from its findings; others are named by their ``Name`` tag, else their
        resource ID.
        """
        cutoff = self._clock() - self.host_window
        if since is not None:
            cutoff = max(cutoff, since.astimezone(timezone.utc))
        body = {"maxResults": COVERAGE_PAGE, "filterCriteria": {
            "scanStatusCode": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            "scanType": [{"comparison": "EQUALS", "value": "PACKAGE"}]}}
        for c in self._pages("/coverage/list", body, "coveredResources"):
            last = _epoch(c.get("lastScannedAt"))
            if last is None or last < cutoff:
                continue
            rid = str(c.get("resourceId") or "")
            meta = c.get("resourceMetadata") or {}
            ec2 = meta.get("ec2") or {}
            name, ip = self._seen.get(rid, ((ec2.get("tags") or {}).get("Name") or rid, ""))
            yield ScannerHost(scanner=self.scanner, source=self.source, host_id=rid, ips=unique([ip]),
                              hostnames=unique([name]), os=str(ec2.get("platform") or ""), first_seen=None,
                              last_seen=last, vendor_ids={"resource_type": str(c.get("resourceType") or ""),
                                                          "account": str(c.get("accountId") or "")})


def _json(resp: httpx.Response) -> dict:
    try:
        body = resp.json()
    except ValueError as exc:
        raise ApiError(f"AWS Inspector: {resp.request.url.path} returned a body that is not JSON",
                       status=resp.status_code) from exc
    if not isinstance(body, dict):
        raise ApiError(f"AWS Inspector: {resp.request.url.path} returned an unexpected body")
    return body


def _error_detail(resp: httpx.Response) -> tuple[str, str | None]:
    """AWS rest-json errors: the type in ``x-amzn-ErrorType`` (``Name:namespace``) and ``message`` in the body."""
    code = (resp.headers.get("x-amzn-ErrorType") or "").split(":")[0] or None
    try:
        message = str(resp.json().get("message") or resp.json().get("Message") or "")
    except (ValueError, AttributeError):
        message = " ".join(resp.text.split())[:300]
    return message, code
