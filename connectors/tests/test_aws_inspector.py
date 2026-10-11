"""Amazon Inspector connector.

The finding fixtures are Elastic's AWS Inspector pipeline test records (elastic/integrations,
``packages/aws/data_stream/inspector/_dev/test/pipeline/test-inspector.log``, lines 2-19), split into two
``ListFindings`` pages. The ``nextToken`` and the coverage records are made up for the test, in the shapes the
Inspector2 service model in botocore defines.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from sutra_connectors.aws_inspector import AwsInspectorConnector, _sign, region_of
from sutra_connectors.errors import ApiError, AuthenticationError, ConfigurationError, ReadOnlyViolation
from sutra_connectors.http import RetryPolicy
from sutra_connectors.models import STATE_FIXED, STATE_OPEN

FIX = Path(__file__).parent / "fixtures" / "aws_inspector"
NOW = datetime(2025, 6, 14, 12, 0, tzinfo=timezone.utc)
URL = "https://inspector2.us-east-2.amazonaws.com"


def load(name):
    return json.loads((FIX / name).read_text())


class FakeInspector:
    def __init__(self, status=200, error=None):
        self.requests = []
        self.status, self.error = status, error

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if self.error:
            return httpx.Response(self.status, json={"message": self.error},
                                  headers={"x-amzn-ErrorType": "AccessDeniedException:http://internal.amazon.com/"})
        body = json.loads(req.content)
        if req.url.path == "/findings/list":
            return httpx.Response(200, json=load("findings_page2.json" if body.get("nextToken") else
                                                 "findings_page1.json"))
        if req.url.path == "/coverage/list":
            return httpx.Response(200, json=load("coverage.json"))
        return httpx.Response(404, json={"message": "not found"})


def connector(fake, **kw):
    return AwsInspectorConnector("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", base_url=URL,
                                 transport=httpx.MockTransport(fake), sleep=lambda s: None, clock=lambda: NOW,
                                 retry=RetryPolicy(max_attempts=2, backoff_base=0), **kw)


def test_full_pull_asks_for_active_package_findings_and_pages():
    fake = FakeInspector()
    findings = list(connector(fake).iter_findings())
    first, second = fake.requests
    body = json.loads(first.content)
    assert first.method == "POST" and first.url.path == "/findings/list" and body["maxResults"] == 100
    assert body["filterCriteria"] == {
        "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]}
    assert "nextToken" not in body and json.loads(second.content)["nextToken"] == "page-2-token"
    # The network reachability finding and the suppressed one are left out. A finding naming three packages
    # (openssh, openssh-clients, openssh-server) gives three findings.
    assert len(findings) == 35
    assert {f.state for f in findings} == {STATE_OPEN, STATE_FIXED}


def test_incremental_pull_filters_on_updated_time():
    fake = FakeInspector()
    list(connector(fake).iter_findings(datetime(2025, 6, 1, tzinfo=timezone.utc)))
    crit = json.loads(fake.requests[0].content)["filterCriteria"]
    assert crit["updatedAt"] == [{"startInclusive": 1748736000}] and "findingStatus" not in crit


def test_maps_findings():
    findings = list(connector(FakeInspector()).iter_findings())
    f = findings[0]
    assert f.scanner == "AWS Inspector" and f.source == "aws-inspector:us-east-2"
    assert f.scanner_ref == "Inspector CVE-2024-35195" and f.cves == ("CVE-2024-35195",)
    assert f.record_id == "arn:aws:inspector2:us-east-2:123451256789:finding/fb6294abcdef0123456789abcdef8404"
    assert (f.hostname, f.ip, f.os) == ("i-059abcdefabcdef1b", "10.90.0.87", "AMAZON_LINUX_2")
    assert (f.package, f.installed, f.fixed_version) == ("python-requests", "0:2.6.0-10.amzn2.0.5",
                                                         "0:2.6.0-10.amzn2.0.6")
    assert f.title == "CVE-2024-35195 in python-requests 0:2.6.0-10.amzn2.0.5"
    assert f.severity == "medium" and f.cvss == 6.5  # the higher of Amazon's 6.5 and NVD's 5.6
    assert f.solution == "yum update python-requests"  # "None Provided" is not repeated
    assert f.first_seen == datetime.fromtimestamp(1748629505.465, tz=timezone.utc)
    assert f.last_seen == datetime.fromtimestamp(1749165997.322, tz=timezone.utc)

    ssh = [x for x in findings if x.cves == ("CVE-2025-32728",)]
    assert sorted(x.package for x in ssh) == ["openssh", "openssh-clients", "openssh-server"]
    assert len({x.record_id for x in ssh}) == 3 and all(x.record_id.endswith("#" + x.package) for x in ssh)

    ecr = next(x for x in findings if "dkr.ecr" in x.hostname)
    assert ecr.hostname == "012345678989.dkr.ecr.us-east-1.amazonaws.com/orestis-onweek-2:latest"
    assert ecr.ip == "" and ecr.os == "AMAZON_LINUX_2023"

    closed = next(x for x in findings if x.state == STATE_FIXED)
    assert closed.last_fixed is not None and closed.cves == ()  # its ID is not a CVE


def test_hosts_from_coverage():
    c = connector(FakeInspector())
    list(c.iter_findings())
    hosts = list(c.iter_hosts())
    assert [h.host_id for h in hosts] == ["i-020babcdefabcdefd", "i-0aaaabbbbccccdddd"]  # the stale one is left out
    seen, tagged = hosts
    assert seen.ips == ("10.90.0.42",) and seen.hostnames == ("i-020babcdefabcdefd",)  # from its findings
    assert tagged.ips == () and tagged.hostnames == ("scada-historian-01",) and tagged.os == "WINDOWS"
    fake = FakeInspector()
    list(connector(fake).iter_hosts())
    assert json.loads(fake.requests[0].content)["filterCriteria"]["scanType"] == [
        {"comparison": "EQUALS", "value": "PACKAGE"}]
    assert len(list(connector(FakeInspector(), host_window=timedelta(days=3650)).iter_hosts())) == 3


def test_signature_matches_botocore():
    botocore = pytest.importorskip("botocore")
    from unittest import mock

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    body = json.dumps({"maxResults": 100}).encode()
    secret = "secret/Key+1"  # noqa: S105 - a test key
    creds = "AKIDEXAMPLE", secret
    for token in ("", "FQoGZXIvYXdzEXAMPLETOKEN"):
        req = httpx.Request("POST", URL + "/findings/list", content=body, headers={"Content-Type": "application/json"})
        _sign(req, access_key=creds[0], secret_key=secret, session_token=token, region="us-east-2",
              now=NOW)
        ref = AWSRequest(method="POST", url=URL + "/findings/list", data=body,
                         headers={"Content-Type": "application/json"})
        with mock.patch("botocore.auth.get_current_datetime", return_value=NOW.replace(tzinfo=None)):
            SigV4Auth(Credentials(*creds, token or None), "inspector2", "us-east-2").add_auth(ref)
        assert req.headers["Authorization"] == ref.headers["Authorization"], botocore.__version__
        assert req.headers["X-Amz-Date"] == ref.headers["X-Amz-Date"] == "20250614T120000Z"


def test_every_request_is_signed():
    fake = FakeInspector()
    list(connector(fake).iter_findings())
    auth = fake.requests[0].headers["authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20250614/us-east-2/inspector2/aws4_request")


def test_errors():
    with pytest.raises(AuthenticationError):
        list(connector(FakeInspector(status=403, error="not authorized")).iter_findings())
    with pytest.raises(ApiError, match="bad filter"):
        list(connector(FakeInspector(status=400, error="bad filter")).iter_findings())


def test_configuration_and_read_only():
    assert region_of("https://inspector2.ap-south-1.amazonaws.com") == "ap-south-1"
    assert region_of("https://inspector2-fips.us-gov-west-1.amazonaws.com") == "us-gov-west-1"
    assert region_of("https://inspector2.cn-north-1.amazonaws.com.cn") == "cn-north-1"
    with pytest.raises(ConfigurationError):
        AwsInspectorConnector("", "x")
    with pytest.raises(ConfigurationError):
        AwsInspectorConnector("a", "b", base_url="https://inspector.example.com")
    with pytest.raises(ConfigurationError):
        AwsInspectorConnector("a", "b", base_url="http://inspector2.ap-south-1.amazonaws.com")
    assert AwsInspectorConnector("a", "b").source == "aws-inspector:ap-south-1"
    c = connector(FakeInspector())
    with pytest.raises(ReadOnlyViolation):
        c.http.request("POST", "/findings/actions/suppress")
