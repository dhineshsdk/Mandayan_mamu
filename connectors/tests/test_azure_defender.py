"""Microsoft Defender for Cloud connector.

The fixtures come from Elastic's Microsoft Defender for Cloud pipeline test records (elastic/integrations,
``packages/microsoft_defender_cloud/data_stream/assessment/_dev/test/pipeline/test-assessment.log``): the seven
sub-assessments they carry make page 1, and the assessments, with their sub-assessment removed, make
``assessments.json``. Made up for the test, from those records: the ``nextLink``, the second page (a copy of the
libxml2 record changed to a healthy openssl one) and a healthy assessment for ``plant-historian-01``.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from sutra_connectors.azure_defender import AzureDefenderConnector, scope_path
from sutra_connectors.errors import ApiError, AuthenticationError, ConfigurationError, ReadOnlyViolation
from sutra_connectors.http import RetryPolicy
from sutra_connectors.models import STATE_FIXED, STATE_OPEN

FIX = Path(__file__).parent / "fixtures" / "azure_defender"
NOW = datetime(2025, 8, 25, 6, 0, tzinfo=timezone.utc)
TENANT = "11111111-2222-3333-4444-555555555555"
SUB = "5abcdef6-1234-5678-8912-e1234abcdef1"


def load(name):
    return json.loads((FIX / name).read_text())


class FakeAzure:
    def __init__(self, next_host="management.azure.com", status=200):
        self.requests, self.tokens = [], []
        self.next_host, self.status = next_host, status

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if req.url.host == "login.microsoftonline.com":
            self.tokens.append(parse_qs(req.content.decode()))
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": "arm"})
        assert req.headers["authorization"] == "Bearer arm"
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"code": "AuthorizationFailed",
                                                               "message": "The client does not have authorization"}})
        if req.url.path.endswith("/subAssessments"):
            assert req.url.params["api-version"] == "2019-01-01-preview"
            if req.url.params.get("$skipToken") == "page2":
                return httpx.Response(200, json=load("subassessments_page2.json"))
            body = load("subassessments_page1.json")
            body["nextLink"] = body["nextLink"].replace("management.azure.com", self.next_host)
            return httpx.Response(200, json=body)
        if req.url.path.endswith("/assessments"):
            assert req.url.params["api-version"] == "2021-06-01"
            return httpx.Response(200, json=load("assessments.json"))
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": "no"}})


def connector(fake, scopes=(SUB,)):
    return AzureDefenderConnector(TENANT, "app-id", "app-secret", list(scopes), transport=httpx.MockTransport(fake),
                                  sleep=lambda s: None, clock=lambda: NOW,
                                  retry=RetryPolicy(max_attempts=2, backoff_base=0))


def test_reads_server_vulnerabilities_across_pages():
    fake = FakeAzure()
    findings = list(connector(fake).iter_findings())
    token, first, second = fake.requests
    assert token.url.path == f"/{TENANT}/oauth2/v2.0/token"
    assert fake.tokens[0]["scope"] == ["https://management.azure.com/.default"]
    assert fake.tokens[0]["grant_type"] == ["client_credentials"]
    assert first.url.path == f"/subscriptions/{SUB}/providers/Microsoft.Security/subAssessments"
    assert second.url.params["$skipToken"] == "page2"
    # Only the two ServerVulnerabilityTvm records: AKS nodes, containers and posture checks are left out.
    open_, fixed = findings
    assert open_.state == STATE_OPEN and fixed.state == STATE_FIXED


def test_maps_a_server_vulnerability():
    f = next(connector(FakeAzure()).iter_findings())
    assert f.scanner == "Defender for Cloud" and f.scanner_ref == "Defender M4B6BH"
    assert f.hostname == "vm-for-defender-cloud-test" and f.ip == ""
    assert f.title == "Update Ubuntu Libxml2 For Linux" and f.severity == "high" and f.cvss == 9.1
    assert f.cves == ("CVE-2025-6021", "CVE-2025-49796", "CVE-2025-6170", "CVE-2025-49794")
    assert (f.package, f.installed, f.fixed_version) == ("libxml2_for_linux", "2.9.14+dfsg-1.3ubuntu3.3", "")
    assert f.last_seen == datetime(2025, 8, 21, 17, 40, 43, 325407, tzinfo=timezone.utc)
    assert f.record_id.endswith("/subassessments/f9abcdfd-1871-5678-1234-477889965446")
    assert "Microsoft Defender vulnerability management" in f.evidence


def test_hosts_are_machines_with_an_assessment_result():
    hosts = list(connector(FakeAzure()).iter_hosts())
    assert [h.hostnames for h in hosts] == [("vm-for-defender-cloud-test",), ("plant-historian-01",)]
    assert all(h.last_seen == NOW and h.ips == () for h in hosts)


def test_scopes():
    assert scope_path(SUB.upper()) == f"/subscriptions/{SUB}"
    assert scope_path(f"/subscriptions/{SUB}") == f"/subscriptions/{SUB}"
    assert scope_path("plant-mg") == "/providers/Microsoft.Management/managementGroups/plant-mg"
    with pytest.raises(ConfigurationError):
        scope_path("a/b")
    fake = FakeAzure()
    list(connector(fake, scopes=(SUB, "plant-mg")).iter_hosts())
    assert [r.url.path for r in fake.requests[1:]] == [
        f"/subscriptions/{SUB}/providers/Microsoft.Security/assessments",
        "/providers/Microsoft.Management/managementGroups/plant-mg/providers/Microsoft.Security/assessments"]


def test_refuses_a_next_link_to_another_host():
    with pytest.raises(ApiError, match="another host"):
        list(connector(FakeAzure(next_host="evil.example")).iter_findings())


def test_errors_and_configuration():
    with pytest.raises(AuthenticationError):
        list(connector(FakeAzure(status=403)).iter_findings())
    with pytest.raises(ConfigurationError):
        AzureDefenderConnector(TENANT, "a", "b", [])
    with pytest.raises(ConfigurationError):
        AzureDefenderConnector("not a tenant!", "a", "b", [SUB])
    with pytest.raises(ConfigurationError):
        AzureDefenderConnector(TENANT, "a", "", [SUB])
    c = connector(FakeAzure())
    with pytest.raises(ReadOnlyViolation):
        c.http.request("PUT", f"/subscriptions/{SUB}/providers/Microsoft.Security/assessments")
    with pytest.raises(ReadOnlyViolation):
        c.http.request("GET", f"/subscriptions/{SUB}/resourceGroups")
