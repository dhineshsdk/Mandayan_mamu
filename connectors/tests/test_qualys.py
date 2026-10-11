import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from sutra_connectors.errors import ApiError, AuthenticationError, ConfigurationError, ReadOnlyViolation
from sutra_connectors.http import RetryPolicy
from sutra_connectors.qualys import QualysConnector

FIX = Path(__file__).parent / "fixtures" / "qualys"
BASE = "https://qualysapi.qg1.apps.qualys.in"


def xml(name):
    return (FIX / name).read_bytes()


def simple_return(code, text):
    return (f'<?xml version="1.0" encoding="UTF-8" ?><SIMPLE_RETURN><RESPONSE><DATETIME>2026-10-11T12:00:00Z'
            f'</DATETIME><CODE>{code}</CODE><TEXT>{text}</TEXT></RESPONSE></SIMPLE_RETURN>').encode()


class FakeQualys:
    def __init__(self, routes):
        self.routes = routes  # path -> list of responses (last one repeats)
        self.requests = []

    def __call__(self, req):
        self.requests.append(req)
        queue = self.routes[req.url.path]
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        return item(req) if callable(item) else item

    def forms(self, path):
        return [{k: v[0] for k, v in parse_qs(r.content.decode()).items()} for r in self.requests
                if r.url.path == path]


def ok(body, **headers):
    return httpx.Response(200, content=body, headers={"Content-Type": "text/xml", **headers})


def detection_pages(req):
    form = parse_qs(req.content.decode())
    return ok(xml("detection_page2.xml") if "id_min" in form else xml("detection_page1.xml"))


def connector(fake, sleeps=None, **kw):
    return QualysConnector(BASE, "user_ro", "pa55", transport=httpx.MockTransport(fake),
                           sleep=(sleeps if sleeps is not None else []).append,
                           retry=kw.pop("retry", RetryPolicy(max_attempts=3, backoff_base=0)), **kw)


DET = "/api/6.0/fo/asset/host/vm/detection/"
KB = "/api/4.0/fo/knowledge_base/vuln/"
HOSTS = "/api/6.0/fo/asset/host/"


def test_full_pull_pages_and_enriches_from_the_knowledgebase():
    fake = FakeQualys({DET: [detection_pages], KB: [ok(xml("kb.xml"))]})
    findings = list(connector(fake).iter_findings())
    first = fake.requests[0]
    assert first.headers["x-requested-with"] == "Sutra Connectors"
    assert first.headers["authorization"].startswith("Basic ")
    det_forms = fake.forms(DET)
    assert det_forms[0] == {"action": "list", "truncation_limit": "1000", "show_results": "1",
                            "output_format": "XML", "status": "New,Active,Re-Opened"}
    assert det_forms[1]["id_min"] == "6506433"  # taken from the 1980 WARNING URL
    assert fake.forms(KB) == [{"action": "list", "details": "All", "ids": "38170,376187"}]
    assert len(findings) == 3

    zip_, cert, fixed = findings
    assert zip_.scanner == "Qualys" and zip_.scanner_ref == "QID 376187"
    assert zip_.source == "qualys-api:qualysapi.qg1.apps.qualys.in" and zip_.record_id == "52664"
    assert zip_.title == "7-Zip Prior to 23.01 Multiple Vulnerabilities"
    assert zip_.cves == ("CVE-2023-31102", "CVE-2023-40481") and zip_.cvss == 7.8
    assert zip_.severity == "high" and zip_.state == "open"
    assert zip_.hostname == "scada-hist01.plant.example.in" and zip_.ip == "10.10.10.11"
    assert zip_.evidence == "7-Zip Version is 22.01"
    assert zip_.solution.startswith("Customers are advised to upgrade to 7-Zip 23.01 or later.")
    assert "<" not in zip_.solution and "& more" in zip_.solution
    assert zip_.first_seen == datetime(2026, 1, 26, 4, 45, 50, tzinfo=timezone.utc)
    assert (cert.port, cert.protocol, cert.state, cert.severity, cert.cvss) == ("3389", "tcp", "reopened", "low", 6.5)
    assert fixed.hostname == "MES-APP02" and fixed.state == "fixed"
    assert fixed.last_fixed == datetime(2026, 10, 5, 10, tzinfo=timezone.utc)


def test_knowledgebase_is_cached_between_pulls():
    fake = FakeQualys({DET: [detection_pages], KB: [ok(xml("kb.xml"))]})
    c = connector(fake)
    list(c.iter_findings())
    list(c.iter_findings())
    assert len(fake.forms(KB)) == 1


def test_incremental_pull_uses_vm_processed_after_and_includes_fixed():
    fake = FakeQualys({DET: [ok(xml("detection_page2.xml"))], KB: [ok(xml("kb.xml"))]})
    list(connector(fake, include_vuln_type="confirmed").iter_findings(
        datetime(2026, 10, 10, 4, 30, 15, 999, tzinfo=timezone.utc)))
    form = fake.forms(DET)[0]
    assert form["vm_processed_after"] == "2026-10-10T04:30:15Z"
    assert form["status"] == "New,Active,Re-Opened,Fixed"
    assert form["include_vuln_type"] == "confirmed"


def test_rate_limit_1965_waits_for_the_advertised_time():
    sleeps = []
    limited = httpx.Response(409, content=simple_return(1965, "This API cannot be run again for another 42 seconds"),
                             headers={"X-RateLimit-ToWait-Sec": "42"})
    fake = FakeQualys({DET: [limited, ok(xml("detection_page2.xml"))], KB: [ok(xml("kb.xml"))]})
    assert len(list(connector(fake, sleeps).iter_findings())) == 1
    assert sleeps == [42.0]


def test_concurrency_1960_waits_30_seconds():
    sleeps = []
    busy = httpx.Response(409, content=simple_return(1960, "This API cannot be run again until 1 currently running "
                                                           "API instance has finished."))
    fake = FakeQualys({DET: [busy, ok(xml("detection_page2.xml"))], KB: [ok(xml("kb.xml"))]})
    list(connector(fake, sleeps).iter_findings())
    assert sleeps == [30.0]


def test_busy_1981_is_retried_and_exhausted_window_is_waited_out():
    sleeps = []
    busy = httpx.Response(202, content=simple_return(1981, "Your request is being processed. Please try this "
                                                           "same request again later."))
    last_call = ok(xml("detection_page2.xml"), **{"X-RateLimit-Remaining": "0", "X-RateLimit-ToWait-Sec": "17"})
    fake = FakeQualys({DET: [busy, last_call], KB: [ok(xml("kb.xml"))]})
    list(connector(fake, sleeps, busy_wait=60).iter_findings())
    assert sleeps == [60, 17.0]


def test_errors_carry_the_qualys_code():
    fake = FakeQualys({DET: [httpx.Response(400, content=simple_return(1905, "parameter status has invalid value"))]})
    with pytest.raises(ApiError) as e:
        list(connector(fake).iter_findings())
    assert e.value.code == "1905" and "invalid value" in str(e.value)

    fake = FakeQualys({DET: [httpx.Response(409, content=simple_return(2011, "SecureID authentication is required"))]})
    with pytest.raises(ApiError) as e:
        list(connector(fake).iter_findings())
    assert e.value.code == "2011"

    with pytest.raises(AuthenticationError):
        list(connector(FakeQualys({DET: [httpx.Response(401, content=simple_return(2000, "Bad Login"))]}))
             .iter_findings())


def test_rejects_hostile_or_broken_xml():
    bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
            b'<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE>&lol2;</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>')
    for body in (bomb, b"<html>maintenance"):
        with pytest.raises(ApiError):
            list(connector(FakeQualys({DET: [ok(body)]})).iter_findings())


def test_lowercase_tags_are_accepted():
    body = xml("detection_page2.xml").decode()
    body = re.sub(r"</?[A-Z_]+", lambda m: m[0].lower(), body)
    fake = FakeQualys({DET: [ok(body.encode())], KB: [ok(xml("kb.xml"))]})
    (f,) = connector(fake).iter_findings()
    assert f.scanner_ref == "QID 376187" and f.state == "fixed"


def test_hosts():
    fake = FakeQualys({HOSTS: [ok(xml("host_list.xml"))]})
    since = datetime(2026, 10, 1, tzinfo=timezone.utc)
    (h,) = connector(fake).iter_hosts(since)
    assert fake.forms(HOSTS)[0] == {"action": "list", "details": "All", "truncation_limit": "1000",
                                    "vm_processed_after": "2026-10-01T00:00:00Z"}
    assert h.host_id == "6506432" and h.ip == "10.10.10.11"
    assert h.hostnames == ("scada-hist01.plant.example.in", "scada-hist01", "SCADA-HIST01")
    assert h.first_seen == datetime(2025, 6, 1, 10, tzinfo=timezone.utc)
    assert h.last_seen == datetime(2026, 10, 9, 3, 49, 5, tzinfo=timezone.utc)
    assert h.vendor_ids["asset_id"] == "11223344"


def test_only_list_actions_are_allowed():
    c = connector(FakeQualys({HOSTS: [ok(b"")]}))
    with pytest.raises(ReadOnlyViolation):
        c.http.request("POST", HOSTS, data={"action": "update", "ids": "1"})
    with pytest.raises(ReadOnlyViolation):
        c.http.request("POST", "/api/2.0/fo/scan/", data={"action": "launch"})


@pytest.mark.parametrize("kw", [{"detection_api_version": "latest"}, {"truncation_limit": 0},
                                {"include_vuln_type": "all"}, {"kb_batch_size": 0}])
def test_rejects_bad_settings(kw):
    with pytest.raises(ConfigurationError):
        QualysConnector(BASE, "u", "p", **kw)


def test_versions_are_configurable_and_password_not_in_repr():
    c = QualysConnector(BASE, "u", "SECRETPW", detection_api_version="5.0")
    assert c.detection_path == "/api/5.0/fo/asset/host/vm/detection/"
    assert "SECRETPW" not in repr(c)
