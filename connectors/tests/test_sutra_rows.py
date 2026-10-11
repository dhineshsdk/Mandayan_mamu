"""The adapter must build exactly the rows Sutra's own importers build. Runs when the sutra app is importable."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sutra_connectors.models import ScannerFinding

ingest = pytest.importorskip("sutra.ingest", reason="the sutra application package is not on the import path")
from sutra_connectors.sutra_rows import to_sutra_row, to_sutra_rows  # noqa: E402

T1 = datetime(2026, 3, 2, 9, 14, tzinfo=timezone.utc)
T2 = datetime(2026, 10, 9, 22, 1, tzinfo=timezone.utc)

CASES = [
    # Tenable package finding (RHEL advisory with package table)
    ScannerFinding("Tenable", "Plugin 170112", "tenable-vm:cloud.tenable.com", "f-1", "10.20.1.15",
                   "his-db01.plant.example.in", "RHEL 8", "RHEL 8 : openssl (RHSA-2023:0946)", "high", 7.4,
                   ("CVE-2023-0286",), "0", "TCP",
                   "Remote package installed : openssl-1.1.1k-7.el8_6\nShould be : openssl-1.1.1k-9.el8_7\n",
                   "Update openssl", "open", T1, T2),
    # Tenable config finding
    ScannerFinding("Tenable", "Plugin 96982", "tenable-sc:sc.example", "1|172.16.4.27|445|TCP|96982", "172.16.4.27",
                   "HMI-07", "Windows 7", "Server Message Block (SMB) Protocol Version 1 Enabled", "medium", 5.0, (),
                   "445", "TCP", "The remote host supports SMBv1.", "Disable SMBv1.", "reopened", T1, T2),
    # Qualys finding with "Prior to" title
    ScannerFinding("Qualys", "QID 376187", "qualys-api:qualysapi.qg1.apps.qualys.in", "123:376187:0:", "10.1.1.5",
                   "app01.corp.example.in", "Windows Server 2019", "7-Zip Prior to 23.01 Multiple Vulnerabilities",
                   "high", 7.8, ("CVE-2023-31102", "CVE-2023-40481"), "", "",
                   "7-Zip Version is 22.01", "Upgrade 7-Zip", "open", T1, None),
    # Informational row
    ScannerFinding("Qualys", "QID 45038", "qualys-api:qualysapi.qg1.apps.qualys.in", "123:45038:0:", "10.1.1.5",
                   "app01", "", "Host Scan Time", "info", None, (), "", "", "Scan duration: 300 seconds", "",
                   "open", None, T2),
]


@pytest.mark.parametrize("f", CASES, ids=lambda f: f.scanner_ref)
def test_matches_the_file_importer_rows(f):
    class Src:
        name = f.source

    nz = ingest.nz
    package_fn = nz.package_from_qualys if f.scanner == "Qualys" else nz.package_from_tenable
    expected = ingest._raw(f.scanner, f.scanner_ref.split(" ", 1)[1], Src, f.record_id, f.ip, f.hostname, f.os,
                           f.title, f.severity, str(f.cvss) if f.cvss is not None else "", " ".join(f.cves), f.port,
                           f.evidence, f.solution, f.first_seen.date() if f.first_seen else None,
                           f.last_seen.date() if f.last_seen else None, package_fn)
    expected["ref"] = f.scanner_ref
    row = to_sutra_row(f)
    assert row.pop("state") == f.state
    row.pop("last_fixed")
    assert row == expected


def test_fixed_rows_are_left_out_by_default():
    fixed = ScannerFinding(**{**CASES[0].__dict__, "state": "fixed", "last_fixed": T2})
    assert len(list(to_sutra_rows([CASES[0], fixed]))) == 1
    rows = list(to_sutra_rows([CASES[0], fixed], include_fixed=True))
    assert rows[1]["state"] == "fixed" and rows[1]["last_fixed"] == T2.date()


def test_rows_flow_through_resolve_and_dedupe():
    rows = list(to_sutra_rows(CASES))
    assets = ingest.resolve_assets([], rows)
    findings = ingest.dedupe(rows)
    assert len(assets) == 3
    assert {f.kind for f in findings} == {"package", "config"}
    assert all(f.sources[0].source_file.endswith(("cloud.tenable.com", "sc.example", "qualys.in")) for f in findings)


def test_receipts_point_at_the_api_source():
    row = to_sutra_row(CASES[0])
    assert (row["file"], row["row"]) == ("tenable-vm:cloud.tenable.com", "f-1")
    assert Path(row["file"]).name == row["file"]  # a plain label, safe where file names are expected


def test_agent_findings_use_the_package_they_name():
    base = dict(scanner="CrowdStrike", scanner_ref="Spotlight CVE-2025-26465",
                source="crowdstrike-api:api.crowdstrike.com", record_id="a_b", ip="10.1.1.9",
                hostname="ub24-50-10-154", os="Ubuntu 24.04", title="CVE-2025-26465 in openssh 1:9.6p1-3ubuntu13.4",
                severity="medium", cvss=6.8, cves=("CVE-2025-26465",), port="", protocol="",
                evidence="Installed: openssh 1:9.6p1-3ubuntu13.4", solution="", state="open", first_seen=T1,
                last_seen=T2)
    row = to_sutra_row(ScannerFinding(**base, package="openssh", installed="1:9.6p1-3ubuntu13.4",
                                      fixed_version="1:9.6p1-3ubuntu13.8"))
    assert (row["kind"], row["package"], row["installed"], row["fixed"]) == (
        "package", "openssh", "9.6p1-3ubuntu13.4", "9.6p1-3ubuntu13.8")
    kb = to_sutra_row(ScannerFinding(**{**base, "title": "CVE-2022-21897 in Windows Server 2016 1607"},
                                     package="Windows Server 2016", installed="1607", fixed_version="KB5053594"))
    # Grouped like a missing KB from a Qualys file.
    assert (kb["package"], kb["installed"], kb["fixed"]) == ("Microsoft Windows OS patch", "missing", "KB5053594")
    ingest.resolve_assets([], [row, kb])
    assert {f.kind for f in ingest.dedupe([row, kb])} == {"package"}
