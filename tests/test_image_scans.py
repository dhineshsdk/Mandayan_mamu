"""Milestone 4: Trivy and Grype image scan reports.

The fixtures are the scanners' own test outputs, unchanged:
- ``trivy_alpine-310.json`` and ``trivy_debian-buster.json`` are Trivy's integration test goldens
  (aquasecurity/trivy, ``integration/testdata/alpine-310.json.golden`` and ``debian-buster.json.golden``).
- ``grype_image.json`` is Grype's JSON presenter snapshot (anchore/grype,
  ``grype/presenter/json/testdata/snapshot/TestJsonImgsPresenter.golden``). Its packages and CVE IDs are Grype's own
  placeholders (``package-1``, ``CVE-1999-0001``).
The CMDB and the two host rows in ``test_a_scanned_image_joins_the_hosts_built_from_it`` are invented for the test.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from sutra import ingest, pipeline

FIX = Path(__file__).parent / "fixtures" / "image_scans"
ALPINE = "ghcr.io/aquasecurity/trivy-test-images:alpine-310"


def test_formats_are_detected_from_content(tmp_path):
    assert ingest.detect_format(FIX / "trivy_alpine-310.json") == "trivy"
    assert ingest.detect_format(FIX / "grype_image.json") == "grype"
    other = tmp_path / "other.json"
    other.write_text('{"SchemaVersion": 2, "ClusterName": "prod"}')
    with pytest.raises(ValueError):
        ingest.detect_format(other)


def test_trivy_rows():
    rows = ingest.load_trivy(FIX / "trivy_alpine-310.json")
    assert len(rows) == 4 and {r["scanner"] for r in rows} == {"Trivy"}
    r = rows[0]
    # Named by the image's tag, not the tarball path it was scanned from.
    assert r["host"] == ALPINE and r["image"] == ALPINE and r["ip"] == "" and r["os"] == "alpine 3.10.2"
    assert (r["kind"], r["package"], r["installed"], r["fixed"]) == ("package", "libcrypto1.1", "1.1.1c-r0",
                                                                     "1.1.1d-r0")
    assert r["ref"] == "CVE-2019-1549" and r["cves"] == ["CVE-2019-1549"] and r["severity"] == "medium"
    assert r["cvss"] == 5.3 and r["last"] == date(2021, 8, 25) and r["first"] is None
    assert "Upgrade libcrypto1.1 to 1.1.1d-r0" in r["solution"]

    bash, idn = ingest.load_trivy(FIX / "trivy_debian-buster.json")
    # No fix published: kept, with the CVSS score from NVD (the severity source).
    assert bash["fixed"] == "" and bash["severity"] == "low" and bash["cvss"] == 7.8
    assert "No fixed version of bash" in bash["solution"]
    assert idn["severity"] == "critical" and idn["cvss"] == 9.8 and idn["fixed"] == "2.0.5-1+deb10u1"


def test_trivy_refuses_other_schema_versions(tmp_path):
    old = tmp_path / "old.json"
    old.write_text('{"SchemaVersion": 1, "ArtifactName": "x", "Results": []}')
    with pytest.raises(ValueError, match="schema version 1"):
        ingest.load_trivy(old)


def test_grype_rows():
    one, two = ingest.load_grype(FIX / "grype_image.json")
    assert one["scanner"] == "Grype" and one["host"] == "user-input" and one["os"] == "centos 8.0"
    # The suggested fix from the match, not just the first listed version.
    assert (one["package"], one["installed"], one["fixed"]) == ("package-1", "1.1.1", "1.2.1")
    assert one["severity"] == "low" and one["cvss"] == 8.2 and one["last"] is None
    assert "/foo/bar/somefile-1.txt" in one["evidence"]
    assert two["severity"] == "critical" and two["fixed"] == "" and two["cves"] == ["CVE-1999-0002"]


def test_image_only_import_runs_through_the_pipeline():
    res = pipeline.run([FIX / "trivy_alpine-310.json", FIX / "trivy_debian-buster.json", FIX / "grype_image.json"])
    names = {a.hostname for a in res.assets.values()}
    assert names == {ALPINE, "ghcr.io/aquasecurity/trivy-test-images:debian-buster", "user-input"}
    assert all(not a.in_cmdb and a.image_source == "scanned image" for a in res.assets.values())
    # Four rows: two CVEs, each in libcrypto1.1 and libssl1.1 (both built from openssl). Rows sharing a CVE on one
    # asset are one finding, as for every scanner, and the finding keeps both rows as its sources.
    alpine = [f for f in res.findings if res.assets[f.asset_id].hostname == ALPINE]
    assert sorted((f.package, f.fixed, len(f.sources)) for f in alpine) == [("libcrypto1.1", "1.1.1d-r0", 2),
                                                                            ("libcrypto1.1", "1.1.1d-r2", 2)]
    assert res.root_causes and res.as_of == date(2021, 8, 25)


def test_a_scanned_image_joins_the_hosts_built_from_it(tmp_path):
    cmdb = tmp_path / "cmdb.csv"
    cmdb.write_text(
        "asset_id,hostname,ip,site,zone,os,owner,business_process,inr_per_hour,criticality,image\n"
        f"IMG-1,{ALPINE},,,corp,,Platform Engineering,apps,0,3,{ALPINE}\n"
        f"VM-1,app01.corp.example,10.0.0.1,HQ,corp,,Platform Engineering,apps,50000,4,{ALPINE}\n"
        f"VM-2,app02.corp.example,10.0.0.2,HQ,corp,,Platform Engineering,apps,50000,4,{ALPINE}\n")
    hosts = tmp_path / "hosts.jsonl"
    base = dict(scanner="Qualys", ref="QID 1", file="hosts.csv", host="", os="Alpine Linux 3.10",
                title="Alpine Linux Security Update for openssl", severity="medium", cvss=5.3, cves=["CVE-2019-1549"],
                port="", evidence="", solution="", first=date(2021, 8, 1), last=date(2021, 8, 25),
                package="libcrypto1.1", installed="1.1.1c-r0", fixed="1.1.1d-r0", control="", credential_fp="",
                kind="package")
    ingest.write_rows(hosts, "test", [dict(base, row=1, ip="10.0.0.1"), dict(base, row=2, ip="10.0.0.2")])

    res = pipeline.run([FIX / "trivy_alpine-310.json", hosts], cmdb)
    img = res.assets["IMG-1"]
    assert img.in_cmdb and img.owner == "Platform Engineering" and img.image_source == "cmdb"
    rc = next(r for r in res.root_causes if r.kind == "base-image")
    assert rc.key == ALPINE and set(rc.asset_ids) == {"IMG-1", "VM-1", "VM-2"}
