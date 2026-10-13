"""Sutra Scan results import like any scanner export.

``fixtures/sutra_scan_alpine_3.19.0.rows`` was produced by ``sutra-scan match`` from the real ``alpine:3.19.0`` image
(manifest digest sha256:13b7e62e...) against the OSV Alpine v3.19 feed of 2026-10-13. The CMDB below is invented.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from sutra import ingest, pipeline

ROWS = Path(__file__).parent / "fixtures" / "sutra_scan_alpine_3.19.0.rows"


def test_rows_file_is_recognised_and_loads():
    assert ingest.detect_format(ROWS) == "rows"
    rows = ingest.load_rows(ROWS)
    assert {r["scanner"] for r in rows} == {"Sutra Scan"} and set(ingest.ROW_KEYS) == set(rows[0])
    info = [r for r in rows if r["kind"] == "info"]
    assert len(info) == 1 and info[0]["host"] == "plant-alpine01" and info[0]["ip"] == "10.20.0.15"
    busybox = next(r for r in rows if r["ref"] == "CVE-2023-42366")
    assert (busybox["kind"], busybox["package"], busybox["installed"], busybox["fixed"], busybox["severity"]) == (
        "package", "busybox", "1.36.1-r15", "1.36.1-r16", "medium")
    assert busybox["cves"] == ["CVE-2023-42366"] and busybox["last"] == date(2026, 10, 13)


def test_scan_findings_reach_assets_and_root_causes(tmp_path):
    cmdb = tmp_path / "cmdb.csv"
    cmdb.write_text(
        "asset_id,hostname,ip,site,zone,os,owner,business_process,inr_per_hour,criticality,image\n"
        "VM-9,plant-alpine01,10.20.0.15,Pune,corp,Alpine Linux v3.19,Platform Engineering,apps,40000,3,\n")
    res = pipeline.run([ROWS], cmdb)
    asset = res.assets["VM-9"]
    assert asset.in_cmdb and asset.owner == "Platform Engineering"
    mine = [f for f in res.findings if f.asset_id == "VM-9"]
    assert mine and all(f.package for f in mine)
    # busybox and busybox-binsh are built from one source, so the root causes group by what fixes them
    assert any(f.package == "busybox" and f.fixed == "1.36.1-r19" for f in mine)
    assert res.root_causes
