"""Feed building and matching, on real OSV records (see conftest) and constructed inventories."""

import json
import socket

import pytest

from sutra_scan import feed, rows
from sutra_scan.inventory import OsInfo
from sutra_scan.match import UnsupportedOs, candidate_ecosystems, match

from .conftest import FIXTURES, make_inventory


def by_adv(result):
    return {(d.package, d.advisory): d for d in result.detections}


def test_snapshot_info(snapshot):
    info = snapshot.info()
    assert info["ecosystems"] == ["AlmaLinux:9", "Alpine:v3.19", "Debian:12", "Red Hat:enterprise_linux:9::baseos",
                                  "Ubuntu:24.04:LTS"]
    assert info["advisories"] == 9 and len(info["digest"]) == 64
    assert info["data_as_of"].startswith("2026-09-21")  # newest `modified` among the fixture records


def test_debian_uses_source_package_and_source_version(snapshot):
    inv = make_inventory("dpkg", "debian", "12", [
        ("libssl3", "3.0.9-1", "openssl", "3.0.9-1", "amd64"),  # old: affected
        ("libssl3", "3.0.11-1~deb12u2+b1", "openssl", "3.0.11-1~deb12u2", "arm64"),  # fixed source, binNMU binary
        ("openssl", "3.0.9-1", "openssl", "3.0.9-1", "amd64"),
    ])
    hits = by_adv(match(inv, snapshot))
    assert set(hits) == {("libssl3", "CVE-2023-2975"), ("libssl3", "DSA-5532-1"),
                         ("openssl", "CVE-2023-2975"), ("openssl", "DSA-5532-1")}
    d = hits[("libssl3", "CVE-2023-2975")]
    assert (d.installed, d.fixed, d.source, d.severity, d.cvss) == ("3.0.9-1", "3.0.10-1~deb12u1", "openssl", "medium", 5.3)


def test_distribution_advisory_absorbs_cve_record_and_keeps_its_cvss(snapshot):
    inv = make_inventory("dpkg", "debian", "12", [("libssl3", "3.0.9-1", "openssl", "3.0.9-1", "amd64")])
    hits = by_adv(match(inv, snapshot))
    assert ("libssl3", "CVE-2023-5363") not in hits  # DSA-5532-1 covers it with the same fix
    dsa = hits[("libssl3", "DSA-5532-1")]
    assert dsa.cves == ("CVE-2023-5363",) and (dsa.severity, dsa.cvss) == ("high", 7.5)  # DSA has none; CVE record does


def test_exactly_at_the_fixed_version_is_not_affected(snapshot):
    inv = make_inventory("dpkg", "debian", "12", [("libssl3", "3.0.11-1~deb12u2", "openssl", "3.0.11-1~deb12u2", "x")])
    assert match(inv, snapshot).detections == []


def test_alpine(snapshot):
    inv = make_inventory("apk", "alpine", "3.19.1", [
        ("busybox", "1.36.1-r15", "busybox", "1.36.1-r15", "x86_64"),
        ("libcrypto3", "3.1.4-r4", "openssl", "3.1.4-r4", "x86_64"),
        ("libssl3", "3.1.4-r5", "openssl", "3.1.4-r5", "x86_64"),  # fixed
    ])
    hits = by_adv(match(inv, snapshot))
    assert set(hits) == {("busybox", "CVE-2023-42366"), ("libcrypto3", "CVE-2024-0727")}
    assert hits[("busybox", "CVE-2023-42366")].fixed == "1.36.1-r16"


def test_almalinux_epoch_and_vendor_rating(snapshot):
    inv = make_inventory("rpm", "almalinux", "9.3", [
        ("openssl-libs", "1:3.0.7-24.el9", "openssl", "1:3.0.7-24.el9", "x86_64"),
        ("openssl", "1:3.0.7-27.el9", "openssl", "1:3.0.7-27.el9", "x86_64"),  # at the newest fix in the fixtures
        ("bash", "5.1.8-6.el9", "bash", "5.1.8-6.el9", "x86_64"),
    ])
    hits = by_adv(match(inv, snapshot))
    assert set(hits) == {("openssl-libs", "ALSA-2024:0310"), ("openssl-libs", "ALSA-2024:2447")}
    a = hits[("openssl-libs", "ALSA-2024:0310")]
    assert (a.installed, a.fixed, a.severity, a.rated_by) == ("3.0.7-24.el9", "3.0.7-25.el9_3", "medium", "distribution rating")
    assert hits[("openssl-libs", "ALSA-2024:2447")].severity == "low"  # "Low: openssl ... security update"


def test_rhel_reads_every_channel_and_uses_cvss(snapshot):
    inv = make_inventory("rpm", "rhel", "9.2", [
        ("curl-minimal", "7.76.1-23.el9_2.4", "curl", "7.76.1-23.el9_2.4", "x86_64"),
        ("libcurl-minimal", "0:7.76.1-26.el9_3.2", "curl", "7.76.1-26.el9_3.2", "x86_64"),  # at the fix
    ])
    res = match(inv, snapshot)
    hits = by_adv(res)
    assert set(hits) == {("curl-minimal", "RHSA-2023:6745")}
    d = hits[("curl-minimal", "RHSA-2023:6745")]
    assert (d.fixed, d.severity, d.cvss, d.ecosystem) == ("7.76.1-26.el9_3.2", "high", 8.1, "Red Hat:enterprise_linux:9::baseos")


def test_ubuntu_priority_and_cvss(snapshot):
    inv = make_inventory("dpkg", "ubuntu", "24.04", [("openssl", "3.0.10-1ubuntu1", "openssl", "3.0.10-1ubuntu1", "x")])
    d = match(inv, snapshot).detections[0]
    assert (d.advisory, d.fixed, d.severity, d.ecosystem) == ("UBUNTU-CVE-2023-5363", "3.0.10-1ubuntu2.1", "high", "Ubuntu:24.04:LTS")


def test_matching_needs_no_network(snapshot, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("matching opened a network socket")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    inv = make_inventory("apk", "alpine", "3.19.1", [("busybox", "1.36.1-r15", "busybox", "1.36.1-r15", "x")])
    assert match(inv, snapshot).detections


def test_unsupported_and_missing_releases(snapshot):
    with pytest.raises(UnsupportedOs, match="not supported"):
        match(make_inventory("dpkg", "debian", "", [("a", "1", "a", "1", "x")]), snapshot)
    with pytest.raises(UnsupportedOs, match="no Debian:10 advisories"):
        match(make_inventory("dpkg", "debian", "10", [("a", "1", "a", "1", "x")]), snapshot)
    with pytest.raises(UnsupportedOs, match="not supported"):
        match(make_inventory("rpm", "sles", "15.5", [("a", "1", "a", "1", "x")]), snapshot)
    with pytest.raises(UnsupportedOs, match="no Red Hat:enterprise_linux:8::"):
        match(make_inventory("rpm", "rhel", "8.8", [("a", "1", "a", "1", "x")]), snapshot)


@pytest.mark.parametrize(("os_id", "version", "want"), [
    ("debian", "12", ["Debian:12"]), ("ubuntu", "22.04", ["Ubuntu:22.04:LTS", "Ubuntu:22.04"]),
    ("alpine", "3.19.1", ["Alpine:v3.19"]), ("almalinux", "9.3", ["AlmaLinux:9"]), ("rocky", "8.9", ["Rocky Linux:8"]),
    ("rhel", "9.2", ["Red Hat:enterprise_linux:9::*"]),
    ("alpine", "edge", []), ("fedora", "40", []), ("debian", "", [])])
def test_candidate_ecosystems(os_id, version, want):
    assert candidate_ecosystems(OsInfo(id=os_id, version_id=version)) == want


# ---- synthetic records: shapes the fixtures do not cover. Built here on purpose, not copied from a feed.


def _snapshot(tmp_path, records, ecosystems):
    d = tmp_path / "osv"
    d.mkdir()
    for r in records:
        (d / f"{r['id']}.json").write_text(json.dumps(r))
    f = feed.build(tmp_path / "s.db", [d], ecosystems)
    assert f["advisories"] == len(records)
    return feed.Feed(tmp_path / "s.db")


def _rec(rid, eco, name, events, **extra):
    return {"id": rid, "modified": "2026-10-01T00:00:00Z", "published": "2026-09-01T00:00:00Z", "summary": "synthetic",
            "affected": [{"package": {"name": name, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}],
            **extra}


def test_unfixed_advisories_only_with_the_flag(tmp_path):
    f = _snapshot(tmp_path, [_rec("CVE-2030-0001", "Debian:12", "foo", [{"introduced": "0"}],
                                  severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])],
                  ["Debian:12"])
    inv = make_inventory("dpkg", "debian", "12", [("foo", "1.0-1", "foo", "1.0-1", "x")])
    assert match(inv, f).detections == []
    d = match(inv, f, include_unfixed=True).detections[0]
    assert (d.fixed, d.severity, d.cvss) == ("", "critical", 9.8)


def test_introduced_last_affected_and_second_range(tmp_path):
    ev = [{"introduced": "1.0"}, {"fixed": "1.5-r1"}, {"introduced": "2.0"}, {"last_affected": "2.3-r1"}]
    f = _snapshot(tmp_path, [_rec("CVE-2030-0002", "Alpine:v3.19", "bar", ev)], ["Alpine:v3.19"])

    def hits(v):
        inv = make_inventory("apk", "alpine", "3.19.0", [("bar", v, "bar", v, "x")])
        return match(inv, f, include_unfixed=True).detections

    assert hits("0.9-r0") == []          # before the first introduced
    assert len(hits("1.2-r0")) == 1      # inside the first range
    assert hits("1.5-r1") == []          # fixed
    assert hits("1.9-r0") == []          # gap between the ranges
    assert len(hits("2.3-r1")) == 1      # last_affected is inclusive
    assert hits("2.3-r2") == []


def test_rpm_modular_streams_are_judged_by_their_own_fix(tmp_path):
    fixes = ["2:16.20.1-1.module+el8.8.0", "2:18.17.1-1.module+el8.8.0", "2:20.5.0-1.module+el8.8.0"]
    rec = _rec("ALSA-2030:0001", "AlmaLinux:8", "nodejs", [{"introduced": "0"}, {"fixed": fixes[0]}])
    rec["affected"] += [_rec("x", "AlmaLinux:8", "nodejs", [{"introduced": "0"}, {"fixed": f}])["affected"][0] for f in fixes[1:]]
    f = _snapshot(tmp_path, [rec], ["AlmaLinux:8"])

    def hits(v):
        return match(make_inventory("rpm", "almalinux", "8.8", [("nodejs", v, "nodejs", v, "x")]), f).detections

    assert len(hits("2:18.16.0-1.module+el8.8.0")) == 1   # old 18.x: below the 18.17.1 fix, not hidden by 16.x
    assert hits("2:18.17.1-1.module+el8.8.0") == []        # patched 18.x: not blamed for the 20.x fix
    assert hits("2:16.20.1-1.module+el8.8.0") == []
    assert len(hits("2:20.4.0-1.module+el8.8.0")) == 1


def test_skips_ranges_it_cannot_parse_and_says_so(tmp_path):
    f = _snapshot(tmp_path, [_rec("CVE-2030-0003", "Alpine:v3.19", "baz", [{"introduced": "0"}, {"fixed": "not a version"}])],
                  ["Alpine:v3.19"])
    inv = make_inventory("apk", "alpine", "3.19.0", [("baz", "1.0-r0", "baz", "1.0-r0", "x")])
    res = match(inv, f)
    assert res.detections == [] and any("could not be parsed" in w for w in res.warnings)


def test_rebuild_keeps_newest_copy_of_an_advisory(tmp_path):
    old = _rec("CVE-2030-0004", "Debian:12", "foo", [{"introduced": "0"}, {"fixed": "1.0-1"}])
    new = _rec("CVE-2030-0004", "Debian:12", "foo", [{"introduced": "0"}, {"fixed": "2.0-1"}])
    new["modified"] = "2026-10-05T00:00:00Z"
    a, b = tmp_path / "a", tmp_path / "b"
    for d, r in ((a, old), (b, new)):
        d.mkdir()
        (d / "r.json").write_text(json.dumps(r))
    f = feed.build(tmp_path / "s.db", [b, a], ["Debian:12"])  # newest first, then a stale duplicate
    assert f["advisories"] == 1
    inv = make_inventory("dpkg", "debian", "12", [("foo", "1.5-1", "foo", "1.5-1", "x")])
    assert match(inv, feed.Feed(tmp_path / "s.db")).detections[0].fixed == "2.0-1"
    f = feed.build(tmp_path / "s2.db", [a, b], ["Debian:12"])  # stale first, then newer replaces it
    assert match(inv, feed.Feed(tmp_path / "s2.db")).detections[0].fixed == "2.0-1"


def test_feed_errors(tmp_path):
    with pytest.raises(feed.FeedError, match="no advisory snapshot"):
        feed.Feed(tmp_path / "none.db")
    junk = tmp_path / "junk.db"
    junk.write_text("not sqlite")
    with pytest.raises(feed.FeedError, match="not a Sutra Scan snapshot"):
        feed.Feed(junk)
    with pytest.raises(feed.FeedError, match="does not exist"):
        feed.build(tmp_path / "x.db", [tmp_path / "missing.zip"])


def test_rows_have_the_importers_keys_and_evidence(snapshot):
    inv = make_inventory("dpkg", "debian", "12", [("libssl3", "3.0.9-1", "openssl", "3.0.9-1", "amd64")], host="web01")
    rs = rows.to_rows(inv, match(inv, snapshot))
    assert rs[0]["kind"] == "info" and rs[0]["host"] == "web01" and rs[0]["ip"] == "10.1.2.3"
    pkg = next(r for r in rs if r["ref"] == "DSA-5532-1")
    assert set(pkg) == set(rows.ROW_KEYS)
    assert (pkg["kind"], pkg["package"], pkg["installed"], pkg["fixed"], pkg["severity"], pkg["cvss"]) == (
        "package", "libssl3", "3.0.9-1", "3.0.11-1~deb12u2", "high", 7.5)
    assert pkg["last"] == "2026-10-13" and "snapshot digest" in pkg["evidence"] and "osv.dev/vulnerability/DSA" in pkg["evidence"]
    assert pkg["solution"] == "Upgrade libssl3 to 3.0.11-1~deb12u2 or later."
    path = FIXTURES.parent / "out.jsonl"
    try:
        assert rows.write(path, rs, "sutra-scan") == len(rs)
        assert json.loads(path.read_text().splitlines()[0]) == {"format": "sutra-rows", "version": 1, "source": "sutra-scan"}
    finally:
        path.unlink(missing_ok=True)
