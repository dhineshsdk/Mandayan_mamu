"""Attack surface engine: parsers, rule evaluation, paths and findings.

Real vendor files: the Batfish FortiOS policy test configuration and Palo Alto's Iron Skillet template
(``connectors/tests/fixtures/netdevices``). Reachability and findings run on the invented sample network in
``examples/attack-surface`` (its README lists the planted problems)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from sutra.attack import analyze as A
from sutra.attack import boxes as bx
from sutra.attack import fortios, hits, ios, panos

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "connectors" / "tests" / "fixtures" / "netdevices"
SAMPLE = ROOT / "examples" / "attack-surface"
NOW = datetime(2026, 10, 13)


def sample(edge: str | None = None):
    edge = edge if edge is not None else (SAMPLE / "fw-edge.conf").read_text()
    devs = (fortios.parse(edge) + [panos.parse((SAMPLE / "fw-plant.xml").read_text()),
                                   ios.parse((SAMPLE / "sw-ot-core.cfg").read_text())])
    zones = [A.Zone(**z) for z in json.loads((SAMPLE / "zones.json").read_text())["zones"]]
    return devs, zones


def sample_hits():
    return {"fw-edge": hits.from_fortios_json((SAMPLE / "hits/fw-edge.json").read_text()),
            "fw-plant": hits.from_panos_xml((SAMPLE / "hits/fw-plant.xml").read_text()),
            "sw-ot-core": hits.from_ios_access_lists((SAMPLE / "hits/sw-ot-core.txt").read_text(),
                                                     datetime(2025, 10, 9))}


# ---------- boxes ----------

def test_subtract_leaves_exactly_the_difference():
    a = ((0, 99), (0, 99), (0, 99))
    b = ((10, 19), (0, 99), (50, 59))
    pieces = bx.subtract(a, b)
    assert sum((p[0][1] - p[0][0] + 1) * (p[1][1] - p[1][0] + 1) * (p[2][1] - p[2][0] + 1) for p in pieces) \
        == 100 ** 3 - 10 * 100 * 10
    assert all(bx.intersect(p, b) is None for p in pieces)
    assert bx.subtract(a, ((200, 300), (0, 1), (0, 1))) == [a]
    assert bx.subtract_all([a], [a]) == []


def test_service_descriptions():
    assert bx.describe_services([(bx.IP_ALL, bx.IP_ALL, bx.SVC_ALL)]) == ["any"]
    got = bx.describe_services([(bx.IP_ALL, bx.IP_ALL, s) for s in (bx.svc(6, 502, 502), bx.svc(17, 1000, 2000),
                                                                     bx.proto_all(1))])
    assert got == ["icmp", "tcp/502", "udp/1000-2000"]


# ---------- parsers, on real files ----------

def test_fortios_batfish_policy_file():
    (dev,) = fortios.parse((FIX / "fortios_firewall_policy.conf").read_text())
    assert dev.name == "firewall_policy" and set(dev.interfaces) == {f"port{i}" for i in range(1, 6)}
    by_key = {r.key: r for r in dev.rules}
    assert not by_key["0"].enabled and by_key["0"].action == "deny"
    # `append` extends the lists; the zones resolve to their member interfaces; `ALL` is every service
    assert by_key["1"].in_ifs == {"port1", "port2"} and len(by_key["1"].src) == 1
    assert by_key["3"].in_ifs == {"port3", "port2", "port5", "port4"}
    assert by_key["3"].out_ifs == {"port3", "port5"}
    assert by_key["2"].in_ifs is None and by_key["2"].services == [bx.SVC_ALL] and by_key["2"].src == [bx.IP_ALL]
    assert bx.merge(by_key["1"].services) == [bx.svc(6, 11, 12)]


def test_panos_iron_skillet_template():
    dev = panos.parse((FIX / "panos_iron_skillet_full.xml").read_text())
    assert [r.key for r in dev.rules] == ["Outbound Block Rule", "Inbound Block Rule"]
    assert all(r.action == "deny" for r in dev.rules)
    assert "panw-highrisk-ip-list" in " ".join(dev.notes)  # external lists are not modelled, and it says so


def test_ios_acl_syntax():
    text = """hostname r1
interface Vlan10
 ip address 10.1.0.1 255.255.255.0
 ip access-group IN in
!
ip access-list extended IN
 remark nothing here
 10 permit tcp 10.1.0.0 0.0.0.255 host 10.2.0.5 eq www 8080
 20 permit udp any any range 5000 5010
 30 permit tcp any any neq 80
 40 deny ip any any log
 50 permit tcp any object-group SERVERS eq 22
 60 permit tcp 10.0.0.0 0.255.0.255 any eq 22
 70 permit tcp any any eq nonsense
access-list 7 permit 10.9.0.0 0.0.255.255
"""
    dev = ios.parse(text)
    rules = {r.key: r for r in dev.rules}
    assert rules["IN 10"].services == [bx.svc(6, 80, 80), bx.svc(6, 8080, 8080)]
    assert rules["IN 10"].dst == [(bx.ip_int("10.2.0.5"),) * 2]
    assert rules["IN 20"].services == [bx.svc(17, 5000, 5010)]
    assert bx.merge(rules["IN 30"].services) == [bx.svc(6, 0, 79), bx.svc(6, 81, 65535)]
    assert rules["IN 60"].approximate and "contiguous" in rules["IN 60"].approximate[0]
    skipped = " ".join(dev.notes)
    assert "IN 50" in skipped and "object-group" in skipped and "IN 70" in skipped
    assert all(r.stage == "in:Vlan10" for r in dev.rules)


# ---------- hit counts ----------

def test_hit_readers():
    h = hits.from_csv("rule,hits,last_hit,since\nA,0,,2026-01-01\nB,5,2026-10-01T00:00:00Z,\n")
    assert h["A"].hits == 0 and h["A"].since == datetime(2026, 1, 1) and h["B"].last_hit == datetime(2026, 10, 1)
    with pytest.raises(ValueError):
        hits.from_csv("rule,hits\nA,many\n")
    h = hits.from_ios_access_lists(
        "Extended IP access list X\n    10 permit ip any any (7 matches)\n    20 deny ip any any\n")
    assert h["X 10"].hits == 7 and h["X 20"].hits == 0
    p = sample_hits()["fw-plant"]
    assert p["Temporary commissioning"].hits == 0
    assert p["Vendor remote support"].last_hit == datetime(2026, 3, 31, 23, 33, 20)
    with pytest.raises(ValueError):
        hits.from_panos_xml("<response/>")


# ---------- evaluation ----------

def test_first_match_and_implicit_deny():
    cfg = """config system interface
    edit "a"
        set ip 10.0.1.1/24
    next
    edit "b"
        set ip 10.0.2.1/24
    next
end
config firewall policy
    edit 1
        set srcintf "a"
        set dstintf "b"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "SSH"
    next
    edit 2
        set srcintf "a"
        set dstintf "b"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH" "HTTPS"
    next
end
"""
    (dev,) = fortios.parse(cfg)
    q = [((0, 2**32 - 1), (0, 2**32 - 1), bx.SVC_ALL)]
    got, used = A.evaluate(dev, "a", "b", q)
    assert bx.describe_services(got) == ["tcp/443"] and used == ["2"]
    assert A.evaluate(dev, "b", "a", q) == ([], [])  # no policy in this direction: implicit deny
    findings = A.shadow_findings(dev)
    assert findings == [] or all(f.rule != "2" for f in findings)  # policy 2 still permits HTTPS, so it is not shadowed


def test_ios_acls_are_checked_in_then_out():
    cfg = """hostname r
interface Vlan1
 ip address 10.1.0.1 255.255.255.0
 ip access-group IN in
interface Vlan2
 ip address 10.2.0.1 255.255.255.0
 ip access-group OUT out
interface Vlan3
 ip address 10.3.0.1 255.255.255.0
ip access-list extended IN
 10 permit tcp any any eq 80
 20 permit tcp any any eq 22
ip access-list extended OUT
 10 permit tcp any any eq 22
 20 permit tcp any any eq 443
"""
    dev = ios.parse(cfg)
    q = [(bx.IP_ALL, bx.IP_ALL, bx.SVC_ALL)]
    assert bx.describe_services(A.evaluate(dev, "Vlan1", "Vlan2", q)[0]) == ["tcp/22"]  # IN ∩ OUT
    assert bx.describe_services(A.evaluate(dev, "Vlan1", "Vlan3", q)[0]) == ["tcp/22", "tcp/80"]  # no OUT ACL
    assert A.evaluate(dev, "Vlan3", "Vlan2", q)[0] != []  # no IN ACL on Vlan3: only the OUT ACL applies
    assert bx.describe_services(A.evaluate(dev, "Vlan3", "Vlan2", q)[0]) == ["tcp/22", "tcp/443"]


def test_routes_prefer_connected_then_longest_prefix():
    (dev,) = fortios.parse((SAMPLE / "fw-edge.conf").read_text())
    assert dev.route(bx.ip_int("10.20.0.99")) == ("port3", None)
    assert dev.route(bx.ip_int("10.50.2.20")) == ("port4", bx.ip_int("10.30.0.2"))
    assert dev.route(bx.ip_int("8.8.8.8")) == ("port1", bx.ip_int("203.0.113.1"))


# ---------- paths and findings on the sample network ----------

def path_of(report, src_kind, dst_kind):
    return [p for p in report.paths if (p.src_kind, p.dst_kind) == (src_kind, dst_kind)]


def test_sample_network_paths():
    devs, zones = sample()
    r = A.analyze(devs, zones, now=NOW)
    (inet,) = path_of(r, "internet", "ot")
    assert inet.services == ["tcp/3389"] and inet.destinations() == ["10.50.2.20/32"]
    assert [(h.device, h.egress) for h in inet.hops] == [("fw-edge", "port4"), ("fw-plant", "ethernet1/2"),
                                                          ("sw-ot-core", "Vlan52")]
    assert A.path_severity(inet) == "critical"
    it = {tuple(p.services): p for p in path_of(r, "it", "ot")}
    assert set(it) == {("any",), ("tcp/502",)}
    assert it[("tcp/502",)].hops[-1].egress == "Vlan51" and it[("tcp/502",)].sources() == ["10.10.5.0/24"]
    assert A.path_severity(it[("any",)]) == "critical"
    (dmz,) = path_of(r, "dmz", "ot")
    assert dmz.services == ["tcp/1433"] and dmz.sources() == ["10.20.0.20/32"] and A.path_severity(dmz) == "low"
    assert path_of(r, "internet", "it") == []  # port 443 reaches the DMZ web host, not IT


def test_closing_the_vendor_hole_removes_the_internet_path():
    text = (SAMPLE / "fw-edge.conf").read_text()
    closed = text.replace('''        set name "Vendor remote support"
        set srcintf "port1"''', '''        set name "Vendor remote support"
        set status disable
        set srcintf "port1"''')
    assert closed != text
    devs, zones = sample(closed)
    r = A.analyze(devs, zones, now=NOW)
    assert path_of(r, "internet", "ot") == []
    assert len(path_of(r, "it", "ot")) == 2  # the other paths are unchanged


def test_an_unknown_next_hop_is_reported_not_hidden():
    devs, zones = sample()
    devs[1].interfaces["ethernet1/2"].up = True
    devs = [devs[0], devs[1]]  # the switch's configuration is missing
    r = A.analyze(devs, zones, now=NOW)
    assert path_of(r, "internet", "ot") and not any(p.complete for p in path_of(r, "internet", "ot"))
    assert "no configuration for" in r.path_findings[0].detail


def test_rule_findings_on_the_sample_network():
    devs, zones = sample()
    r = A.analyze(devs, zones, sample_hits(), NOW)
    found = {(f.kind, f.device, f.rule): f for f in r.findings}
    for key in (("broad", "fw-edge", "5"), ("broad", "fw-edge", "6"), ("broad", "fw-plant", "Temporary commissioning"),
                ("broad", "sw-ot-core", "SCADA-OUT 40"), ("broad", "sw-ot-core", "SCADA-OUT 50"),
                ("disabled", "fw-edge", "9"), ("shadowed", "fw-edge", "7"), ("shadowed", "fw-edge", "8")):
        assert key in found, key
    assert found[("shadowed", "fw-edge", "7")].severity == "medium"  # a deny that never takes effect
    assert "permit" in found[("shadowed", "fw-edge", "7")].detail
    assert found[("shadowed", "fw-edge", "8")].severity == "low"  # a harmless duplicate
    # the legacy rules have no hits in a year of counters; the vendor rule was last used long ago
    assert found[("unused", "fw-edge", "5")].title.startswith("No hits in 368 days")
    assert found[("unused", "sw-ot-core", "SCADA-OUT 50")].severity == "medium"
    assert found[("unused", "fw-plant", "Vendor remote support")].title == "Last used 195 days ago"
    assert ("unused", "fw-edge", "4") not in found and ("unused", "fw-edge", "10") not in found
    assert found[("broad", "fw-edge", "5")].on_risky_path and not found[("broad", "fw-edge", "3")].on_risky_path


def test_chokepoints_rank_the_cuts():
    devs, zones = sample()
    r = A.analyze(devs, zones, sample_hits(), NOW)
    top = {(c.device, c.rule): c for c in r.chokepoints}
    vendor = top[("fw-plant", "Vendor remote support")]
    assert vendor.sole >= 1 and vendor.unused  # a sole cut, and last used 195 days ago
    assert top[("fw-edge", "6")].sole == 1
    legacy = top[("fw-plant", "Temporary commissioning")]
    assert legacy.unused and legacy.paths == 2 and legacy.sole == 0  # another rule also carries those paths
    assert r.chokepoints[0].sole >= r.chokepoints[-1].sole


def test_too_short_a_window_is_not_called_unused():
    devs, zones = sample()
    h = sample_hits()
    h["fw-edge"]["5"].since = datetime(2026, 9, 20)
    r = A.analyze(devs, zones, h, NOW)
    f = next(f for f in r.findings if (f.kind, f.device, f.rule) == ("unused", "fw-edge", "5"))
    assert f.severity == "info" and "23 days" in f.title


def test_no_zones_say_so():
    devs, _ = sample()
    r = A.analyze(devs, [A.Zone("Plant", "it", ["10.10.0.0/16"])], now=NOW)
    assert r.paths == [] and any("No OT zone" in n for n in r.notes)
