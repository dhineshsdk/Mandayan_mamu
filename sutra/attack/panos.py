"""Palo Alto Networks PAN-OS configuration (XML, as ``type=config&action=show`` returns it) -> :class:`Device`.

Read: Ethernet, aggregate, VLAN and loopback layer-3 interfaces and sub-interfaces, zones, addresses and address groups,
custom services and groups, static routes and the security rulebase in file order (first vsys; Panorama pre and post
rulebases are not merged).

Not modelled (``Device.notes`` or the rule's ``approximate``): IPv6, FQDN and dynamic address groups, applications
(a rule with specific applications and ``application-default`` services becomes the pseudo-service ``unresolved``),
users, URL categories, NAT, rule types other than universal, the implicit intrazone-allow rule, dynamic routing.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element

from defusedxml import ElementTree as ET

from . import boxes as bx
from .boxes import IP_ALL, SVC_ALL, Interval
from .fortios import UNRESOLVED, _complement
from .model import Device, Interface, Route, Rule

PREDEFINED = {"service-http": [bx.svc(6, 80, 80), bx.svc(6, 8080, 8080)], "service-https": [bx.svc(6, 443, 443)]}
PERMIT = {"allow"}


def _members(el: Element | None, path: str) -> list[str]:
    if el is None:
        return []
    return [m.text.strip() for m in el.findall(f"{path}/member") if m.text and m.text.strip()]


def _text(el: Element | None, path: str, default: str = "") -> str:
    if el is None:
        return default
    node = el.find(path)
    return node.text.strip() if node is not None and node.text else default


def _ports(spec: str, proto: int) -> list[Interval]:
    out = []
    for item in spec.split(","):
        lo, _, hi = item.strip().partition("-")
        try:
            out.append(bx.svc(proto, int(lo), int(hi or lo)))
        except ValueError:
            continue
    return out


def _address(e: Element, dev: Device) -> list[Interval]:
    try:
        if e.find("ip-netmask") is not None:
            return [bx.cidr(_text(e, "ip-netmask"))]
        if e.find("ip-range") is not None:
            a, _, b = _text(e, "ip-range").partition("-")
            return [(bx.ip_int(a.strip()), bx.ip_int(b.strip()))]
        if e.find("ip-wildcard") is not None:
            a, _, m = _text(e, "ip-wildcard").partition("/")
            base, wild = bx.ip_int(a), bx.ip_int(m)
            return [(base & ~wild & 0xFFFFFFFF, base | wild)]
    except ValueError:
        pass
    dev.notes.append(f"Address {e.get('name')!r} is not an IPv4 range (FQDN, IPv6 or wildcard) and is not modelled.")
    return []


def parse(text: str, fallback_name: str = "panos") -> Device:
    root = ET.fromstring(text.encode() if isinstance(text, str) else text)
    cfg = root.find(".//devices/entry") if root.tag != "config" else root.find("devices/entry")
    if cfg is None:
        cfg = root.find(".//devices/entry")
    if cfg is None:
        raise ValueError("This is not a PAN-OS configuration (no devices/entry element).")
    dev = Device(name=_text(cfg, "deviceconfig/system/hostname", fallback_name) or fallback_name, vendor="panos")
    vsys = cfg.find("vsys/entry")
    if vsys is None:
        raise ValueError("The PAN-OS configuration has no vsys.")
    if len(cfg.findall("vsys/entry")) > 1:
        dev.notes.append("Only the first virtual system is read.")
    if cfg.find("device-group") is not None:
        dev.notes.append("Panorama device groups are present; pre and post rulebases are not merged.")

    # interfaces
    net = cfg.find("network")
    def add_iface(name: str, holder: Element | None) -> None:
        i = Interface(name)
        for ip in (holder.findall("ip/entry") if holder is not None else []):
            n = ip.get("name", "")
            try:
                addr, _, plen = n.partition("/")
                i.networks.append((bx.ip_int(addr), int(plen or 32)))
            except ValueError:
                continue  # an address object name, or IPv6
        dev.interfaces[name] = i

    if net is not None:
        for kind in ("ethernet", "aggregate-ethernet", "vlan", "loopback"):
            for e in net.findall(f"interface/{kind}/entry") + net.findall(f"interface/{kind}/units/entry"):
                layer3 = e.find("layer3") if e.find("layer3") is not None else e
                add_iface(e.get("name", ""), layer3)
                for u in layer3.findall("units/entry"):
                    add_iface(u.get("name", ""), u)
    zones: dict[str, list[str]] = {}
    for z in vsys.findall("zone/entry"):
        kinds = ("layer3", "layer2", "virtual-wire", "tap", "external")
        members = [m for k in kinds for m in _members(z, f"network/{k}")]
        zones[z.get("name", "")] = members
        for m in members:
            if m in dev.interfaces:
                dev.interfaces[m].zone = z.get("name", "")
    if net is not None:
        for r in net.findall("virtual-router/entry/routing-table/ip/static-route/entry"):
            dest = _text(r, "destination")
            try:
                prefix = bx.cidr(dest)
                plen = int(dest.partition("/")[2] or 32)
            except ValueError:
                continue
            nh = _text(r, "nexthop/ip-address")
            try:
                nh_int = bx.ip_int(nh) if nh else None
            except ValueError:
                nh_int = None
            dev.routes.append(Route(prefix, plen, nh_int, _text(r, "interface")))
        if len(net.findall("virtual-router/entry")) > 1:
            dev.notes.append("Several virtual routers: their routes are read as one table.")

    # objects
    addr = {e.get("name", ""): _address(e, dev) for e in vsys.findall("address/entry")}
    groups = {g.get("name", ""): _members(g, "static") for g in vsys.findall("address-group/entry")}
    for g in vsys.findall("address-group/entry"):
        if g.find("dynamic") is not None:
            dev.notes.append(f"Address group {g.get('name')!r} is dynamic and is not modelled.")
    services: dict[str, list[Interval]] = {}
    for s in vsys.findall("service/entry"):
        services[s.get("name", "")] = (_ports(_text(s, "protocol/tcp/port"), 6)
                                       + _ports(_text(s, "protocol/udp/port"), 17))
    service_groups = {g.get("name", ""): _members(g, "members") for g in vsys.findall("service-group/entry")}
    unresolved: set[str] = set()

    def addresses(names: list[str], seen: frozenset[str] = frozenset()) -> list[Interval]:
        out: list[Interval] = []
        for n in names:
            if n == "any":
                out.append(IP_ALL)
            elif n in addr:
                out += addr[n]
            elif n in groups and n not in seen:
                out += addresses(groups[n], seen | {n})
            else:
                try:
                    out.append(bx.cidr(n))  # a rule may carry a literal address or range
                except ValueError:
                    unresolved.add(n)
        return bx.merge(out)

    def service_set(names: list[str], apps: list[str], approx: list[str],
                    seen: frozenset[str] = frozenset()) -> list[Interval]:
        out: list[Interval] = []
        for n in names:
            if n == "any":
                out.append(SVC_ALL)
            elif n == "application-default":
                if apps == ["any"] or not apps:
                    out.append(SVC_ALL)
                    approx.append("application-default with application any (ports not limited here)")
                else:
                    out.append(UNRESOLVED)
                    approx.append("application-default for: " + ", ".join(apps))
            elif n in services:
                out += services[n]
            elif n in PREDEFINED:
                out += PREDEFINED[n]
            elif n in service_groups and n not in seen:
                out += service_set(service_groups[n], apps, approx, seen | {n})
            else:
                out.append(UNRESOLVED)
                unresolved.add(n)
        return bx.merge(out)

    def ifaces(zone_names: list[str]) -> frozenset[str] | None:
        if not zone_names or "any" in zone_names:
            return None
        out: set[str] = set()
        for z in zone_names:
            out.update(zones.get(z, []))
        return frozenset(out)

    for pos, r in enumerate(vsys.findall("rulebase/security/rules/entry")):
        approx: list[str] = []
        apps = _members(r, "application")
        src = addresses(_members(r, "source"))
        dst = addresses(_members(r, "destination"))
        if _text(r, "negate-source") == "yes":
            src = _complement(src, IP_ALL)
        if _text(r, "negate-destination") == "yes":
            dst = _complement(dst, IP_ALL)
        svcs = service_set(_members(r, "service"), apps, approx)
        if _text(r, "rule-type", "universal") != "universal":
            approx.append(f"rule type {_text(r, 'rule-type')} (applied as universal)")
        bad = sorted({n for n in _members(r, "source") + _members(r, "destination") + _members(r, "service")
                      if n in unresolved})
        if bad:
            approx.append("unresolved names: " + ", ".join(bad))
        dev.rules.append(Rule(
            key=r.get("name", ""), name=r.get("name", ""), position=pos,
            action="permit" if _text(r, "action") in PERMIT else "deny",
            enabled=_text(r, "disabled") != "yes", src=src, dst=dst, services=svcs,
            src_text=_members(r, "source"), dst_text=_members(r, "destination"),
            service_text=_members(r, "service") + ([f"app: {', '.join(apps)}"] if apps and apps != ["any"] else []),
            in_ifs=ifaces(_members(r, "from")), out_ifs=ifaces(_members(r, "to")),
            comment=_text(r, "description"), approximate=approx))
    if unresolved:
        dev.notes.append("Names the parser could not resolve: " + ", ".join(sorted(unresolved)) + ".")
    dev.notes.append("The implicit intrazone-allow and interzone-deny rules are not shown. "
                     "Dynamic routing is not read.")
    return dev
