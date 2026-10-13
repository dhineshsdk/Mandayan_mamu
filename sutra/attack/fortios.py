"""Fortinet FortiGate (FortiOS) configuration -> :class:`~sutra.attack.model.Device` (one per VDOM).

Syntax: the FortiOS CLI configuration file (``config`` / ``edit`` / ``set`` / ``append`` / ``next`` / ``end``), as
Batfish's FortiOS grammar fixtures and Fortinet's own examples show it. Read: interfaces and their addresses, zones,
address objects and groups, custom and built-in services and groups, static routes and firewall policies in file order.

Not modelled (reported in ``Device.notes`` or on the rule): IPv6, FQDN / geography / dynamic addresses, internet
services, NAT, schedules, user and device identity, UTM profiles, SD-WAN rules, dynamic routing. A service name the
parser does not know becomes the pseudo-service ``unresolved`` so it still shows up as allowed traffic.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from . import boxes as bx
from .boxes import IP_ALL, SVC_ALL, Interval
from .model import Device, Interface, Route, Rule

UNRESOLVED = bx.svc(255, 0, 0)  # protocol 255: "a service this parser does not know"

# Built-in service names the parser knows (FortiOS predefined services; ports are the IANA assignments).
BUILTIN: dict[str, list[Interval]] = {
    "ALL": [SVC_ALL],
    "ALL_TCP": [bx.proto_all(6)], "ALL_UDP": [bx.proto_all(17)], "ALL_ICMP": [bx.proto_all(1)],
    "PING": [bx.proto_all(1)],
    "HTTP": [bx.svc(6, 80, 80)], "HTTPS": [bx.svc(6, 443, 443)], "SSH": [bx.svc(6, 22, 22)],
    "TELNET": [bx.svc(6, 23, 23)], "RDP": [bx.svc(6, 3389, 3389)], "SMB": [bx.svc(6, 445, 445)],
    "FTP": [bx.svc(6, 21, 21)], "SMTP": [bx.svc(6, 25, 25)], "DNS": [bx.svc(6, 53, 53), bx.svc(17, 53, 53)],
    "NTP": [bx.svc(17, 123, 123)], "SNMP": [bx.svc(6, 161, 162), bx.svc(17, 161, 162)],
    "LDAP": [bx.svc(6, 389, 389)], "LDAPS": [bx.svc(6, 636, 636)], "SYSLOG": [bx.svc(17, 514, 514)],
    "TFTP": [bx.svc(17, 69, 69)], "VNC": [bx.svc(6, 5900, 5900)], "MYSQL": [bx.svc(6, 3306, 3306)],
    "POP3": [bx.svc(6, 110, 110)], "IMAP": [bx.svc(6, 143, 143)], "KERBEROS": [bx.svc(6, 88, 88), bx.svc(17, 88, 88)],
}


@dataclass
class Node:
    name: str
    sets: dict[str, list[str]] = field(default_factory=dict)
    children: list[Node] = field(default_factory=list)  # `config` blocks inside, or `edit` entries inside a config

    def find(self, name: str) -> Node | None:
        return next((c for c in self.children if c.name == name), None)

    def entries(self, name: str) -> list[Node]:
        c = self.find(name)
        return c.children if c else []

    def get(self, key: str, default: str = "") -> str:
        v = self.sets.get(key)
        return v[0] if v else default

    def get_all(self, key: str) -> list[str]:
        return self.sets.get(key, [])


def _split(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def parse_tree(text: str) -> Node:
    root = Node("")
    stack = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tok = _split(line)
        word = tok[0]
        top = stack[-1]
        if word == "config" and len(tok) > 1:
            node = Node(" ".join(tok[1:]))
            top.children.append(node)
            stack.append(node)
        elif word == "edit" and len(tok) > 1:
            node = Node(tok[1])
            top.children.append(node)
            stack.append(node)
        elif word in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif word == "set" and len(tok) > 1:
            top.sets[tok[1]] = tok[2:]
        elif word == "append" and len(tok) > 1:
            top.sets.setdefault(tok[1], []).extend(tok[2:])
        elif word == "unset" and len(tok) > 1:
            top.sets.pop(tok[1], None)
    return root


def _ipmask(tokens: list[str]) -> Interval | None:
    if not tokens:
        return None
    try:
        if len(tokens) == 1:
            return bx.cidr(tokens[0])
        return bx.cidr(f"{tokens[0]}/{tokens[1]}")
    except ValueError:
        return None


def _addr_and_plen(tokens: list[str]) -> tuple[int, int] | None:
    try:
        if len(tokens) == 1 and "/" in tokens[0]:
            ip, plen = tokens[0].split("/")
            return bx.ip_int(ip), int(plen)
        if len(tokens) >= 2:
            import ipaddress

            return bx.ip_int(tokens[0]), ipaddress.IPv4Network(f"0.0.0.0/{tokens[1]}").prefixlen
    except ValueError:
        return None
    return None


def _ports(spec: list[str], proto: int) -> list[Interval]:
    out = []
    for item in spec:
        dst = item.split(":")[0]
        lo, _, hi = dst.partition("-")
        try:
            out.append(bx.svc(proto, int(lo), int(hi or lo)))
        except ValueError:
            continue
    return out


class _Resolver:
    def __init__(self, vdom: Node, device: Device):
        self.dev = device
        self.addr: dict[str, list[Interval]] = {}
        self.addr_groups: dict[str, list[str]] = {}
        self.services: dict[str, list[Interval]] = {}
        self.service_groups: dict[str, list[str]] = {}
        self.unresolved: set[str] = set()
        for e in vdom.entries("firewall address"):
            self.addr[e.name] = self._address(e)
        for e in vdom.entries("firewall addrgrp"):
            self.addr_groups[e.name] = e.get_all("member")
        for e in vdom.entries("firewall service custom"):
            self.services[e.name] = self._custom_service(e)
        for e in vdom.entries("firewall service group"):
            self.service_groups[e.name] = e.get_all("member")

    def _address(self, e: Node) -> list[Interval]:
        kind = e.get("type", "ipmask")
        if kind == "ipmask":
            if "subnet" not in e.sets:
                return [IP_ALL] if e.name == "all" else []
            r = _ipmask(e.get_all("subnet"))
            return [r] if r else []
        if kind == "iprange":
            try:
                return [(bx.ip_int(e.get("start-ip")), bx.ip_int(e.get("end-ip")))]
            except ValueError:
                return []
        if kind == "wildcard":
            toks = e.get_all("wildcard")
            try:
                a, w = bx.ip_int(toks[0]), bx.ip_int(toks[1])
                return [(a & ~w & 0xFFFFFFFF, a | w)]
            except (ValueError, IndexError):
                return []
        self.dev.notes.append(f"Address {e.name!r} is of type {kind} (not an IP range) and is not modelled.")
        return []

    def _custom_service(self, e: Node) -> list[Interval]:
        proto = e.get("protocol", "TCP/UDP/SCTP").upper()
        if proto == "IP":
            n = e.get("protocol-number", "0")
            return [SVC_ALL] if n in ("0", "") else [bx.proto_all(int(n))]
        if proto == "ICMP":
            return [bx.proto_all(1)]
        out = _ports(e.get_all("tcp-portrange"), 6) + _ports(e.get_all("udp-portrange"), 17)
        out += _ports(e.get_all("sctp-portrange"), 132)
        return out

    def addresses(self, names: list[str], negate: bool,
                  seen: frozenset[str] = frozenset()) -> tuple[list[Interval], list[str]]:
        out: list[Interval] = []
        text: list[str] = []
        for n in names:
            text.append(n)
            if n in self.addr:
                out += self.addr[n]
            elif n in self.addr_groups and n not in seen:
                sub, _ = self.addresses(self.addr_groups[n], False, seen | {n})
                out += sub
            elif n == "all":
                out.append(IP_ALL)
            elif n != "none":
                self.unresolved.add(n)
        out = bx.merge(out)
        if negate:
            out = _complement(out, IP_ALL)
        return out, text

    def service_list(self, names: list[str], negate: bool,
                     seen: frozenset[str] = frozenset()) -> tuple[list[Interval], list[str]]:
        out: list[Interval] = []
        for n in names:
            if n in self.services:
                out += self.services[n]
            elif n in self.service_groups and n not in seen:
                out += self.service_list(self.service_groups[n], False, seen | {n})[0]
            elif n.upper() in BUILTIN:
                out += BUILTIN[n.upper()]
            else:
                out.append(UNRESOLVED)
                self.unresolved.add(n)
        out = bx.merge(out)
        if negate:
            out = _complement(out, SVC_ALL)
        return out, list(names)


def _complement(items: list[Interval], universe: Interval) -> list[Interval]:
    out, cur = [], universe[0]
    for lo, hi in bx.merge(items):
        if lo > cur:
            out.append((cur, lo - 1))
        cur = max(cur, hi + 1)
    if cur <= universe[1]:
        out.append((cur, universe[1]))
    return out


def parse(text: str, fallback_name: str = "fortigate") -> list[Device]:
    root = parse_tree(text)
    glob = root.find("global")
    vdoms = root.find("vdom")
    scope = glob if glob is not None else root
    hostname = (scope.find("system global") or root.find("system global") or Node("")).get("hostname", fallback_name)
    iface_nodes = scope.entries("system interface")
    if vdoms is not None and vdoms.children:
        return [_device(v, iface_nodes, f"{hostname}/{v.name}", v.name, scope) for v in vdoms.children]
    return [_device(root, iface_nodes, hostname, None, scope)]


def _device(vdom: Node, iface_nodes: list[Node], name: str, vdom_name: str | None, scope: Node) -> Device:
    dev = Device(name=name, vendor="fortigate")
    for e in iface_nodes:
        if vdom_name is not None and e.get("vdom", "root") != vdom_name:
            continue
        i = Interface(e.name, up=e.get("status", "up") != "down")
        ip = _addr_and_plen(e.get_all("ip"))
        if ip and ip[0] != 0:
            i.networks.append(ip)
        for s in e.entries("secondaryip"):
            sec = _addr_and_plen(s.get_all("ip"))
            if sec:
                i.networks.append(sec)
        dev.interfaces[e.name] = i
    zones: dict[str, list[str]] = {}
    for z in scope.entries("system zone") + vdom.entries("system zone"):
        zones[z.name] = z.get_all("interface")
        for member in zones[z.name]:
            if member in dev.interfaces:
                dev.interfaces[member].zone = z.name
    for r in vdom.entries("router static"):
        if r.get("status", "enable") == "disable":
            continue
        dst = _ipmask(r.get_all("dst")) if "dst" in r.sets else IP_ALL
        if dst is None:
            continue
        gw = r.get("gateway")
        try:
            nh = bx.ip_int(gw) if gw else None
        except ValueError:
            nh = None
        plen = 32 - (dst[1] - dst[0] + 1).bit_length() + 1
        dev.routes.append(Route(dst, plen, nh, r.get("device")))
    res = _Resolver(vdom, dev)

    def ifaces(names: list[str]) -> frozenset[str] | None:
        if not names or "any" in names:
            return None
        out: set[str] = set()
        for n in names:
            out.update(zones.get(n, [n]))
        return frozenset(out)

    for pos, p in enumerate(vdom.entries("firewall policy")):
        approx: list[str] = []
        if p.get("internet-service") == "enable" or p.get("internet-service-src") == "enable":
            approx.append("uses an internet service object (not modelled)")
        src, src_t = res.addresses(p.get_all("srcaddr"), p.get("srcaddr-negate") == "enable")
        dst, dst_t = res.addresses(p.get_all("dstaddr"), p.get("dstaddr-negate") == "enable")
        svcs, svc_t = res.service_list(p.get_all("service"), p.get("service-negate") == "enable")
        bad = [n for n in p.get_all("srcaddr") + p.get_all("dstaddr") if n in res.unresolved]
        bad += [n for n in p.get_all("service") if n in res.unresolved]
        if bad:
            approx.append("unresolved names: " + ", ".join(sorted(set(bad))))
        if p.get("action", "deny") == "ipsec":
            approx.append("action ipsec (treated as permit)")
        dev.rules.append(Rule(
            key=p.name, name=p.get("name"), position=pos,
            action="permit" if p.get("action", "deny") in ("accept", "ipsec") else "deny",
            enabled=p.get("status", "enable") != "disable", src=src, dst=dst, services=svcs,
            src_text=src_t, dst_text=dst_t, service_text=svc_t,
            in_ifs=ifaces(p.get_all("srcintf")), out_ifs=ifaces(p.get_all("dstintf")),
            comment=p.get("comments"), approximate=approx))
    if res.unresolved:
        dev.notes.append("Names the parser could not resolve: " + ", ".join(sorted(res.unresolved)) + ".")
    dev.notes.append("Dynamic routing (OSPF, BGP) is not read; only connected networks and static routes.")
    return dev


