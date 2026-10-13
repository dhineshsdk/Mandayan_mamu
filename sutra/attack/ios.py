"""Cisco IOS / IOS-XE running configuration -> :class:`Device` (a layer-3 switch or router).

Read: interfaces with an ``ip address`` and ``shutdown``, ``ip route``, standard and extended ACLs (named and
numbered) and where they are applied (``ip access-group <acl> in|out``). Each ACL applied to an interface is a stage:
traffic must pass the ingress interface's ``in`` ACL, then the egress interface's ``out`` ACL, and each ACL ends in an
implicit deny. An interface with no ACL passes everything.

Not modelled (on the rule's ``approximate``): ``object-group`` references (the rule is skipped and noted), wildcard
masks that are not a contiguous block (widened to their outer range), ``neq`` is exact, ``established`` and TCP flags
(treated as matching all TCP), ``time-range``, VRFs, route-maps, NAT, OSPF/EIGRP/BGP.
"""

from __future__ import annotations

import ipaddress
import re

from . import boxes as bx
from .boxes import IP_ALL, SVC_ALL, Interval
from .model import Device, Interface, Route, Rule

# Port names IOS accepts after eq/gt/lt/range (IANA assignments).
PORTS = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "tacacs": 49, "domain": 53, "tftp": 69,
    "www": 80, "pop3": 110, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138, "netbios-ss": 139, "snmp": 161,
    "snmptrap": 162, "bgp": 179, "ldap": 389, "https": 443, "syslog": 514, "ldaps": 636, "isakmp": 500,
    "pop3s": 995, "lpd": 515, "sunrpc": 111, "nntp": 119, "msrpc": 135, "bootps": 67, "bootpc": 68,
}
_ADDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class _Skip(Exception):
    pass


def _addr(tok: list[str], approx: list[str]) -> tuple[list[Interval], str, int]:
    """(addresses, text, tokens used) for ``any`` | ``host A`` | ``A wildcard``."""
    if not tok:
        raise _Skip("incomplete entry")
    if tok[0] == "any":
        return [IP_ALL], "any", 1
    if tok[0] == "host" and len(tok) > 1:
        a = bx.ip_int(tok[1])
        return [(a, a)], f"host {tok[1]}", 2
    if tok[0] in ("object-group", "object"):
        raise _Skip("uses an object-group")
    if _ADDR.match(tok[0]):
        if len(tok) > 1 and _ADDR.match(tok[1]):
            a, w = bx.ip_int(tok[0]), bx.ip_int(tok[1])
            if (w + 1) & w:
                approx.append(f"wildcard {tok[1]} is not a contiguous block (widened)")
            return [(a & ~w & 0xFFFFFFFF, a | w)], f"{tok[0]} {tok[1]}", 2
        a = bx.ip_int(tok[0])  # standard ACL shorthand: a bare address is a host
        return [(a, a)], f"host {tok[0]}", 1
    raise _Skip(f"cannot read the address {tok[0]!r}")


def _port(tok: str) -> int:
    if tok.isdigit():
        return int(tok)
    if tok in PORTS:
        return PORTS[tok]
    raise _Skip(f"unknown port name {tok!r}")


def _portspec(tok: list[str], proto: int) -> tuple[list[Interval] | None, str, int]:
    """Port match after an address: (intervals within the protocol, text, tokens used); None when absent."""
    if not tok or tok[0] not in ("eq", "neq", "gt", "lt", "range"):
        return None, "", 0
    op = tok[0]
    if op == "range":
        lo, hi = _port(tok[1]), _port(tok[2])
        return [bx.svc(proto, lo, hi)], f"range {tok[1]} {tok[2]}", 3
    if op in ("gt", "lt"):
        p = _port(tok[1])
        return ([bx.svc(proto, p + 1, 65535)] if op == "gt" else [bx.svc(proto, 0, p - 1)]), f"{op} {tok[1]}", 2
    # eq / neq take one or more ports
    ports, i = [], 1
    while i < len(tok):
        try:
            ports.append(_port(tok[i]))
        except _Skip:
            break
        i += 1
    if not ports:
        raise _Skip("no port after eq")
    ivs = [bx.svc(proto, p, p) for p in ports]
    if op == "neq":
        ivs = _invert(ivs, bx.proto_all(proto))
    return ivs, f"{op} {' '.join(tok[1:i])}", i


def _invert(items: list[Interval], universe: Interval) -> list[Interval]:
    out, cur = [], universe[0]
    for lo, hi in bx.merge(items):
        if lo > cur:
            out.append((cur, lo - 1))
        cur = hi + 1
    if cur <= universe[1]:
        out.append((cur, universe[1]))
    return out


def _entry(acl: str, seq: str, pos: int, tok: list[str], extended: bool, stage: str) -> Rule:
    action = tok[0]
    if action not in ("permit", "deny"):
        raise _Skip(f"unsupported action {action!r}")
    approx: list[str] = []
    rest = tok[1:]
    if not extended:
        src, stext, _ = _addr(rest, approx)
        return Rule(f"{acl} {seq}", f"{acl} {seq}", pos, action, True, src, [IP_ALL], [SVC_ALL], [stext], ["any"],
                    ["ip"], stage=stage, comment="", approximate=approx)
    proto = rest[0]
    rest = rest[1:]
    if proto == "ip":
        services = [SVC_ALL]
    elif proto in bx.PROTOCOLS:
        services = [bx.proto_all(bx.PROTOCOLS[proto])]
    elif proto.isdigit():
        services = [bx.proto_all(int(proto))]
    else:
        raise _Skip(f"unsupported protocol {proto!r}")
    src, stext, n = _addr(rest, approx)
    rest = rest[n:]
    pnum = bx.PROTOCOLS.get(proto, -1)
    if pnum in (6, 17):
        sp, _, n = _portspec(rest, pnum)
        rest = rest[n:]  # source ports are read and dropped (any source port): a superset, noted below
        if sp is not None:
            approx.append("source-port match ignored")
    dst, dtext, n = _addr(rest, approx)
    rest = rest[n:]
    text = proto
    if pnum in (6, 17):
        dp, ptxt, n = _portspec(rest, pnum)
        rest = rest[n:]
        if dp is not None:
            services, text = dp, f"{proto} {ptxt}"
        if "established" in rest or "ack" in rest:
            approx.append("established/ack keyword treated as matching all TCP")
    return Rule(f"{acl} {seq}", f"{acl} {seq}", pos, action, True, src, dst, services, [stext], [dtext], [text],
                stage=stage, approximate=approx)


def parse(text: str, fallback_name: str = "ios") -> Device:
    lines = text.splitlines()
    host = next((m.group(1) for ln in lines if (m := re.match(r"^hostname\s+(\S+)", ln))), fallback_name)
    dev = Device(name=host, vendor="cisco_ios")
    acls: dict[str, list[tuple[str, list[str], bool]]] = {}  # name -> [(seq, tokens, extended)]
    applied: list[tuple[str, str, str]] = []  # (interface, acl, direction)
    cur_iface: Interface | None = None
    cur_acl: tuple[str, bool] | None = None
    skipped: list[str] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("!"):
            if not raw.startswith(" "):
                cur_iface = cur_acl = None
            continue
        indented = raw.startswith(" ")
        tok = raw.split()
        if not indented:
            cur_iface = cur_acl = None
            if tok[0] == "interface" and len(tok) > 1:
                cur_iface = Interface(tok[1])
                dev.interfaces[tok[1]] = cur_iface
            elif tok[:2] == ["ip", "access-list"] and len(tok) >= 4 and tok[2] in ("standard", "extended"):
                cur_acl = (tok[3], tok[2] == "extended")
                acls.setdefault(tok[3], [])
            elif tok[0] == "access-list" and len(tok) > 3 and tok[1].isdigit():
                n = int(tok[1])
                extended = 100 <= n <= 199 or 2000 <= n <= 2699
                if tok[2] != "remark":
                    acls.setdefault(tok[1], []).append((str(10 * (len(acls.get(tok[1], [])) + 1)), tok[2:], extended))
            elif tok[:2] == ["ip", "route"] and len(tok) >= 5:
                _route(dev, tok[2:])
            continue
        if cur_iface is not None:
            if tok[:2] == ["ip", "address"] and len(tok) >= 4 and tok[2] != "dhcp":
                try:
                    plen = ipaddress.IPv4Network(f"0.0.0.0/{tok[3]}").prefixlen
                    cur_iface.networks.append((bx.ip_int(tok[2]), plen))
                except ValueError:
                    pass
            elif tok[0] == "shutdown":
                cur_iface.up = False
            elif tok[:2] == ["ip", "access-group"] and len(tok) >= 4 and tok[3] in ("in", "out"):
                applied.append((cur_iface.name, tok[2], tok[3]))
        elif cur_acl is not None and tok[0] != "remark":
            seq = tok[0] if tok[0].isdigit() else str(10 * (len(acls[cur_acl[0]]) + 1))
            body = tok[1:] if tok[0].isdigit() else tok
            acls[cur_acl[0]].append((seq, body, cur_acl[1]))
    # bind each applied ACL to its interface as a stage
    for iface, name, direction in applied:
        stage = f"{direction}:{iface}"
        entries = acls.get(name)
        if entries is None:
            dev.notes.append(f"Interface {iface} applies ACL {name} ({direction}), which is not in the configuration; "
                             "treated as no ACL.")
            continue
        for pos, (seq, body, extended) in enumerate(entries):
            try:
                dev.rules.append(_entry(name, seq, pos, body, extended, stage))
            except (_Skip, ValueError, IndexError) as e:
                skipped.append(f"{name} {seq}: {e}")
        if not entries:
            dev.rules.append(Rule(f"{name} (empty)", f"{name} (empty)", 0, "deny", True, [], [], [], stage=stage,
                                  implicit=True))
    if skipped:
        dev.notes.append("ACL entries not modelled and left out: " + "; ".join(skipped[:20])
                         + (" …" if len(skipped) > 20 else ""))
    dev.notes.append("Dynamic routing (OSPF, EIGRP, BGP) is not read; only connected networks and static routes.")
    return dev


def _route(dev: Device, tok: list[str]) -> None:
    try:
        net = bx.cidr(f"{tok[0]}/{tok[1]}")
        plen = ipaddress.IPv4Network(f"0.0.0.0/{tok[1]}").prefixlen
        target = tok[2]
        if _ADDR.match(target):
            dev.routes.append(Route(net, plen, bx.ip_int(target), ""))
        else:
            dev.routes.append(Route(net, plen, None, target))
    except ValueError:
        return
