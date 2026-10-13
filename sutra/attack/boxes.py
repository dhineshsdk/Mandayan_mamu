"""Boxes in (source address, destination address, service) space, so first-match rule lists can be evaluated exactly.

A service is one integer, ``protocol * 65536 + port`` (the port is 0 for protocols without ports), so "tcp 502" is a
single point, "all of tcp" an interval and "any" the whole range. Everything is a closed integer interval.
"""

from __future__ import annotations

import ipaddress

Interval = tuple[int, int]
Box = tuple[Interval, Interval, Interval]

IP_ALL: Interval = (0, 2**32 - 1)
SVC_ALL: Interval = (0, 256 * 65536 - 1)
PROTOCOLS = {"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "ospf": 89, "sctp": 132}
PROTO_NAMES = {v: k for k, v in PROTOCOLS.items()}


def svc(proto: int, lo: int = 0, hi: int = 65535) -> Interval:
    return proto * 65536 + lo, proto * 65536 + hi


def proto_all(proto: int) -> Interval:
    return svc(proto, 0, 65535)


def cidr(text: str) -> Interval:
    """``10.0.0.0/24``, ``10.0.0.1`` or ``10.0.0.0 255.255.255.0`` as an interval (host bits are ignored)."""
    text = text.strip().replace(" ", "/") if " " in text.strip() and "/" not in text else text.strip()
    net = ipaddress.ip_network(text, strict=False)
    if net.version != 4:
        raise ValueError("IPv6 is not modelled")
    return int(net.network_address), int(net.broadcast_address)


def ip_int(text: str) -> int:
    return int(ipaddress.IPv4Address(text))


def ip_text(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def merge(items: list[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for lo, hi in sorted(items):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def size(iv: Interval) -> int:
    return iv[1] - iv[0] + 1


def prefixes(iv: Interval) -> list[str]:
    first, last = ipaddress.IPv4Address(iv[0]), ipaddress.IPv4Address(iv[1])
    return [str(n) for n in ipaddress.summarize_address_range(first, last)]


def overlaps(a: Interval, b: Interval) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


def contains(outer: Interval, inner: Interval) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def intersect(a: Box, b: Box) -> Box | None:
    out = []
    for x, y in zip(a, b, strict=True):
        lo, hi = max(x[0], y[0]), min(x[1], y[1])
        if lo > hi:
            return None
        out.append((lo, hi))
    return out[0], out[1], out[2]


def subtract(a: Box, b: Box) -> list[Box]:
    """``a`` without ``b``, as disjoint boxes."""
    if intersect(a, b) is None:
        return [a]
    pieces: list[Box] = []
    cur = list(a)
    for d in range(3):
        lo, hi = max(cur[d][0], b[d][0]), min(cur[d][1], b[d][1])
        if cur[d][0] < lo:
            piece = list(cur)
            piece[d] = (cur[d][0], lo - 1)
            pieces.append((piece[0], piece[1], piece[2]))
        if hi < cur[d][1]:
            piece = list(cur)
            piece[d] = (hi + 1, cur[d][1])
            pieces.append((piece[0], piece[1], piece[2]))
        cur[d] = (lo, hi)
    return pieces


def subtract_all(boxes: list[Box], others: list[Box]) -> list[Box]:
    for o in others:
        nxt: list[Box] = []
        for b in boxes:
            nxt.extend(subtract(b, o))
        boxes = nxt
        if not boxes:
            break
    return boxes


def expand(src: list[Interval], dst: list[Interval], services: list[Interval]) -> list[Box]:
    return [(s, d, v) for s in merge(src) for d in merge(dst) for v in merge(services)]


def describe_services(boxes: list[Box]) -> list[str]:
    """Readable service list for the union of ``boxes`` ("tcp/502", "udp/1000-2000", "all tcp", "any")."""
    items = merge([b[2] for b in boxes])
    if items == [SVC_ALL]:
        return ["any"]
    out: list[str] = []
    for lo, hi in items:
        while lo <= hi:
            proto, port = divmod(lo, 65536)
            end = min(hi, proto * 65536 + 65535)
            name = PROTO_NAMES.get(proto, f"ip-protocol-{proto}")
            lo_port, hi_port = port, end - proto * 65536
            if proto in (6, 17):
                if (lo_port, hi_port) == (0, 65535):
                    out.append(f"all {name}")
                else:
                    out.append(f"{name}/{lo_port}" if lo_port == hi_port else f"{name}/{lo_port}-{hi_port}")
            else:
                out.append(f"all {name}" if proto != 1 else "icmp")
            lo = end + 1
    return out
