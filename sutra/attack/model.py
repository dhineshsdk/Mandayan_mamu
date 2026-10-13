"""The device model the parsers fill in and ``analyze`` reads."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import boxes as bx
from .boxes import Box, Interval

MAX_BOXES = 4000  # one rule is never expanded to more boxes than this; beyond it the address sets are widened


@dataclass
class Rule:
    key: str  # what hit counts are matched on: FortiOS policy id, PAN-OS rule name, IOS "ACL-NAME seq"
    name: str
    position: int
    action: str  # "permit" | "deny"
    enabled: bool
    src: list[Interval]
    dst: list[Interval]
    services: list[Interval]
    src_text: list[str] = field(default_factory=list)
    dst_text: list[str] = field(default_factory=list)
    service_text: list[str] = field(default_factory=list)
    in_ifs: frozenset[str] | None = None  # None: any interface
    out_ifs: frozenset[str] | None = None
    stage: str = "main"  # IOS: "in:<interface>" or "out:<interface>"; firewalls: "main"
    comment: str = ""
    approximate: list[str] = field(default_factory=list)  # parts of the rule the parser could only over-approximate
    implicit: bool = False

    def boxes(self) -> list[Box]:
        src, dst, svc = bx.merge(self.src), bx.merge(self.dst), bx.merge(self.services)
        if len(src) * len(dst) * len(svc) > MAX_BOXES:
            src, dst = [(src[0][0], src[-1][1])] if src else src, [(dst[0][0], dst[-1][1])] if dst else dst
            if len(src) * len(dst) * len(svc) > MAX_BOXES:
                svc = [(svc[0][0], svc[-1][1])] if svc else svc
            if "address list widened to its outer range" not in self.approximate:
                self.approximate.append("address list widened to its outer range")
        return bx.expand(src, dst, svc)

    def matches_interfaces(self, ingress: str | None, egress: str | None) -> bool:
        return ((self.in_ifs is None or ingress in self.in_ifs)
                and (self.out_ifs is None or egress in self.out_ifs))

    def covers_interfaces_of(self, other: Rule) -> bool:
        return ((self.in_ifs is None or (other.in_ifs is not None and other.in_ifs <= self.in_ifs))
                and (self.out_ifs is None or (other.out_ifs is not None and other.out_ifs <= self.out_ifs)))


@dataclass
class Interface:
    name: str
    networks: list[tuple[int, int]] = field(default_factory=list)  # (address, prefix length)
    zone: str = ""
    up: bool = True

    def connected(self) -> list[Interval]:
        out = []
        for addr, plen in self.networks:
            mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
            out.append((addr & mask, (addr & mask) | (~mask & 0xFFFFFFFF)))
        return out


@dataclass
class Route:
    prefix: Interval
    plen: int
    next_hop: int | None = None
    interface: str = ""


@dataclass
class Device:
    name: str
    vendor: str  # fortigate | panos | cisco_ios
    interfaces: dict[str, Interface] = field(default_factory=dict)
    routes: list[Route] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # what the parser could not model, shown to the reader
    site: str = ""

    def stage_rules(self, stage: str) -> list[Rule]:
        return [r for r in self.rules if r.stage == stage]

    def has_stage(self, stage: str) -> bool:
        return any(r.stage == stage for r in self.rules)

    def owner_of(self, ip: int) -> str | None:
        """The interface that has address ``ip``."""
        for i in self.interfaces.values():
            if i.up and any(a == ip for a, _ in i.networks):
                return i.name
        return None

    def attached(self, rng: Interval) -> str | None:
        """The interface whose connected network overlaps ``rng``."""
        for i in self.interfaces.values():
            if i.up and any(bx.overlaps(c, rng) for c in i.connected()):
                return i.name
        return None

    def route(self, ip: int) -> tuple[str, int | None] | None:
        """(egress interface, next hop) for ``ip``: a connected network first, then the longest static route."""
        for i in self.interfaces.values():
            if i.up and any(c[0] <= ip <= c[1] for c in i.connected()):
                return i.name, None
        best: Route | None = None
        for r in self.routes:
            if r.prefix[0] <= ip <= r.prefix[1] and (best is None or r.plen > best.plen):
                best = r
        if best is None:
            return None
        if best.next_hop is not None:
            for i in self.interfaces.values():
                if i.up and any(c[0] <= best.next_hop <= c[1] for c in i.connected()):
                    return i.name, best.next_hop
            return None
        return (best.interface, None) if best.interface in self.interfaces else None
