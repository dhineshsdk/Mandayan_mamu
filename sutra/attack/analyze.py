"""Reachability across the collected devices, and what is wrong with the rules.

* **Paths.** For each pair of zones that matters (internet, IT or DMZ into OT; internet into IT) the walk starts on the
  devices attached to the source zone, finds each device's egress interface for the destination from its connected
  networks and static routes, evaluates the device's rules exactly (first match, implicit deny, set arithmetic over
  source, destination and service), and follows the next hop into the next known device. The services left at the end
  are what the whole path permits.
* **Rule findings.** Broad permits, rules that can never match because earlier rules cover them, disabled rules, and
  rules with no hits in the observation window.
* **Chokepoints.** Rules ranked by how many of the risky paths depend on them; a rule that is the only permit on its
  hop is a cut that removes the path, and one that is also unused is the safest to remove.

Limits that apply to every result: IPv4 only, no dynamic routing, no NAT, rules read as the parsers describe.
Anything a parser could only approximate is carried on the path or finding as ``approximate``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from . import boxes as bx
from .boxes import IP_ALL, Box, Interval
from .hits import HitMap
from .model import Device, Rule

KINDS = {"internet": "Internet", "it": "IT", "dmz": "DMZ", "ot": "OT"}
PAIRS = [("internet", "ot"), ("it", "ot"), ("dmz", "ot"), ("internet", "it")]
PRIVATE = [bx.cidr(c) for c in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                                 "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3")]
SEVERITY = ["info", "low", "medium", "high", "critical"]
# Ports a path should not carry into OT unless there is a reason (IANA assignments).
ADMIN_PORTS = {22: "SSH", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC"}
OT_PORTS = {102: "S7comm", 502: "Modbus/TCP", 2404: "IEC 60870-5-104", 4840: "OPC UA", 20000: "DNP3",
            44818: "EtherNet/IP", 47808: "BACnet"}
WIDE = 2**24  # a /8 or wider counts as "wide" for a source or destination
BROAD_SERVICES = 1000  # a path or rule that opens this many (protocol, port) pairs counts as broad
MAX_DEPTH = 8


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)  # naive UTC, as the rest of the app stores times


@dataclass
class Zone:
    name: str
    kind: str  # internet | it | dmz | ot
    cidrs: list[str] = field(default_factory=list)

    def intervals(self) -> list[Interval]:
        if self.cidrs:
            return bx.merge([bx.cidr(c) for c in self.cidrs])
        if self.kind == "internet":  # every address that is not private, loopback, link-local or multicast
            out, cur = [], 0
            for lo, hi in bx.merge(PRIVATE):
                if lo > cur:
                    out.append((cur, lo - 1))
                cur = hi + 1
            return out
        return []


@dataclass
class Hop:
    device: str
    ingress: str
    egress: str
    rules: list[str]  # keys of the rules that permit traffic here


@dataclass
class Path:
    src_zone: str
    dst_zone: str
    src_kind: str
    dst_kind: str
    hops: list[Hop]
    boxes: list[Box]
    complete: bool  # False when the last next hop is a device Sutra has no configuration for
    approximate: list[str]

    @property
    def services(self) -> list[str]:
        return bx.describe_services(self.boxes)

    def sources(self, limit: int = 6) -> list[str]:
        return _prefix_list([b[0] for b in self.boxes], limit)

    def destinations(self, limit: int = 6) -> list[str]:
        return _prefix_list([b[1] for b in self.boxes], limit)

    def port_set(self) -> set[int]:
        found: set[int] = set()
        for _, _, (lo, hi) in self.boxes:
            for proto in (6, 17):
                for port in list(ADMIN_PORTS) + list(OT_PORTS):
                    if lo <= proto * 65536 + port <= hi:
                        found.add(port)
        return found

    def broad(self) -> bool:
        return sum(bx.size(s) for s in bx.merge([b[2] for b in self.boxes])) >= BROAD_SERVICES


def _prefix_list(ivs: list[Interval], limit: int) -> list[str]:
    out: list[str] = []
    for iv in bx.merge(ivs):
        out.extend(bx.prefixes(iv))
    return out[:limit] + ([f"… +{len(out) - limit} more"] if len(out) > limit else [])


@dataclass
class Finding:
    kind: str  # path | broad | shadowed | disabled | unused
    severity: str
    title: str
    detail: str
    device: str = ""
    rule: str = ""
    approximate: list[str] = field(default_factory=list)
    on_risky_path: bool = False


# ---------------------------------------------------------------- evaluation

def evaluate(dev: Device, ingress: str, egress: str, boxes: list[Box]) -> tuple[list[Box], list[str]]:
    """The part of ``boxes`` this device lets from ``ingress`` to ``egress``, and the rules that permit it."""
    used: list[str] = []
    for stage in (f"in:{ingress}", f"out:{egress}", "main"):
        if not dev.has_stage(stage):
            continue
        remaining, permitted = boxes, []
        for rule in dev.stage_rules(stage):
            if not rule.enabled or not remaining or not rule.matches_interfaces(ingress, egress):
                continue
            for rb in rule.boxes():
                if rule.action == "permit":
                    hit = [x for b in remaining if (x := bx.intersect(b, rb))]
                    if hit:
                        permitted += hit
                        if rule.key not in used:
                            used.append(rule.key)
                remaining = bx.subtract_all(remaining, [rb])
        boxes = permitted
        if not boxes:
            return [], []
    return boxes, used


def _ingresses(dev: Device, devices: list[Device], src: Interval, internet: bool) -> list[str]:
    if internet:  # the internet is reached through a default route whose next hop is not another known device
        for r in dev.routes:
            if r.prefix == IP_ALL and r.next_hop is not None:
                hop = dev.route(r.next_hop)
                if hop and hop[0] in dev.interfaces and not any(d is not dev and d.owner_of(r.next_hop)
                                                                 for d in devices):
                    return [hop[0]]
        return []
    attached = [i.name for i in dev.interfaces.values() if i.up and any(bx.overlaps(c, src) for c in i.connected())]
    if attached:
        return attached
    hop = dev.route(src[0])
    if hop and hop[1] is not None and not any(d is not dev and d.owner_of(hop[1]) for d in devices):
        return [hop[0]]  # the source sits behind a router Sutra has no configuration for
    return []


def _minus(iv: Interval, others: list[Interval]) -> list[Interval]:
    out, cur = [], iv[0]
    for lo, hi in bx.merge(others):
        if lo > cur:
            out.append((cur, lo - 1))
        cur = max(cur, hi + 1)
    if cur <= iv[1]:
        out.append((cur, iv[1]))
    return out


def _egresses(dev: Device, dst: Interval) -> list[tuple[str, int | None, Interval]]:
    """(egress interface, next hop or None when attached, the part of ``dst`` that goes that way)."""
    out: list[tuple[str, int | None, Interval]] = []
    covered: list[Interval] = []
    for i in dev.interfaces.values():
        if not i.up:
            continue
        for c in i.connected():
            ov = (max(c[0], dst[0]), min(c[1], dst[1]))
            if ov[0] <= ov[1]:
                out.append((i.name, None, ov))
                covered.append(ov)
    for piece in _minus(dst, covered):
        hop = dev.route(piece[0])
        if hop:
            out.append((hop[0], hop[1], piece))
    return out


def find_paths(devices: list[Device], src_zone: Zone, dst_zone: Zone) -> list[Path]:
    out: list[Path] = []
    for src in src_zone.intervals():
        for dst in dst_zone.intervals():
            q: Box = (src, dst, bx.SVC_ALL)
            for dev in devices:
                for ingress in _ingresses(dev, devices, src, src_zone.kind == "internet"):
                    _walk(dev, ingress, [q], dst, devices, [], {dev.name}, src_zone, dst_zone, out)
    merged: dict[tuple, Path] = {}
    for p in out:  # one path per route through the devices; the address ranges that use it are joined
        key = (p.src_zone, p.dst_zone, tuple((h.device, h.ingress, h.egress, tuple(h.rules)) for h in p.hops))
        if key in merged:
            merged[key].boxes = sorted(set(merged[key].boxes) | set(p.boxes))
        else:
            merged[key] = p
    return list(merged.values())


def _walk(dev: Device, ingress: str, boxes: list[Box], dst: Interval, devices: list[Device], hops: list[Hop],
          visited: set[str], sz: Zone, dz: Zone, out: list[Path]) -> None:
    if len(hops) >= MAX_DEPTH:
        return
    for egress, nh, part in _egresses(dev, dst):
        clipped = [x for b in boxes if (x := bx.intersect(b, (IP_ALL, part, bx.SVC_ALL)))]
        permitted, used = evaluate(dev, ingress, egress, clipped)
        if not permitted:
            continue
        here = hops + [Hop(dev.name, ingress, egress, used)]
        if nh is None:
            out.append(_path(sz, dz, here, permitted, devices, True))
            continue
        owner = next(((d, d.owner_of(nh)) for d in devices if d.owner_of(nh)), None)
        if owner is None:
            out.append(_path(sz, dz, here, permitted, devices, False))
        elif owner[0].name not in visited:  # a hop back to a device already crossed is a loop, not a path
            _walk(owner[0], owner[1], permitted, part, devices, here, visited | {owner[0].name}, sz, dz, out)


def _path(sz: Zone, dz: Zone, hops: list[Hop], boxes: list[Box], devices: list[Device], complete: bool) -> Path:
    by_name = {d.name: d for d in devices}
    approx = [f"{h.device} rule {r.key}: " + "; ".join(r.approximate)
              for h in hops for r in by_name[h.device].rules if r.key in h.rules and r.approximate]
    return Path(sz.name, dz.name, sz.kind, dz.kind, hops, boxes, complete, approx)


# ---------------------------------------------------------------- findings

def path_severity(p: Path) -> str:
    base = {("internet", "ot"): "critical", ("it", "ot"): "medium", ("dmz", "ot"): "low",
            ("internet", "it"): "low"}[(p.src_kind, p.dst_kind)]
    i = SEVERITY.index(base)
    if p.broad():
        i += 2
    elif p.port_set() & set(ADMIN_PORTS):
        i += 1
    return SEVERITY[min(i, 4)]


def path_title(p: Path) -> str:
    return f"{KINDS[p.src_kind]} zone {p.src_zone} can reach {KINDS[p.dst_kind]} zone {p.dst_zone}"


def path_detail(p: Path) -> str:
    names = {**ADMIN_PORTS, **OT_PORTS}
    ports = sorted(p.port_set())
    extra = f" Includes {', '.join(f'{names[x]} ({x})' for x in ports)}." if ports else ""
    via = " → ".join(f"{h.device} ({h.ingress}→{h.egress})" for h in p.hops)
    tail = "" if p.complete else " The path continues through a device Sutra has no configuration for."
    return f"Allowed services: {', '.join(p.services[:8])}.{extra} Through {via}.{tail}"


def _wide(items: list[Interval]) -> bool:
    return sum(bx.size(i) for i in bx.merge(items)) >= WIDE


def _is_any_service(rule: Rule) -> bool:
    return bx.merge(rule.services) == [bx.SVC_ALL]


def rule_summary(rule: Rule) -> str:
    return (f"{', '.join(rule.src_text) or 'none'} → {', '.join(rule.dst_text) or 'none'} "
            f"[{', '.join(rule.service_text) or 'none'}]")


def _label(rule: Rule) -> str:
    return f"{rule.key} ({rule.name})" if rule.name and rule.name != rule.key else rule.key


def broad_findings(dev: Device, ot: list[Interval]) -> list[Finding]:
    out = []
    for r in dev.rules:
        if r.action != "permit" or not r.enabled or r.implicit or not r.src or not r.dst:
            continue
        sw, dw = _wide(r.src), _wide(r.dst)
        to_ot = any(bx.overlaps(d, o) for d in r.dst for o in ot)
        any_svc = _is_any_service(r)
        if sw and dw and any_svc:
            sev, title = "critical", "Permits any traffic from a wide source to a wide destination"
        elif sw and to_ot and any_svc:
            sev, title = "critical", "Permits any service from a wide source into an OT zone"
        elif sw and to_ot:
            sev, title = "high", "Lets a wide source reach an OT zone"
        elif any_svc:
            sev, title = "high", "Permits every service"
        elif sw and dw:
            sev, title = "medium", "Wide source and wide destination"
        else:
            continue
        out.append(Finding("broad", sev, title, rule_summary(r), dev.name, r.key, list(r.approximate)))
    return out


def shadow_findings(dev: Device) -> list[Finding]:
    out = []
    for r in dev.rules:
        if not r.enabled or r.implicit:
            continue
        remaining = r.boxes()
        if not remaining:
            continue
        covering: list[Rule] = []
        for e in dev.rules:
            if e.stage != r.stage or e.position >= r.position or not e.enabled or e.implicit:
                continue
            if not e.covers_interfaces_of(r):
                continue
            before = remaining
            remaining = bx.subtract_all(remaining, e.boxes())
            if remaining != before:
                covering.append(e)
            if not remaining:
                break
        if remaining:
            continue
        by = ", ".join(_label(e) for e in covering[:3])
        if all(e.action == r.action for e in covering):
            out.append(Finding("shadowed", "low", "Redundant: earlier rules already do this",
                               f"{rule_summary(r)} is covered by {by}, which have the same action.",
                               dev.name, r.key, list(r.approximate)))
        else:
            other = "deny" if r.action == "permit" else "permit"
            out.append(Finding("shadowed", "medium", "Never takes effect: earlier rules decide first",
                               f"{rule_summary(r)} ({r.action}) is covered by {by}, which {other} the same traffic. "
                               "Someone may believe this rule is in force.", dev.name, r.key, list(r.approximate)))
    return out


def disabled_findings(dev: Device) -> list[Finding]:
    return [Finding("disabled", "low", "Disabled rule still in the policy",
                    f"{rule_summary(r)}. It does nothing now and can be switched back on by mistake: a cleanup "
                    "candidate.",
                    dev.name, r.key) for r in dev.rules if not r.enabled and not r.implicit]


def unused_findings(dev: Device, hits: HitMap | None, now: datetime, days: int) -> tuple[list[Finding], bool]:
    """(findings, whether hit counts exist for this device)."""
    if not hits:
        return [], False
    out = []
    cutoff = now - timedelta(days=days)
    for r in dev.rules:
        if not r.enabled or r.implicit or r.action != "permit":
            continue
        h = hits.get(r.key)
        if h is None:
            continue
        if h.hits == 0:
            window = (now - h.since).days if h.since else None
            if window is not None and window < days:
                out.append(Finding("unused", "info", f"No hits yet, but only {window} days of counters",
                                   f"{rule_summary(r)}. Too short to call it unused; check again after {days} days.",
                                   dev.name, r.key))
            else:
                span = f"in {window} days of counters" if window is not None else "since the counters started"
                out.append(Finding("unused", "medium" if window is not None else "low", f"No hits {span}",
                                   rule_summary(r), dev.name, r.key))
        elif h.last_hit and h.last_hit < cutoff:
            out.append(Finding("unused", "low", f"Last used {(now - h.last_hit).days} days ago",
                               rule_summary(r), dev.name, r.key))
    return out, True


@dataclass
class Chokepoint:
    device: str
    rule: str
    name: str
    paths: int
    sole: int  # on how many paths this rule is the only permit on its hop
    summary: str
    unused: bool = False
    approximate: list[str] = field(default_factory=list)


@dataclass
class Report:
    zones: list[Zone]
    devices: list[str]
    paths: list[Path]
    path_findings: list[Finding]
    findings: list[Finding]
    chokepoints: list[Chokepoint]
    coverage: list[dict]
    notes: list[str]

    def counts(self) -> dict[str, int]:
        c = dict.fromkeys(SEVERITY, 0)
        for f in self.path_findings + self.findings:
            c[f.severity] += 1
        return c


def analyze(devices: list[Device], zones: list[Zone], hits: dict[str, HitMap] | None = None,
            now: datetime | None = None, unused_days: int = 90) -> Report:
    now = now or _now()
    hits = hits or {}
    by_kind: dict[str, list[Zone]] = {}
    for z in zones:
        by_kind.setdefault(z.kind, []).append(z)
    paths: list[Path] = []
    for sk, dk in PAIRS:
        for sz in by_kind.get(sk, []):
            for dz in by_kind.get(dk, []):
                paths.extend(find_paths(devices, sz, dz))
    path_findings = [Finding("path", path_severity(p), path_title(p), path_detail(p), p.hops[0].device, "",
                             list(p.approximate), True) for p in paths]
    ot_ranges = [iv for z in by_kind.get("ot", []) for iv in z.intervals()]
    findings: list[Finding] = []
    coverage = []
    for d in devices:
        findings += broad_findings(d, ot_ranges) + shadow_findings(d) + disabled_findings(d)
        u, has = unused_findings(d, hits.get(d.name), now, unused_days)
        findings += u
        coverage.append({"device": d.name, "vendor": d.vendor, "rules": len([r for r in d.rules if not r.implicit]),
                         "interfaces": len(d.interfaces), "hit_counts": has, "notes": d.notes})
    chokes = chokepoints(devices, paths, findings)
    risky = {(c.device, c.rule) for c in chokes}
    for f in findings:
        f.on_risky_path = (f.device, f.rule) in risky
    rank = {s: i for i, s in enumerate(SEVERITY)}
    findings.sort(key=lambda f: (-rank[f.severity], not f.on_risky_path, f.device, f.rule))
    path_findings.sort(key=lambda f: -rank[f.severity])
    notes = []
    if not any(z.kind == "ot" for z in zones):
        notes.append("No OT zone is defined, so no path into OT was looked for. Add the plant networks as an OT zone.")
    if not any(z.kind in ("it", "internet", "dmz") for z in zones):
        notes.append("No IT, DMZ or Internet zone is defined.")
    return Report(zones, [d.name for d in devices], paths, path_findings, findings, chokes, coverage, notes)


def chokepoints(devices: list[Device], paths: list[Path], findings: list[Finding]) -> list[Chokepoint]:
    by_name = {d.name: d for d in devices}
    count: dict[tuple[str, str], list[int]] = {}
    for p in paths:
        for h in p.hops:
            for key in h.rules:
                c = count.setdefault((h.device, key), [0, 0])
                c[0] += 1
                if len(h.rules) == 1:
                    c[1] += 1
    unused = {(f.device, f.rule) for f in findings if f.kind == "unused" and f.severity != "info"}
    out = []
    for (dev, key), (n, sole) in count.items():
        rule = next((r for r in by_name[dev].rules if r.key == key), None)
        if rule is not None:
            out.append(Chokepoint(dev, key, rule.name, n, sole, rule_summary(rule), (dev, key) in unused,
                                  list(rule.approximate)))
    out.sort(key=lambda c: (-c.sole, -c.paths, not c.unused, c.device, c.rule))
    return out
