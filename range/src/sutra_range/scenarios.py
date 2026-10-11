"""Estates with causes planted in them, so the right answer is known before any tool looks.

Each estate is a small synthetic company written as the files Sutra imports (a Tenable CSV and a CMDB). The planted
causes are the ones the plan names that today's product can find: a stale golden image (some hosts missing from the
CMDB, to be recognised by their packages), a shared OEM login on plant HMIs, a configuration template that sets an
insecure option, and one library that no image explains. Decoys sit beside each, built to look alike: the same
insecure option on hosts with no template, the same package version on a different image. The people who wrote this
file also wrote the grouping rules, so this is a regression and honesty harness, not an independent benchmark.

Not planted, and said so in the score: a forgotten firewall rule. That needs the attack-surface module, which is
after V1.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from sutra import synth
from sutra.synth import AS_OF, CMDB_COLS, SEV_TENABLE, TENABLE_COLS, Host, V, _port, _tenable_output

PROCESSES = {"web": ("Customer portal", 250_000), "plant": ("Unit control", 900_000), "back": ("Back office", 90_000)}
STALE_PKGS = ("openssl8", "openssh8", "sudo8", "glibc8")


@dataclass(frozen=True)
class Planted:
    kind: str  # the Sutra root-cause kind that should name it
    label: str
    members: frozenset[tuple[str, int]]  # (ip, scanner plugin id): one finding on one host


@dataclass
class Scenario:
    name: str
    seed: int
    hosts: list[Host]
    planted: list[Planted]
    notes: str = ""
    poison: dict[str, dict] = field(default_factory=dict)  # (nothing at build time; see attacks.apply)


def _host(n: int, ip: str, **kw) -> Host:
    base = dict(site="Range", zone="corp", os="Linux", owner="Team A", process="back", criticality=3, image="",
                template="", is_ot=False, safety=False, pii=False, scanners=("tenable",), in_cmdb=True, vulns=[])
    base.update(kw)
    return Host(asset_id=f"RNG-{n:04d}", hostname=kw.pop("hostname", None) or f"rng-host-{n:03d}", ip=ip,
                **{k: v for k, v in base.items() if k != "hostname"})


def _members(hosts: list[Host], key: str) -> frozenset[tuple[str, int]]:
    return frozenset((h.ip, V[key].plugin) for h in hosts if key in h.vulns)


def build(seed: int = 1) -> Scenario:
    rng = random.Random(seed)
    hosts: list[Host] = []
    planted: list[Planted] = []

    def add(count: int, **kw) -> list[Host]:
        made = []
        for _ in range(count):
            n = len(hosts) + 1
            h = _host(n, f"10.{seed}.{n // 250}.{n % 250 + 1}", **kw)
            hosts.append(h)
            made.append(h)
        return made

    # 1. A stale golden image: 30 hosts, 4 of them missing from the CMDB, all carrying the same four package flaws.
    stale = add(30, image="rhel8-stale-2022", process="web", owner="Linux", criticality=4)
    for h in stale:
        h.vulns = list(STALE_PKGS)
    for h in rng.sample(stale, 4):
        h.in_cmdb = False
    stale_members = frozenset(m for k in STALE_PKGS for m in _members(stale, k))
    planted.append(Planted("base-image", "stale golden image rhel8-stale-2022", stale_members))

    # 2. A shared OEM login on plant HMIs (12), with 3 look-alike HMIs that carry no credential finding.
    hmis = add(12, zone="ot-l2", os="Windows 7 Embedded", is_ot=True, safety=True, process="plant", owner="Plant",
               image="hmi-vendor-2016", criticality=5)
    for h in hmis:
        h.vulns = ["hmidefault"]
    add(3, zone="ot-l2", os="Windows 7 Embedded", is_ot=True, process="plant", owner="Plant", image="hmi-vendor-2016",
        criticality=5)
    planted.append(Planted("shared-credential", "shared OEM login on HMIs", _members(hmis, "hmidefault")))

    # 3. A template sets SMBv1: 20 hosts share the template; 5 decoys have the same finding with no template.
    tpl = add(20, template="win2019-baseline", os="Windows Server 2019", process="back", owner="Windows")
    for h in tpl:
        h.vulns = ["smbv1"]
    decoys = add(5, os="Windows Server 2019", process="back", owner="Windows")
    for h in decoys:
        h.vulns = ["smbv1"]
    planted.append(Planted("config-template", "template win2019-baseline sets SMBv1", _members(tpl, "smbv1")))

    # 4. One library no image explains: Log4j on 6 hosts spread over three images; a second library on the same hosts
    #    stays a separate cause.
    spread = []
    for image in ("app-img-a", "app-img-b", "app-img-c"):
        spread += add(2, image=image, process="web", owner="Apps")
    for h in spread:
        h.vulns = ["log4j"]
    for image in ("app-img-a", "app-img-b", "app-img-c"):  # images need members that do not carry it, or they would
        add(4, image=image, process="web", owner="Apps")    # explain it as the image's fault
    planted.append(Planted("package", "Log4j on hosts of three images", _members(spread, "log4j")))

    # Singles: one-off findings that are nobody's shared cause.
    for h in add(6, process="back", owner="Team B"):
        h.vulns = [rng.choice(["tomcat", "jquery", "trace"])]
    rng.shuffle(hosts)
    for i, h in enumerate(hosts, 1):  # stable IDs after shuffling
        h.asset_id = f"RNG-{i:04d}"
    return Scenario(f"estate-{seed}", seed, hosts, planted,
                    notes="stale image, shared OEM login, template setting, library spread over images; with decoys")


def write(s: Scenario, out: Path, poison=None) -> tuple[Path, Path]:
    """Write the CMDB and a Tenable export. ``poison`` is ``attacks.Poison`` or None."""
    out.mkdir(parents=True, exist_ok=True)
    cmdb, scan = out / "cmdb_assets.csv", out / "tenable_export.csv"
    with cmdb.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CMDB_COLS)
        for h in s.hosts:
            if not h.in_cmdb:
                continue
            name, inr = PROCESSES[h.process]
            hostname = poison.hostname(h) if poison else h.hostname
            w.writerow([h.asset_id, hostname, h.ip, h.site, h.zone, h.os, h.owner, name, inr, h.criticality,
                        h.image, h.template, int(h.is_ot), int(h.safety), int(h.pii)])
    rows = []
    last = AS_OF
    for h in s.hosts:
        fqdn = f"{h.hostname}.range.example"
        rows.append([19506, "Nessus Scan Information", "Settings", "Info", h.ip, "TCP", "0", "No", fqdn,
                     h.hostname.upper()[:15], "Credentialed checks : yes", "", "", "", "", "", "",
                     f"{last - timedelta(days=1):%b %d, %Y} 02:10:00 UTC", f"{last:%b %d, %Y} 02:10:00 UTC", ""])
        for key in h.vulns:
            v = V[key]
            port, proto = _port(v)
            title, solution, output = v.title_t, v.solution, _tenable_output(v)
            if poison:
                title, solution, output = poison.fields(h, key, title, solution, output)
            first = last - timedelta(days=sum(v.age_days) // 2)
            rows.append([v.plugin, title, v.family, SEV_TENABLE[v.sev], h.ip, proto.upper(), port, "No", fqdn,
                         h.hostname.upper()[:15], output, title, title, solution, "", v.cvss, ",".join(v.cves),
                         f"{first:%b %d, %Y} 02:10:00 UTC", f"{last:%b %d, %Y} 02:10:00 UTC", ""])
    with scan.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(TENABLE_COLS)
        w.writerows(rows)
    return scan, cmdb


__all__ = ["Planted", "Scenario", "build", "synth", "write"]
