"""Match an inventory against a feed snapshot.

How a package is judged, per system:

- **dpkg / apk**: advisories name the *source* package, so the inventory's source name and source version are looked
  up. A package is affected when its version is inside an ``introduced`` .. ``fixed`` (or ``last_affected``) range,
  compared with the system's own ordering (:mod:`sutra_scan.versions`).
- **rpm** (AlmaLinux, Rocky Linux): errata name binary packages. One erratum often lists several fixed builds of the
  same package, one per module stream or minor release. A build is judged against the fixes of its *own* stream: those
  that share its epoch and first version component, else all of them, taking the lowest. HEURISTIC: a stale build that
  sorts between two same-stream fixes can be missed; the container tests in CI cover the common cases.

Records with no fixed version are dropped unless ``include_unfixed`` is set, because nothing can be patched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from . import versions
from .feed import Advisory, Feed, ecosystem_matches
from .inventory import Inventory, OsInfo, Package


class UnsupportedOs(Exception):
    """The inventory is from an operating system the snapshot cannot judge."""


@dataclass(frozen=True)
class Detection:
    advisory: str
    cves: tuple[str, ...]
    package: str  # as installed
    installed: str
    fixed: str  # "" when no fix is published
    severity: str
    cvss: float | None
    rated_by: str
    summary: str
    ecosystem: str
    source: str = ""  # the source package, when it differs from ``package``
    published: str = ""

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.advisory}"


@dataclass
class MatchResult:
    detections: list[Detection]
    ecosystem: str
    feed: dict
    packages_checked: int
    warnings: list[str] = field(default_factory=list)


def candidate_ecosystems(os_info: OsInfo) -> list[str]:
    """Snapshot ecosystem names that can describe this operating system, most specific first."""
    v = os_info.version_id
    major = v.split(".")[0]
    minor = ".".join(v.split(".")[:2])
    if os_info.id == "debian" and major.isdigit():
        return [f"Debian:{major}"]
    if os_info.id == "ubuntu" and re.fullmatch(r"\d\d\.\d\d", minor):
        return [f"Ubuntu:{minor}:LTS", f"Ubuntu:{minor}"]
    if os_info.id == "alpine" and re.fullmatch(r"\d+\.\d+", minor):
        return [f"Alpine:v{minor}"]
    if os_info.id == "almalinux" and major.isdigit():
        return [f"AlmaLinux:{major}"]
    if os_info.id == "rocky" and major.isdigit():
        return [f"Rocky Linux:{major}"]
    if os_info.id == "rhel" and major.isdigit():
        return [f"Red Hat:enterprise_linux:{major}::*"]  # every channel: baseos, appstream, crb ...
    return []


def _rpm_candidates(installed: str, fixes: list[str]) -> list[str]:
    ep, ver, _ = versions.rpm_split(installed)
    first = re.split(r"[^0-9A-Za-z]+", ver, maxsplit=1)[0]
    same = [f for f in fixes if versions.rpm_split(f)[0] == ep
            and re.split(r"[^0-9A-Za-z]+", versions.rpm_split(f)[1], maxsplit=1)[0] == first]
    return same or fixes


def _strip_epoch(v: str) -> str:
    return re.sub(r"^\d+:", "", v)


def match(inv: Inventory, feed: Feed, *, include_unfixed: bool = False) -> MatchResult:
    candidates = candidate_ecosystems(inv.os)
    if not candidates:
        raise UnsupportedOs(f"{inv.os.pretty_name or inv.os.id or 'this system'} is not supported; Sutra Scan covers "
                            "Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux and RHEL releases that have an OSV feed")
    present = [e for e in feed.ecosystems() if ecosystem_matches(e, candidates)]
    present.sort(key=lambda e: (candidates.index(next(c for c in candidates if ecosystem_matches(e, [c]))), e))
    if not present:
        raise UnsupportedOs(f"the snapshot has no {' or '.join(candidates)} advisories; build it with that release "
                            f"(it has {', '.join(feed.ecosystems()) or 'nothing'})")
    system = inv.system
    cmp = versions.COMPARE[system]
    info = feed.info()
    warnings = []

    # The (name, version) the advisories speak about, for every distinct installed package.
    subjects: dict[tuple[str, str], list[Package]] = {}
    for p in inv.packages:
        if system == "rpm":
            key = (p.name, p.version)
        else:
            key = (p.source or p.name, p.source_version or p.version)
        subjects.setdefault(key, []).append(p)

    by_name: dict[str, list[tuple[str, list[Package]]]] = {}
    for (name, ver), pkgs in subjects.items():
        by_name.setdefault(name, []).append((ver, pkgs))

    grouped: dict[tuple[str, str], list] = {}
    for r in feed.ranges(present, by_name):
        grouped.setdefault((r.advisory, r.package), []).append(r)

    hits: list[tuple[str, str, str, str, list[Package]]] = []  # advisory, ecosystem, version, fixed, packages
    bad = 0
    for (adv, name), ranges in grouped.items():
        for ver, pkgs in by_name[name]:
            try:
                fixed = _affected(system, cmp, ver, ranges)
            except ValueError:
                bad += 1
                continue
            if fixed is None or (fixed == "" and not include_unfixed):
                continue
            hits.append((adv, ranges[0].ecosystem, ver, fixed, pkgs))
    if bad:
        warnings.append(f"{bad} package/advisory pairs were skipped because a version could not be parsed")

    advisories: dict[str, Advisory] = {}
    raw: list[Detection] = []
    for adv, eco, _ver, fixed, pkgs in hits:
        if adv not in advisories:
            advisories[adv] = feed.advisory(adv)
        a = advisories[adv]
        for p in pkgs:
            raw.append(Detection(
                advisory=adv, cves=a.cves, package=p.name, installed=_strip_epoch(p.version),
                fixed=_strip_epoch(fixed), severity=a.severity, cvss=a.cvss, rated_by=a.rated_by, summary=a.summary,
                ecosystem=eco, source=(p.source if p.source and p.source != p.name else ""), published=a.published))
    detections = _collapse(raw)
    detections.sort(key=lambda d: (d.package, d.advisory))
    if info["data_as_of"]:
        warnings.extend(_staleness(info["data_as_of"]))
    return MatchResult(detections, present[0], info, len(inv.packages), warnings)


def _affected(system: str, cmp, installed: str, ranges) -> str | None:
    """None when not affected; otherwise the fixed version ('' if there is none)."""
    if system == "rpm":
        fixes = [r.fixed for r in ranges if r.fixed]
        if fixes:
            pool = _rpm_candidates(installed, fixes)
            lowest = pool[0]
            for f in pool[1:]:
                if cmp(f, lowest) < 0:
                    lowest = f
            return lowest if cmp(installed, lowest) < 0 else None
    best: str | None = None
    for r in ranges:
        if r.introduced != "0" and cmp(installed, r.introduced) < 0:
            continue
        if r.fixed is not None:
            if cmp(installed, r.fixed) < 0:
                best = r.fixed
                break
        elif r.last_affected is not None:
            if cmp(installed, r.last_affected) <= 0:
                best = best or ""
        else:
            best = best or ""
    return best


def _collapse(raw: list[Detection]) -> list[Detection]:
    """One detection per installed package and fix: drop a CVE record when a distribution advisory (DSA, ALSA...) for
    the same package already covers every CVE it lists, and de-duplicate by advisory. The surviving advisory takes
    the highest CVSS rating among the records it absorbed, because distribution advisories often carry none."""
    by_pkg: dict[tuple[str, str], list[Detection]] = {}
    for d in raw:
        by_pkg.setdefault((d.package, d.installed), []).append(d)
    out: list[Detection] = []
    for items in by_pkg.values():
        uniq = {d.advisory: d for d in items}
        absorbed: dict[str, list[Detection]] = {}
        for d in uniq.values():
            mine = set(d.cves)
            for o in uniq.values():
                if o is not d and mine and mine <= set(o.cves) and o.fixed == d.fixed \
                        and (mine < set(o.cves) or _prefer(o, d)):
                    absorbed.setdefault(o.advisory, []).append(d)
                    break
            else:
                absorbed.setdefault(d.advisory, [])
        for adv, others in absorbed.items():
            if adv in uniq and not any(adv == x.advisory for lst in absorbed.values() for x in lst):
                out.append(_inherit_rating(uniq[adv], others))
    return out


def _inherit_rating(winner: Detection, absorbed: list[Detection]) -> Detection:
    best = winner
    for d in absorbed:
        if d.cvss is not None and (best.cvss is None or d.cvss > best.cvss):
            best = d
    if best is winner:
        return winner
    return replace(winner, severity=best.severity, cvss=best.cvss, rated_by=best.rated_by)


def _prefer(a: Detection, b: Detection) -> bool:
    """Same CVEs and fix in both records: keep the distribution advisory over the bare CVE record."""
    a_cve, b_cve = a.advisory.startswith("CVE-"), b.advisory.startswith("CVE-")
    if a_cve != b_cve:
        return b_cve
    return a.advisory < b.advisory


def _staleness(data_as_of: str) -> list[str]:
    from datetime import date
    try:
        days = (date.today() - date.fromisoformat(data_as_of[:10])).days
    except ValueError:
        return []
    return [f"the newest advisory in the snapshot is {days} days old; refresh it"] if days > 14 else []
