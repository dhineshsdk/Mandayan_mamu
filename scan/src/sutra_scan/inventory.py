"""What is installed on a host: the packages, the operating system, and enough identity to name the host.

The collector reads the package databases the system itself keeps, so it needs no network and no agent daemon:

- **dpkg**: ``/var/lib/dpkg/status`` (Debian, Ubuntu). A package counts only when its status is ``install ok
  installed``. The ``Source:`` field is kept, because Debian and Ubuntu advisories name the *source* package.
- **apk**: ``/lib/apk/db/installed`` (Alpine). The ``o:`` origin is the source package advisories name.
- **rpm**: the ``rpm`` command (``rpm -qa``; ``--root`` for a mounted image), because the rpm database is SQLite,
  Berkeley DB or NDB depending on the release and only rpm itself reads all of them.

Standard library only. The inventory is plain JSON (:func:`Inventory.to_json`), so it can be collected on a plant
server, carried across an air gap on a USB stick and matched elsewhere.
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import socket
import subprocess  # noqa: S404 - runs rpm with a fixed argument list, never a shell
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "sutra-scan/inventory/1"
SYSTEMS = ("dpkg", "rpm", "apk")


class InventoryError(Exception):
    """The host cannot be inventoried (unknown package system, missing database, unreadable file)."""


@dataclass(frozen=True)
class Package:
    name: str
    version: str  # the system's full version string; rpm: ``[epoch:]version-release``
    source: str = ""  # source package name when the system has one (dpkg ``Source:``, apk ``o:``)
    source_version: str = ""  # dpkg: version of the source package, which differs from ``version`` after a binNMU
    arch: str = ""


@dataclass(frozen=True)
class OsInfo:
    id: str = ""  # os-release ID, e.g. debian, ubuntu, alpine, almalinux, rocky
    version_id: str = ""
    pretty_name: str = ""
    id_like: tuple[str, ...] = ()


@dataclass
class Inventory:
    system: str  # one of SYSTEMS
    os: OsInfo
    packages: list[Package]
    hostname: str = ""
    fqdn: str = ""
    ips: list[str] = field(default_factory=list)
    kernel: str = ""
    arch: str = ""
    collected_at: str = ""
    schema: str = SCHEMA

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=1, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> Inventory:
        try:
            raw = json.loads(text)
            if raw.get("schema") != SCHEMA:
                raise InventoryError(f"not a {SCHEMA} file (schema is {raw.get('schema')!r})")
            os_raw = raw["os"]
            os_info = OsInfo(**{**os_raw, "id_like": tuple(os_raw.get("id_like", ()))})
            pkgs = [Package(**p) for p in raw["packages"]]
            if raw["system"] not in SYSTEMS:
                raise InventoryError(f"unknown package system {raw['system']!r}")
            return cls(**{**raw, "os": os_info, "packages": pkgs})
        except (KeyError, TypeError, json.JSONDecodeError, AttributeError) as exc:
            raise InventoryError(f"unreadable inventory: {exc}") from exc


# ---------------------------------------------------------------------------------------------- parsers


def parse_os_release(text: str) -> OsInfo:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key] = val.strip().strip("\"'")
    return OsInfo(id=values.get("ID", "").lower(), version_id=values.get("VERSION_ID", ""),
                  pretty_name=values.get("PRETTY_NAME", ""), id_like=tuple(values.get("ID_LIKE", "").lower().split()))


def _paragraphs(text: str):
    block: dict[str, str] = {}
    last = ""
    for line in text.splitlines():
        if not line.strip():
            if block:
                yield block
            block, last = {}, ""
        elif line[0] in " \t":
            if last:
                block[last] += "\n" + line.strip()
        elif ":" in line:
            last, _, val = line.partition(":")
            block[last] = val.strip()
    if block:
        yield block


_DPKG_SOURCE = re.compile(r"^(?P<name>\S+)(?:\s+\((?P<version>[^)]+)\))?$")


def parse_dpkg_status(text: str) -> list[Package]:
    out = []
    for p in _paragraphs(text):
        status = p.get("Status", "").split()
        if len(status) != 3 or status[2] != "installed" or "Package" not in p or "Version" not in p:
            continue  # removed, config-files only, half-installed and so on
        m = _DPKG_SOURCE.match(p.get("Source", "").strip())
        source = m["name"] if m else p["Package"]
        source_version = (m["version"] if m and m["version"] else p["Version"])
        out.append(Package(p["Package"], p["Version"], source, source_version, p.get("Architecture", "")))
    return out


def parse_apk_installed(text: str) -> list[Package]:
    out = []
    for block in re.split(r"\n\s*\n", text.strip()):
        f = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                f.setdefault(line[0], line[2:].strip())
        if "P" in f and "V" in f:
            out.append(Package(f["P"], f["V"], f.get("o", f["P"]), f["V"], f.get("A", "")))
    return out


RPM_QUERYFORMAT = "%{NAME}\\t%|EPOCH?{%{EPOCH}}:{0}|\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"


def parse_rpm_query(text: str) -> list[Package]:
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 6 or parts[0] == "gpg-pubkey":
            continue
        name, epoch, version, release, arch, srpm = parts
        full = f"{epoch}:{version}-{release}" if epoch not in ("0", "") else f"{version}-{release}"
        source = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", srpm) if srpm.endswith(".src.rpm") else ""
        out.append(Package(name, full, source or name, full, arch))
    return out


# ---------------------------------------------------------------------------------------------- collection


def _read(root: Path, *candidates: str) -> str:
    base = root.resolve()
    for c in candidates:
        p = (root / c.lstrip("/")).resolve()
        # An image's absolute symlink (etc/os-release -> /usr/lib/os-release) resolves against the host, not the
        # image, so a link that leaves the image is ignored rather than followed.
        if p.is_file() and (p == base or base in p.parents):
            return p.read_text(encoding="utf-8", errors="replace")
    raise InventoryError(f"none of {', '.join(candidates)} found under {root}")


def detect_system(root: Path) -> str:
    if (root / "var/lib/dpkg/status").is_file():
        return "dpkg"
    if (root / "lib/apk/db/installed").is_file():
        return "apk"
    for rpmdb in ("var/lib/rpm", "usr/lib/sysimage/rpm"):
        if (root / rpmdb).is_dir():
            return "rpm"
    raise InventoryError(f"no dpkg, apk or rpm database under {root}")


def _rpm_packages(root: Path) -> list[Package]:
    rpm = shutil.which("rpm")
    if not rpm:
        raise InventoryError("this is an rpm-based system but the rpm command is not on PATH")
    cmd = [rpm, "-qa", "--queryformat", RPM_QUERYFORMAT]
    if str(root) != "/":
        # The image's database sits where its own rpm put it; the rpm running here may default to the other place
        # (Fedora and RHEL 9 moved it to /usr/lib/sysimage/rpm), and then reports an empty database without an error.
        dbpath = next(d for d in ("/var/lib/rpm", "/usr/lib/sysimage/rpm") if (root / d.lstrip("/")).is_dir())
        cmd[1:1] = ["--root", str(root.resolve()), "--dbpath", dbpath]
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
    except subprocess.TimeoutExpired as exc:
        raise InventoryError("rpm -qa took longer than 120 seconds") from exc
    if done.returncode != 0:
        raise InventoryError(f"rpm -qa failed: {done.stderr.strip()[:300]}")
    return parse_rpm_query(done.stdout)


def _local_ips() -> list[str]:
    ips: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_STREAM):
            ip = str(info[4][0])
            if ":" not in ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    if not ips:  # the hostname often resolves to 127.0.1.1; asking the routing table needs no traffic
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 9))  # TEST-NET-1: nothing is sent, the kernel just picks a source address
                if not s.getsockname()[0].startswith("127."):
                    ips.append(s.getsockname()[0])
        except OSError:
            pass
    return ips


def collect(root: str | Path = "/", *, hostname: str = "", now: datetime | None = None) -> Inventory:
    """Inventory the system at ``root``: ``/`` for this host, or a mounted or extracted image."""
    root = Path(root)
    system = detect_system(root)
    os_info = parse_os_release(_read(root, "etc/os-release", "usr/lib/os-release"))
    if system == "dpkg":
        pkgs = parse_dpkg_status(_read(root, "var/lib/dpkg/status"))
    elif system == "apk":
        pkgs = parse_apk_installed(_read(root, "lib/apk/db/installed"))
    else:
        pkgs = _rpm_packages(root)
    if not pkgs:
        raise InventoryError(f"found the {system} database under {root} but it lists no packages; "
                             "refusing to report an empty host as clean")
    live = str(root) == "/"
    name = hostname or (socket.gethostname() if live else "")
    return Inventory(
        system=system, os=os_info, packages=sorted(pkgs, key=lambda p: (p.name, p.version, p.arch)),
        hostname=name.split(".")[0].lower(), fqdn=socket.getfqdn() if live and not hostname else name,
        ips=_local_ips() if live else [], kernel=platform.release() if live else "",
        arch=platform.machine() if live else "",
        collected_at=(now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"))
