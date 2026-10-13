import json
from pathlib import Path

import pytest

from sutra_scan.inventory import (
    Inventory,
    InventoryError,
    OsInfo,
    Package,
    collect,
    detect_system,
    parse_apk_installed,
    parse_dpkg_status,
    parse_os_release,
    parse_rpm_query,
)

DPKG = """Package: libssl3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 5982
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.9-1
Description: Secure Sockets Layer toolkit - shared libraries
 This package is part of the OpenSSL project's implementation of the SSL
 and TLS cryptographic protocols.

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2+b2
Source: bash (5.2.15-2)

Package: oldpkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1

Package: coreutils
Status: install ok installed
Architecture: amd64
Version: 9.1-1
"""

APK = """C:Q1abc=
P:musl
V:1.2.4-r2
A:x86_64
S:383152
o:musl
T:the musl c library (libc) implementation

C:Q1def=
P:libcrypto3
V:3.1.4-r5
A:x86_64
o:openssl

"""

RPM = ("openssl-libs\t1\t3.0.7\t24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\n"
       "bash\t0\t5.1.8\t6.el9_1\tx86_64\tbash-5.1.8-6.el9_1.src.rpm\n"
       "gpg-pubkey\t0\t8483c65d\t5ccc5b19\t(none)\t(none)\n")


def test_dpkg_status_keeps_installed_only_and_source():
    pkgs = {p.name: p for p in parse_dpkg_status(DPKG)}
    assert set(pkgs) == {"libssl3", "bash", "coreutils"}
    assert pkgs["libssl3"].source == "openssl" and pkgs["libssl3"].source_version == "3.0.9-1"
    assert pkgs["bash"].version == "5.2.15-2+b2" and pkgs["bash"].source_version == "5.2.15-2"  # binNMU
    assert pkgs["coreutils"].source == "coreutils"


def test_apk_installed_uses_origin():
    pkgs = {p.name: p for p in parse_apk_installed(APK)}
    assert pkgs["libcrypto3"].source == "openssl" and pkgs["libcrypto3"].version == "3.1.4-r5"
    assert pkgs["musl"].arch == "x86_64"


def test_rpm_query_epoch_and_source():
    pkgs = {p.name: p for p in parse_rpm_query(RPM)}
    assert "gpg-pubkey" not in pkgs
    assert pkgs["openssl-libs"].version == "1:3.0.7-24.el9" and pkgs["openssl-libs"].source == "openssl"
    assert pkgs["bash"].version == "5.1.8-6.el9_1"


def test_os_release():
    o = parse_os_release('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n# c\nID_LIKE="a b"\n')
    assert (o.id, o.version_id, o.id_like) == ("debian", "12", ("a", "b"))


def _image(tmp_path: Path, kind: str) -> Path:
    root = tmp_path / kind
    (root / "etc").mkdir(parents=True)
    if kind == "dpkg":
        (root / "var/lib/dpkg").mkdir(parents=True)
        (root / "var/lib/dpkg/status").write_text(DPKG)
        (root / "etc/os-release").write_text("ID=debian\nVERSION_ID=12\n")
    else:
        (root / "lib/apk/db").mkdir(parents=True)
        (root / "lib/apk/db/installed").write_text(APK)
        (root / "etc/os-release").write_text("ID=alpine\nVERSION_ID=3.19.1\n")
    return root


@pytest.mark.parametrize("kind", ["dpkg", "apk"])
def test_collect_rootfs_and_json_round_trip(tmp_path, kind):
    root = _image(tmp_path, kind)
    inv = collect(root, hostname="Web01.Plant.Example")
    assert inv.system == kind == detect_system(root) and inv.hostname == "web01"
    again = Inventory.from_json(inv.to_json())
    assert again == inv and isinstance(again.os, OsInfo) and isinstance(again.packages[0], Package)


def test_collect_rejects_unknown_system(tmp_path):
    with pytest.raises(InventoryError, match="no dpkg, apk or rpm database"):
        collect(tmp_path)


def test_from_json_rejects_other_schemas():
    with pytest.raises(InventoryError, match="not a sutra-scan/inventory/1"):
        Inventory.from_json(json.dumps({"schema": "other"}))
    with pytest.raises(InventoryError, match="unreadable"):
        Inventory.from_json("{")
