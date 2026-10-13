"""Real distribution images, real advisories.

Pulls the exact image layers (pinned by digest) of old releases that are known to carry vulnerable packages, reads
their package databases with the collector, matches them against the live OSV feed, and checks the findings.
Needs the internet and about 400 MB of OSV downloads, so it runs only when ``SUTRA_SCAN_CONTAINERS=1`` (the
``containers`` CI job sets it). Set ``SUTRA_SCAN_CACHE`` to keep the downloads between runs.

``test_inventory_equals_the_distros_own_tool`` additionally needs Docker (``SUTRA_SCAN_DOCKER=1``): it runs
``dpkg-query``, ``apk info`` and ``rpm -qa`` inside the image and compares their package lists with the collector's.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from sutra_scan import feed
from sutra_scan.inventory import collect
from sutra_scan.match import match
from sutra_scan.versions import COMPARE

from . import registry

pytestmark = pytest.mark.skipif(os.environ.get("SUTRA_SCAN_CONTAINERS") != "1",
                                reason="set SUTRA_SCAN_CONTAINERS=1 to pull real images and the live feed")

# name -> (image pinned by digest, OSV ecosystem)
IMAGES = {
    "debian": ("debian@sha256:88b0908ef4de0f7015fd61b7fcbfa407854349af42d1e2081595768d575995c1", "Debian:12"),  # bookworm-20230904
    "ubuntu": ("ubuntu@sha256:c985bc3f77946b8e92c9a3648c6f31751a7dd972e06604785e47303f4ad47c4c", "Ubuntu:22.04:LTS"),  # jammy-20230126
    "alpine": ("alpine@sha256:13b7e62e8df80264dbb747995705a986aa530415763a6c58f84a3ca8af9a5bcd", "Alpine:v3.19"),  # 3.19.0
    "almalinux": ("almalinux@sha256:e78278ef22f8227423532e9694e9ed5c362f3e81067c7986f05f38f2968bb438", "AlmaLinux:9"),  # 9.2
    "rhel": ("redhat/ubi9@sha256:204383c3d96c0e6c7154c91d07764f92035738dd67aa8896679f7feb73f66bfd",
             "Red Hat:enterprise_linux:9::*"),  # UBI 9.2: Red Hat's own userland, os-release ID=rhel
    "rockylinux": ("rockylinux@sha256:3387f6adc2fcdba59b9ff07acb955b4dbb610d3d93f7c68182107c1d25fac39c", "Rocky Linux:9"),  # 9.2
}

# Facts about those images that cannot change: (installed package, installed version) -> advisory and its fix.
EXPECTED = {
    "debian": ("libc6", "2.36-9+deb12u1", "DSA-5514-1", "2.36-9+deb12u3"),        # CVE-2023-4911 "Looney Tunables"
    "ubuntu": ("bash", "5.1-6ubuntu1", "UBUNTU-CVE-2022-3715", "5.1-6ubuntu1.1"),
    "alpine": ("busybox", "1.36.1-r15", "CVE-2023-42366", "1.36.1-r16"),
    "almalinux": ("glibc", "2.34-60.el9", "ALSA-2023:5453", "2.34-60.el9_2.7"),
    "rhel": ("curl-minimal", "7.76.1-23.el9_2.4", "RHSA-2023:6745", "7.76.1-26.el9_3.2"),
    "rockylinux": ("glibc", "2.34-60.el9", "RLSA-2024:3339", "2.34-100.el9_4.2"),
}


@pytest.fixture(scope="session")
def snapshot(tmp_path_factory):
    cache = Path(os.environ["SUTRA_SCAN_CACHE"]) if os.environ.get("SUTRA_SCAN_CACHE") else tmp_path_factory.mktemp("osv")
    ecosystems = [eco for _, eco in IMAGES.values()]
    zips = feed.fetch(cache, ecosystems)
    path = tmp_path_factory.mktemp("feed") / "snapshot.db"
    feed.build(path, zips, ecosystems)
    f = feed.Feed(path)
    yield f
    f.close()


@pytest.fixture(scope="session")
def roots(tmp_path_factory):
    out = {}
    for name, (image, _) in IMAGES.items():
        dest = tmp_path_factory.mktemp(name)
        registry.pull(image, dest)
        out[name] = dest
    return out


@pytest.mark.parametrize("name", IMAGES)
def test_known_vulnerable_image(name, roots, snapshot):
    if name in ("almalinux", "rockylinux", "rhel") and not shutil.which("rpm"):
        pytest.skip("the rpm command is needed to read an rpm database")
    inv = collect(roots[name], hostname=f"{name}-image")
    assert len(inv.packages) > 10
    res = match(inv, snapshot)
    pkg, installed, advisory, fixed = EXPECTED[name]
    found = [d for d in res.detections if d.package == pkg and d.advisory == advisory]
    assert found, f"{advisory} not reported for {pkg}; got {[(d.package, d.advisory) for d in res.detections][:10]}"
    assert (found[0].installed, found[0].fixed) == (installed, fixed)
    assert len(res.detections) >= 10 and all(d.severity in ("low", "medium", "high", "critical") for d in res.detections)
    # Every claim must hold under the system's own ordering: installed is strictly older than the fix.
    cmp = COMPARE[inv.system]
    versions = {(p.name, p.version.split(":", 1)[-1]): p.version for p in inv.packages}
    for d in res.detections:
        if d.fixed:
            assert cmp(versions[(d.package, d.installed)], d.fixed) < 0 or cmp(d.installed, d.fixed) < 0, d


@pytest.mark.skipif(os.environ.get("SUTRA_SCAN_DOCKER") != "1" or not shutil.which("docker"),
                    reason="needs Docker (SUTRA_SCAN_DOCKER=1)")
@pytest.mark.parametrize("name", IMAGES)
def test_inventory_equals_the_distros_own_tool(name, roots):
    image = IMAGES[name][0]
    inv = collect(roots[name])
    cmd = {"dpkg": ["dpkg-query", "-W", "-f", "${Package} ${Version} ${db:Status-Abbrev}\\n"], "apk": ["apk", "info", "-v"],
           "rpm": ["rpm", "-qa", "--qf", "%{NAME} %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\\n"]}[inv.system]
    out = subprocess.run(["docker", "run", "--rm", image, *cmd], capture_output=True, text=True, check=True).stdout  # noqa: S603, S607
    if inv.system == "apk":  # "name-version" lines
        native = {line for line in out.split() if line}
        ours = {f"{p.name}-{p.version}" for p in inv.packages}
    else:
        rows = [line.split(" ") for line in out.splitlines() if line and not line.startswith("gpg-pubkey")]
        # dpkg-query also lists removed packages (status other than "ii"); rpm prints an explicit epoch 0
        native = {(r[0], r[1].removeprefix("0:")) for r in rows if inv.system != "dpkg" or r[2].startswith("ii")}
        ours = {(p.name, p.version) for p in inv.packages}
    assert ours == native
