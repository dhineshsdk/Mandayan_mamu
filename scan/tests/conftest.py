"""Shared fixtures. The advisories in ``fixtures/osv`` are real OSV records copied from the public feeds on
2026-10-13, with only ``references``, the per-version ``versions`` lists and long ``details`` trimmed. The
inventories below are constructed (package names and versions chosen to sit either side of those real fixes); the
real-image tests are in ``test_containers.py``."""

from pathlib import Path

import pytest

from sutra_scan import feed
from sutra_scan.inventory import Inventory, OsInfo, Package

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def snapshot(tmp_path_factory):
    path = tmp_path_factory.mktemp("feed") / "snapshot.db"
    feed.build(path, [FIXTURES / "osv"], ["Debian:12", "Alpine:v3.19", "AlmaLinux:9", "Ubuntu:24.04:LTS", "Red Hat:enterprise_linux:9::*"])
    f = feed.Feed(path)
    yield f
    f.close()


def make_inventory(system, os_id, version_id, packages, host="h1"):
    return Inventory(system=system, os=OsInfo(id=os_id, version_id=version_id, pretty_name=f"{os_id} {version_id}"),
                     packages=[Package(*p) for p in packages], hostname=host, fqdn=host, ips=["10.1.2.3"],
                     collected_at="2026-10-13T06:00:00Z")
