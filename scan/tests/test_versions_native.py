"""Cross-check the comparators against the real package tools when they are installed (always true in the CI
container job; elsewhere the test is skipped)."""

import random
import shutil
import subprocess

import pytest

from sutra_scan.versions import apk_compare, dpkg_compare, rpm_compare

ALPHABET_DEB = "0123456789" * 3 + "abcXYZ" + ".+-~:"
ALPHABET_RPM = "0123456789" * 3 + "abcXYZ" + ".+-~^_"
ALPHABET_APK = "0123456789" * 3 + "abc."


def _rand(rng, alphabet, n=9):
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, n)))


@pytest.mark.skipif(not shutil.which("dpkg"), reason="dpkg not installed")
def test_dpkg_matches_native():
    rng = random.Random(7)
    checked = 0
    for _ in range(3000):
        a, b = "1" + _rand(rng, ALPHABET_DEB), "1" + _rand(rng, ALPHABET_DEB)
        probe = subprocess.run(["dpkg", "--compare-versions", a, "lt", b], capture_output=True)  # noqa: S603, S607
        if probe.returncode > 1 or b"error" in probe.stderr.lower():
            continue  # dpkg refuses the string as not a valid version
        lt = probe.returncode == 0
        eq = subprocess.run(["dpkg", "--compare-versions", a, "eq", b], capture_output=True).returncode == 0  # noqa: S603, S607
        want = -1 if lt else 0 if eq else 1
        assert dpkg_compare(a, b) == want, (a, b)
        checked += 1
    assert checked > 500


@pytest.mark.skipif(not shutil.which("rpm"), reason="rpm not installed")
def test_rpm_matches_native():
    rng = random.Random(11)
    for _ in range(500):
        a, b = _rand(rng, ALPHABET_RPM), _rand(rng, ALPHABET_RPM)
        expr = f"%{{lua:print(rpm.vercmp('{a}', '{b}'))}}"
        out = subprocess.run(["rpm", "--eval", expr], capture_output=True, text=True).stdout.strip()  # noqa: S603, S607
        assert rpm_compare(a, b) == int(out), (a, b)


@pytest.mark.skipif(not shutil.which("apk"), reason="apk not installed")
def test_apk_matches_native():
    rng = random.Random(13)
    for _ in range(500):
        a = _rand(rng, ALPHABET_APK, 6).strip(".") or "1"
        b = _rand(rng, ALPHABET_APK, 6).strip(".") or "1"
        a, b = "1." + a, "1." + b
        out = subprocess.run(["apk", "version", "-t", a, b], capture_output=True, text=True).stdout.strip()  # noqa: S603, S607
        if out not in ("<", ">", "="):
            continue
        assert apk_compare(a, b) == {"<": -1, "=": 0, ">": 1}[out], (a, b)
