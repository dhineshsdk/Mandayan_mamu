"""Version comparison for the three package systems, each a port of the system's own rules.

- **dpkg**: Debian Policy Manual 5.6.12 and ``verrevcmp`` in dpkg's ``lib/dpkg/version.c``. ``epoch:upstream-revision``;
  the revision is whatever follows the last hyphen; ``~`` sorts before everything, even the end of the string.
- **rpm**: ``rpmvercmp`` in rpm's ``rpmio/rpmvercmp.c`` (including ``~`` and ``^``), applied to epoch, version and
  release in turn.
- **apk**: ``apk_version_compare`` in apk-tools ``src/version.c``: dotted numbers, an optional letter, ``_alpha``
  ``_beta`` ``_pre`` ``_rc`` (before the release) and ``_cvs`` ``_svn`` ``_git`` ``_hg`` ``_p`` (after it), then
  ``-r<n>``.

Every function returns -1, 0 or 1. The tests check them against published vectors, and the container job in CI
checks them against the real ``dpkg``, ``rpm`` and ``apk`` binaries.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

# ---------------------------------------------------------------------------------------------- dpkg


def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if not c or c.isdigit():
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i] if i < len(a) else "")
            bc = _dpkg_order(b[j] if j < len(b) else "")
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = (ord(a[i]) > ord(b[j])) - (ord(a[i]) < ord(b[j]))
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, revision = (v.rsplit("-", 1) + [""])[:2] if "-" in v else (v, "")
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


# ---------------------------------------------------------------------------------------------- rpm


def _rpm_segment(s: str, i: int, numeric: bool) -> tuple[str, int]:
    j = i
    while j < len(s) and s[j].isascii() and (s[j].isdigit() if numeric else s[j].isalpha()):
        j += 1
    return s[i:j], j


def _rpm_skip(s: str, i: int) -> int:
    while i < len(s) and not (s[i].isascii() and s[i].isalnum()) and s[i] not in "~^":
        i += 1
    return i


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        i, j = _rpm_skip(a, i), _rpm_skip(b, j)
        ca, cb = a[i] if i < len(a) else "", b[j] if j < len(b) else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (ca and cb):
            break
        num_a = ca.isdigit()
        sa, i = _rpm_segment(a, i, num_a)
        sb, j = _rpm_segment(b, j, num_a)
        if not sb:
            return 1 if num_a else -1
        if num_a:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1
    if i >= len(a) and j >= len(b):
        return 0
    return 1 if i < len(a) else -1


def rpm_split(evr: str) -> tuple[int, str, str]:
    """``[epoch:]version[-release]`` (an empty release means none was given)."""
    evr = evr.strip()
    epoch = 0
    m = re.match(r"^(\d+):(.*)$", evr)
    if m:
        epoch, evr = int(m[1]), m[2]
    version, _, release = evr.rpartition("-") if "-" in evr else (evr, "", "")
    return epoch, version, release


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = rpm_split(a)
    eb, vb, rb = rpm_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = rpmvercmp(va, vb)
    if c or not (ra and rb):  # rpm ignores the release when either side has none
        return c
    return rpmvercmp(ra, rb)


# ---------------------------------------------------------------------------------------------- apk

_APK_PRE = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1}
_APK_POST = {"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
_APK_SUFFIX = {**_APK_PRE, **_APK_POST}
_APK = re.compile(
    r"^(?P<num>\d+(?:\.\d+)*)(?P<letter>[a-z])?(?P<suffixes>(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)"
    r"(?:~(?P<hash>[0-9a-f]+))?(?:-r(?P<rev>\d+))?$")


def _apk_parse(v: str):
    m = _APK.match(v.strip())
    if not m:
        raise ValueError(f"not an apk version: {v!r}")
    suffixes = [(_APK_SUFFIX[s], int(n or 0)) for s, n in re.findall(r"_([a-z]+)(\d*)", m["suffixes"] or "")]
    return m["num"].split("."), m["letter"] or "", suffixes, int(m["rev"] or 0)


def _apk_numbers(a: list[str], b: list[str]) -> int:
    for k in range(max(len(a), len(b))):
        if k >= len(a):
            return -1
        if k >= len(b):
            return 1
        x, y = a[k], b[k]
        if k > 0 and (x.startswith("0") or y.startswith("0")):  # apk compares such parts as decimal fractions
            c = (x > y) - (x < y)
        else:
            c = (int(x) > int(y)) - (int(x) < int(y))
        if c:
            return c
    return 0


def apk_compare(a: str, b: str) -> int:
    na, la, sa, ra = _apk_parse(a)
    nb, lb, sb, rb = _apk_parse(b)
    c = _apk_numbers(na, nb) or (la > lb) - (la < lb)
    if c:
        return c
    for k in range(max(len(sa), len(sb))):
        xa = sa[k] if k < len(sa) else (0, 0)
        xb = sb[k] if k < len(sb) else (0, 0)
        if xa != xb:
            return -1 if xa < xb else 1
    return (ra > rb) - (ra < rb)


# ---------------------------------------------------------------------------------------------- dispatch

COMPARE = {"dpkg": dpkg_compare, "rpm": rpm_compare, "apk": apk_compare}


def compare(system: str, a: str, b: str) -> int:
    return COMPARE[system](a, b)


def sort_key(system: str):
    return cmp_to_key(COMPARE[system])
