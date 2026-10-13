"""The advisory feed snapshot: OSV records for the distributions Sutra Scan supports, in one SQLite file.

**Source.** OSV (https://osv.dev) republishes each distribution's own security data in one schema: Debian Security
Tracker, Ubuntu Security Notices, Alpine secdb, AlmaLinux errata and Rocky Linux errata. The bulk files are
``https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`` (format: OSV schema 1.x, see
https://ossf.github.io/osv-schema/). Only ``ECOSYSTEM`` ranges are read; ``GIT`` ranges name upstream commits, not
package versions.

**Offline.** Matching reads only the snapshot file. ``build`` makes it from zip files already on disk, so an
air-gapped plant imports a snapshot built elsewhere (``fetch`` is the only step that needs the internet, and the
snapshot file or the zips can cross the gap on removable media). The snapshot records the SHA-256 of every source
file and the newest advisory date inside it, and every finding quotes both.

**Sizes** (measured 2026-10-13): Debian 12 about 43 MB of zip, Ubuntu 22.04 LTS about 150 MB, Alpine 3.19 about 7 MB,
AlmaLinux (all releases) about 7 MB, Rocky Linux (all releases) about 5 MB. A snapshot of one release of each is
well under 100 MB.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import cvss

BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
SCHEMA_VERSION = 1
# One current release of each supported family. Pass your own list to ``build`` and ``fetch`` for others.
# A trailing ``*`` is a prefix: Red Hat publishes one ecosystem per channel (``...:9::baseos``, ``...::appstream``).
DEFAULT_ECOSYSTEMS = ("Debian:12", "Ubuntu:22.04:LTS", "Alpine:v3.19", "AlmaLinux:9", "Rocky Linux:9",
                      "Red Hat:enterprise_linux:9::*")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_VENDOR_RATING = re.compile(r"^\s*(Critical|Important|Moderate|Low)\s*:", re.I)
_VENDOR_SEVERITY = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}
_URGENCY = {"high": "high", "medium": "medium", "low": "low", "unimportant": "low", "end-of-life": "low"}
# AlmaLinux, Rocky Linux and Red Hat publish bug-fix (ALBA, RLBA, RHBA) and enhancement (ALEA, RLEA, RHEA) errata in
# the same feed as security errata (ALSA, RLSA, RXSA, RHSA). Only security errata are vulnerabilities.
_NOT_SECURITY = re.compile(r"^(ALBA|ALEA|RLBA|RLEA|RHBA|RHEA)-")
_UBUNTU_PRIORITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "low"}

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE source (ecosystem TEXT, file TEXT, sha256 TEXT, records INTEGER, bytes INTEGER);
CREATE TABLE advisory (id TEXT PRIMARY KEY, summary TEXT, severity TEXT, rated_by TEXT, cvss REAL, vector TEXT,
                       published TEXT, modified TEXT, cves TEXT);
CREATE TABLE affected (advisory TEXT NOT NULL, ecosystem TEXT NOT NULL, package TEXT NOT NULL,
                       introduced TEXT NOT NULL, fixed TEXT, last_affected TEXT);
CREATE INDEX affected_lookup ON affected (ecosystem, package);
"""


class FeedError(Exception):
    """The snapshot is missing, unreadable, or built by an incompatible version."""


def ecosystem_family(ecosystem: str) -> str:
    return ecosystem.split(":", 1)[0]


def ecosystem_matches(ecosystem: str, wanted: Iterable[str]) -> bool:
    """Exact name, or a ``prefix*`` entry in ``wanted``."""
    return any(ecosystem == w or (w.endswith("*") and ecosystem.startswith(w[:-1])) for w in wanted)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------------------------- reading OSV


def _severity(record: dict, affected: list[dict]) -> tuple[str, str, float | None, str]:
    """(label, how it was rated, score, vector). CVSS v3 first; otherwise what the distribution itself says."""
    for s in record.get("severity", []):
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss.base_score(s.get("score", ""))
            if score is not None:
                return cvss.rating(score) or "low", "cvss", score, s["score"]
    for a in affected:  # Debian carries its own urgency per package
        eco = a.get("ecosystem_specific", {})
        urgency = str(eco.get("urgency", "")).lower()
        if urgency in _URGENCY:
            return _URGENCY[urgency], "distribution urgency", None, ""
        priority = str(eco.get("ubuntu_priority", "")).lower()  # Ubuntu's own priority per CVE
        if priority in _UBUNTU_PRIORITY:
            return _UBUNTU_PRIORITY[priority], "distribution priority", None, ""
    m = _VENDOR_RATING.match(record.get("summary", ""))  # "Important: openssl security update"
    if m:
        return _VENDOR_SEVERITY[m[1].lower()], "distribution rating", None, ""
    return "medium", "unrated", None, ""  # kept visible rather than dropped


def _intervals(rng: dict) -> Iterator[tuple[str, str | None, str | None]]:
    """(introduced, fixed, last_affected) for each introduced..end pair in an ECOSYSTEM range."""
    introduced = None
    for ev in rng.get("events", []):
        if "introduced" in ev:
            if introduced is not None:
                yield introduced, None, None
            introduced = ev["introduced"]
        elif "fixed" in ev and introduced is not None:
            yield introduced, ev["fixed"], None
            introduced = None
        elif "last_affected" in ev and introduced is not None:
            yield introduced, None, ev["last_affected"]
            introduced = None
    if introduced is not None:
        yield introduced, None, None


def _summary(record: dict) -> str:
    text = (record.get("summary") or record.get("details") or "").strip().replace("\n", " ")
    return text if len(text) <= 240 else text[:237].rstrip() + "..."


def _add_record(db: sqlite3.Connection, record: dict, wanted: set[str]) -> bool:
    rows = []
    affected = [a for a in record.get("affected", [])
                if ecosystem_matches(a.get("package", {}).get("ecosystem", ""), wanted)]
    for a in affected:
        pkg = a["package"]
        for rng in a.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            for intro, fixed, last in _intervals(rng):
                rows.append((record["id"], pkg["ecosystem"], pkg["name"], intro, fixed, last))
    if not rows:
        return False
    label, how, score, vector = _severity(record, affected)
    ids = [record["id"], *record.get("aliases", []), *record.get("related", []), *record.get("upstream", [])]
    cves = sorted(set(_CVE.findall(" ".join(ids))))
    db.execute("INSERT OR REPLACE INTO advisory VALUES (?,?,?,?,?,?,?,?,?)",
               (record["id"], _summary(record), label, how, score, vector, record.get("published", ""),
                record.get("modified", ""), json.dumps(cves)))
    db.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?)", rows)
    return True


def iter_records(source: Path) -> Iterator[dict]:
    """OSV records from a ``.zip`` (the bulk files), a directory of ``.json`` files, or one ``.json`` file."""
    if source.is_dir():
        for p in sorted(source.rglob("*.json")):
            yield json.loads(p.read_text(encoding="utf-8"))
    elif source.suffix == ".zip":
        with zipfile.ZipFile(source) as zf:
            for name in zf.namelist():
                if name.endswith(".json"):
                    yield json.loads(zf.read(name))
    else:
        yield json.loads(source.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------------- building


def build(dest: str | Path, sources: Iterable[str | Path], ecosystems: Iterable[str] = DEFAULT_ECOSYSTEMS) -> dict:
    """Build the snapshot at ``dest`` (replaced atomically) from OSV zips, folders or files; returns its info."""
    dest = Path(dest)
    wanted = set(ecosystems)
    tmp = dest.with_name(dest.name + ".building")
    tmp.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    try:
        db.executescript(_SCHEMA)
        seen: dict[str, str] = {}
        newest = ""
        for src in map(Path, sources):
            if not src.exists():
                raise FeedError(f"{src} does not exist")
            kept = 0
            for rec in iter_records(src):
                rid, modified = rec.get("id", ""), rec.get("modified", "")
                if not rid or _NOT_SECURITY.match(rid) or (rid in seen and seen[rid] >= modified):
                    continue  # the same advisory arrives in several per-release files
                if rid in seen:
                    db.execute("DELETE FROM affected WHERE advisory = ?", (rid,))
                if _add_record(db, rec, wanted):
                    seen[rid] = modified
                    kept += 1
                    newest = max(newest, modified)
            files = [src] if src.is_file() else []
            db.execute("INSERT INTO source VALUES (?,?,?,?,?)",
                       ("", src.name, _sha256(src) if files else "(directory)", kept,
                        src.stat().st_size if files else 0))
        have = {r[0] for r in db.execute("SELECT DISTINCT ecosystem FROM affected")}
        missing = sorted(w for w in wanted if not any(ecosystem_matches(h, [w]) for h in have))
        meta = {"schema": str(SCHEMA_VERSION), "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "data_as_of": newest, "ecosystems": json.dumps(sorted(have)),
                "requested_ecosystems": json.dumps(sorted(wanted)), "origin": "OSV (https://osv.dev)"}
        db.executemany("INSERT INTO meta VALUES (?,?)", meta.items())
        db.commit()
    except BaseException:
        db.close()
        tmp.unlink(missing_ok=True)
        raise
    db.close()
    os.replace(tmp, dest)
    info = Feed(dest).info()
    info["missing_ecosystems"] = missing
    return info


def fetch(dest_dir: str | Path, ecosystems: Iterable[str] = DEFAULT_ECOSYSTEMS, *, timeout: float = 120,
          opener=urllib.request.urlopen) -> list[Path]:
    """Download the bulk zip for each ecosystem. Needs the internet; everything else here works offline.

    A release-specific file (``Debian:12/all.zip``) is used when OSV publishes one, otherwise the whole family file
    (``AlmaLinux/all.zip``), which ``build`` then filters to the requested release."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    for eco in ecosystems:
        for path in (() if "*" in eco else (eco,)) + (ecosystem_family(eco),):
            url = f"{BASE_URL}/{urllib.parse.quote(path)}/all.zip"
            target = dest_dir / (re.sub(r"[^A-Za-z0-9._-]+", "_", path) + ".zip")
            if target in out:
                break
            try:
                with opener(url, timeout=timeout) as resp, target.open("wb") as fh:  # noqa: S310 - fixed https URL
                    while chunk := resp.read(1 << 20):
                        fh.write(chunk)
            except urllib.error.HTTPError as exc:
                target.unlink(missing_ok=True)
                if exc.code == 404 and path == eco and path != ecosystem_family(eco):
                    continue
                raise FeedError(f"{url}: HTTP {exc.code}") from exc
            except OSError as exc:
                target.unlink(missing_ok=True)
                raise FeedError(f"{url}: {exc}") from exc
            out.append(target)
            break
    return out


# ---------------------------------------------------------------------------------------------- reading


@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str
    severity: str
    rated_by: str
    cvss: float | None
    vector: str
    cves: tuple[str, ...]
    published: str


@dataclass(frozen=True)
class Range:
    advisory: str
    ecosystem: str
    package: str
    introduced: str
    fixed: str | None
    last_affected: str | None


class Feed:
    """Read-only access to a snapshot file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_file():
            raise FeedError(f"no advisory snapshot at {self.path}; build one with 'sutra-scan feed build'")
        self._db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        try:
            self._meta = dict(self._db.execute("SELECT key, value FROM meta"))
        except sqlite3.DatabaseError as exc:
            raise FeedError(f"{self.path} is not a Sutra Scan snapshot ({exc})") from exc
        if self._meta.get("schema") != str(SCHEMA_VERSION):
            raise FeedError(f"{self.path} has snapshot schema {self._meta.get('schema')}; "
                            f"this build reads {SCHEMA_VERSION}")

    def close(self) -> None:
        self._db.close()

    def ecosystems(self) -> list[str]:
        return json.loads(self._meta["ecosystems"])

    def info(self) -> dict:
        sources = [{"file": f, "sha256": s, "records": r, "bytes": b}
                   for f, s, r, b in self._db.execute("SELECT file, sha256, records, bytes FROM source ORDER BY file")]
        digest = hashlib.sha256("\n".join(s["sha256"] for s in sources).encode()).hexdigest()
        n_adv = self._db.execute("SELECT COUNT(*) FROM advisory").fetchone()[0]
        return {"built_at": self._meta["built_at"], "data_as_of": self._meta["data_as_of"],
                "ecosystems": self.ecosystems(), "advisories": n_adv, "sources": sources, "digest": digest,
                "origin": self._meta["origin"]}

    def ranges(self, ecosystems: Iterable[str], packages: Iterable[str]) -> Iterator[Range]:
        eco = list(ecosystems)
        names = sorted(set(packages))
        marks = ",".join("?" * len(eco))
        for i in range(0, len(names), 400):
            chunk = names[i:i + 400]
            q = ("SELECT advisory, ecosystem, package, introduced, fixed, last_affected FROM affected "  # noqa: S608
                 f"WHERE ecosystem IN ({marks}) AND package IN ({','.join('?' * len(chunk))})")  # only '?' marks
            for row in self._db.execute(q, [*eco, *chunk]):
                yield Range(*row)

    def advisory(self, advisory_id: str) -> Advisory:
        row = self._db.execute("SELECT id, summary, severity, rated_by, cvss, vector, cves, published FROM advisory "
                               "WHERE id = ?", (advisory_id,)).fetchone()
        if row is None:
            raise FeedError(f"advisory {advisory_id} is not in the snapshot")
        return Advisory(row[0], row[1], row[2], row[3], row[4], row[5], tuple(json.loads(row[6])), row[7])
