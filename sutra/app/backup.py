"""Backup, verify and restore of one Sutra installation (the SQLite database and the workspace files).

A backup is one ``.tar.gz`` with a ``manifest.json`` (SHA-256 of every file, the schema revision, the Sutra version).
With a passphrase it is also encrypted (AES-256-GCM in 1 MiB chunks, key from scrypt), because the archive holds the
database, evidence files and the server's secret key. The passphrase is never stored; lose it and the backup cannot be
read.

* SQLite is copied with SQLite's online backup API, so the server may keep running while a backup is taken.
* PostgreSQL is not handled here: back the database up with ``pg_dump`` (see docs/operations.md) and use
  ``--files-only`` for the workspace.
* Restore checks every hash before touching the workspace, refuses a running server or a newer schema than this
  release knows, moves what it replaces into ``pre-restore-<time>/`` instead of deleting it, then migrates to head.
* ``SUTRA_SECRET_KEY``, if the secret is supplied by the environment rather than the workspace, is NOT in the archive.
  Stored scanner credentials need it; without it they must be entered again.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import struct
import tarfile
import tempfile
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import create_engine, text

from . import migrate

FORMAT = 1
MAGIC = b"SUTRABK1"
CHUNK = 1024 * 1024
SKIP_DIRS = {"staging", "backups"}
DB_NAMES = ("sutra.db", "sutra.db-wal", "sutra.db-shm")
PREFIX = "sutra-backup-"


class BackupError(Exception):
    """A backup or restore could not be done safely. The message says what to do."""


# ---------------------------------------------------------------- encryption
def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def encrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    salt, prefix = os.urandom(16), os.urandom(8)
    aes = AESGCM(_key(passphrase, salt))
    with src.open("rb") as r, dst.open("wb") as w:
        w.write(MAGIC + salt + prefix)
        n, block = 0, r.read(CHUNK)
        while True:
            nxt = r.read(CHUNK)
            ct = aes.encrypt(prefix + struct.pack(">I", n), block, b"last" if not nxt else b"more")
            w.write(struct.pack(">I", len(ct)) + ct)
            if not nxt:
                break
            block, n = nxt, n + 1


def is_encrypted(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(len(MAGIC)) == MAGIC


def decrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    with src.open("rb") as r, dst.open("wb") as w:
        head = r.read(len(MAGIC) + 24)
        if len(head) < len(MAGIC) + 24 or head[:8] != MAGIC:
            raise BackupError("This file is not an encrypted Sutra backup.")
        aes = AESGCM(_key(passphrase, head[8:24]))
        prefix, n, last = head[24:32], 0, False
        size_raw = r.read(4)
        while size_raw:
            if len(size_raw) < 4:
                raise BackupError("The backup file is damaged (cut short).")
            ct = r.read(struct.unpack(">I", size_raw)[0])
            size_raw = r.read(4)
            last = not size_raw
            try:
                w.write(aes.decrypt(prefix + struct.pack(">I", n), ct, b"last" if last else b"more"))
            except InvalidTag as e:
                raise BackupError("Wrong passphrase, or the backup file was changed or cut short.") from e
            n += 1
        if n == 0 or not last:
            raise BackupError("The backup file is damaged or incomplete.")


# ---------------------------------------------------------------- helpers
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def sqlite_path(database_url: str) -> Path | None:
    if not database_url.startswith("sqlite"):
        return None
    raw = database_url.split("///", 1)[-1]
    return Path(raw) if raw and raw != ":memory:" else None


def schema_revision(db_file: Path) -> str:
    con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    try:
        row = con.execute("select version_num from alembic_version").fetchone()
    except sqlite3.DatabaseError:
        row = None
    finally:
        con.close()
    return row[0] if row else ""


def head_revision() -> str:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(migrate.config("sqlite://")).get_current_head() or ""


def _workspace_files(ws: Path) -> Iterator[Path]:
    for p in sorted(ws.rglob("*")):
        rel = p.relative_to(ws)
        if p.is_symlink() or not p.is_file():
            continue
        if rel.parts[0] in SKIP_DIRS or rel.parts[0].startswith("pre-restore-") or rel.name in DB_NAMES:
            continue
        if rel.name.endswith(".tmp") or rel.parts[0] == "evidence" and ".incoming" in rel.parts:
            continue
        yield p


# ---------------------------------------------------------------- create
def create(workspace: Path, database_url: str, out_dir: Path, passphrase: str | None = None, files_only: bool = False,
           keep: int | None = None, now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> Path:
    workspace, out_dir = Path(workspace), Path(out_dir)
    db_file = sqlite_path(database_url)
    if db_file is None and not files_only:
        raise BackupError("This installation uses PostgreSQL. Back the database up with pg_dump (docs/operations.md) "
                          "and run this with --files-only for the workspace files.")
    if db_file is not None and not files_only and not db_file.exists():
        raise BackupError(f"No database at {db_file}. Is this the right workspace?")
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    stamp = now().strftime("%Y%m%dT%H%M%SZ")
    final = out_dir / f"{PREFIX}{stamp}.tar.gz{'.enc' if passphrase else ''}"
    if final.exists():
        raise BackupError(f"{final} already exists.")
    with tempfile.TemporaryDirectory(dir=out_dir, prefix=".work-") as tmp_s:
        tmp = Path(tmp_s)
        entries: list[dict] = []
        manifest = {"format": FORMAT, "created": now().isoformat(timespec="seconds"),
                    "sutra_version": version("sutra"), "schema_revision": "", "database": None, "files": entries}
        tar_path = tmp / "backup.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            if db_file is not None and not files_only:
                snap = tmp / "sutra.db"
                src = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
                dst = sqlite3.connect(snap)
                try:
                    src.backup(dst)
                finally:
                    dst.close()
                    src.close()
                manifest["schema_revision"] = schema_revision(snap)
                manifest["database"] = "db/sutra.db"
                entries.append({"path": "db/sutra.db", "size": snap.stat().st_size, "sha256": _sha256(snap)})
                tar.add(snap, arcname="db/sutra.db")
            for p in _workspace_files(workspace):
                arc = "files/" + p.relative_to(workspace).as_posix()
                entries.append({"path": arc, "size": p.stat().st_size, "sha256": _sha256(p)})
                tar.add(p, arcname=arc, recursive=False)
            raw = json.dumps(manifest, indent=1, sort_keys=True).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mtime = len(raw), int(now().timestamp())
            tar.addfile(info, io.BytesIO(raw))
        staged = tmp / "final"
        if passphrase:
            encrypt_file(tar_path, staged, passphrase)
        else:
            shutil.move(tar_path, staged)
        os.chmod(staged, 0o600)
        os.replace(staged, final)
    if keep:
        for old in list_backups(out_dir)[keep:]:
            old.unlink()
    return final


def list_backups(out_dir: Path) -> list[Path]:
    """Newest first."""
    return sorted((p for p in Path(out_dir).glob(f"{PREFIX}*.tar.gz*") if p.suffix in (".gz", ".enc")),
                  key=lambda p: p.name, reverse=True)


# ---------------------------------------------------------------- verify and restore
def _open(archive: Path, passphrase: str | None, tmp: Path) -> Path:
    if not archive.exists():
        raise BackupError(f"{archive} does not exist.")
    if is_encrypted(archive):
        if not passphrase:
            raise BackupError("This backup is encrypted. Give the passphrase (--passphrase-file or "
                              "SUTRA_BACKUP_PASSPHRASE).")
        out = tmp / "plain.tar.gz"
        decrypt_file(archive, out, passphrase)
        return out
    return archive


def _safe_members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = tar.getmembers()
    for m in members:
        p = Path(m.name)
        if p.is_absolute() or ".." in p.parts or not (m.isfile() or m.isdir()):
            raise BackupError(f"The backup contains an unsafe entry ({m.name!r}); it will not be restored.")
    return members


def extract(archive: Path, passphrase: str | None, dest: Path) -> dict:
    """Unpack into ``dest`` after checking every hash. Returns the manifest."""
    with tempfile.TemporaryDirectory(dir=dest.parent) as t:
        plain = _open(archive, passphrase, Path(t))
        try:
            with tarfile.open(plain, "r:gz") as tar:
                members = _safe_members(tar)
                if "manifest.json" not in {m.name for m in members}:
                    raise BackupError("This is not a Sutra backup (no manifest).")
                tar.extractall(dest, members=members, filter="data")  # noqa: S202 - members checked above
        except (tarfile.TarError, EOFError, OSError) as e:
            raise BackupError(f"The backup file is damaged: {e}") from e
    manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("format") != FORMAT:
        raise BackupError(f"Backup format {manifest.get('format')} is not supported by this release.")
    for e in manifest["files"]:
        p = dest / e["path"]
        if not p.is_file() or p.stat().st_size != e["size"] or _sha256(p) != e["sha256"]:
            raise BackupError(f"The backup is damaged: {e['path']} does not match its recorded checksum.")
    listed = {e["path"] for e in manifest["files"]} | {"manifest.json"}
    for p in dest.rglob("*"):
        if p.is_file() and p.relative_to(dest).as_posix() not in listed:
            raise BackupError(f"The backup holds a file that is not in its manifest ({p.relative_to(dest)}).")
    return manifest


def verify(archive: Path, passphrase: str | None = None) -> dict:
    with tempfile.TemporaryDirectory(dir=Path(archive).resolve().parent) as t:
        scratch = Path(t) / "x"
        scratch.mkdir()
        return extract(Path(archive), passphrase, scratch)


def _server_running(db_file: Path) -> bool:
    if not db_file.exists():
        return False
    try:
        con = sqlite3.connect(db_file, timeout=0.2)
        con.execute("BEGIN EXCLUSIVE")
        con.rollback()
        con.close()
        return False
    except sqlite3.OperationalError:
        return True


def restore(archive: Path, workspace: Path, database_url: str, passphrase: str | None = None, force: bool = False,
            now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> dict:
    workspace = Path(workspace)
    db_file = sqlite_path(database_url)
    workspace.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(dir=workspace, prefix=".restore-"))
    try:
        manifest = extract(Path(archive), passphrase, scratch)
        if manifest["database"] and db_file is None:
            raise BackupError("This backup holds a SQLite database but this installation is configured for another "
                              "database. Restore it with SUTRA_DATABASE_URL pointing at SQLite, or use pg_restore.")
        head = head_revision()
        rev = manifest["schema_revision"]
        if rev and rev != head and not _is_ancestor(rev, head):
            raise BackupError(f"This backup is from a newer or unknown schema ({rev}); this release is at {head}. "
                              f"Install the release that made it, or a newer one.")
        if db_file is not None and _server_running(db_file):
            raise BackupError("Sutra is running (the database is in use). Stop the service, then restore.")
        existing = [p for p in [db_file, *(workspace / n for n in DB_NAMES[1:])] if p is not None and p.exists()]
        existing += [p for p in workspace.iterdir() if p.name not in SKIP_DIRS and p.name not in DB_NAMES
                     and not p.name.startswith((".restore-", "pre-restore-"))]
        if existing and not force:
            raise BackupError(f"{workspace} already holds an installation. Add --force to move it aside into "
                              f"pre-restore-<time>/ and restore over it.")
        aside = workspace / f"pre-restore-{now().strftime('%Y%m%dT%H%M%SZ')}"
        if existing:
            aside.mkdir()
            for p in existing:
                shutil.move(p, aside / p.name)
        if manifest["database"] and db_file is not None:
            db_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(scratch / "db" / "sutra.db", db_file)
        src_files = scratch / "files"
        if src_files.exists():
            for p in src_files.iterdir():
                shutil.move(p, workspace / p.name)
        if db_file is not None and manifest["database"]:
            migrate.upgrade(database_url)
        return {**manifest, "moved_aside": str(aside) if existing else ""}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _is_ancestor(rev: str, head: str) -> bool:
    """True when ``rev`` is an older revision on the path to ``head`` (so migrating forward is safe)."""
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(migrate.config("sqlite://"))
    return any(r.revision == rev for r in script.walk_revisions(base="base", head=head))


# ---------------------------------------------------------------- upgrade
def pending(database_url: str) -> tuple[str, str]:
    """(current revision in the database, head revision this release expects)."""
    engine = create_engine(database_url)
    try:
        with engine.connect() as c:
            row = c.execute(text("select version_num from alembic_version")).first()
    except Exception:  # noqa: BLE001 - no table yet: a fresh install
        row = None
    finally:
        engine.dispose()
    return (row[0] if row else ""), head_revision()
