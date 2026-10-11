"""Milestone 7: backups that restore, upgrades that take a backup first."""

from __future__ import annotations

import io
import json
import sqlite3
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from sutra.app import backup, cli, migrate
from sutra.app.config import Settings
from sutra.app.models import AuditEvent, Role, User

PW = "correct horse battery staple"


def make_install(tmp_path, name="ws") -> Settings:
    ws = tmp_path / name
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    cli.demo_users(settings, "power", months=1)
    ev = ws / "evidence" / "ab"
    ev.mkdir(parents=True)
    (ev / "abcdef").write_bytes(b"proof that a finding closed" * 1000)
    (ws / "staging").mkdir()
    (ws / "staging" / "half-uploaded.csv").write_text("x")
    return settings


def counts(url: str) -> dict:
    engine = create_engine(url)
    with Session(engine) as db:
        out = {"users": db.scalar(select(func.count(User.id))),
               "roles": db.scalar(select(func.count()).select_from(Role)),
               "audit": db.scalar(select(func.count(AuditEvent.id)))}
    engine.dispose()
    return out


def clock(y=2027, m=1, d=2, h=3):
    return lambda: datetime(y, m, d, h, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def install(tmp_path_factory):
    return make_install(tmp_path_factory.mktemp("src"))


def test_roundtrip_plain_and_encrypted(install, tmp_path):
    for passphrase in (None, PW):
        out = backup.create(install.workspace, install.database_url, tmp_path / f"b{bool(passphrase)}", passphrase)
        assert out.stat().st_mode & 0o077 == 0
        assert backup.is_encrypted(out) == bool(passphrase)
        m = backup.verify(out, passphrase)
        paths = {e["path"] for e in m["files"]}
        assert "db/sutra.db" in paths and "files/evidence/ab/abcdef" in paths and "files/.secret_key" in paths
        assert not any("staging" in p or p.endswith("-wal") for p in paths), "scratch and WAL files are not backed up"
        assert m["schema_revision"] == backup.head_revision()

        ws2 = tmp_path / f"restored{bool(passphrase)}"
        url2 = f"sqlite:///{ws2 / 'sutra.db'}"
        backup.restore(out, ws2, url2, passphrase)
        assert counts(url2) == counts(install.database_url)
        proof = "evidence/ab/abcdef"
        assert (ws2 / proof).read_bytes() == (install.workspace / proof).read_bytes()
        assert (ws2 / ".secret_key").read_text() == (install.workspace / ".secret_key").read_text()
        assert not list(ws2.glob(".restore-*")), "scratch folder is removed"


def test_backup_taken_while_the_server_writes_is_consistent(install, tmp_path):
    con = sqlite3.connect(install.workspace / "sutra.db", isolation_level=None)
    con.execute("BEGIN IMMEDIATE")  # a writer holds the lock, as a running server may
    con.execute("insert into audit_events (action, target_type, target_id, detail, ip, actor_email, at) "
                "values ('test.uncommitted','','', '{}','', '', '2027-01-01')")
    try:
        out = backup.create(install.workspace, install.database_url, tmp_path / "b")
    finally:
        con.execute("ROLLBACK")
        con.close()
    ws2 = tmp_path / "r"
    backup.restore(out, ws2, f"sqlite:///{ws2 / 'sutra.db'}")
    c = sqlite3.connect(ws2 / "sutra.db")
    assert c.execute("select count(*) from audit_events where action='test.uncommitted'").fetchone()[0] == 0
    assert c.execute("pragma integrity_check").fetchone()[0] == "ok"


def test_encryption_failures(install, tmp_path):
    out = backup.create(install.workspace, install.database_url, tmp_path / "b", PW)
    with pytest.raises(backup.BackupError, match="passphrase"):
        backup.verify(out, None)
    with pytest.raises(backup.BackupError, match="Wrong passphrase"):
        backup.verify(out, "not it")
    raw = bytearray(out.read_bytes())
    raw[len(raw) // 2] ^= 1
    flipped = tmp_path / "flipped.tar.gz.enc"
    flipped.write_bytes(bytes(raw))
    with pytest.raises(backup.BackupError, match="Wrong passphrase|changed"):
        backup.verify(flipped, PW)
    cut = tmp_path / "cut.tar.gz.enc"
    data = out.read_bytes()
    cut.write_bytes(data[: len(data) - 40])
    with pytest.raises(backup.BackupError):
        backup.verify(cut, PW)
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"not a tar at all")
    with pytest.raises(backup.BackupError, match="damaged|not a Sutra"):
        backup.verify(junk)


def test_large_files_cross_chunk_boundaries(tmp_path):
    src, enc, back = tmp_path / "a", tmp_path / "a.enc", tmp_path / "a.out"
    src.write_bytes(bytes(range(256)) * (backup.CHUNK // 256 * 2 + 5))  # 2 MiB and a bit: three chunks
    backup.encrypt_file(src, enc, PW)
    backup.decrypt_file(enc, back, PW)
    assert back.read_bytes() == src.read_bytes()
    empty = tmp_path / "e"
    empty.write_bytes(b"")
    backup.encrypt_file(empty, tmp_path / "e.enc", PW)
    backup.decrypt_file(tmp_path / "e.enc", tmp_path / "e.out", PW)
    assert (tmp_path / "e.out").read_bytes() == b""


def rebuild(archive: Path, mutate) -> Path:
    """Unpack, let ``mutate(members: dict[name, bytes])`` change the contents, and write a new archive."""
    members: dict[str, bytes] = {}
    with tarfile.open(archive) as t:
        for m in t.getmembers():
            members[m.name] = t.extractfile(m).read()
    mutate(members)
    out = archive.with_name("rebuilt.tar.gz")
    with tarfile.open(out, "w:gz") as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return out


def test_tampered_or_unsafe_archives_are_refused(install, tmp_path):
    out = backup.create(install.workspace, install.database_url, tmp_path / "b")

    def change_file(m):
        m["files/evidence/ab/abcdef"] = b"swapped evidence"
    with pytest.raises(backup.BackupError, match="checksum"):
        backup.verify(rebuild(out, change_file))

    def extra(m):
        m["files/unlisted.txt"] = b"x"
    with pytest.raises(backup.BackupError, match="not in its manifest"):
        backup.verify(rebuild(out, extra))

    def traversal(m):
        m["../../etc/evil"] = b"x"
    with pytest.raises(backup.BackupError, match="unsafe entry"):
        backup.verify(rebuild(out, traversal))

    def no_manifest(m):
        del m["manifest.json"]
    with pytest.raises(backup.BackupError, match="no manifest"):
        backup.verify(rebuild(out, no_manifest))


def test_restore_protects_what_is_there(install, tmp_path):
    out = backup.create(install.workspace, install.database_url, tmp_path / "b")
    target = make_install(tmp_path, "target")
    url = target.database_url
    before = counts(url)
    with pytest.raises(backup.BackupError, match="--force"):
        backup.restore(out, target.workspace, url)
    assert counts(url) == before, "a refused restore changes nothing"

    held = sqlite3.connect(target.workspace / "sutra.db", isolation_level=None)
    held.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(backup.BackupError, match="running"):
            backup.restore(out, target.workspace, url, force=True)
    finally:
        held.execute("ROLLBACK")
        held.close()

    result = backup.restore(out, target.workspace, url, force=True, now=clock())
    aside = Path(result["moved_aside"])
    assert aside.name == "pre-restore-20270102T030000Z" and (aside / "sutra.db").exists()
    assert counts(url) == counts(install.database_url)


def test_a_backup_from_a_newer_schema_is_refused(install, tmp_path):
    out = backup.create(install.workspace, install.database_url, tmp_path / "b")

    def newer(m):
        mf = json.loads(m["manifest.json"])
        mf["schema_revision"] = "ffffffffffff"
        m["manifest.json"] = json.dumps(mf).encode()
    with pytest.raises(backup.BackupError, match="newer or unknown schema"):
        backup.restore(rebuild(out, newer), tmp_path / "w", f"sqlite:///{tmp_path / 'w' / 'sutra.db'}")


def test_an_older_backup_is_migrated_forward_on_restore(tmp_path):
    script = ScriptDirectory.from_config(migrate.config("sqlite://"))
    revs = [r.revision for r in script.walk_revisions()]  # newest first
    assert len(revs) >= 3
    old_ws = tmp_path / "old"
    old_ws.mkdir()
    url = f"sqlite:///{old_ws / 'sutra.db'}"
    migrate.upgrade(url, revs[2])
    assert backup.pending(url) == (revs[2], revs[0])
    out = backup.create(old_ws, url, tmp_path / "b")
    ws2 = tmp_path / "new"
    url2 = f"sqlite:///{ws2 / 'sutra.db'}"
    assert backup.verify(out)["schema_revision"] == revs[2]
    backup.restore(out, ws2, url2)
    assert backup.pending(url2) == (revs[0], revs[0])


def test_retention_keeps_the_newest(install, tmp_path):
    d = tmp_path / "b"
    for h in (1, 2, 3, 4):
        backup.create(install.workspace, install.database_url, d, keep=2, now=clock(h=h))
    names = [p.name for p in backup.list_backups(d)]
    assert names == ["sutra-backup-20270102T040000Z.tar.gz", "sutra-backup-20270102T030000Z.tar.gz"]
    with pytest.raises(backup.BackupError, match="already exists"):
        backup.create(install.workspace, install.database_url, d, now=clock(h=4))


def test_postgres_is_not_pretended(tmp_path):
    with pytest.raises(backup.BackupError, match="pg_dump"):
        backup.create(tmp_path, "postgresql+psycopg://u:p@h/db", tmp_path / "b")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "evidence").mkdir()
    (ws / "evidence" / "f").write_text("x")
    out = backup.create(ws, "postgresql+psycopg://u:p@h/db", tmp_path / "b", files_only=True)
    m = backup.verify(out)
    assert m["database"] is None and [e["path"] for e in m["files"]] == ["files/evidence/f"]


# ---------------------------------------------------------------- command line
def args(**kw):
    return SimpleNamespace(**kw)


def test_cli_backup_verify_list_restore(install, tmp_path, capsys, monkeypatch):
    pwfile = tmp_path / "pw"
    pwfile.write_text(PW + "\n")
    out = tmp_path / "b"
    cli.backup_command(args(bcmd="create", workspace=install.workspace, passphrase_file=pwfile, out=out, keep=None,
                            files_only=False))
    printed = capsys.readouterr().out
    assert "encrypted" in printed and "NOT" not in printed
    (archive,) = backup.list_backups(out)
    cli.backup_command(args(bcmd="verify", workspace=install.workspace, passphrase_file=pwfile, archive=archive))
    assert "files match their checksums" in capsys.readouterr().out
    cli.backup_command(args(bcmd="list", workspace=install.workspace, out=out))
    assert archive.name in capsys.readouterr().out
    monkeypatch.delenv("SUTRA_DATABASE_URL", raising=False)
    dest = tmp_path / "dest"
    cli.backup_command(args(bcmd="restore", workspace=dest, passphrase_file=pwfile, archive=archive, force=False))
    assert "Restored" in capsys.readouterr().out and (dest / "sutra.db").exists()
    with pytest.raises(SystemExit, match="Backup error"):
        cli.backup_command(args(bcmd="verify", workspace=dest, passphrase_file=None, archive=archive))
    cli.backup_command(args(bcmd="create", workspace=install.workspace, passphrase_file=None, out=tmp_path / "plain",
                            keep=None, files_only=False))
    assert "NOT encrypted" in capsys.readouterr().out


def test_upgrade_backs_up_first_then_migrates(tmp_path, capsys, monkeypatch):
    revs = [r.revision for r in ScriptDirectory.from_config(migrate.config("sqlite://")).walk_revisions()]
    ws = tmp_path / "ws"
    ws.mkdir()
    url = f"sqlite:///{ws / 'sutra.db'}"
    migrate.upgrade(url, revs[1])
    monkeypatch.setenv("SUTRA_DATABASE_URL", url)
    with pytest.raises(SystemExit) as e:
        cli.upgrade_command(args(workspace=ws, check=True, no_backup=False, db_backed_up=False, passphrase_file=None))
    assert e.value.code == 1 and "->" in capsys.readouterr().out
    cli.upgrade_command(args(workspace=ws, check=False, no_backup=False, db_backed_up=False, passphrase_file=None))
    out = capsys.readouterr().out
    assert "Backup before upgrading" in out and "Upgraded" in out
    assert backup.pending(url) == (revs[0], revs[0]) and len(backup.list_backups(ws / "backups")) == 1
    cli.upgrade_command(args(workspace=ws, check=False, no_backup=False, db_backed_up=False, passphrase_file=None))
    assert "Already up to date" in capsys.readouterr().out


def test_failed_upgrade_says_how_to_go_back(tmp_path, monkeypatch):
    revs = [r.revision for r in ScriptDirectory.from_config(migrate.config("sqlite://")).walk_revisions()]
    ws = tmp_path / "ws"
    ws.mkdir()
    url = f"sqlite:///{ws / 'sutra.db'}"
    migrate.upgrade(url, revs[1])
    monkeypatch.setenv("SUTRA_DATABASE_URL", url)

    def boom(_url, revision="head"):
        raise RuntimeError("disk full")
    monkeypatch.setattr(migrate, "upgrade", boom)
    with pytest.raises(SystemExit, match="Upgrade failed: disk full\nRestore with: python -m sutra backup restore"):
        cli.upgrade_command(args(workspace=ws, check=False, no_backup=False, db_backed_up=False, passphrase_file=None))
    (archive,) = backup.list_backups(ws / "backups")
    backup.verify(archive)


def test_upgrade_on_postgres_demands_a_dump(tmp_path, monkeypatch):
    monkeypatch.setenv("SUTRA_DATABASE_URL", "postgresql+psycopg://u:p@h/db")
    monkeypatch.setattr(backup, "pending", lambda url: ("aaa", "bbb"))
    with pytest.raises(SystemExit, match="pg_dump"):
        cli.upgrade_command(args(workspace=tmp_path, check=False, no_backup=False, db_backed_up=False,
                                 passphrase_file=None))
