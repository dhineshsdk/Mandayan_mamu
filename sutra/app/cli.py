"""Operator commands: database upgrade, first admin account, demo accounts, and the web server."""

from __future__ import annotations

import getpass
import os
import re
import secrets
import sys
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select

from .. import synth
from . import migrate
from .analysis import AnalysisStore
from .catalog import sync_catalog
from .config import Settings
from .db import make_engine, make_sessionmaker
from .models import OwnershipTeam, User, UserRole, utcnow
from .security import audit, hash_password, password_problem


def _db(settings: Settings):
    migrate.upgrade(settings.database_url)
    engine = make_engine(settings.database_url)
    sm = make_sessionmaker(engine)
    with sm() as db:
        sync_catalog(db)
    return engine, sm


def db_upgrade(settings: Settings) -> None:
    migrate.upgrade(settings.database_url)
    print(f"Database is up to date: {settings.database_url.split('@')[-1]}")


def create_admin(settings: Settings, email: str, name: str, password: str | None = None) -> None:
    engine, sm = _db(settings)
    email = email.strip().lower()
    if password is None:
        password = getpass.getpass("Password for the new admin: ")
        if getpass.getpass("Again: ") != password:
            sys.exit("Passwords do not match.")
    problem = password_problem(password, settings.min_password_length)
    if problem:
        sys.exit(problem)
    with sm() as db:
        if db.scalars(select(User).where(func.lower(User.email) == email)).first():
            sys.exit(f"{email} already exists.")
        user = User(email=email, display_name=name, password_hash=hash_password(password))
        user.roles = [UserRole(role_key="admin", scope_type="org", scope_value="")]
        db.add(user)
        db.flush()
        audit(db, "admin.user_created", None, "user", user.id, "cli", email=email, roles=["admin"])
        db.commit()
    engine.dispose()
    print(f"Created admin {email}. Sign in and create the other accounts from Administration.")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", ".", text.lower()).strip(".")


def demo_users(settings: Settings, profile: str, months: int = 1) -> list[tuple[str, str, str]]:
    """Load a synthetic demo company and create one account per role on its ownership chart.

    ``months`` imports are loaded, 30 days apart, so history and "fixed since last import" have data.
    Every password is random and printed once. These accounts are for the SYNTHETIC demo data only.
    """
    from types import SimpleNamespace

    from .routes.data import load_demo

    engine, sm = _db(settings)
    app = SimpleNamespace(state=SimpleNamespace(settings=settings, analysis=AnalysisStore()))
    dom = synth.PROFILES[profile]["domain"]
    made: list[tuple[str, str, str]] = []
    with sm() as db:
        for month in range(max(1, months)):
            load_demo(app, db, profile, None, month)
        res = app.state.analysis.result
        chart = list(db.scalars(select(OwnershipTeam)))
        people: dict[str, dict] = {}

        def person(email: str, name: str, role: str, scope_type: str = "org", scope_value: str = "",
                   expires_days: int | None = None):
            p = people.setdefault(email, {"name": name, "roles": [], "expires": None})
            p["roles"].append((role, scope_type, scope_value))
            if expires_days:
                p["expires"] = utcnow() + timedelta(days=expires_days)

        for t in chart:
            person(t.manager_email, t.manager_name, "team_manager", "team", t.team)
            local = _slug(t.team) if _slug(t.team).endswith("team") else _slug(t.team) + ".team"
            person(f"{local}@{dom}", f"{t.team} engineer (demo account)", "team_member", "team", t.team)
            person(t.vertical_head_email, t.vertical_head_name, "vertical_head", "vertical", t.vertical)
            person(t.vm_analyst_email, t.vm_analyst_name, "vm_analyst")
        for site in sorted({a.site for a in res.assets.values() if a.is_ot and a.site}):
            person(f"plant.engineer.{_slug(site)}@{dom}", f"Plant engineer, {site} (demo account)", "plant_engineer",
                   "site", site)
        person(f"ciso@{dom}", "CISO (demo account)", "ciso")
        person(f"compliance@{dom}", "Compliance officer (demo account)", "compliance_officer")
        person(f"executive@{dom}", "Executive (demo account)", "executive")
        person(f"auditor@{dom}", "External auditor (demo account)", "auditor", expires_days=30)
        person(f"admin@{dom}", "Administrator (demo account)", "admin")

        for email, p in people.items():
            user = db.scalars(select(User).where(func.lower(User.email) == email)).first()
            password = secrets.token_urlsafe(12)
            if user is None:
                user = User(email=email, display_name=p["name"])
                db.add(user)
            user.password_hash, user.must_change_password, user.is_active = hash_password(password), False, True
            user.expires_at, user.locked_until, user.failed_logins = p["expires"], None, 0
            user.roles.clear()
            db.flush()
            user.roles = [UserRole(role_key=r, scope_type=st, scope_value=sv)
                          for r, st, sv in dict.fromkeys(p["roles"])]
            db.flush()
            audit(db, "admin.demo_user", None, "user", user.id, "cli", email=email, roles=[r for r, _, _ in p["roles"]])
            made.append((email, password, ", ".join(sorted({r for r, _, _ in p["roles"]}))))
        db.commit()
    engine.dispose()
    return made


def serve(settings: Settings, host: str, port: int) -> None:
    import uvicorn

    from .main import create_app

    if not settings.cookie_secure and host not in ("127.0.0.1", "localhost", "::1"):
        print("Warning: cookies are not marked Secure. Serve over HTTPS and unset SUTRA_COOKIE_SECURE=0.",
              file=sys.stderr)
    uvicorn.run(create_app(settings), host=host, port=port, proxy_headers=True, server_header=False)


def licence_command(args) -> None:
    import os
    from datetime import date

    from . import licence
    from .config import Settings

    def text(value: str) -> str:
        return open(value[1:], encoding="utf-8").read() if value.startswith("@") else value

    try:
        if args.lcmd == "keygen":
            private, public = licence.generate_keypair()
            args.out.mkdir(parents=True, exist_ok=True)
            priv_path, pub_path = args.out / "sutra-licence-private.pem", args.out / "sutra-licence-public.pem"
            if priv_path.exists() or pub_path.exists():
                sys.exit(f"{priv_path} or {pub_path} already exists; refusing to overwrite a signing key.")
            fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(private)
            pub_path.write_bytes(public)
            print(f"Private key: {priv_path}  (keep offline; anyone with it can issue licences)")
            print(f"Public key:  {pub_path}  (copy to sutra/data/licence_public.pem before building a release)")
        elif args.lcmd == "issue":
            try:
                expires = date.fromisoformat(args.expires)
            except ValueError:
                sys.exit("--expires must be a date like 2027-03-31.")
            modules = [m.strip() for m in args.modules.split(",") if m.strip()]
            print(licence.issue(args.private_key.read_bytes(), args.customer, modules, expires, args.id))
        elif args.lcmd == "show":
            pub = licence.load_public_key(args.public_key)
            if pub is None:
                sys.exit("No vendor public key found. Pass --public-key or set SUTRA_LICENCE_PUBLIC_KEY.")
            lic = licence.verify(text(args.key), pub)
            print(f"Valid signature. Customer {lic.customer}, id {lic.id}, issued {lic.issued}, expires {lic.expires}")
            print("Modules:", ", ".join(lic.modules))
        else:
            settings = Settings(workspace=args.workspace) if args.workspace else Settings()
            engine, sm = _db(settings)
            svc = licence.LicenceService(settings.require_licence)
            with sm() as db:
                ent = svc.install(db, text(args.key), None)
                lic = ent.licence
                audit(db, "admin.licence_installed", None, "licence", lic.id, "cli", customer=lic.customer,
                      expires=lic.expires.isoformat(), modules=list(lic.modules))
                db.commit()
            engine.dispose()
            print(ent.message)
    except licence.LicenceError as e:
        sys.exit(f"Licence error: {e}")


def _paths(workspace_arg) -> tuple[Path, str]:
    """Workspace folder and database URL, read the way Settings does but without creating anything."""
    ws = Path(workspace_arg or os.environ.get("SUTRA_WORKSPACE", "workspace"))
    return ws, os.environ.get("SUTRA_DATABASE_URL") or f"sqlite:///{ws / 'sutra.db'}"


def _passphrase(args) -> str | None:
    if getattr(args, "passphrase_file", None):
        text = args.passphrase_file.read_text(encoding="utf-8").strip()
        if not text:
            sys.exit(f"{args.passphrase_file} is empty.")
        return text
    return os.environ.get("SUTRA_BACKUP_PASSPHRASE") or None


def backup_command(args) -> None:
    from . import backup

    ws, url = _paths(args.workspace)
    try:
        if args.bcmd == "create":
            pw = _passphrase(args)
            out = backup.create(ws, url, args.out or ws / "backups", pw, args.files_only, args.keep)
            print(f"Wrote {out} ({out.stat().st_size:,} bytes, {'encrypted' if pw else 'NOT encrypted'}).")
            if not pw:
                print("This file holds the database, evidence and the server's secret key. Protect it, or set a "
                      "passphrase (--passphrase-file / SUTRA_BACKUP_PASSPHRASE).")
        elif args.bcmd == "verify":
            m = backup.verify(args.archive, _passphrase(args))
            print(f"OK: {len(m['files'])} files match their checksums. Made {m['created']} by Sutra "
                  f"{m['sutra_version']}, schema {m['schema_revision'] or 'n/a'}.")
        elif args.bcmd == "list":
            found = backup.list_backups(args.out or ws / "backups")
            for p in found:
                print(f"{p.name}  {p.stat().st_size:>14,}")
            if not found:
                print("No backups there.")
        else:
            m = backup.restore(args.archive, ws, url, _passphrase(args), args.force)
            print(f"Restored the backup made {m['created']} into {ws}; the database is at the current schema.")
            if m["moved_aside"]:
                print(f"What was there before is in {m['moved_aside']}.")
    except backup.BackupError as e:
        sys.exit(f"Backup error: {e}")


def upgrade_command(args) -> None:
    from . import backup, migrate

    ws, url = _paths(args.workspace)
    current, head = backup.pending(url)
    if current == head:
        print(f"Already up to date (schema {head}).")
        return
    print(f"Schema {current or 'none (new install)'} -> {head}.")
    if args.check:
        sys.exit(1)  # non-zero: a migration is pending, useful in scripts
    made = None
    if current and not args.no_backup:
        sqlite = backup.sqlite_path(url) is not None
        if not sqlite and not args.db_backed_up:
            sys.exit("PostgreSQL: take a pg_dump first, then run again with --db-backed-up.")
        try:
            made = backup.create(ws, url, ws / "backups", _passphrase(args), files_only=not sqlite)
        except backup.BackupError as e:
            sys.exit(f"Could not take the pre-upgrade backup, so nothing was changed: {e}")
        print(f"Backup before upgrading: {made}")
    try:
        migrate.upgrade(url)
        after, _ = backup.pending(url)
        if after != head:
            raise RuntimeError(f"the database is at {after or 'no revision'} after migrating, expected {head}")
    except Exception as e:  # noqa: BLE001 - whatever failed, the operator needs the way back
        hint = (f"Restore with: python -m sutra backup restore {made} --force" if made else
                "No automatic backup was taken; restore from your own backup.")
        sys.exit(f"Upgrade failed: {e}\n{hint}")
    print("Upgraded. Start the service again.")


def doctor_command(args) -> None:
    import json

    from . import doctor

    checks = doctor.run(workspace=args.workspace)
    if args.json:
        print(json.dumps([c.__dict__ for c in checks], indent=1))
    else:
        print(doctor.render(checks))
    if any(c.level == "FAIL" for c in checks):
        sys.exit(1)
