"""``python -m sutra doctor``: reads an installation (read-only) and reports what is unsafe or unfinished.

Each check is PASS, WARN or FAIL with the exact thing to change. FAIL means the installation should not hold real data
yet. The command changes nothing and sends nothing; it reads the environment, file permissions and the database.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import backup, egress, licence

DEMO_DOMAIN = "@vindhyapower.example"  # accounts made by `sutra demo-users`
BACKUP_MAX_AGE = timedelta(hours=48)


@dataclass(frozen=True)
class Check:
    level: str  # PASS | WARN | FAIL
    name: str
    detail: str


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _truthy(v: str | None, default: bool) -> bool:
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def run(env: Mapping[str, str] | None = None, workspace: Path | None = None, now: datetime | None = None,
        euid: int | None = None) -> list[Check]:
    env = os.environ if env is None else env
    now = now or datetime.now(UTC)
    ws = Path(workspace or env.get("SUTRA_WORKSPACE", "workspace"))
    url = env.get("SUTRA_DATABASE_URL") or f"sqlite:///{ws / 'sutra.db'}"
    out: list[Check] = []

    def add(ok: bool | None, name: str, good: str, bad: str, level_if_bad: str = "FAIL") -> None:
        out.append(Check("PASS" if ok else level_if_bad, name, good if ok else bad))

    # --- process and files ---
    uid = os.geteuid() if euid is None and hasattr(os, "geteuid") else (euid if euid is not None else 1)
    add(uid != 0, "service user", "Not running as root.",
        "Running as root. Run Sutra as an unprivileged user (the installer creates `sutra`).", "WARN")
    if not ws.exists():
        out.append(Check("FAIL", "workspace", f"{ws} does not exist. Run `python -m sutra db-upgrade` first."))
        return out
    add(_mode(ws) & 0o077 == 0, "workspace permissions", f"{ws} is private to its owner.",
        f"{ws} is readable by other users (mode {_mode(ws):o}). chmod 700 it.", "WARN")
    secret_env = env.get("SUTRA_SECRET_KEY", "")
    secret_file = ws / ".secret_key"
    if secret_env:
        add(len(secret_env) >= 32, "secret key", "SUTRA_SECRET_KEY is set and long enough.",
            "SUTRA_SECRET_KEY is shorter than 32 characters. Make one with `openssl rand -base64 48`.")
    elif secret_file.exists():
        add(_mode(secret_file) & 0o077 == 0, "secret key", "The generated secret key file is private.",
            f"{secret_file} is readable by others (mode {_mode(secret_file):o}). chmod 600 it.")
    else:
        out.append(Check("WARN", "secret key", "No secret key yet; Sutra generates one on first start."))
    db_file = backup.sqlite_path(url)
    if db_file is not None and db_file.exists():
        add(_mode(db_file) & 0o007 == 0, "database permissions", "The database file is not world-readable.",
            f"{db_file} is readable by everyone (mode {_mode(db_file):o}). chmod 600 it.")

    # --- web ---
    add(_truthy(env.get("SUTRA_COOKIE_SECURE"), True), "secure cookies", "Session cookies are Secure (HTTPS only).",
        "SUTRA_COOKIE_SECURE is off: sessions can travel over plain HTTP. Only acceptable on a developer laptop.")
    base = env.get("SUTRA_BASE_URL", "")
    add(base.startswith("https://"), "base URL", f"Links use {base}.",
        "SUTRA_BASE_URL is not an https:// address. Put Sutra behind TLS and set it.", "WARN")
    sso = bool(env.get("SUTRA_OIDC_ISSUER") and env.get("SUTRA_OIDC_CLIENT_ID"))
    local = _truthy(env.get("SUTRA_ALLOW_LOCAL_LOGIN"), True)
    add(sso or not local, "sign-in", "Single sign-on is configured." if sso else "Local passwords are off.",
        "Only local passwords protect sign-in. Configure SSO (SUTRA_OIDC_*) so your identity provider's MFA applies.",
        "WARN")
    try:
        minimum = int(env.get("SUTRA_MIN_PASSWORD_LENGTH", "12"))
    except ValueError:
        minimum = 12
    add(minimum >= 12, "password length", f"Local passwords need at least {minimum} characters.",
        "Minimum password length is below 12.", "WARN")

    # --- data stays put ---
    policy = (env.get("SUTRA_EGRESS", "open") or "open").strip().lower()
    allow = egress.parse_allow(env.get("SUTRA_EGRESS_ALLOW", ""))
    add(policy == "allowlist", "outbound connections",
        "Outbound connections are limited to the allow-list" + (f" ({', '.join(allow)})." if allow else " (none)."),
        "SUTRA_EGRESS is not `allowlist`: Sutra may connect to any host. Set it, and also block egress at the "
        "firewall.", "WARN")
    provider = (env.get("SUTRA_AI_PROVIDER", "auto") or "auto").lower()
    cloud = provider == "anthropic" or (provider == "auto" and not env.get("SUTRA_AI_LOCAL_URL")
                                        and bool(env.get("ANTHROPIC_API_KEY") or env.get("ANTHROPIC_AUTH_TOKEN")))
    if cloud and (policy != "allowlist" or egress.EgressGuard(policy, allow).host_allowed("api.anthropic.com")):
        out.append(Check("WARN", "AI model", "Prompts (root-cause facts, no raw finding text) go to the Anthropic API. "
                                             "Use SUTRA_AI_LOCAL_URL or SUTRA_AI_PROVIDER=off to keep them inside."))
    else:
        out.append(Check("PASS", "AI model", "No prompt leaves the network."))

    # --- licence, schema, accounts ---
    require = _truthy(env.get("SUTRA_REQUIRE_LICENCE"), False)
    add(require, "licence", "A licence key is required (SUTRA_REQUIRE_LICENCE=1).",
        "Licence is not required: every built module runs as an evaluation. Set SUTRA_REQUIRE_LICENCE=1.", "WARN")
    if db_file is not None and not db_file.exists():
        out.append(Check("FAIL", "database", f"No database at {db_file}. Run `python -m sutra db-upgrade`."))
    elif db_file is not None:
        out.extend(_database_checks(db_file, url, require, env, now))
    else:
        out.append(Check("WARN", "database", "PostgreSQL: schema, accounts and licence were not checked here. "
                                             "Back up with pg_dump (docs/operations.md)."))

    # --- backups ---
    found = backup.list_backups(ws / "backups") if (ws / "backups").exists() else []
    external = env.get("SUTRA_BACKUP_DIR")
    if external and Path(external).exists():
        found = backup.list_backups(Path(external))
    if not found:
        out.append(Check("WARN", "backups", "No backup found in the workspace or SUTRA_BACKUP_DIR. Schedule "
                                            "`python -m sutra backup create` (docs/operations.md)."))
    else:
        newest = found[0]
        age = now - datetime.fromtimestamp(newest.stat().st_mtime, UTC)
        add(age <= BACKUP_MAX_AGE, "backups", f"Newest backup is {age.total_seconds() / 3600:.0f} hours old.",
            f"Newest backup ({newest.name}) is {age.days} days old. Check the backup schedule.", "WARN")
        add(newest.suffix == ".enc", "backup encryption", "The newest backup is encrypted.",
            "The newest backup is not encrypted but holds the database and the server secret.", "WARN")
    return out


def _database_checks(db_file: Path, url: str, require: bool, env: Mapping[str, str], now: datetime) -> list[Check]:
    out: list[Check] = []
    current, head = backup.schema_revision(db_file), backup.head_revision()
    out.append(Check("PASS" if current == head else "FAIL", "schema",
                     f"Database schema is current ({head})." if current == head else
                     f"Database schema is {current or 'empty'}, this release needs {head}. "
                     f"Run `python -m sutra upgrade`."))
    con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    try:
        demo = con.execute("select count(*) from users where lower(email) like ?", (f"%{DEMO_DOMAIN}",)).fetchone()[0]
        admins = con.execute("select count(*) from user_roles where role_key='admin'").fetchone()[0]
        token = con.execute("select value from settings where key='licence'").fetchone()
        built = {r[0] for r in con.execute("select key from modules where built=1")} or set()
    except sqlite3.DatabaseError:
        demo = admins = 0
        token, built = None, set()
    finally:
        con.close()
    out.append(Check("FAIL" if demo else "PASS", "demo accounts",
                     f"{demo} synthetic demo accounts exist. Remove them: they are for demonstration data only."
                     if demo else "No synthetic demo accounts."))
    out.append(Check("PASS" if admins else "FAIL", "administrator",
                     f"{admins} administrator role assignment(s)." if admins else
                     "No administrator account. Run `python -m sutra create-admin`."))
    if require:
        if not token:
            out.append(Check("WARN", "licence key", "No licence key installed: only Administration is on."))
        else:
            pub = None
            try:
                pub = licence.load_public_key(env.get("SUTRA_LICENCE_PUBLIC_KEY"))
            except licence.LicenceError as e:
                out.append(Check("FAIL", "licence key", str(e)))
            if pub is None:
                out.append(Check("FAIL", "licence key", "This build has no vendor public key, so the stored key "
                                                        "cannot be checked."))
            else:
                try:
                    key = json.loads(token[0])["token"]
                    ent = licence.evaluate(licence.verify(key, pub), built, now.date())
                    out.append(Check("PASS" if ent.state == "valid" and not ent.warnings else "WARN", "licence key",
                                     ent.message + (" " + " ".join(ent.warnings) if ent.warnings else "")))
                except (licence.LicenceError, KeyError, ValueError, TypeError) as e:
                    out.append(Check("FAIL", "licence key", f"The stored key is not valid: {e}"))
    return out


def render(checks: list[Check]) -> str:
    width = max(len(c.name) for c in checks)
    lines = [f"{c.level:<4}  {c.name:<{width}}  {c.detail}" for c in checks]
    counts = {lvl: sum(1 for c in checks if c.level == lvl) for lvl in ("PASS", "WARN", "FAIL")}
    lines.append(f"\n{counts['PASS']} passed, {counts['WARN']} warnings, {counts['FAIL']} failures.")
    return "\n".join(lines)
