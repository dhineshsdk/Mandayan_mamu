"""Entra ID directory sync: people and roles from group membership, so access follows the organisation's directory.

An administrator maps Entra ID groups to Sutra roles (for example "SG-VM-Analysts" to VM analyst for the whole
organisation, or "SG-Plant-Engineers-Unit2" to plant engineer for one site). Once a day, and on demand, Sutra reads
the members of every mapped group from Microsoft Graph and:

- creates a single-sign-on account (no password) for each enabled member who has no account yet, or links the
  existing account with the same email;
- gives each member the mapped roles, and takes away synced roles from people no longer in the group. Roles an
  administrator gave by hand are never touched;
- disables an account that the sync manages once it has no roles left, and enables it again if the person returns
  to a mapped group. An account an administrator disabled stays disabled.

Reading is all or nothing: if any group cannot be read, nothing changes. A sync that would leave nobody able to
administer Sutra is refused.

Microsoft Graph, as described by the official Python SDK (msgraph-sdk 1.64.0, generated request builders and models):
``GET /v1.0/groups/{group-id}?$select=id,displayName``, ``GET
/v1.0/groups/{group-id}/transitiveMembers/graph.user?$select=...`` (users in nested groups too), paged with
``@odata.nextLink``; user fields ``id``, ``displayName``, ``mail``, ``userPrincipalName``, ``accountEnabled``.
Tokens: client credentials at ``https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`` with scope
``https://graph.microsoft.com/.default``. The app registration needs the Microsoft Graph application permissions
GroupMember.Read.All and User.Read.All, granted by a tenant administrator.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlsplit

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import vault
from .models import AuthSession, DirectoryGroupMap, RolePermission, Setting, User, UserRole, utcnow
from .security import audit

log = logging.getLogger("sutra.directory")
LOGIN_URL = "https://login.microsoftonline.com"
GRAPH_URL = "https://graph.microsoft.com"
USER_FIELDS = "id,displayName,mail,userPrincipalName,accountEnabled"
SETTING = "directory"
STATUS = "directory_status"
DEFAULTS = {"enabled": False, "tenant_id": "", "client_id": "", "secret": "", "login_url": LOGIN_URL,
            "graph_url": GRAPH_URL}
TIMEOUT = httpx.Timeout(60.0)
MAX_ATTEMPTS = 4
MAX_WAIT = 120.0
SYNC_EVERY = timedelta(hours=24)
CHECK_SECONDS = 3600


class DirectoryError(Exception):
    """Graph could not be read, or the sync was refused. The message is safe to show an administrator."""


def config(db: Session) -> dict:
    s = db.get(Setting, SETTING)
    return {**DEFAULTS, **(dict(s.value) if s else {})}


def config_json(cfg: dict) -> dict:
    return {k: v for k, v in cfg.items() if k != "secret"} | {"has_secret": bool(cfg.get("secret"))}


def status(db: Session) -> dict:
    s = db.get(Setting, STATUS)
    return dict(s.value) if s else {}


def _set(db: Session, key: str, value: dict) -> None:
    s = db.get(Setting, key)
    if s is None:
        db.add(Setting(key=key, value=value))
    else:
        s.value = value


# ---------- Microsoft Graph ----------

class Graph:
    """Read-only Graph client: one token request, then GETs on groups and their members."""

    def __init__(self, tenant_id: str, client_id: str, secret: str, login_url: str = LOGIN_URL,
                 graph_url: str = GRAPH_URL, transport: httpx.BaseTransport | None = None, sleep=time.sleep):
        self.token_url = f"{login_url.rstrip('/')}/{quote(tenant_id, safe='')}/oauth2/v2.0/token"
        self.graph_url = graph_url.rstrip("/")
        self.graph_host = urlsplit(self.graph_url).hostname
        self._form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret,
                      "scope": f"{self.graph_url}/.default"}
        self._sleep = sleep
        self._client = httpx.Client(timeout=TIMEOUT, transport=transport, follow_redirects=False,
                                    headers={"User-Agent": "Sutra directory sync"})
        self._token = ""

    def close(self) -> None:
        self._client.close()

    def _send(self, method: str, url: str, **kw) -> httpx.Response:
        for attempt in range(MAX_ATTEMPTS):
            try:
                r = self._client.request(method, url, **kw)
            except httpx.TransportError as e:
                if attempt + 1 == MAX_ATTEMPTS:
                    raise DirectoryError(f"Could not reach {urlsplit(url).hostname}: {type(e).__name__}") from e
                self._sleep(2 ** attempt)
                continue
            if r.status_code in (429, 503, 504) and attempt + 1 < MAX_ATTEMPTS:
                wait = r.headers.get("Retry-After", "")
                self._sleep(min(MAX_WAIT, float(wait)) if wait.isdigit() else 2 ** attempt)
                continue
            return r
        raise DirectoryError("Microsoft Graph kept asking Sutra to slow down; try again later.")

    def _login(self) -> None:
        r = self._send("POST", self.token_url, data=self._form)
        if r.status_code != 200:
            detail = _graph_error(r)
            raise DirectoryError(f"Entra ID refused the app credentials (HTTP {r.status_code}){detail}. Check the "
                                 "tenant ID, client ID and secret.")
        self._token = r.json().get("access_token", "")
        if not self._token:
            raise DirectoryError("Entra ID returned no access token.")

    def _get(self, url: str, params: dict | None = None) -> dict:
        if urlsplit(url).hostname != self.graph_host:  # a nextLink must never take the token elsewhere
            raise DirectoryError("Microsoft Graph returned a paging link to another host; stopping.")
        if not self._token:
            self._login()
        r = self._send("GET", url, params=params, headers={"Authorization": f"Bearer {self._token}"})
        if r.status_code == 401:
            self._login()
            r = self._send("GET", url, params=params, headers={"Authorization": f"Bearer {self._token}"})
        if r.status_code == 404:
            raise DirectoryError(f"Group not found in Entra ID ({urlsplit(url).path.split('/')[3]}).")
        if r.status_code == 403:
            raise DirectoryError("Microsoft Graph denied access. Grant the app GroupMember.Read.All and "
                                 "User.Read.All (application permissions) with admin consent.")
        if r.status_code != 200:
            raise DirectoryError(f"Microsoft Graph returned HTTP {r.status_code}{_graph_error(r)}.")
        return r.json()

    def group_name(self, group_id: str) -> str:
        body = self._get(f"{self.graph_url}/v1.0/groups/{quote(group_id, safe='')}",
                         {"$select": "id,displayName"})
        return str(body.get("displayName") or "")

    def members(self, group_id: str) -> list[dict]:
        url = f"{self.graph_url}/v1.0/groups/{quote(group_id, safe='')}/transitiveMembers/graph.user"
        params: dict | None = {"$select": USER_FIELDS}
        out = []
        while url:
            body = self._get(url, params)
            out += body.get("value") or []
            url, params = body.get("@odata.nextLink") or "", None  # the link carries the query
        return out


def _graph_error(r: httpx.Response) -> str:
    try:
        err = r.json()
        msg = err.get("error_description") or (err.get("error") or {}).get("message") or ""
    except (ValueError, AttributeError):
        msg = ""
    if not msg:
        return ""
    first = str(msg).splitlines()[0].strip()
    if len(first) > 300:  # cut at a sentence end, not mid-word
        first = first[:300].rsplit(". ", 1)[0] + "."
    return f": {first.rstrip('.')}"


# ---------- the sync ----------

@dataclass
class Person:
    directory_id: str
    email: str
    name: str
    roles: set[tuple[str, str, str]]


def read(graph: Graph, maps: list[DirectoryGroupMap]) -> tuple[dict[str, Person], dict[str, str]]:
    """Everyone in a mapped group, with the roles the mappings give them, and the current group names."""
    people: dict[str, Person] = {}
    names: dict[str, str] = {}
    by_group: dict[str, list[DirectoryGroupMap]] = {}
    for m in maps:
        by_group.setdefault(m.group_id, []).append(m)
    for gid, gmaps in by_group.items():
        names[gid] = graph.group_name(gid)
        for u in graph.members(gid):
            email = str(u.get("mail") or u.get("userPrincipalName") or "").strip().lower()
            if u.get("accountEnabled") is not True or not u.get("id") or "@" not in email:
                continue
            p = people.setdefault(u["id"], Person(u["id"], email, str(u.get("displayName") or email)[:120], set()))
            p.roles |= {(m.role_key, m.scope_type, m.scope_value) for m in gmaps}
    return people, names


def _admin_roles(db: Session) -> set[str]:
    return set(db.scalars(select(RolePermission.role_key).where(RolePermission.module_key == "M-ADM",
                                                                RolePermission.action == "admin")))


def _end_sessions(db: Session, user: User) -> None:
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id)):
        db.delete(s)


def apply(db: Session, people: dict[str, Person]) -> dict:
    """Bring accounts and synced roles in line with ``people``. The caller commits."""
    out = {"created": 0, "linked": 0, "roles_changed": 0, "disabled": 0, "enabled": 0, "conflicts": []}
    for p in people.values():
        user = db.scalars(select(User).where(User.directory_id == p.directory_id)).first()
        if user is None:
            user = db.scalars(select(User).where(func.lower(User.email) == p.email)).first()
            if user is not None and user.directory_id:
                out["conflicts"].append(f"{p.email} is already linked to another Entra ID account")
                continue
            if user is None:
                user = User(email=p.email, display_name=p.name)  # single sign-on only: no password
                db.add(user)
                db.flush()
                out["created"] += 1
                audit(db, "directory.user_created", None, "user", user.id, email=p.email)
            else:
                out["linked"] += 1
                audit(db, "directory.user_linked", None, "user", user.id, email=user.email)
            user.directory_id = p.directory_id
        if user.directory_state == "removed" and not user.is_active:
            user.is_active = True
            out["enabled"] += 1
            audit(db, "directory.user_enabled", None, "user", user.id)
        user.directory_state = "active"
        _set_synced_roles(db, user, p.roles, out)
    for user in db.scalars(select(User).where(User.directory_id.is_not(None), User.directory_state == "active")):
        if user.directory_id in people:
            continue
        _set_synced_roles(db, user, set(), out)
        if not user.roles:
            user.is_active, user.directory_state = False, "removed"
            _end_sessions(db, user)
            out["disabled"] += 1
            audit(db, "directory.user_disabled", None, "user", user.id, reason="no longer in any mapped group")
        else:
            user.directory_state = "left"  # keeps the roles an administrator gave by hand
    db.flush()
    admin_roles = _admin_roles(db)
    admins = db.scalars(select(func.count(func.distinct(User.id))).join(UserRole).where(
        User.is_active.is_(True), UserRole.role_key.in_(admin_roles))).one()
    if not admins:
        raise DirectoryError("This sync would leave nobody able to administer Sutra, so nothing was changed. "
                             "Give an administrator role by hand or map an administrators' group first.")
    return out


def _set_synced_roles(db: Session, user: User, wanted: set[tuple[str, str, str]], out: dict) -> None:
    synced = {(r.role_key, r.scope_type, r.scope_value): r for r in user.roles if r.source == "entra"}
    manual = {(r.role_key, r.scope_type, r.scope_value) for r in user.roles if r.source != "entra"}
    wanted = wanted - manual  # a role given by hand already covers it
    if set(synced) == wanted:
        return
    for key, row in synced.items():
        if key not in wanted:
            user.roles.remove(row)
    db.flush()
    for key in sorted(wanted - set(synced)):
        user.roles.append(UserRole(role_key=key[0], scope_type=key[1], scope_value=key[2], source="entra"))
    out["roles_changed"] += 1
    audit(db, "directory.roles_changed", None, "user", user.id, before=sorted(map(list, synced)),
          after=sorted(map(list, wanted)))


def run(db: Session, secret_key: str, transport: httpx.BaseTransport | None = None, trigger: str = "manual",
        actor: User | None = None) -> dict:
    """Read Entra ID and apply it. Records the outcome in the ``directory_status`` setting and commits."""
    cfg = config(db)
    started = utcnow()
    try:
        if not (cfg["tenant_id"] and cfg["client_id"] and cfg["secret"]):
            raise DirectoryError("Enter the tenant ID, client ID and client secret first.")
        maps = list(db.scalars(select(DirectoryGroupMap)))
        if not maps:
            raise DirectoryError("Map at least one Entra ID group to a role first.")
        graph = Graph(cfg["tenant_id"], cfg["client_id"], vault.open_(secret_key, cfg["secret"]),
                      cfg["login_url"], cfg["graph_url"], transport)
        try:
            people, names = read(graph, maps)
        finally:
            graph.close()
        for m in maps:
            m.group_name = names.get(m.group_id, m.group_name)
        result = apply(db, people)
        result["people"] = len(people)
    except (DirectoryError, vault.CannotDecrypt, ValueError) as e:  # ValueError: a body that is not JSON
        db.rollback()
        value = {**status(db), "last_attempt": started.isoformat(timespec="seconds"), "ok": False,
                 "error": str(e), "trigger": trigger}
        _set(db, STATUS, value)
        audit(db, "directory.sync", actor, "setting", SETTING, ok=False, error=str(e), trigger=trigger)
        db.commit()
        raise DirectoryError(str(e)) from e
    value = {"last_attempt": started.isoformat(timespec="seconds"), "last_success": started.isoformat(
        timespec="seconds"), "ok": True, "error": "", "trigger": trigger,
        **{k: v for k, v in result.items() if k != "conflicts"}, "conflicts": result["conflicts"][:20]}
    _set(db, STATUS, value)
    audit(db, "directory.sync", actor, "setting", SETTING, ok=True, trigger=trigger,
          **{k: v for k, v in result.items() if k != "conflicts"}, conflicts=len(result["conflicts"]))
    db.commit()
    return value


class Syncer:
    """Runs the sync once a day when it is switched on, one run at a time."""

    def __init__(self, app, transport: httpx.BaseTransport | None = None):
        self.app = app
        self.transport = transport
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def run(self, trigger: str = "manual", actor_id: int | None = None) -> dict:
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("A directory sync is already running.")
        try:
            with self.app.state.sessionmaker() as db:
                actor = db.get(User, actor_id) if actor_id else None
                return run(db, self.app.state.settings.secret_key, self.transport, trigger, actor)
        finally:
            self._lock.release()

    def due(self, db: Session, now: datetime) -> bool:
        if not config(db)["enabled"]:
            return False
        last = status(db).get("last_attempt")
        return not last or datetime.fromisoformat(last) <= now - SYNC_EVERY

    def tick(self) -> None:
        with self.app.state.sessionmaker() as db:
            if not self.due(db, datetime.now(UTC).replace(tzinfo=None)):
                return
        try:
            self.run("schedule")
        except (DirectoryError, RuntimeError) as e:
            log.warning("directory sync: %s", e)

    def start(self) -> None:
        threading.Thread(target=self._loop, name="sutra-directory", daemon=True).start()

    def _loop(self) -> None:
        while not self._stop.wait(CHECK_SECONDS):
            try:
                self.tick()
            except Exception:
                log.exception("directory sync failed")

    def stop(self) -> None:
        self._stop.set()
