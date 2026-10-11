"""Administration: people, roles, per-person module grants, licences, the ownership chart, approval
thresholds and the audit log. Nobody can change their own access."""

from __future__ import annotations

import csv
import io
import secrets
from datetime import UTC, date, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import ingest
from ...synth import TEAMS_COLS
from .. import drafting, sla
from ..access import ORG, Principal
from ..analysis import replace_ownership
from ..catalog import DEFAULT_APPROVAL_RULES, FIXED_RULES, load_catalog
from ..deps import client_ip, get_db, require, require_any
from ..jobs import approval_rules
from ..models import (
    AuditEvent,
    AuthSession,
    Module,
    ModuleGrant,
    Outbox,
    OwnershipTeam,
    Role,
    Setting,
    User,
    UserRole,
    utcnow,
)
from ..security import audit, hash_password

router = APIRouter(prefix="/api/admin")
ADMIN = require("M-ADM", "admin")
SSVC = ["Act", "Attend", "Track*", "Track"]


class RoleAssign(BaseModel):
    role: str = Field(max_length=40)
    scope_type: Literal["org", "vertical", "site", "team"] = "org"
    scope_value: str = Field(default="", max_length=120)


class UserIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    name: str = Field(min_length=1, max_length=120)
    roles: list[RoleAssign] = Field(default_factory=list, max_length=20)
    expires_at: datetime | None = None
    sso_only: bool = False


class UserPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    is_active: bool | None = None
    expires_at: datetime | None = None
    clear_expiry: bool = False
    unlock: bool = False


class GrantIn(BaseModel):
    module: str = Field(max_length=16)
    action: str = Field(max_length=16)
    effect: Literal["allow", "deny"]
    scope_type: Literal["org", "vertical", "site", "team"] = "org"
    scope_value: str = Field(default="", max_length=120)
    reason: str = Field(min_length=3, max_length=500)


class ModulePatch(BaseModel):
    licensed: bool


class RulesIn(BaseModel):
    vertical_head_for_ssvc: list[Literal["Act", "Attend", "Track*", "Track"]]
    crown_jewel_min_criticality: int = Field(ge=1, le=5)
    emergency_fast_track_for_act: bool


def temp_password() -> str:
    return secrets.token_urlsafe(12)


def _naive_utc(dt: datetime | None) -> datetime | None:
    """Stored times are naive UTC. A time sent without a zone is taken as UTC."""
    if dt is None or dt.tzinfo is None:
        return dt
    return dt.astimezone(UTC).replace(tzinfo=None)


def user_json(u: User) -> dict:
    return {"id": u.id, "email": u.email, "name": u.display_name, "active": u.is_active,
            "sso_linked": bool(u.oidc_subject), "has_password": bool(u.password_hash),
            "must_change_password": u.must_change_password,
            "locked": bool(u.locked_until and u.locked_until > utcnow()),
            "expires_at": u.expires_at.isoformat(timespec="seconds") if u.expires_at else None,
            "last_login_at": u.last_login_at.isoformat(timespec="seconds") if u.last_login_at else None,
            "roles": [{"id": r.id, "role": r.role_key, "scope_type": r.scope_type, "scope_value": r.scope_value}
                      for r in u.roles],
            "grants": [{"id": g.id, "module": g.module_key, "action": g.action, "effect": g.effect,
                        "scope_type": g.scope_type, "scope_value": g.scope_value, "reason": g.reason}
                       for g in u.grants]}


def _not_self(p: Principal, user: User) -> None:
    if user.id == p.user.id:
        raise HTTPException(403, "You cannot change your own access. Ask another admin.")


def _user(db: Session, uid: int) -> User:
    user = db.get(User, uid)
    if user is None:
        raise LookupError("No such user.")
    return user


def _check_scope(db: Session, scope_type: str, scope_value: str) -> str:
    value = scope_value.strip()
    if scope_type == ORG:
        return ""
    if not value:
        raise ValueError(f"Give the {scope_type} this applies to.")
    if scope_type == "team" and db.get(OwnershipTeam, value) is None:
        raise ValueError(f"Team {value!r} is not in the ownership chart. Upload the chart first.")
    in_chart = db.scalars(select(OwnershipTeam).where(OwnershipTeam.vertical == value)).first()
    if scope_type == "vertical" and not in_chart:
        raise ValueError(f"Vertical {value!r} is not in the ownership chart.")
    return value


def _apply_roles(db: Session, user: User, roles: list[RoleAssign], expires_at: datetime | None) -> list[dict]:
    known = {r.key: r for r in db.scalars(select(Role))}
    rows, seen = [], set()
    for a in roles:
        role = known.get(a.role)
        if role is None:
            raise ValueError(f"Unknown role {a.role!r}.")
        if a.scope_type != role.scope_type:
            raise ValueError(f"{role.name} is assigned per {role.scope_type}, not per {a.scope_type}.")
        if role.time_limited and (expires_at is None or expires_at <= utcnow()):
            raise ValueError(f"{role.name} access must have a future expiry date.")
        value = _check_scope(db, a.scope_type, a.scope_value)
        key = (a.role, a.scope_type, value)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"role": a.role, "scope_type": a.scope_type, "scope_value": value})
    user.roles.clear()
    db.flush()  # delete the old rows first: the unit of work would otherwise insert before deleting
    user.roles = [UserRole(role_key=r["role"], scope_type=r["scope_type"], scope_value=r["scope_value"])
                  for r in rows]
    return rows


def _end_sessions(db: Session, user: User) -> None:
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id)):
        db.delete(s)


# ---------- people ----------

@router.get("/users")
def list_users(p: Principal = Depends(ADMIN), db: Session = Depends(get_db)):
    return [user_json(u) for u in db.scalars(select(User).order_by(User.display_name))]


@router.post("/users", status_code=201)
def create_user(body: UserIn, request: Request, p: Principal = Depends(ADMIN), db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if "@" not in email:
        raise ValueError("Give a valid email address.")
    if db.scalars(select(User).where(func.lower(User.email) == email)).first():
        raise HTTPException(409, "A user with this email already exists.")
    expires = _naive_utc(body.expires_at)
    user = User(email=email, display_name=body.name.strip(), expires_at=expires)
    password = None
    if not body.sso_only:
        password = temp_password()
        user.password_hash, user.must_change_password = hash_password(password), True
    db.add(user)
    db.flush()
    roles = _apply_roles(db, user, body.roles, expires)
    audit(db, "admin.user_created", p.user, "user", user.id, client_ip(request), email=email, roles=roles,
          expires_at=expires.isoformat() if expires else None, sso_only=body.sso_only)
    db.commit()
    # The one-time password is shown to the admin once and never stored in clear.
    return {**user_json(user), "temporary_password": password}


@router.patch("/users/{uid}")
def update_user(uid: int, body: UserPatch, request: Request, p: Principal = Depends(ADMIN),
                db: Session = Depends(get_db)):
    user = _user(db, uid)
    _not_self(p, user)
    changes = {}
    if body.name is not None:
        user.display_name = changes["name"] = body.name.strip()
    if body.is_active is not None:
        user.is_active = changes["active"] = body.is_active
        if not body.is_active:
            _end_sessions(db, user)
    if body.clear_expiry:
        if any(r.time_limited for r in db.scalars(select(Role).where(Role.key.in_([x.role_key for x in user.roles])))):
            raise ValueError("This person holds a time-limited role, so the account needs an expiry date.")
        user.expires_at, changes["expires_at"] = None, None
    elif body.expires_at is not None:
        user.expires_at = _naive_utc(body.expires_at)
        changes["expires_at"] = user.expires_at.isoformat()
    if body.unlock:
        user.locked_until, user.failed_logins, changes["unlocked"] = None, 0, True
    audit(db, "admin.user_updated", p.user, "user", user.id, client_ip(request), **changes)
    db.commit()
    return user_json(user)


@router.post("/users/{uid}/reset-password")
def reset_password(uid: int, request: Request, p: Principal = Depends(ADMIN), db: Session = Depends(get_db)):
    user = _user(db, uid)
    _not_self(p, user)
    password = temp_password()
    user.password_hash, user.must_change_password = hash_password(password), True
    user.locked_until, user.failed_logins = None, 0
    _end_sessions(db, user)
    audit(db, "admin.password_reset", p.user, "user", user.id, client_ip(request))
    db.commit()
    return {"temporary_password": password}


@router.put("/users/{uid}/roles")
def set_roles(uid: int, roles: list[RoleAssign], request: Request, p: Principal = Depends(ADMIN),
              db: Session = Depends(get_db)):
    user = _user(db, uid)
    _not_self(p, user)
    before = [{"role": r.role_key, "scope_type": r.scope_type, "scope_value": r.scope_value} for r in user.roles]
    after = _apply_roles(db, user, roles, user.expires_at)
    audit(db, "admin.roles_changed", p.user, "user", user.id, client_ip(request), before=before, after=after)
    db.commit()
    return user_json(user)


@router.post("/users/{uid}/grants", status_code=201)
def add_grant(uid: int, body: GrantIn, request: Request, p: Principal = Depends(ADMIN),
              db: Session = Depends(get_db)):
    user = _user(db, uid)
    _not_self(p, user)
    module = db.get(Module, body.module)
    if module is None:
        raise ValueError(f"Unknown module {body.module!r}.")
    actions = set(load_catalog()["actions"])
    if not (body.action in actions or (body.effect == "deny" and body.action == "*")):
        raise ValueError(f"Action must be one of {', '.join(sorted(actions))}" +
                         (" or * (the whole module)." if body.effect == "deny" else "."))
    value = _check_scope(db, body.scope_type, body.scope_value) if body.effect == "allow" else ""
    g = ModuleGrant(user_id=user.id, module_key=module.key, action=body.action, effect=body.effect,
                    scope_type=body.scope_type if body.effect == "allow" else ORG, scope_value=value,
                    granted_by=p.user.id, reason=body.reason.strip())
    db.add(g)
    db.flush()
    audit(db, "admin.grant_added", p.user, "user", user.id, client_ip(request), grant=g.id, module=g.module_key,
          action=g.action, effect=g.effect, scope=f"{g.scope_type}:{g.scope_value}", reason=g.reason,
          module_built=module.built)
    db.commit()
    db.refresh(user)
    return user_json(user)


@router.delete("/grants/{gid}")
def remove_grant(gid: int, request: Request, p: Principal = Depends(ADMIN), db: Session = Depends(get_db)):
    g = db.get(ModuleGrant, gid)
    if g is None:
        raise LookupError("No such grant.")
    user = _user(db, g.user_id)
    _not_self(p, user)
    audit(db, "admin.grant_removed", p.user, "user", user.id, client_ip(request), grant=g.id, module=g.module_key,
          action=g.action, effect=g.effect)
    db.delete(g)
    db.commit()
    db.refresh(user)
    return user_json(user)


# ---------- catalogue and licences ----------

@router.get("/catalog")
def catalog(p: Principal = Depends(ADMIN), db: Session = Depends(get_db)):
    return {
        "modules": [{"key": m.key, "name": m.name, "built": m.built, "licensed": m.licensed}
                    for m in db.scalars(select(Module).order_by(Module.key))],
        "roles": [{"key": r.key, "name": r.name, "description": r.description, "scope_type": r.scope_type,
                   "time_limited": r.time_limited,
                   "permissions": sorted(f"{x.module_key}:{x.action}" for x in r.permissions)}
                  for r in db.scalars(select(Role).order_by(Role.name))],
        "actions": load_catalog()["actions"],
        "teams": [t.team for t in db.scalars(select(OwnershipTeam).order_by(OwnershipTeam.team))],
        "verticals": sorted({t.vertical for t in db.scalars(select(OwnershipTeam)) if t.vertical}),
    }


@router.patch("/modules/{key}")
def set_licence(key: str, body: ModulePatch, request: Request, p: Principal = Depends(ADMIN),
                db: Session = Depends(get_db)):
    m = db.get(Module, key)
    if m is None:
        raise LookupError("No such module.")
    if key == "M-ADM" and not body.licensed:
        raise ValueError("Administration cannot be switched off.")
    m.licensed = body.licensed
    audit(db, "admin.licence_changed", p.user, "module", key, client_ip(request), licensed=body.licensed)
    db.commit()
    return {"key": m.key, "licensed": m.licensed}


# ---------- ownership chart ----------

def _team_json(t: OwnershipTeam) -> dict:
    return {c: getattr(t, c) for c in ("team", "jira_project", "manager_name", "manager_email", "vertical",
                                        "vertical_head_name", "vertical_head_email", "vm_analyst_name",
                                        "vm_analyst_email")}


@router.get("/ownership")
def ownership(p: Principal = Depends(ADMIN), db: Session = Depends(get_db)):
    return [_team_json(t) for t in db.scalars(select(OwnershipTeam).order_by(OwnershipTeam.team))]


@router.post("/ownership")
async def upload_ownership(file: UploadFile, request: Request, p: Principal = Depends(ADMIN),
                           db: Session = Depends(get_db)):
    raw = await file.read(5 * 1024 * 1024 + 1)
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(413, "The ownership chart is larger than 5 MB.")
    tmp = request.app.state.settings.workspace / f".ownership-{secrets.token_hex(4)}.csv"
    try:
        tmp.write_bytes(raw)
        if ingest.detect_format(tmp) != "teams":
            raise ValueError("This is not an ownership chart. Expected columns: " + ", ".join(TEAMS_COLS))
        rows = ingest.load_teams(tmp)
    finally:
        tmp.unlink(missing_ok=True)
    if not rows:
        raise ValueError("The ownership chart has no rows.")
    n = replace_ownership(db, rows)
    audit(db, "admin.ownership_replaced", p.user, "ownership", "", client_ip(request), teams=n,
          file=(file.filename or "")[:120])
    db.commit()
    return {"teams": n}


# ---------- approval thresholds ----------

@router.get("/approval-rules")
def get_rules(p: Principal = Depends(require_any(("M-ADM", "act"), ("M-ADM", "admin"))),
              db: Session = Depends(get_db)):
    return {"rules": {**DEFAULT_APPROVAL_RULES, **approval_rules(db)}, "fixed": FIXED_RULES, "ssvc": SSVC}


@router.put("/approval-rules")
def put_rules(body: RulesIn, request: Request, p: Principal = Depends(require_any(("M-ADM", "act"),
                                                                                  ("M-ADM", "admin"))),
              db: Session = Depends(get_db)):
    before = approval_rules(db)
    value = body.model_dump()
    row = db.get(Setting, "approval_rules")
    if row is None:
        row = Setting(key="approval_rules", value=value)
        db.add(row)
    row.value, row.updated_by, row.updated_at = value, p.user.id, utcnow()
    audit(db, "admin.approval_rules_changed", p.user, "setting", "approval_rules", client_ip(request),
          before=before, after=value)
    db.commit()
    return {"rules": value, "fixed": FIXED_RULES, "ssvc": SSVC}


# ---------- maintenance windows ----------

class MaintenanceIn(BaseModel):
    weekday: int = Field(ge=0, le=6)  # Monday = 0
    start: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    duration_hours: int = Field(ge=1, le=24)
    timezone_label: str = Field(min_length=1, max_length=16)
    ot_shutdowns: dict[str, date] = Field(default_factory=dict, max_length=500)  # site -> next planned shutdown


def _maintenance_out(db: Session, request: Request) -> dict:
    res = request.app.state.analysis.result
    sites = sorted({a.site for a in res.assets.values() if a.is_ot and a.site}) if res else []
    return {"maintenance": drafting.maintenance(db), "ot_sites": sites, "today": drafting.today().isoformat(),
            "ai_drafting": request.app.state.drafts.background}


@router.get("/maintenance")
def get_maintenance(request: Request, p: Principal = Depends(require_any(("M-ADM", "act"), ("M-ADM", "admin"))),
                    db: Session = Depends(get_db)):
    return _maintenance_out(db, request)


@router.put("/maintenance")
def put_maintenance(body: MaintenanceIn, request: Request,
                    p: Principal = Depends(require_any(("M-ADM", "act"), ("M-ADM", "admin"))),
                    db: Session = Depends(get_db)):
    before = drafting.maintenance(db)
    value = body.model_dump(mode="json")
    value["ot_shutdowns"] = {k.strip()[:200]: v for k, v in value["ot_shutdowns"].items() if k.strip()}
    row = db.get(Setting, "maintenance")
    if row is None:
        row = Setting(key="maintenance", value=value)
        db.add(row)
    row.value, row.updated_by, row.updated_at = value, p.user.id, utcnow()
    audit(db, "admin.maintenance_changed", p.user, "setting", "maintenance", client_ip(request),
          before=before, after=value)
    db.commit()
    return _maintenance_out(db, request)


# ---------- service levels ----------

class SlaIn(BaseModel):
    step_hours: dict[Literal["manager", "vm_analyst", "vertical_head", "ciso"], int]
    fix_days: dict[Literal["Act", "Attend", "Track*", "Track"], int]


@router.get("/sla")
def get_sla(p: Principal = Depends(require_any(("M-ADM", "act"), ("M-ADM", "admin"))),
            db: Session = Depends(get_db)):
    return {"sla": sla.settings(db), "defaults": sla.DEFAULT_SLA}


@router.put("/sla")
def put_sla(body: SlaIn, request: Request, p: Principal = Depends(require_any(("M-ADM", "act"), ("M-ADM", "admin"))),
            db: Session = Depends(get_db)):
    lo, hi = sla.STEP_LIMITS
    if any(not lo <= v <= hi for v in body.step_hours.values()):
        raise ValueError(f"Approval steps may wait between {lo} and {hi} hours.")
    lo, hi = sla.FIX_LIMITS
    if any(not lo <= v <= hi for v in body.fix_days.values()):
        raise ValueError(f"Fix targets must be between {lo} and {hi} days.")
    before = sla.settings(db)
    value = body.model_dump()
    row = db.get(Setting, "sla")
    if row is None:
        row = Setting(key="sla", value=value)
        db.add(row)
    row.value, row.updated_by, row.updated_at = value, p.user.id, utcnow()
    audit(db, "admin.sla_changed", p.user, "setting", "sla", client_ip(request), before=before, after=value)
    db.commit()
    return {"sla": sla.settings(db), "defaults": sla.DEFAULT_SLA}


# ---------- integrations ----------

@router.get("/integrations")
def integrations(request: Request, p: Principal = Depends(require("M-ADM", "admin")), db: Session = Depends(get_db)):
    """What is configured (never the secrets) and how delivery is going."""
    s = request.app.state.settings
    counts: dict[str, dict[str, int]] = {}
    for kind, status, n in db.execute(select(Outbox.kind, Outbox.status, func.count()).group_by(Outbox.kind,
                                                                                               Outbox.status)):
        counts.setdefault(kind, {})[status] = n
    problems = db.scalars(select(Outbox).where(Outbox.status.in_(("failed", "skipped")))
                          .order_by(Outbox.id.desc()).limit(25))
    return {
        "base_url": s.base_url,
        "email": {"enabled": s.email_enabled, "host": s.smtp_host, "port": s.smtp_port, "from": s.smtp_from},
        "teams": {"enabled": bool(s.teams_webhook_url)},
        "jira": {"enabled": s.jira_enabled, "url": s.jira_url, "api": s.jira_api, "issue_type": s.jira_issue_type,
                 "done_status": s.jira_done_status, "auth": "account + API token" if s.jira_user else "token"},
        "servicenow": {"enabled": s.servicenow_enabled, "url": s.servicenow_url, "table": s.servicenow_table},
        "outbox": counts,
        "problems": [{"id": o.id, "kind": o.kind, "event": o.event, "job": o.job_id, "recipient": o.recipient,
                      "status": o.status, "attempts": o.attempts, "error": o.last_error,
                      "at": o.created_at.isoformat(timespec="seconds")} for o in problems],
    }


@router.post("/integrations/retry")
def retry_failed(request: Request, p: Principal = Depends(require("M-ADM", "admin")), db: Session = Depends(get_db)):
    """Queue failed and skipped deliveries again, for example after fixing a setting."""
    rows = db.scalars(select(Outbox).where(Outbox.status.in_(("failed", "skipped")))).all()
    for o in rows:
        o.status, o.attempts, o.next_attempt_at = "queued", 0, utcnow()
    audit(db, "admin.outbox_retry", p.user, "outbox", "", client_ip(request), rows=len(rows))
    db.commit()
    return {"queued": len(rows)}


# ---------- audit log ----------

audit_router = APIRouter(prefix="/api/audit")


@audit_router.get("")
def audit_log(action: str = "", actor: str = "", before_id: int | None = None, limit: int = 100,
              p: Principal = Depends(require_any(("M-AUD", "view"), ("M-ADM", "admin"))),
              db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    q = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if action:
        q = q.where(AuditEvent.action.startswith(action[:60]))
    if actor:
        q = q.where(func.lower(AuditEvent.actor_email).contains(actor[:254].lower()))
    if before_id:
        q = q.where(AuditEvent.id < before_id)
    rows = list(db.scalars(q))
    return {"events": [{"id": e.id, "at": e.at.isoformat(timespec="seconds"), "actor": e.actor_email or "system",
                        "action": e.action, "target": f"{e.target_type}:{e.target_id}" if e.target_type else "",
                        "detail": e.detail, "ip": e.ip} for e in rows],
            "next_before_id": rows[-1].id if len(rows) == limit else None}


@audit_router.get(".csv")
def audit_csv(p: Principal = Depends(require_any(("M-AUD", "view"), ("M-ADM", "admin"))),
              db: Session = Depends(get_db)):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "at_utc", "actor", "action", "target_type", "target_id", "ip", "detail"])
    for e in db.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        w.writerow([e.id, e.at.isoformat(timespec="seconds"), e.actor_email, e.action, e.target_type, e.target_id,
                    e.ip, e.detail])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="sutra_audit_log.csv"'})
