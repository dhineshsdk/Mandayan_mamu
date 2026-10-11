"""Sign-in (local password and OpenID Connect), sign-out, the current person and password changes."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..access import Principal, account_usable, build_principal
from ..deps import SESSION_COOKIE, client_ip, current_principal, get_db, load_session
from ..models import AuthSession, Module, OwnershipTeam, User, utcnow
from ..security import audit, hash_password, needs_rehash, new_token, password_problem, token_hash, verify_password

router = APIRouter(prefix="/api/auth")


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=256)


class PasswordIn(BaseModel):
    current: str = Field(default="", max_length=256)
    new: str = Field(max_length=256)


def start_session(request: Request, db: Session, user: User, method: str) -> tuple[str, AuthSession]:
    settings = request.app.state.settings
    token = new_token()
    now = utcnow()
    sess = AuthSession(token_hash=token_hash(token), csrf_token=new_token(), user_id=user.id, created_at=now,
                       last_seen_at=now, expires_at=now + timedelta(hours=settings.session_max_hours),
                       ip=client_ip(request), user_agent=request.headers.get("user-agent", "")[:255], method=method)
    db.add(sess)
    user.last_login_at, user.failed_logins, user.locked_until = now, 0, None
    audit(db, "auth.login", user, "user", user.id, client_ip(request), method=method)
    db.commit()
    return token, sess


def set_session_cookie(request: Request, response, token: str) -> None:
    settings = request.app.state.settings
    response.set_cookie(SESSION_COOKIE, token, max_age=settings.session_max_hours * 3600, httponly=True,
                        secure=settings.cookie_secure, samesite="lax", path="/")


def teams_for(p: Principal, db: Session, module: str, action: str) -> list[str]:
    """Teams in the ownership chart this person may act for with this module action."""
    teams = [t.team for t in db.scalars(select(OwnershipTeam).order_by(OwnershipTeam.team))]
    return [t for t in teams if p.team_allowed(t, module, action)]


def me_json(db: Session, p: Principal, sess: AuthSession) -> dict:
    names = {m.key: m.name for m in db.scalars(select(Module))}
    mods = p.modules()
    return {
        "user": {"id": p.user.id, "email": p.user.email, "name": p.user.display_name,
                 "must_change_password": p.user.must_change_password, "has_password": bool(p.user.password_hash),
                 "expires_at": p.user.expires_at.isoformat(timespec="seconds") if p.user.expires_at else None,
                 "read_only": p.read_only},
        "roles": [{"role": r, "scope": s.label(), "scope_type": s.type, "scope_value": s.value} for r, s in p.roles],
        "modules": [{"key": k, "name": names.get(k, k), "actions": mods[k],
                     "scope": sorted({s.label() for a in mods[k] for s in p.scopes(k, a)})} for k in sorted(mods)],
        "raise_for_teams": teams_for(p, db, "M-PJ", "act"),
        "csrf_token": sess.csrf_token,
        "session_method": sess.method,
    }


@router.get("/config")
def auth_config(request: Request):
    s = request.app.state.settings
    return {"local": s.allow_local_login, "oidc": s.oidc_enabled, "oidc_label": s.oidc_label,
            "min_password_length": s.min_password_length}


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    settings = request.app.state.settings
    if not settings.allow_local_login:
        raise HTTPException(403, "Password sign-in is turned off. Use single sign-on.")
    email = body.email.strip().lower()
    user = db.scalars(select(User).where(func.lower(User.email) == email)).first()
    ip = client_ip(request)
    now = utcnow()
    if user and user.locked_until and user.locked_until > now:
        verify_password(None, body.password)  # same work either way
        audit(db, "auth.login_locked", user, "user", user.id, ip)
        db.commit()
        raise HTTPException(429, "Too many failed attempts. Try again later or ask an admin to unlock the account.")
    ok = verify_password(user, body.password)
    if not ok or not account_usable(user):
        if user is not None:
            user.failed_logins += 1
            if user.failed_logins >= settings.max_failed_logins:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_logins = 0
                audit(db, "auth.locked", user, "user", user.id, ip)
        audit(db, "auth.login_failed", user, "user", user.id if user else "", ip,
              email=email if user is None else None)
        db.commit()
        raise HTTPException(401, "Email or password is wrong, or the account is disabled.")
    if needs_rehash(user):
        user.password_hash = hash_password(body.password)
    token, sess = start_session(request, db, user, "password")
    p = build_principal(db, user)
    response = JSONResponse(me_json(db, p, sess))
    set_session_cookie(request, response, token)
    return response


@router.post("/logout")
def logout(request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    found = load_session(request, db)
    if found:
        db.delete(found[0])
    audit(db, "auth.logout", p.user, "user", p.user.id, client_ip(request))
    db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/me")
def me(request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    sess, _ = load_session(request, db)
    return me_json(db, p, sess)


@router.post("/password")
def change_password(body: PasswordIn, request: Request, p: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    user = db.get(User, p.user.id)
    if user.password_hash and not verify_password(user, body.current):
        audit(db, "auth.password_change_failed", user, "user", user.id, client_ip(request))
        db.commit()
        raise HTTPException(400, "Your current password is wrong.")
    problem = password_problem(body.new, request.app.state.settings.min_password_length)
    if problem:
        raise HTTPException(400, problem)
    if user.password_hash and verify_password(user, body.new):
        raise HTTPException(400, "Choose a password different from the current one.")
    user.password_hash = hash_password(body.new)
    user.must_change_password = False
    current, _ = load_session(request, db)
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.id != current.id)):
        db.delete(s)  # sign out everywhere else
    audit(db, "auth.password_changed", user, "user", user.id, client_ip(request))
    db.commit()
    return {"ok": True}


# ---------- OpenID Connect (Entra ID or any standard provider) ----------

def _oauth(request: Request):
    app = request.app
    if getattr(app.state, "oauth", None) is None:
        from authlib.integrations.starlette_client import OAuth

        s = app.state.settings
        oauth = OAuth()
        oauth.register("oidc", client_id=s.oidc_client_id, client_secret=s.oidc_client_secret,
                       server_metadata_url=s.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
                       client_kwargs={"scope": "openid email profile"})
        app.state.oauth = oauth
    return app.state.oauth.oidc


@router.get("/oidc/login")
async def oidc_login(request: Request):
    if not request.app.state.settings.oidc_enabled:
        raise HTTPException(404, "Single sign-on is not configured.")
    return await _oauth(request).authorize_redirect(request, str(request.url_for("oidc_callback")))


@router.get("/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request, db: Session = Depends(get_db)):
    if not request.app.state.settings.oidc_enabled:
        raise HTTPException(404, "Single sign-on is not configured.")
    from authlib.integrations.base_client import OAuthError

    try:
        token = await _oauth(request).authorize_access_token(request)
    except OAuthError as e:
        audit(db, "auth.sso_failed", None, "", "", client_ip(request), error=e.error)
        db.commit()
        return RedirectResponse("/#/login?error=sso", status_code=303)
    claims = token.get("userinfo") or {}
    subject = f"{claims.get('iss', '')}|{claims.get('sub', '')}"
    # Entra ID puts the sign-in name in preferred_username; other providers use email.
    email = str(claims.get("email") or claims.get("preferred_username") or "").strip().lower()
    user = db.scalars(select(User).where(User.oidc_subject == subject)).first()
    if user is None and email:
        # No self sign-up: an admin must have created the account. Link it on first SSO sign-in.
        user = db.scalars(select(User).where(func.lower(User.email) == email, User.oidc_subject.is_(None))).first()
        if user is not None:
            user.oidc_subject = subject
            audit(db, "auth.sso_linked", user, "user", user.id, client_ip(request))
    if not account_usable(user):
        audit(db, "auth.sso_refused", user, "user", user.id if user else "", client_ip(request), email=email)
        db.commit()
        return RedirectResponse("/#/login?error=no-account", status_code=303)
    token_value, _ = start_session(request, db, user, "oidc")
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(request, response, token_value)
    return response

