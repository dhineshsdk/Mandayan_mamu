"""Request dependencies: database session, the signed-in person, module checks and CSRF."""

from __future__ import annotations

import hmac
from collections.abc import Callable, Iterator
from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .access import Principal, account_usable, build_principal
from .models import AuthSession, User, utcnow
from .security import audit, token_hash

SESSION_COOKIE = "sutra_session"
CSRF_HEADER = "x-csrf-token"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def get_db(request: Request) -> Iterator[Session]:
    db = request.app.state.sessionmaker()
    try:
        yield db
    finally:
        db.close()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def load_session(request: Request, db: Session) -> tuple[AuthSession, User] | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    sess = db.scalars(select(AuthSession).where(AuthSession.token_hash == token_hash(token))).first()
    if sess is None:
        return None
    now = utcnow()
    settings = request.app.state.settings
    if sess.expires_at <= now or sess.last_seen_at + timedelta(minutes=settings.session_idle_minutes) <= now:
        db.delete(sess)
        db.commit()
        return None
    user = db.get(User, sess.user_id)
    if not account_usable(user):
        db.delete(sess)
        db.commit()
        return None
    if (now - sess.last_seen_at).total_seconds() > 60:
        sess.last_seen_at = now
        db.commit()
    return sess, user


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    found = load_session(request, db)
    if found is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    sess, user = found
    if request.method in UNSAFE:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not hmac.compare_digest(sent, sess.csrf_token):
            raise HTTPException(status_code=403, detail="Missing or invalid CSRF token. Reload the page.")
    if user.must_change_password and request.url.path not in ("/api/auth/password", "/api/auth/logout",
                                                              "/api/auth/me"):
        raise HTTPException(status_code=403, detail="Change your password to continue.")
    p = build_principal(db, user)
    request.state.principal = p
    return p


def require(module: str, action: str) -> Callable[..., Principal]:
    """Dependency: the signed-in person must have ``action`` on ``module`` (in some scope)."""

    def check(request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        if not p.can(module, action):
            audit(db, "access.denied", p.user, "module", module, client_ip(request), action=action,
                  path=request.url.path, method=request.method)
            db.commit()
            raise HTTPException(status_code=403, detail="You do not have access to this.")
        return p

    return check


def require_any(*pairs: tuple[str, str]) -> Callable[..., Principal]:
    def check(request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        if not any(p.can(m, a) for m, a in pairs):
            audit(db, "access.denied", p.user, "module", ",".join(m for m, _ in pairs), client_ip(request),
                  path=request.url.path, method=request.method)
            db.commit()
            raise HTTPException(status_code=403, detail="You do not have access to this.")
        return p

    return check
