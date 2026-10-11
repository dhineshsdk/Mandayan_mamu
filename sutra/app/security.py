"""Passwords (Argon2id), session tokens and the audit log writer."""

from __future__ import annotations

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy.orm import Session

from .models import AuditEvent, User

_hasher = PasswordHasher()  # argon2-cffi defaults follow RFC 9106 recommendations
# Verified against when an account does not exist, so a failed login takes the same time either way.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(user: User | None, password: str) -> bool:
    stored = user.password_hash if user and user.password_hash else _DUMMY_HASH
    try:
        ok = _hasher.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return ok and user is not None and user.password_hash is not None


def needs_rehash(user: User) -> bool:
    return bool(user.password_hash) and _hasher.check_needs_rehash(user.password_hash)


def password_problem(password: str, min_length: int) -> str | None:
    if len(password) < min_length:
        return f"Use at least {min_length} characters."
    if len(password) > 256:
        return "Use at most 256 characters."
    if len(set(password)) < 5:
        return "Use a less repetitive password."
    return None


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def audit(db: Session, event: str, actor: User | None = None, target_type: str = "", target_id: str = "",
          ip: str = "", **detail) -> None:
    """Append an audit event. The caller commits."""
    db.add(AuditEvent(actor_id=actor.id if actor else None, actor_email=actor.email if actor else "",
                      action=event, target_type=target_type, target_id=str(target_id), detail=detail, ip=ip))
