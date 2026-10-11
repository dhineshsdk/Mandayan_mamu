"""Database tables for people, access, ownership, jobs and the audit log.

All timestamps are stored as naive UTC (``utcnow()``) so SQLite and Postgres behave the same.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Module(Base):
    __tablename__ = "modules"
    key: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    built: Mapped[bool] = mapped_column(Boolean, default=False)
    licensed: Mapped[bool] = mapped_column(Boolean, default=True)


class Role(Base):
    __tablename__ = "roles"
    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(Text, default="")
    scope_type: Mapped[str] = mapped_column(String(16))  # the kind of scope an assignment of this role takes
    time_limited: Mapped[bool] = mapped_column(Boolean, default=False)
    permissions: Mapped[list[RolePermission]] = relationship(cascade="all, delete-orphan", lazy="selectin")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_key: Mapped[str] = mapped_column(ForeignKey("roles.key", ondelete="CASCADE"), primary_key=True)
    module_key: Mapped[str] = mapped_column(ForeignKey("modules.key", ondelete="CASCADE"), primary_key=True)
    action: Mapped[str] = mapped_column(String(16), primary_key=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    oidc_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    roles: Mapped[list[UserRole]] = relationship(cascade="all, delete-orphan", lazy="selectin")
    grants: Mapped[list[ModuleGrant]] = relationship(cascade="all, delete-orphan", lazy="selectin",
                                                     foreign_keys="ModuleGrant.user_id")


class UserRole(Base):
    """A role held by a person, over one scope (org, a vertical, a site or a team)."""

    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_key", "scope_type", "scope_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role_key: Mapped[str] = mapped_column(ForeignKey("roles.key"))
    scope_type: Mapped[str] = mapped_column(String(16))
    scope_value: Mapped[str] = mapped_column(String(120), default="")


class ModuleGrant(Base):
    """A per-person exception: add a module action (effect=allow) or take a module away (effect=deny)."""

    __tablename__ = "module_grants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    module_key: Mapped[str] = mapped_column(ForeignKey("modules.key"))
    action: Mapped[str] = mapped_column(String(16))  # for deny, "*" removes the whole module
    effect: Mapped[str] = mapped_column(String(8))  # allow | deny
    scope_type: Mapped[str] = mapped_column(String(16), default="org")
    scope_value: Mapped[str] = mapped_column(String(120), default="")
    granted_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    method: Mapped[str] = mapped_column(String(16), default="password")


class OwnershipTeam(Base):
    """One row of the ownership chart: who owns, manages and heads each team's assets."""

    __tablename__ = "ownership_teams"
    team: Mapped[str] = mapped_column(String(120), primary_key=True)
    jira_project: Mapped[str] = mapped_column(String(40), default="")
    manager_name: Mapped[str] = mapped_column(String(120), default="")
    manager_email: Mapped[str] = mapped_column(String(254), default="")
    vertical: Mapped[str] = mapped_column(String(120), default="")
    vertical_head_name: Mapped[str] = mapped_column(String(120), default="")
    vertical_head_email: Mapped[str] = mapped_column(String(254), default="")
    vm_analyst_name: Mapped[str] = mapped_column(String(120), default="")
    vm_analyst_email: Mapped[str] = mapped_column(String(254), default="")


class Setting(Base):
    """Small JSON settings, such as approval thresholds."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Dataset(Base):
    """An analysed set of import files (Milestone 2 replaces this with per-import snapshots)."""

    __tablename__ = "datasets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_name: Mapped[str] = mapped_column(String(200), default="")
    kind: Mapped[str] = mapped_column(String(16))  # upload | demo
    files: Mapped[list] = mapped_column(JSON)  # [{"path", "name", "format"}]
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    rc_id: Mapped[str] = mapped_column(String(16))
    rc_title: Mapped[str] = mapped_column(Text)
    team: Mapped[str] = mapped_column(String(120), index=True)
    vertical: Mapped[str] = mapped_column(String(120), default="")
    mode: Mapped[str] = mapped_column(String(16))  # patch | manual
    status: Mapped[str] = mapped_column(String(20))  # pending | approved | rejected | sent-back | fixing-manually
    ssvc: Mapped[str] = mapped_column(String(8))
    is_ot: Mapped[bool] = mapped_column(Boolean, default=False)
    jira_key: Mapped[str] = mapped_column(String(40), default="")
    ticket: Mapped[str] = mapped_column(String(80), default="")
    hosts: Mapped[list] = mapped_column(JSON)
    findings: Mapped[list] = mapped_column(JSON)
    route: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    draft: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    raised_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    steps: Mapped[list[JobStep]] = relationship(cascade="all, delete-orphan", lazy="selectin",
                                                order_by="JobStep.position")


class JobStep(Base):
    __tablename__ = "job_steps"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    role: Mapped[str] = mapped_column(String(20))  # manager | vm_analyst | vertical_head
    expected_email: Mapped[str] = mapped_column(String(254), default="")  # from the ownership chart
    expected_name: Mapped[str] = mapped_column(String(120), default="")
    state: Mapped[str] = mapped_column(String(12), default="waiting")  # waiting|current|approved|rejected|sent-back
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    comment: Mapped[str] = mapped_column(Text, default="")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_email: Mapped[str] = mapped_column(String(254), default="")
    action: Mapped[str] = mapped_column(String(60), index=True)
    target_type: Mapped[str] = mapped_column(String(40), default="")
    target_id: Mapped[str] = mapped_column(String(120), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")
