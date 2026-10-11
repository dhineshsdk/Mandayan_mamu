"""Database tables for people, access, ownership, jobs and the audit log.

All timestamps are stored as naive UTC (``utcnow()``) so SQLite and Postgres behave the same.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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
    # Entra ID object ID once directory sync has matched this person; "" state means not managed by the sync,
    # "active" means in a mapped group, "removed" means the sync disabled the account after they left every group.
    directory_id: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    directory_state: Mapped[str] = mapped_column(String(16), default="", server_default="")
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
    # "manual" (set by an admin) or "entra" (granted by directory sync from a group mapping; the sync owns it)
    source: Mapped[str] = mapped_column(String(16), default="manual", server_default="manual")


class DirectoryGroupMap(Base):
    """Members of an Entra ID group get this role over this scope. Directory sync applies the mappings."""

    __tablename__ = "directory_group_maps"
    __table_args__ = (UniqueConstraint("group_id", "role_key", "scope_type", "scope_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[str] = mapped_column(String(64), index=True)
    group_name: Mapped[str] = mapped_column(String(256), default="")
    role_key: Mapped[str] = mapped_column(ForeignKey("roles.key"))
    scope_type: Mapped[str] = mapped_column(String(16))
    scope_value: Mapped[str] = mapped_column(String(120), default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
    """One import: the files, when the scans happened (as_of) and when Sutra saw them (created_at).

    Every import is kept. Its assets and findings are stored as a snapshot (AssetSnapshot, Observation),
    which is what history, "first seen" and "fixed since the last import" are computed from.
    """

    __tablename__ = "datasets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_name: Mapped[str] = mapped_column(String(200), default="")
    kind: Mapped[str] = mapped_column(String(16))  # upload | demo
    files: Mapped[list] = mapped_column(JSON)  # [{"path", "name", "format"}]
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)  # when Sutra saw it
    as_of: Mapped[date | None] = mapped_column(Date, nullable=True)  # latest scan date in the files
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class AssetSnapshot(Base):
    """An asset as it stood in one import."""

    __tablename__ = "asset_snapshots"
    __table_args__ = (UniqueConstraint("dataset_id", "asset_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(String(120))
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    site: Mapped[str] = mapped_column(String(120), default="")
    team: Mapped[str] = mapped_column(String(120), default="")  # owner in the asset register
    owned: Mapped[bool] = mapped_column(Boolean, default=False)  # team is in the ownership chart
    in_cmdb: Mapped[bool] = mapped_column(Boolean, default=True)
    scanned: Mapped[bool] = mapped_column(Boolean, default=False)
    is_ot: Mapped[bool] = mapped_column(Boolean, default=False)
    criticality: Mapped[int] = mapped_column(Integer, default=3)


class Observation(Base):
    """A finding seen in one import. ``first_seen``/``last_seen`` are when the scanners saw it happen;
    ``first_imported_at`` is when Sutra first saw it, in this or an earlier import."""

    __tablename__ = "observations"
    __table_args__ = (UniqueConstraint("dataset_id", "asset_id", "fingerprint"),
                      Index("ix_observations_identity", "asset_id", "fingerprint"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(String(120))
    fingerprint: Mapped[str] = mapped_column(String(400))
    team: Mapped[str] = mapped_column(String(120), default="")
    site: Mapped[str] = mapped_column(String(120), default="")
    title: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(12), default="")
    cves: Mapped[list] = mapped_column(JSON, default=list)
    rc_key: Mapped[str] = mapped_column(String(400), default="")
    rc_title: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_seen: Mapped[date | None] = mapped_column(Date, nullable=True)
    first_imported_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    rc_id: Mapped[str] = mapped_column(String(16))  # the ID in the import the job was raised from
    rc_key: Mapped[str] = mapped_column(String(400), default="")  # stable across imports
    rc_title: Mapped[str] = mapped_column(Text)
    team: Mapped[str] = mapped_column(String(120), index=True)
    vertical: Mapped[str] = mapped_column(String(120), default="")
    mode: Mapped[str] = mapped_column(String(16))  # patch | manual | exception
    # drafting | pending | approved | fixing-manually | reopened (open); rejected | sent-back | draft-failed |
    # verified-fixed (closed). Only a rescan sets verified-fixed or reopened (sutra.app.closure).
    # Risk acceptances (mode "exception"): pending -> accepted -> expired (sutra.app.sweeper), or verified-fixed.
    status: Mapped[str] = mapped_column(String(20))
    ssvc: Mapped[str] = mapped_column(String(8))
    is_ot: Mapped[bool] = mapped_column(Boolean, default=False)
    jira_key: Mapped[str] = mapped_column(String(40), default="")  # set only once Jira has created the issue
    servicenow_number: Mapped[str] = mapped_column(String(40), default="")
    servicenow_sys_id: Mapped[str] = mapped_column(String(32), default="")
    ticket: Mapped[str] = mapped_column(String(80), default="")
    hosts: Mapped[list] = mapped_column(JSON)
    findings: Mapped[list] = mapped_column(JSON)
    route: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    draft: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # The (asset_id, fingerprint) pairs the job must make disappear; what rescans are checked against.
    targets: Mapped[list] = mapped_column(JSON, default=list)
    # Risk acceptance only: why, what holds the risk down meanwhile, and when the acceptance ends.
    justification: Mapped[str] = mapped_column(Text, default="")
    compensating_control: Mapped[str] = mapped_column(Text, default="")
    expires_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    raised_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    due_on: Mapped[date | None] = mapped_column(Date, nullable=True)  # fix SLA by SSVC (sutra.app.sla)
    sla_breached_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    fixed_on: Mapped[date | None] = mapped_column(Date, nullable=True)  # scan date of the rescan that proved it
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # when Sutra saw that rescan
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
    opened_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # when it became the current step
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    escalated_to: Mapped[str] = mapped_column(String(20), default="")  # the role told the step has stalled


class OtPlan(Base):
    """What the plant engineer records for an OT job: OEM approval, the compensating control held until the
    shutdown, the confirmed shutdown slot, and each attempt to apply the fix. Closure still comes only from a rescan."""

    __tablename__ = "ot_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), unique=True)
    sites: Mapped[list] = mapped_column(JSON, default=list)  # plants of the job's OT hosts; who may act on it
    oem_state: Mapped[str] = mapped_column(String(16), default="not-requested")  # requested | approved | refused
    oem_reference: Mapped[str] = mapped_column(String(120), default="")  # the OEM's case or letter reference
    oem_requested_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    oem_decided_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    oem_note: Mapped[str] = mapped_column(Text, default="")
    control: Mapped[str] = mapped_column(Text, default="")  # compensating control confirmed in place
    control_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    slot_on: Mapped[date | None] = mapped_column(Date, nullable=True)  # confirmed shutdown date
    slot_start: Mapped[str] = mapped_column(String(5), default="")  # HH:MM, plant local time
    slot_hours: Mapped[int] = mapped_column(Integer, default=0)
    slot_with: Mapped[str] = mapped_column(String(120), default="")  # who in operations confirmed it
    # [{"on", "result", "hosts", "note", "by", "at"}], newest last
    executions: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class JobCheck(Base):
    """What one import showed for one job's targets."""

    __tablename__ = "job_checks"
    __table_args__ = (UniqueConstraint("job_id", "dataset_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    as_of: Mapped[date | None] = mapped_column(Date, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    fixed: Mapped[int] = mapped_column(Integer, default=0)
    still_open: Mapped[int] = mapped_column(Integer, default=0)
    not_rescanned: Mapped[int] = mapped_column(Integer, default=0)
    outcome: Mapped[str] = mapped_column(String(16))  # fixed | partly-fixed | not-fixed | not-rescanned | reopened
    still_open_items: Mapped[list] = mapped_column(JSON, default=list)  # [[asset_id, fingerprint]], capped


class Outbox(Base):
    """A message or ticket update waiting to go out, retried until it is sent or gives up.

    kind: email | teams | jira.create | jira.comment | jira.done | servicenow.create | servicenow.note
    status: queued | sent | failed (gave up) | skipped (that integration is not configured)
    """

    __tablename__ = "outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(40), default="")
    recipient: Mapped[str] = mapped_column(String(254), default="")
    subject: Mapped[str] = mapped_column(String(300), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(10), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")


class ScannerConnection(Base):
    """A scanner API Sutra pulls from (``sutra_connectors``). The secret is encrypted (``sutra.app.vault``)."""

    __tablename__ = "scanner_connections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # a key of sutra.app.scanpull.KINDS
    name: Mapped[str] = mapped_column(String(80))
    base_url: Mapped[str] = mapped_column(String(300))
    username: Mapped[str] = mapped_column(String(200), default="")  # Qualys user name or Tenable access key
    secret: Mapped[str] = mapped_column(Text, default="")  # encrypted password or secret key
    ca_bundle: Mapped[str] = mapped_column(String(500), default="")  # path to a CA bundle for an internal CA
    options: Mapped[dict] = mapped_column(JSON, default=dict)  # settings only some kinds have (scanpull.KINDS)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ScanPull(Base):
    """One scheduled or manual refresh from every enabled scanner API, and what it produced."""

    __tablename__ = "scan_pulls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    trigger: Mapped[str] = mapped_column(String(16))  # schedule | manual
    started_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(12), default="running")  # running | ok | failed
    # [{"connection", "name", "findings", "hosts", "error"}] per scanner connection
    results: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    dataset_id: Mapped[int | None] = mapped_column(ForeignKey("datasets.id", ondelete="SET NULL"), nullable=True)


class NetworkDevice(Base):
    """A firewall or switch Sutra reads its configuration from, read-only (``sutra.app.netconfig``). The secret is
    encrypted (``sutra.app.vault``)."""

    __tablename__ = "network_devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # a key of sutra.app.netconfig.KINDS
    name: Mapped[str] = mapped_column(String(80))
    address: Mapped[str] = mapped_column(String(300))  # https:// URL for API kinds, host or host:port for SSH
    username: Mapped[str] = mapped_column(String(200), default="")  # SSH kinds only
    secret: Mapped[str] = mapped_column(Text, default="")  # encrypted API token, API key or password
    ca_bundle: Mapped[str] = mapped_column(String(500), default="")
    host_key: Mapped[str] = mapped_column(String(100), default="")  # pinned SSH host key fingerprint
    site: Mapped[str] = mapped_column(String(80), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # "" (never tried) | first | changed | unchanged | failed
    last_status: Mapped[str] = mapped_column(String(12), default="")
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ConfigSnapshot(Base):
    """One distinct configuration of a device, secrets already masked. A collection that finds the same configuration
    as the latest snapshot only moves ``last_seen_at``."""

    __tablename__ = "config_snapshots"
    __table_args__ = (Index("ix_config_snapshots_device", "device_id", "id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)  # first seen
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    digest: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str] = mapped_column(String(200), default="")
    model: Mapped[str] = mapped_column(String(120), default="")
    serial: Mapped[str] = mapped_column(String(120), default="")
    version: Mapped[str] = mapped_column(String(120), default="")
    config_format: Mapped[str] = mapped_column(String(16))
    config: Mapped[str] = mapped_column(Text)
    masked: Mapped[int] = mapped_column(Integer, default=0)
    facts: Mapped[dict] = mapped_column(JSON, default=dict)
    # [{"ip", "mac", "interface"}] and [{"mac", "vlan", "port"}] as of last_seen_at (switches only)
    arp: Mapped[list] = mapped_column(JSON, default=list)
    mac_table: Mapped[list] = mapped_column(JSON, default=list)


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
