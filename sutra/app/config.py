"""Settings, read from environment variables (prefix SUTRA_)."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    workspace: Path = field(default_factory=lambda: Path(os.environ.get("SUTRA_WORKSPACE", "workspace")))
    database_url: str = ""
    # Signs the short-lived OIDC state cookie. Sessions themselves are random tokens stored hashed in the database.
    secret_key: str = ""
    # Cookies are Secure (HTTPS only) unless explicitly turned off for local http development.
    cookie_secure: bool = field(default_factory=lambda: _bool("SUTRA_COOKIE_SECURE", True))
    session_idle_minutes: int = field(default_factory=lambda: int(os.environ.get("SUTRA_SESSION_IDLE_MINUTES", "60")))
    session_max_hours: int = field(default_factory=lambda: int(os.environ.get("SUTRA_SESSION_MAX_HOURS", "12")))
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    min_password_length: int = 12
    max_upload_bytes: int = 300 * 1024 * 1024
    # OpenID Connect (Entra ID or any OIDC provider). SSO is on when issuer and client id are set.
    oidc_issuer: str = field(default_factory=lambda: os.environ.get("SUTRA_OIDC_ISSUER", ""))
    oidc_client_id: str = field(default_factory=lambda: os.environ.get("SUTRA_OIDC_CLIENT_ID", ""))
    oidc_client_secret: str = field(default_factory=lambda: os.environ.get("SUTRA_OIDC_CLIENT_SECRET", ""), repr=False)
    oidc_label: str = field(default_factory=lambda: os.environ.get("SUTRA_OIDC_LABEL", "Single sign-on"))
    allow_local_login: bool = field(default_factory=lambda: _bool("SUTRA_ALLOW_LOCAL_LOGIN", True))
    # Links in notifications and tickets, e.g. https://sutra.example.in (no trailing slash). Optional.
    base_url: str = field(default_factory=lambda: os.environ.get("SUTRA_BASE_URL", "").rstrip("/"))
    # Email over SMTP. Off unless SUTRA_SMTP_HOST and SUTRA_SMTP_FROM are set.
    smtp_host: str = field(default_factory=lambda: os.environ.get("SUTRA_SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: int(os.environ.get("SUTRA_SMTP_PORT", "587")))
    smtp_user: str = field(default_factory=lambda: os.environ.get("SUTRA_SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.environ.get("SUTRA_SMTP_PASSWORD", ""), repr=False)
    smtp_from: str = field(default_factory=lambda: os.environ.get("SUTRA_SMTP_FROM", ""))
    smtp_starttls: bool = field(default_factory=lambda: _bool("SUTRA_SMTP_STARTTLS", True))
    # Microsoft Teams: the URL of a Workflows "Send webhook alerts to a channel" flow (or a legacy incoming webhook).
    teams_webhook_url: str = field(default_factory=lambda: os.environ.get("SUTRA_TEAMS_WEBHOOK_URL", ""), repr=False)
    # Jira. Cloud: API version 3 with an account email and API token. Data Center: version 2 with a personal access
    # token and no user. Issues go to the team's project from the ownership chart.
    jira_url: str = field(default_factory=lambda: os.environ.get("SUTRA_JIRA_URL", "").rstrip("/"))
    jira_user: str = field(default_factory=lambda: os.environ.get("SUTRA_JIRA_USER", ""))
    jira_token: str = field(default_factory=lambda: os.environ.get("SUTRA_JIRA_TOKEN", ""), repr=False)
    jira_api: str = field(default_factory=lambda: os.environ.get("SUTRA_JIRA_API", "3"))
    jira_issue_type: str = field(default_factory=lambda: os.environ.get("SUTRA_JIRA_ISSUE_TYPE", "Task"))
    # Status to move the issue to when a rescan proves the fix, e.g. "Done". Empty: comment only.
    jira_done_status: str = field(default_factory=lambda: os.environ.get("SUTRA_JIRA_DONE_STATUS", ""))
    # ServiceNow Table API (basic auth). Records go to this table, e.g. change_request or incident.
    servicenow_url: str = field(default_factory=lambda: os.environ.get("SUTRA_SERVICENOW_URL", "").rstrip("/"))
    servicenow_user: str = field(default_factory=lambda: os.environ.get("SUTRA_SERVICENOW_USER", ""))
    servicenow_password: str = field(default_factory=lambda: os.environ.get("SUTRA_SERVICENOW_PASSWORD", ""),
                                     repr=False)
    servicenow_table: str = field(default_factory=lambda: os.environ.get("SUTRA_SERVICENOW_TABLE", "change_request"))
    # Fetch the CISA KEV catalog and EPSS scores once a day. Off for servers with no internet access; the feed URLs
    # can instead point at an internal mirror (SUTRA_KEV_URL, SUTRA_EPSS_URL).
    intel_refresh: bool = field(default_factory=lambda: _bool("SUTRA_INTEL_REFRESH", True))

    def __post_init__(self):
        self.workspace = Path(self.workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        if not self.database_url:
            self.database_url = os.environ.get("SUTRA_DATABASE_URL") or f"sqlite:///{self.workspace / 'sutra.db'}"
        if not self.secret_key:
            self.secret_key = os.environ.get("SUTRA_SECRET_KEY") or self._local_secret()

    def _local_secret(self) -> str:
        """Generate once and keep in the workspace, readable only by the owner."""
        path = self.workspace / ".secret_key"
        if path.exists():
            return path.read_text().strip()
        key = secrets.token_urlsafe(48)
        path.write_text(key)
        path.chmod(0o600)
        return key

    @property
    def email_enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)

    @property
    def jira_enabled(self) -> bool:
        return bool(self.jira_url and self.jira_token)

    @property
    def servicenow_enabled(self) -> bool:
        return bool(self.servicenow_url and self.servicenow_user and self.servicenow_password)

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)
