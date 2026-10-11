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
    oidc_client_secret: str = field(default_factory=lambda: os.environ.get("SUTRA_OIDC_CLIENT_SECRET", ""))
    oidc_label: str = field(default_factory=lambda: os.environ.get("SUTRA_OIDC_LABEL", "Single sign-on"))
    allow_local_login: bool = field(default_factory=lambda: _bool("SUTRA_ALLOW_LOCAL_LOGIN", True))

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
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)
