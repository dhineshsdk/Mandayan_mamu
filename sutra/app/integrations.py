"""Senders for email (SMTP), Microsoft Teams, Jira and ServiceNow. Each call either succeeds or raises.

Endpoints used, all documented by the vendors:

- Jira REST API (Cloud v3, Data Center v2): ``POST /rest/api/{v}/issue`` with ``{"fields": {...}}`` returns the new
  issue's ``key``; ``POST /rest/api/{v}/issue/{key}/comment`` with ``{"body": ...}`` (Atlassian Document Format in
  v3, plain text in v2); ``GET`` and ``POST /rest/api/{v}/issue/{key}/transitions`` with
  ``{"transition": {"id": ...}}`` to move an issue to a status. Cloud authenticates with the account email and an API
  token (basic auth); Data Center with a personal access token (bearer).
- ServiceNow Table API: ``POST /api/now/table/{table}`` returns ``{"result": {"sys_id", "number", ...}}``;
  ``PATCH /api/now/table/{table}/{sys_id}`` with ``work_notes`` adds a work note. Basic auth.
- Microsoft Teams: a JSON ``message`` with an Adaptive Card attachment POSTed to a webhook URL, as in Microsoft's
  incoming-webhook documentation. Microsoft is retiring Office 365 connectors in favour of Workflows; the
  "Send webhook alerts to a channel" workflow gives a URL that accepts the same envelope.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

import httpx

from .config import Settings

TIMEOUT = httpx.Timeout(30.0)


class NotConfigured(Exception):
    """The integration has no settings; the message is skipped rather than retried."""


class Senders:
    """``transport`` and ``smtp`` are for tests: an httpx transport and an SMTP class."""

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None, smtp=None):
        self.s = settings
        self.transport = transport
        self.smtp = smtp or (smtplib.SMTP_SSL if settings.smtp_port == 465 else smtplib.SMTP)

    def _client(self, **kw) -> httpx.Client:
        # follow_redirects stays off so credentials are never sent to another host.
        return httpx.Client(timeout=TIMEOUT, transport=self.transport, follow_redirects=False, **kw)

    # ---------- email ----------

    def email(self, to: str, subject: str, body: str) -> None:
        s = self.s
        if not s.email_enabled:
            raise NotConfigured("email is not configured (SUTRA_SMTP_HOST, SUTRA_SMTP_FROM)")
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = s.smtp_from, to, subject
        msg.set_content(body)
        ctx = ssl.create_default_context()
        kwargs = {"context": ctx} if self.smtp is smtplib.SMTP_SSL else {}
        with self.smtp(s.smtp_host, s.smtp_port, timeout=30, **kwargs) as smtp:
            if self.smtp is not smtplib.SMTP_SSL and s.smtp_starttls:
                smtp.starttls(context=ctx)
            if s.smtp_user:
                smtp.login(s.smtp_user, s.smtp_password)
            smtp.send_message(msg)

    # ---------- Teams ----------

    def teams(self, title: str, text: str, link: str = "") -> None:
        if not self.s.teams_webhook_url:
            raise NotConfigured("Teams is not configured (SUTRA_TEAMS_WEBHOOK_URL)")
        body = [{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
                {"type": "TextBlock", "text": text, "wrap": True}]
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.4", "body": body}
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in Sutra", "url": link}]
        payload = {"type": "message",
                   "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
        with self._client() as c:
            c.post(self.s.teams_webhook_url, json=payload).raise_for_status()

    # ---------- Jira ----------

    def _jira(self) -> httpx.Client:
        s = self.s
        if not s.jira_enabled:
            raise NotConfigured("Jira is not configured (SUTRA_JIRA_URL, SUTRA_JIRA_TOKEN)")
        if s.jira_user:  # Cloud: account email + API token
            return self._client(base_url=s.jira_url, auth=(s.jira_user, s.jira_token),
                                headers={"Accept": "application/json"})
        return self._client(base_url=s.jira_url, headers={"Accept": "application/json",
                                                          "Authorization": f"Bearer {s.jira_token}"})

    def _jira_text(self, text: str):
        if self.s.jira_api == "2":
            return text
        paragraphs = [p for p in text.split("\n") if p.strip()] or [""]
        return {"type": "doc", "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": p}] if p else []}
                            for p in paragraphs]}

    def jira_create(self, project: str, summary: str, description: str) -> str:
        fields = {"project": {"key": project}, "summary": summary[:250],
                  "issuetype": {"name": self.s.jira_issue_type}, "description": self._jira_text(description)}
        with self._jira() as c:
            r = c.post(f"/rest/api/{self.s.jira_api}/issue", json={"fields": fields})
            r.raise_for_status()
            return r.json()["key"]

    def jira_comment(self, key: str, text: str) -> None:
        with self._jira() as c:
            c.post(f"/rest/api/{self.s.jira_api}/issue/{key}/comment",
                   json={"body": self._jira_text(text)}).raise_for_status()

    def jira_transition(self, key: str, status: str) -> bool:
        """Move the issue to ``status`` if a transition leads there. False if none does (the issue is left alone)."""
        with self._jira() as c:
            r = c.get(f"/rest/api/{self.s.jira_api}/issue/{key}/transitions")
            r.raise_for_status()
            match = next((t for t in r.json().get("transitions", [])
                          if t.get("to", {}).get("name", "").lower() == status.lower()), None)
            if match is None:
                return False
            c.post(f"/rest/api/{self.s.jira_api}/issue/{key}/transitions",
                   json={"transition": {"id": match["id"]}}).raise_for_status()
            return True

    # ---------- ServiceNow ----------

    def _snow(self) -> httpx.Client:
        s = self.s
        if not s.servicenow_enabled:
            raise NotConfigured("ServiceNow is not configured (SUTRA_SERVICENOW_URL, _USER, _PASSWORD)")
        return self._client(base_url=s.servicenow_url, auth=(s.servicenow_user, s.servicenow_password),
                            headers={"Accept": "application/json"})

    def servicenow_create(self, short_description: str, description: str) -> tuple[str, str]:
        with self._snow() as c:
            r = c.post(f"/api/now/table/{self.s.servicenow_table}",
                       json={"short_description": short_description[:160], "description": description})
            r.raise_for_status()
            res = r.json()["result"]
            return res["sys_id"], res.get("number", "")

    def servicenow_note(self, sys_id: str, text: str) -> None:
        with self._snow() as c:
            c.patch(f"/api/now/table/{self.s.servicenow_table}/{sys_id}",
                    json={"work_notes": text}).raise_for_status()
