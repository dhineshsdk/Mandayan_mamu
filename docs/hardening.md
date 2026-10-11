# Hardening and data residency

## Layers, and what enforces each

| Layer | What it does | Enforced by |
|---|---|---|
| Service confinement | Runs as the unprivileged `sutra` user; writes only to its data folder; no new privileges, no kernel or device access | `systemd/sutra.service` |
| Files | Data folder 700, `sutra.env` 640 root:sutra, secret key 600, database not world-readable | `install.sh`; `sutra doctor` re-checks |
| Transport | TLS at the proxy, secure cookies, HSTS sent by Sutra when cookies are secure | nginx example; `SUTRA_COOKIE_SECURE=1` |
| Sign-in | SSO with your identity provider's MFA; local passwords of 12+ characters with lockout after repeated failures | `SUTRA_OIDC_*`; `doctor` warns when only local passwords exist |
| Access | Every request is checked on the server by role, module and scope; every change is audited | the application (role matrix test) |
| Licence | Without a valid key only Administration runs | `SUTRA_REQUIRE_LICENCE=1` |
| Outbound connections | Only hosts on `SUTRA_EGRESS_ALLOW` (plus private addresses) can be contacted; refused attempts are listed in Administration → AI | `sutra/app/egress.py` |
| Backups | Nightly, encrypted, hash-verified, pruned to 14 | `sutra-backup.timer`; `doctor` warns when stale |

## Network rules (do these too)

The egress allow-list lives inside the Sutra process. It is the second lock: a library that connects without Python's
socket module (PostgreSQL's `libpq`) is not covered, and a compromised process could remove it. Put the same rule at the
firewall:

* Inbound to the Sutra server: only your TLS proxy (443 from users) and SSH from your admin network.
* Outbound from the Sutra server: deny by default; allow only the hosts in `SUTRA_EGRESS_ALLOW` and your internal
  scanner, directory, ticketing and mail systems.

## Data kept in India

Sutra stores everything on the server you install it on: the database, uploaded scanner exports and evidence, the
secret key and the backups. That server's location is your choice; put it in your own premises or an Indian data
centre, or a cloud region in India (for example AWS Asia Pacific (Mumbai) `ap-south-1`, Azure Central India, Google
Cloud `asia-south1`; confirm the region list with your provider). What this software adds:

* **No telemetry and no update check.** Sutra contains no code that reports usage or checks for versions. The only
  outbound connections are the integrations you configure, and each one is off until configured: scanner pulls and
  cloud connectors, Teams, Jira, ServiceNow, SMTP, Entra ID directory sync, the CISA and FIRST feeds, a cloud AI model.
* **Allow-list by default.** The installer sets `SUTRA_EGRESS=allowlist`, so none of those can send anything until an
  administrator names the host. Refusals are visible and counted.
* **Cloud AI is blocked by default.** With the allow-list on, the Anthropic API is unreachable until
  `api.anthropic.com` is allowed. Using a model inside your network needs no listing for private addresses. Even when a
  model is used it is shown typed facts, not raw scanner text (see the README's AI section).
* **Backups** are encrypted. Where you copy them is your responsibility: keep the off-server copy in India as well.

This is a description of the software's behaviour, not legal advice about the DPDP Act or sector rules. Your counsel and
your auditor decide what satisfies them; `docs/range/SCORE.md` and the audit log are the evidence Sutra can give.

## The check

`python -m sutra doctor` (with the service's environment) prints PASS, WARN or FAIL for: service user, file permissions,
secret key, secure cookies, base URL, sign-in method, password length, outbound policy, AI model, licence, database
schema, demo accounts, administrator, backup age and backup encryption. It exits 1 on any FAIL, so it can run from your
monitoring. It reads and reports; it changes nothing and sends nothing.

## Not done by Sutra

Hardening of the operating system itself (CIS benchmark, SSH policy, host patching, disk encryption, time sync),
the TLS certificate, the firewall, and off-server backup transport are the customer's. Sutra does not manage them.
