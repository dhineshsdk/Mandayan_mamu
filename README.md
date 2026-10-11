# Sutra: root causes and rupee risk from scanner exports

Sutra reads Qualys and Tenable exports, merges duplicate findings, groups them by the one thing that fixes them,
and shows the board its cyber risk in rupees. It runs on your own server or laptop; files never leave it. Until a design
partner shares real exports, it runs on realistic synthetic data in the same formats.

## Install and run

Python 3.11 or later.

```
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
sutra db-upgrade                                   # creates workspace/sutra.db (SQLite)
sutra create-admin --email you@company.com --name "Your Name"
sutra serve                                        # http://127.0.0.1:8765
```

Sign in as the admin, upload the ownership chart, add people and give them roles, then import scanner exports
under **Import data** (any account with the VM analyst or admin role can).

For a demonstration on synthetic data, `sutra demo-users --profile power` (or `manufacturing`) loads an invented
company and creates one account per role from its ownership chart. Each password is random and printed once.
Restart `sutra serve` afterwards so it picks up the new data.

### Stack and why

| Part | Choice | Why |
| --- | --- | --- |
| Web API | FastAPI on Uvicorn | Typed request validation (pydantic), dependency-injected access checks on every route |
| Database | SQLAlchemy 2 + Alembic migrations | SQLite for a single box; set `SUTRA_DATABASE_URL` to a Postgres URL (`pip install -e .[postgres]`) for a server |
| Passwords | Argon2id (argon2-cffi) | Memory-hard hashing with RFC 9106 defaults |
| Single sign-on | OpenID Connect via Authlib | Works with Entra ID and other OIDC providers |
| Uploads | defusedxml | `.nessus` files are untrusted XML; entity expansion and external entities are refused |
| Web app | Plain HTML, CSS and JavaScript | No build step, so it runs air-gapped |

### Settings

All settings are environment variables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SUTRA_WORKSPACE` | `workspace` | Folder for the database, uploads and analysed datasets |
| `SUTRA_DATABASE_URL` | SQLite in the workspace | Any SQLAlchemy URL |
| `SUTRA_SECRET_KEY` | generated once into `workspace/.secret_key` | Signs the short-lived SSO state cookie |
| `SUTRA_COOKIE_SECURE` | `1` | Session cookies are sent over HTTPS only. Set `0` only for plain-HTTP use on localhost |
| `SUTRA_SESSION_IDLE_MINUTES` / `SUTRA_SESSION_MAX_HOURS` | `60` / `12` | Session timeouts |
| `SUTRA_OIDC_ISSUER`, `SUTRA_OIDC_CLIENT_ID`, `SUTRA_OIDC_CLIENT_SECRET` | unset | Turn on SSO, e.g. issuer `https://login.microsoftonline.com/<tenant-id>/v2.0` for Entra ID. Register `https://<host>/api/auth/oidc/callback` as the redirect URI |
| `SUTRA_OIDC_LABEL` | `Single sign-on` | Text on the sign-in button |
| `SUTRA_ALLOW_LOCAL_LOGIN` | `1` | Set `0` to allow SSO only |

Because `SUTRA_COOKIE_SECURE` defaults to on, run behind HTTPS (a reverse proxy such as nginx or Caddy), or set it to
`0` when trying Sutra on `http://127.0.0.1`.

## Who sees what

Access is **module × action × scope**, decided on the server for every request; the acting person always comes from
the session, never from the request. The roles and modules are data in
[`sutra/data/access_catalog.json`](sutra/data/access_catalog.json), following the product's roles-and-modules design.

| Role | Modules (actions) | Scope |
| --- | --- | --- |
| Team member | Team portal (view, act), Patch jobs (view, act) | Their team |
| Team manager | Team portal (view), Patch jobs (view, approve) | Their team |
| VM analyst | Root causes, Assets, Import data (view, act), Headline check, Patch jobs (view, approve), Board (view) | Organisation |
| Vertical head | Patch jobs (view, approve), Board, Root causes (view) | Their vertical |
| Plant engineer | Team portal (view); OT plans when built | Their site |
| CISO | Board, Root causes, Patch jobs (view), approval thresholds | Organisation |
| Compliance officer | Board, Audit log (view); Compliance when built | Organisation |
| Executive | Board (view) | Organisation |
| Auditor | Audit log (view); Compliance when built. The account must have an end date | Organisation |
| Administrator | Administration, Import data | Organisation |

- An admin can add or remove a single module action for one person, with a reason that goes in the audit log.
- Modules that are not built yet (CISO dashboard, OT plans, Compliance) grant nothing, and an admin can switch a
  module's licence off for everyone.
- Every screen is cut to the person's scope: a vertical head's board shows the rupee risk of their vertical only, and a
  team sees only its own assets.
- **Patch-job approvals**: the manager and vertical head steps can be signed only by the person the ownership chart
  names (matched by email) who also holds that role for the team; the VM analyst step by any VM analyst. The person
  who raised a job cannot approve any step of it, and nobody signs two steps of the same job.
- **Audit log**: sign-ins (and failures and lockouts), every access refused, every role, grant, licence and threshold
  change, every job decision, upload, analysis and export.
- **Sign-in**: Argon2id passwords of at least 12 characters, lockout for 15 minutes after 5 failures, new accounts get a
  one-time password they must change, sessions are random tokens stored hashed, cookies are HttpOnly, Secure and
  SameSite=Lax, and every state change needs a CSRF token. Nobody can change their own access.

SAML sign-in is not built yet; OIDC covers Entra ID. Analysis results are held in memory and rebuilt from the current
import at start-up; moving them into the database with history is Milestone 2 of the roadmap.

## Supported inputs

| Source | Format |
| --- | --- |
| Qualys VM | Detection report CSV (the preamble lines are skipped) |
| Tenable.sc, Tenable.io, Nessus | Vulnerability CSV export (column names from any of the three) |
| Nessus / Tenable | `.nessus` XML (NessusClientData_v2). It has no first-seen date, so a finding's age comes from the earliest scan file that contains it. |
| Ownership chart | CSV with `team, jira_project, manager, manager_email, vertical, vertical_head, vertical_head_email, vm_analyst, vm_analyst_email` |
| Asset register | CSV with `asset_id, hostname, ip, site, zone, os, owner, business_process, inr_per_hour, criticality, image, config_template, is_ot, safety_critical, personal_data` |

## What it does

1. **Ingest** any mix of the inputs above. The CMDB is optional, but rupee impact needs it.
2. **Resolve assets** by IP, then hostname. Hosts the scanners found but the CMDB lacks are kept and counted.
3. **Dedupe** across scanners: rows on the same asset merge when they share a package and fixed version, a
   misconfigured control, a credential fingerprint, or any CVE.
4. **Group by root cause**, in this order:
   - *Shared credential*: the same credential fingerprint accepted on several hosts.
   - *Config template*: the same misconfiguration on hosts built from one GPO, Ansible role or switch baseline.
   - *Base image*: a package flaw on at least half the hosts built from one golden image or VM template. Hosts
     missing from the CMDB are matched to an image by their package fingerprint (Jaccard ≥ 0.6).
   - *Package*: the same package below the same fixed version across hosts with no common image.
   - Whatever remains becomes a fleet-wide control issue or a single finding.
5. **Triage** each root cause with a simplified CISA SSVC decision (Act, Attend, Track\*, Track) from exploitation
   state, exposure and human or safety impact.
6. **Price** each root cause the FAIR way, loss event frequency × loss magnitude, with 3,000 Monte Carlo runs. Magnitude
   uses each business process's ₹ per hour of downtime from the CMDB, plus response, data-breach and OT costs.
7. **CEA fix clock**: counts findings open longer than one month (critical, high) or three months (medium, low).
8. **Report**: the board page, plus `receipts.json`, `root_causes.csv` and `findings.csv`. Every root-cause ID traces
   to its findings, hosts, scanner references (QID or plugin ID) and the exact source-file rows.

## Synthetic data

Two fictional companies, each written as a Qualys CSV, a Tenable.sc CSV of the IT estate, two `.nessus` plant scans
six months apart, a CMDB and an ownership chart:

- **power**: an HQ with RHEL, Ubuntu Kubernetes and Windows server fleets and 80 laptops, internet-facing NetScaler
  gateways, a thermal plant with Windows 7 HMIs, engineering workstations and Siemens S7-1500 PLCs, and a solar park.
- **manufacturing**: press, paint and assembly lines with Rockwell ControlLogix PLCs and FactoryTalk HMIs, MES
  servers sharing an `sa` password, a FortiGate SSL-VPN edge, and a second plant that is never scanned.

Both include hosts missing from the CMDB and registered assets that are never scanned. The organisations,
hostnames, IPs, QIDs, plugin IDs and advisory numbers are invented; CVE IDs are real so the threat-intel lookup
behaves as it would on real data.

## Assumptions to argue with

All risk assumptions are in `ASSUMPTIONS` in `sutra/risk.py`, and the exploitation states in
`sutra/data/threat_intel.json` are a small sample snapshot, not a live CISA KEV or EPSS feed. The rupee figures are
hypotheses for demos, not calibrated loss data. The CEA windows come from a vendor summary quoted in the plan and need
checking against the gazette text.

## Tests

```
pip install -e .[dev]
ruff check .
pytest
```

`tests/test_access.py` is the Milestone 1 exit check: for every role, the screens it should have return data and every
other API returns 403; a manager cannot approve another team's job; nobody approves their own job.
