# Sutra: root causes and rupee risk from scanner exports

Sutra reads Qualys and Tenable exports, merges duplicate findings, groups them by the one thing that fixes them,
and shows the board its cyber risk in rupees. It runs on your own server or laptop; files never leave it. Until a design
partner shares real exports, it runs on realistic synthetic data in the same formats.

## Install and run

Python 3.11 or later.

```
python3 -m venv .venv && . .venv/bin/activate
pip install -e ./patchdraft -e .                   # add "./patchdraft[ai]" for Claude drafting
sutra db-upgrade                                   # creates workspace/sutra.db (SQLite)
sutra create-admin --email you@company.com --name "Your Name"
sutra serve                                        # http://127.0.0.1:8765
```

Sign in as the admin, upload the ownership chart, add people and give them roles, then import scanner exports
under **Import data** (any account with the VM analyst or admin role can).

For a demonstration on synthetic data, `sutra demo-users --profile power` (or `manufacturing`) loads an invented
company as two monthly imports (5 Sep and 5 Oct 2026; `--months` changes the count) and creates one account per role
from its ownership chart. Each password is random and printed once.
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

SAML sign-in is not built yet; OIDC covers Entra ID.

### Patch-job drafts

When a team raises a patch job, Sutra drafts it with the `sutra_patchdraft` library in `patchdraft/` (see its
README): target hosts in rings, steps, pre-checks, rollback, and for OT a staged plan with an OEM approval request
and compensating controls. Every step cites the root cause, hosts, changes and findings it rests on.

- With `ANTHROPIC_API_KEY` set and `./patchdraft[ai]` installed, Claude writes the draft. Sutra checks it against
  the scan data (no version, KB, CVE, IP or URL that the scan did not report) and falls back to the templates if
  it fails. `SUTRA_AI_DRAFTING=off` keeps air-gapped installs on the templates. The draft page says which was used.
- A Claude draft can take minutes, so the job shows "Drafting" and its first approval step opens when the draft
  is written. Drafts interrupted by a restart are finished at start-up.
- Ring windows come from the IT change window under **Administration → Maintenance windows** (default Saturday
  22:00 to 02:00 IST), counted from the day the job is raised. OT plans use the next planned shutdown an
  administrator names for the site; without one, the plan says the slot is not set rather than guessing.
- Who approves is decided by the routing rules, never by the draft.

### Verified closure

Nobody marks a job fixed. Each job records the findings it covers (host plus finding fingerprint). After every
import, Sutra checks each open job against it: a finding still reported keeps the job open; a finding gone from a
host that was scanned again counts as fixed; a finding gone from a host that was not scanned proves nothing. When
all of a job's findings are fixed, the job becomes **Fixed (proved by rescan)** with the scan date that proved it.
If a later import reports them again, the job reopens. An import whose scans are older than a job's last check is
ignored for that job. Every check is kept and shown on the job page, and recorded in the audit log.

### Import history

Every import is kept. Sutra records when it saw the import and the scan date it covers, and stores each import's
assets and findings in the database (`asset_snapshots`, `observations`). From that:

- **What changed** compares any two imports, per team: fixed, new, still open, and not rescanned. A finding missing
  from the newer import counts as fixed only if its host was scanned in that import; otherwise it is "not rescanned",
  because a missing scan is not a fix. Teams see their own rows; the board sees counts without host names.
- **First seen survives**: a finding is identified by its asset and a fingerprint of what is wrong (package and fixed
  version, credential, control, or CVEs and title). When a scan carries no first-seen date (`.nessus` does not), the
  earliest date from earlier imports is kept, so the CEA clock does not restart.
- **Patch jobs** are tied to a root cause's stable key, not its per-import ID, so they survive a new import and a
  second open job for the same root cause and team is refused.
- **Unowned assets**: hosts missing from the asset register, or whose owner is not in the ownership chart, are listed
  as a coverage gap because nobody is asked to fix them.

The analysis of the current import is held in memory and rebuilt at start-up, using the history for first-seen dates.

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
six months apart, a CMDB and an ownership chart. `sutra synth --month N` writes the same estate N × 30 days later:
Log4j is fixed everywhere, about a quarter of other IT findings are fixed, a Chrome flaw arrives on laptops that run
Acrobat, and OT is unchanged because it waits for a shutdown. Later months carry only the latest plant scan, as a
real monthly export would. All of this is in `sutra/synth.py` and is deterministic.

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
pip install -e ./patchdraft -e .[dev]
ruff check .
pytest
```

`tests/test_access.py` is the Milestone 1 exit check: for every role, the screens it should have return data and every
other API returns 403; a manager cannot approve another team's job; nobody approves their own job.
`tests/test_history.py` is the Milestone 2 exit check: two imports 30 days apart show what was fixed, new and still
open per team, and the counts reconcile with both imports.
