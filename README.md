# Sutra: root causes and rupee risk from scanner exports

Sutra reads Qualys and Tenable exports, merges duplicate findings, groups them by the one thing that fixes them,
and shows the board its cyber risk in rupees. It runs on your own server or laptop; files never leave it. Until a design
partner shares real exports, it runs on realistic synthetic data in the same formats.

## Install and run

Python 3.11 or later.

```
python3 -m venv .venv && . .venv/bin/activate
pip install -e ./patchdraft -e ./connectors -e ./compliance -e ./explain -e .  # add "./patchdraft[ai]" for Claude drafting
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
| Team manager | Team portal (view), Patch jobs (view, approve), Scorecards (view) | Their team |
| VM analyst | Root causes, Assets, Import data (view, act), Headline check, Patch jobs (view, approve), Board (view) | Organisation |
| Vertical head | Patch jobs (view, approve), Board, Root causes, Scorecards (view) | Their vertical |
| Plant engineer | Team portal (view), OT plans (view, act) | Their site |
| CISO | Board, Root causes, Patch jobs (view), CISO dashboard, approval thresholds | Organisation |
| Compliance officer | Board, Audit log (view); Compliance when built | Organisation |
| Executive | Board (view) | Organisation |
| Auditor | Audit log (view); Compliance when built. The account must have an end date | Organisation |
| Administrator | Administration, Import data | Organisation |

- An admin can add or remove a single module action for one person, with a reason that goes in the audit log.
- Modules that are not built yet (Compliance) grant nothing, and an admin can switch a
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

### AI explanations and the board briefing

Root-cause pages carry an **Explanation**, and the Board has a **Quarterly briefing** (also available inside the
printable board pack with `?briefing=1`). They come from `sutra_explain` in `explain/` (see its README) and are
designed so that hostile scanner text cannot steer them:

- The model never sees a scanner title, hostname, banner or ticket comment. It sees typed facts (numbers, fixed
  vocabularies, CVE IDs, rupee labels) with short refs like `R1` and `A2`. Names are filled in by Sutra afterwards.
- Every sentence cites the refs it rests on. A sentence is dropped, and the whole answer replaced by a rule-written
  one, unless its refs exist, its numbers come from the cited facts, and strong words (exploited, internet, safety,
  plant, overdue) are backed by a cited field. Wording about ignoring, closing, lowering or accepting is refused.
- A model can only suggest ticket, pull request, stage, notify or rescan; a policy gate checks it (plant systems stop
  at ticket, stage and notify) and nothing is done until a person does it. It never changes a risk figure, a triage
  decision or an approval level.
- Text that looks aimed at an AI is counted and shown as a reason for concern. It is never obeyed.
- Explanations run with the asker's own scope, are kept until the facts change, and each one generated is audited.

| Variable | Meaning |
| --- | --- |
| `SUTRA_AI_PROVIDER` | `auto` (default), `anthropic`, `local` or `off`. `auto`: a local model if `SUTRA_AI_LOCAL_URL` is set, else Claude if `ANTHROPIC_API_KEY` is set, else rules only. |
| `SUTRA_AI_LOCAL_URL`, `SUTRA_AI_LOCAL_MODEL`, `SUTRA_AI_LOCAL_KEY` | An OpenAI-compatible chat endpoint inside the customer's network (vLLM, llama.cpp, Ollama, LM Studio). Used for explanations and patch-job drafts; no prompt leaves the box. It must support JSON-schema constrained output. |
| `SUTRA_AI_EXPLAIN_MODEL`, `SUTRA_AI_EXPLAIN_EFFORT` | Claude model (default `claude-sonnet-5-5`) and effort for explanations. Patch drafts keep `SUTRA_AI_MODEL`. |
| `SUTRA_AI_READER` | `rules` (default) or `model`. With `model`, finding titles are sent to the model to be labelled with one word from a fixed list; leave it on `rules` if finding text must not leave the box. |
| `SUTRA_AI_EXPLAIN=off` | Rule-written explanations only. |

**Administration → AI** shows what is in use. With the Anthropic API selected, prompts leave the customer's network; for
data that must stay in India or on the box, use a local model or `SUTRA_AI_PROVIDER=off`. Install
`./explain[ai]` for the Anthropic client.

### Verified closure

Nobody marks a job fixed. Each job records the findings it covers (host plus finding fingerprint). After every
import, Sutra checks each open job against it: a finding still reported keeps the job open; a finding gone from a
host that was scanned again counts as fixed; a finding gone from a host that was not scanned proves nothing. When
all of a job's findings are fixed, the job becomes **Fixed (proved by rescan)** with the scan date that proved it.
If a later import reports them again, the job reopens. An import whose scans are older than a job's last check is
ignored for that job. Every check is kept and shown on the job page, and recorded in the audit log.

### Risk acceptance

A team can ask to accept a root cause's risk instead of fixing it now: it says why, names the compensating control,
and gives an end date (at most 365 days ahead). The request goes to the team's manager, the VM analyst and the
vertical head, and for SSVC Act also to the CISO for the final sign-off. Once accepted, it lasts until the end date;
the next day it expires on its own (an hourly job, also run at start-up and after each import) and the team can fix it
or ask again. A team can still fix something it has accepted, and a rescan that shows the findings gone closes the
acceptance early. Accepting risk does not stop the CEA fix clock.

### Service levels and escalation

Each customer sets its own targets under **Administration → Service levels**: how many hours each approval step may
wait (default 48 for the manager and VM analyst, 72 for the vertical head and the CISO) and how many days a fix may
take by SSVC decision (default Act 14, Attend 30, Track\* 90, Track 180). These are product defaults, not regulatory
values; the CEA fix clock is tracked separately and never relaxed by them.

A step that waits past its limit is escalated once to the next approver in the chain (the CISO after the last step):
it appears under **Escalated to you** on their Patch jobs page and in the audit log. Escalation informs; it never lets
anyone sign a step that is not theirs. A fix not proved by a rescan by its due date is recorded as an SLA breach and
stays open. Both checks run hourly, at start-up and after each import.

### Notifications and tickets

Job events are queued in the database together with the change that caused them, and a background dispatcher
delivers them, retrying failures with growing waits (six tries). Each integration is off until its settings are in the
server's environment; **Administration → Integrations** shows what is on (never the secrets), delivery counts and
recent problems, with a button to retry.

| Integration | Settings | What it does |
| --- | --- | --- |
| Email (SMTP) | `SUTRA_SMTP_HOST`, `SUTRA_SMTP_FROM`; optional `SUTRA_SMTP_PORT` (587; 465 for TLS), `SUTRA_SMTP_USER`, `SUTRA_SMTP_PASSWORD`, `SUTRA_SMTP_STARTTLS` | The next approver when a step needs them; the raiser when a job is approved, accepted, rejected or sent back; the escalation target; the manager when a fix date is missed; the raiser and manager when a rescan fixes or reopens a job or a risk acceptance expires |
| Microsoft Teams | `SUTRA_TEAMS_WEBHOOK_URL` (a Workflows "Send webhook alerts to a channel" URL, or a legacy incoming webhook) | Escalations and missed fix dates, as an Adaptive Card |
| Jira | `SUTRA_JIRA_URL`, `SUTRA_JIRA_TOKEN`; Cloud also `SUTRA_JIRA_USER` (account email); Data Center `SUTRA_JIRA_API=2`; optional `SUTRA_JIRA_ISSUE_TYPE` (Task), `SUTRA_JIRA_DONE_STATUS` | An issue per job in the team's Jira project from the ownership chart; decisions and rescans as comments; moved to the done status when a rescan proves the fix |
| ServiceNow | `SUTRA_SERVICENOW_URL`, `SUTRA_SERVICENOW_USER`, `SUTRA_SERVICENOW_PASSWORD`; optional `SUTRA_SERVICENOW_TABLE` (change_request) | A record per job through the Table API; later events as work notes |

`SUTRA_BASE_URL` (for example `https://sutra.example.in`) adds a link back to the job. A job shows a Jira key or
ServiceNow number only once that system has issued it.

### OT plans

An OT job is approved like any other, but nothing is pushed to a controller. The plant engineer of the job's plant
opens it under **OT plans** and records, with dates: the OEM's approval (requested, approved or refused, with the
OEM's own reference), the compensating control held until the shutdown, the shutdown slot confirmed with operations
(the plant's planned shutdown from the maintenance policy is offered as a suggestion), and each attempt to apply the
fix with its result. Execution can be recorded only once the job is approved, the OEM has approved and a slot is
confirmed; a partial or rolled-back attempt needs a note. Recording an execution never closes the job: the next
rescan does. An engineer can record only on plans whose OT hosts are all at their own plant. Each record goes to the
audit log, to whoever raised the job and the team's manager, and to the job's Jira issue and ServiceNow record.

### Scorecards and the CISO dashboard

**Scorecards** shows, for each team and each plant in the person's scope (a manager their teams, a vertical head
their vertical, the CISO everything): open findings in the current import and how many have no job and no risk
acceptance, the oldest open finding, jobs open and overdue, SLA breaches, jobs proved fixed, the median time to fix
and the share fixed on time, plus open findings at each import. Time to fix is counted from the scanner first
reporting a job's findings to the scan that proved them gone, so it measures exposure, not approval speed. A budget
view is not built: Sutra holds no cost data to base one on.

### Scanner API pulls

Under **Import data → Scanner connections** an administrator adds read-only API connections to Qualys VMDR, Tenable
Vulnerability Management, Tenable Security Center, CrowdStrike Falcon Spotlight, Amazon Inspector, Microsoft
Defender for Cloud or, for OT networks, a Nozomi Networks Guardian or CMC (the `sutra_connectors` library in
`connectors/`). For CrowdStrike, create an API client with read access to
Vulnerabilities and Hosts and use your cloud's API address (for example `https://api.eu-1.crowdstrike.com`); hosts
whose sensor has not reported for 30 days do not count as assessed. For Amazon Inspector, create an access key for
an IAM user whose policy allows only `inspector2:ListFindings` and `inspector2:ListCoverage`, and add one connection
per region with that region's endpoint (for example `https://inspector2.ap-south-1.amazonaws.com`). Inspector's
delegated administrator account should cover every account in an AWS Organization (to confirm on a live organization;
see `connectors/docs/api-notes/aws-inspector.md`). Sutra reads package vulnerabilities
on EC2 instances, ECR images and Lambda functions; an instance is named by its `Name` tag, else its instance ID, so
give the asset register the same host names. For Defender for Cloud, register an app in Entra ID, give it the
Security Reader role on the subscriptions or management groups to read, and enter its tenant ID, client ID and secret
with those subscription IDs or management group names. Sutra reads the software vulnerabilities Defender
Vulnerability Management reports on virtual machines; a machine is named by its Azure VM name, and every machine with
a vulnerability assessment result counts as assessed. Container image and AKS node findings are not read yet. For Nozomi, create a local user with
Open API read access on the Guardian or CMC; Sutra reads the vulnerabilities Nozomi matched to each asset's product
and firmware, and every asset active in the last 30 days counts as assessed (Nozomi watches traffic, it does not
scan). A pull reads
every enabled connection in full (all open detections, and every host the scanner has assessed) and imports the
result like an export, carrying over the asset register from the latest import that had one. Pulls run by hand
(VM analyst or admin) or once a day at a chosen hour, India time.

- If any connection fails, nothing is imported: a scanner that did not answer must never make findings look fixed.
- Each host the scanner reports as assessed counts as scanned, so a fully patched host can prove a fix.
- Passwords and secret keys are encrypted at rest with a key derived from `SUTRA_SECRET_KEY` (or the key generated
  in the workspace) and are never returned by the API. If that key changes, enter the credentials again.
- An internal CA can be trusted by giving the path of its CA bundle on the Sutra server.

### Firewall and switch configurations

Under **Import data → Firewall and switch configurations** an administrator adds devices Sutra reads its
configuration from, read-only: Fortinet FortiGate (a REST API token for an administrator with a read-only profile),
Palo Alto Networks firewalls (an XML API key for a read-only administrator) and Cisco IOS or IOS-XE switches and
routers over SSH (an account that logs in at the `#` prompt; Sutra never sends `enable`). From switches Sutra also
reads the ARP and MAC address tables. Collection runs with the daily scanner pull, and VM analysts and
administrators can collect by hand.

- Passwords, keys, pre-shared keys and SNMP communities are replaced with `SUTRA-MASKED` before a configuration is
  stored, so Sutra never holds a device secret beyond the credential it logs in with (encrypted like scanner ones).
- A new version is stored only when the configuration really changed (lines a device rewrites by itself, such as the
  IOS "Last configuration change" stamp, are ignored). Each version can be viewed, compared with the one before it and
  downloaded; every view and download is audited.
- One device failing does not stop the others, and its last good configuration is kept.
- An SSH device's host key is pinned the first time it answers. If a different key appears, collection from that
  device stops until an administrator clears the pinned key (after replacing the device) or enters the new
  fingerprint.
- Not yet: routes, ARP tables from firewalls, and other vendors (see `connectors/docs/api-notes/network-devices.md`).

### Compliance (CEA fix clock)

The Compliance module (M-CMP) records each regulated entity (a plant, a substation, a load-despatch centre), its
cyber security audits, the auditor's findings, compensating controls, fix dates scheduled for a named shutdown,
recurring activities (policy reviews, drills, self-audits) and the evidence files behind them. Every state and deadline
comes from the CEA rule pack in `./compliance` (`sutra_compliance`); Sutra computes no clock of its own.

- A finding linked to a patch job is fixed only when the rescan that verified the job says so: its fix date is that
  scan's date and the rescan is attached as fix evidence. A fix date typed in by hand is allowed only without a job.
- A compensating control in place turns an overdue critical or high finding from a breach into "past deadline,
  compensating control in place"; a scheduled shutdown fix is shown with the clock and flagged when it falls after
  the deadline, but never stops it.
- Evidence files are stored once under their SHA-256 in `<workspace>/evidence`, never changed or deleted, and every
  upload, link, unlink and download is in the audit log.
- The compliance officer and the CISO record (M-CMP act); the time-limited auditor account reads (M-CMP view).
- Assets are imported from the current asset register by the entity's site, and a person classes each one as a
  critical system or not (the register's 1-to-5 criticality is shown, never copied). The per-asset review shows each
  asset's last risk assessment (due every six months), backup age for critical systems and its open findings.
- The audit pack downloads as a ZIP: `audit-pack.json` (status, every finding's clock and timeline, citations,
  per-asset review, evidence index and evidence gaps, with a SHA-256 digest that
  `sutra_compliance.verify_audit_pack()` checks) and every evidence file. The same evidence gaps are on screen.
- The auditor account is read-only and time-limited: it must have an expiry date, cannot be combined with another
  role or given more than view access (anything else is refused, and removed if it was given before), and its access
  end date is shown to the auditor.
- Second Schedule: each patch job says whether its change needs a cyber security audit before deployment. People
  tick what kind of change it is (authentication and privilege changes, new interfaces and so on, from the rule pack);
  Sutra adds "fix for a previously found critical vulnerability" itself when the job is linked to a critical CEA
  finding. Once the regulation is in force (1 April 2027) the final approval waits until the pre-deployment audit is
  recorded on the job; before then it is a warning.
- Incidents: record when an incident was detected and when each report went to CSIRT-Power and CERT-In. The rule
  pack's 6-hour clock (and the 24-hour clock for concluded sabotage of a critical system) shows each report as due,
  sent on time, sent late or overdue. Sutra writes a draft of the report from the recorded facts and lists what is
  still missing; it sends nothing, and the pack gives no required report fields, so a person copies the draft into
  the format CSIRT-Power and CERT-In ask for. Proof of sending is attached as evidence.
- The bundled rule pack has not been checked against the gazette text; every screen says so. The entity page lists
  what is not checked.

### Entra ID directory sync

Under **Administration → Entra ID sync** an administrator maps Entra ID groups to Sutra roles, for example a VM team
group to VM analyst, or a plant group to plant engineer for one site. Sutra reads the members of each mapped group
(nested groups included) through Microsoft Graph once a day, and on demand:

- Each enabled member gets the mapped roles. Sutra creates a single-sign-on account for them, or links the existing
  account with the same email.
- People who leave a group lose the roles it gave. If an account the sync manages ends up with no roles, it is
  disabled, and it is enabled again if the person comes back. An account an administrator disabled stays disabled.
- Roles given by hand are never changed. Time-limited roles such as auditor cannot be mapped to a group.
- If any group cannot be read, nothing changes. A sync that would leave nobody able to administer Sutra is refused.

Register an app in Entra ID with the Microsoft Graph application permissions GroupMember.Read.All and User.Read.All,
grant admin consent, and enter the tenant ID, client ID and a client secret (stored encrypted, never shown again).
National clouds can change the sign-in and Graph addresses.

### Threat intelligence

Sutra fetches the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog and [FIRST EPSS](https://www.first.org/epss/) scores once a day (and on demand under **Import data**), then
re-analyses the current import.

- A CVE in the KEV catalog counts as actively exploited, which drives the SSVC decision. Sutra also shows when CISA
  added it and whether it is known to be used in ransomware.
- EPSS scores (the probability of exploitation activity in the next 30 days) are fetched for the CVEs in the current
  import and shown next to each root cause. They do not change SSVC.
- Public exploit code has no free authoritative feed, so "public exploit" comes from the short curated list in
  `sutra/data/threat_intel.json`, and every screen says so.
- Until the catalog has been fetched, Sutra uses that file's sample list for both states and marks them as a sample.
  A failed or malformed download keeps the last good copy and is shown on the Import data page.
- Servers without internet access: set `SUTRA_KEV_URL` and `SUTRA_EPSS_URL` to an internal mirror, or
  `SUTRA_INTEL_REFRESH=0` to stop the daily fetch.

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
| Trivy | JSON report, schema version 2 (`trivy image --format json`; also `fs`, `rootfs` and `vm`) |
| Grype | JSON report (`grype <target> -o json`) |
| Ownership chart | CSV with `team, jira_project, manager, manager_email, vertical, vertical_head, vertical_head_email, vm_analyst, vm_analyst_email` |
| Asset register | CSV with `asset_id, hostname, ip, site, zone, os, owner, business_process, inr_per_hour, criticality, image, config_template, is_ot, safety_critical, personal_data` |

Trivy and Grype scan one artifact, such as a container or VM image, rather than a host. Each report becomes one asset
named after the artifact (its first repository tag when Trivy recorded one), with no IP address, and every
vulnerability is a package finding with the installed and fixed versions the scanner reported. To give the image an
owner, criticality and rupee value, add a CMDB row whose `hostname` is that name. Hosts whose CMDB `image` is the same
name are grouped with it, so a flaw found both in the image and on the hosts built from it becomes one base-image root
cause. Trivy `UNKNOWN` and Grype `Unknown` or `Negligible` severities count as low. A report has no first-seen
date; the scan date (Trivy `CreatedAt`, Grype `descriptor.timestamp`) is the last-seen date, and age builds up across
imports.

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

All risk assumptions are in `ASSUMPTIONS` in `sutra/risk.py`. The server uses live CISA KEV and EPSS data (see
Threat intelligence); the command-line reports still use the sample list in `sutra/data/threat_intel.json`. The
"public exploit" list in that file is curated by hand and short. The rupee figures are
hypotheses for demos, not calibrated loss data. The CEA windows come from a vendor summary quoted in the plan and need
checking against the gazette text.

## Tests

```
pip install -e ./patchdraft -e ./connectors -e ./compliance -e ./explain -e .[dev]
ruff check .
pytest
```

`tests/test_access.py` is the Milestone 1 exit check: for every role, the screens it should have return data and every
other API returns 403; a manager cannot approve another team's job; nobody approves their own job.
`tests/test_history.py` is the Milestone 2 exit check: two imports 30 days apart show what was fixed, new and still
open per team, and the counts reconcile with both imports.

## Sutra Range

Every release is scored by Range: planted-cause scenarios, prompt-injection payloads and damaged model answers, with the
result published in [`docs/range/SCORE.md`](docs/range/SCORE.md). See [`range/README.md`](range/README.md).

## Licence keys

Modules are switched on per customer by an offline-checked signed key. See [`docs/licensing.md`](docs/licensing.md).

## Backups and upgrades

`python -m sutra backup create | verify | list | restore` and `python -m sutra upgrade` (backs up first, then migrates).
See [`docs/operations.md`](docs/operations.md).

## Installing on a server, hardening, data residency

An offline install bundle, systemd units, `python -m sutra doctor`, and an outbound allow-list (`SUTRA_EGRESS`) are in
[`docs/installation.md`](docs/installation.md) and [`docs/hardening.md`](docs/hardening.md).
