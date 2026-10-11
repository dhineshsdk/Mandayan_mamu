# sutra-compliance

Regulations as code for Sutra. The first rule pack covers the Central Electricity Authority (Cyber Security in
Power Sector) Regulations, 2026. The library turns an entity's audits, findings, incidents and recurring
activities into deadlines, compliance states and an audit pack, and every result says which rule, which pack
version and which sources it rests on.

It is a plain Python library (3.11+, standard library only) with no server, database or framework code. The app
server calls it with records from its own store.

## Status of the rules: unverified

Every rule in the bundled pack is marked `unverified_against_gazette`. The gazette PDF could not be read when the
pack was written, so the rules come from secondary summaries collected in the project's research note
([`docs/cea-cyber-regulations-2026.md`](docs/cea-cyber-regulations-2026.md), copied from the project files). Results carry that status with them. Before any of this reaches a
customer, someone should read the gazette and update the pack as described under [Correcting a rule](#correcting-a-rule).

## What the CEA pack models

| Rule | What it checks | Confidence |
| --- | --- | --- |
| `CEA-FIX-CRITICAL-HIGH` | Critical and high findings fixed within 1 month of the audit report | Corroborated (clock start from Beacon only) |
| `CEA-FIX-MEDIUM-LOW` | Medium and low findings fixed within 3 months of the audit report | Corroborated (clock start from Beacon only) |
| `CEA-COMPENSATING-CONTROLS` | Open critical and high findings past their window have a compensating control until the auditor clears them | Single source |
| `CEA-AUDIT-REPORT` | Auditor's report within 6 weeks of the audit starting | Corroborated |
| `CEA-CLOSURE-REPORT` | Closure report within 6 months of the audit starting, with a head or board report on file | Corroborated |
| `CEA-AUDIT-INTERVAL` | An audit every financial year, and 9 to 15 months after the last one (both checked separately) | Corroborated; the two may conflict |
| `CEA-AUDITOR-ELIGIBILITY` | Auditor is CERT-In empanelled or Ministry of Power designated | Corroborated |
| `CEA-PRIOR-FINDINGS` | The next audit rechecks earlier findings | Single source |
| `CEA-AUDITOR-ROTATION` | **Disabled.** Sources disagree on the limit | Conflicting |
| `CEA-INCIDENT-6H` | Incident reported to CSIRT-Power and CERT-In within 6 hours | Corroborated (clock start not stated) |
| `CEA-SABOTAGE-24H` | Concluded sabotage of a critical system reported within 24 hours of the conclusion | Corroborated |
| `CEA-SELF-AUDIT`, `CEA-POLICY-REVIEW`, `CEA-CCMP-DRILL`, `CEA-ASSET-REGISTER-REVIEW` | Yearly activities | Corroborated |
| `CEA-IR-PLAN-REVIEW`, `CEA-ASSET-RISK-ASSESSMENT` | Six-monthly activities (risk assessment per asset) | Corroborated |
| `CEA-BACKUP-AGE` | Backups of critical systems no older than one month | Corroborated |
| `CEA-SECOND-SCHEDULE` | Which change categories need a cyber security audit before deployment | Corroborated |

The pack also records who is covered (generators, captive plants and storage at 50 MW and above; transmission,
distribution and load-despatch entities with no threshold; exchanges and OTC platforms without the OT and vendor
chapters; vendors) and the clauses deferred to later CEA orders, which the engine never enforces.

**Not modelled**, because the sources do not give enough to compute anything: the 30-day VAPT notice to
CSIRT-Power (no start event given), drill scenario rotation, the asset-register review owed on commissioning or
replacement, incident report fields and log retention.

## Engine conventions

These are choices the sources do not settle. Each one is a single place in the code or the pack.

- **Months are calendar months.** 10 May + 1 month = 10 June. A day the target month lacks moves to its last day
  (31 January + 1 month = 28 or 29 February).
- **Deadlines are inclusive.** A fix dated on the due date is on time.
- **The fix clock starts when the audit report is submitted.** Until then a finding is `clock_not_started`.
- **Closure** is the fix date, or the auditor's clearance date when no fix date is recorded.
- **Compensating controls** are required once a critical or high finding is past its window (`trigger =
  "after_fix_deadline"`). If the gazette requires them for every open critical or high finding, set `trigger =
  "while_open"`.
- **A scheduled fix** (such as the next shutdown) is shown next to the clock and flagged when it falls after the
  deadline. It never stops the clock.
- **In force.** An obligation binds when the event that starts its clock is on or after 1 April 2027. Earlier
  results are still computed and flagged `in_force: false`; `status` ignores them and `status_if_in_force`
  counts them, which is the readiness view.
- **Time zone.** Dates are Indian calendar dates (UTC+05:30 from the pack). Incident clocks run on timezone-aware
  datetimes, so a detection logged in UTC is handled correctly.
- **"Due soon"** defaults to 14 days. It is a product setting, not a regulatory value.

## Use

```python
from datetime import date, datetime, timedelta, timezone
from sutra_compliance import (Audit, AuditFinding, CompensatingControl, Entity, EntityRecords,
                              build_audit_pack, evaluate_entity, load_rule_pack)

IST = timezone(timedelta(hours=5, minutes=30))
pack = load_rule_pack()  # bundled CEA pack; pass a path to load a corrected copy

records = EntityRecords(
    entity=Entity("tps-1", "Example Thermal Station", "generator", capacity_mw=600),
    audits=(Audit("A-2027", "tps-1", "Example Auditors LLP", "cert_in_empanelled",
                  started_on=date(2027, 4, 5), report_submitted_on=date(2027, 5, 10)),),
    findings=(AuditFinding("F-1", "A-2027", "critical", "SMBv1 enabled on historian",
                           compensating_controls=(CompensatingControl(
                               "C-1", "SMB blocked from corporate VLAN", implemented_on=date(2027, 6, 5)),)),),
)

now = datetime(2027, 6, 15, 9, 0, tzinfo=IST)
result = evaluate_entity(records, pack, now)
result.status                       # EntityStatus.ATTENTION: F-1 is overdue but compensated
result.audits[0].findings[0].due_on  # date(2027, 6, 10)
result.to_dict()                    # plain JSON for the API

audit_pack = build_audit_pack(records, pack, now)
audit_pack.to_json()                # export with a SHA-256 digest; check later with verify_audit_pack()
```

Other entry points: `assess_finding`, `assess_audit`, `assess_audit_cycle`, `assess_incident`, `assess_periodic`,
`assess_applicability`, and `check_change(categories, pack)` for the Second Schedule flag on fix plans.

## Correcting a rule

The pack is `src/sutra_compliance/rules/cea_cs_2026.toml`. To correct it:

1. Change the value on the rule (a duration, a severity list, a trigger, a list of categories).
2. Once a rule has been read against the gazette, set `verification = "verified_against_gazette"` and fill
   `gazette_clause`. The loader refuses a verified rule without a clause or without the gazette as a source.
3. Bump `[pack].version`. Every result and audit pack records the version it was computed with.

The loader checks the whole file and lists every problem at once: unknown keys, unknown sources, rules with no
sources, two rules covering the same severity, bad durations, and a pack marked verified while its rules are not.

## Audit pack

`build_audit_pack` produces one JSON document with:

- the status, issues and upcoming deadlines;
- each audit with its deliverables, auditor eligibility and every finding's state, citations, compensating
  controls, scheduled fix and dated timeline;
- the audit-cycle checks, prior-finding rechecks, incident report clocks and recurring obligations;
- a per-asset section for the six-monthly risk review, with open findings per asset;
- an evidence index (what each item proves and who references it) and a list of evidence gaps: referenced but
  missing items, closed findings with no fix evidence or only evidence captured before the fix, compensating
  controls and activities with no evidence, and missing report copies;
- the rule pack's version, verification status and full source list;
- a SHA-256 digest over the canonical JSON, checked by `verify_audit_pack`.

The engine only checks references to evidence; storing and hashing the files is the caller's job.

## Develop

```
cd compliance
python3 -m pip install -e '.[test]'
python3 -m pytest
```
