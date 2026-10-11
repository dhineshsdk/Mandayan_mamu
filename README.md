# Sutra: root causes and rupee risk from scanner exports

Sutra reads Qualys and Tenable exports, merges duplicate findings, groups them by the one thing that fixes them,
and shows the board its cyber risk in rupees. It runs entirely on one machine; files never leave it. Until a design
partner shares real exports, it runs on realistic synthetic data in the same formats.

## Run the app

```
python3 -m sutra serve
```

A browser opens at http://127.0.0.1:8765 with the power-utility demo loaded. Python 3.10+ standard library only;
nothing to install. The app has seven views:

- **Board**: expected annual loss in ₹, the CEA fix clock, SSVC triage, blind spots, risk by process and site, and
  a printable one-page board pack.
- **Root causes**: the analyst queue with filters, and a page per root cause showing the fix, why it got its SSVC
  call, the rupee-risk inputs, hosts, and every finding's receipts (scanner, QID or plugin, file and row).
- **Assets and coverage**: registered assets that are never scanned, and scanned hosts missing from the CMDB.
- **Team portal**: every asset maps to a team, manager, vertical and Jira project (from `teams.csv`). Signed in as a
  team, you see only your assets and fixes, and can build a patch job or mark a fix as manual with a change ticket.
- **Patch jobs**: each job gets a draft (targets, rings, playbook or staged plan, pre-checks, rollback, window) and an
  approval route set by fixed rules: manager and VM analyst always, the vertical head for Act, Attend, Track\* or
  crown-jewel assets, and OT jobs become staged plans with OEM approval and a shutdown slot. Approvers see an inbox;
  every step lands in an audit trail. "Signed in as" at the top right switches between personas for the demo (real
  deployments use SSO). Drafts come from templates for now; an AI drafting step slots in without changing routing.
- **Headline check**: "are we exposed?" for a CVE or product in the news.
- **Import data**: switch between the power and manufacturing demos, or drop in real exports.

[`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) walks through a 15-minute customer demo.

## Command line

```
python3 -m sutra demo --profile power            # or manufacturing; writes out/board_summary.html
python3 -m sutra analyze a.csv b.nessus --cmdb cmdb.csv --org "Plant name" --out out/
python3 -m sutra synth --profile manufacturing --out data/synthetic/manufacturing
```

`analyze` detects each file's format from its content.

## Supported inputs

| Source | Format |
| --- | --- |
| Qualys VM | Detection report CSV (the preamble lines are skipped) |
| Tenable.sc, Tenable.io, Nessus | Vulnerability CSV export (column names from any of the three) |
| Nessus / Tenable | `.nessus` XML (NessusClientData_v2). It has no first-seen date, so a finding's age comes from the earliest scan file that contains it. |
| Ownership chart | CSV with `team, jira_project, manager, vertical, vertical_head, vm_analyst` |
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
python3 -m unittest -v
```
