# Sutra prototype: root causes and rupee risk from scanner exports

The Weeks 4–8 prototype from the Sutra startup plan. A local tool that reads Qualys and Tenable exports, merges
duplicate findings, groups them by the one thing that fixes them, and writes a one-page board summary with risk in
rupees. It runs on synthetic data only.

```
python3 -m sutra demo
```

That generates a synthetic estate into `data/synthetic/`, analyses it, and writes `out/board_summary.html`
(prints to one A4 page). A copy of the output is in [`examples/`](examples/). Python 3.10+ standard library only;
nothing to install.

## What it does

1. **Ingest** a Qualys VM detection CSV (preamble lines are skipped) and a Tenable.sc / Tenable.io vulnerability CSV,
   plus an optional CMDB asset register.
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

## On your own exports

```
python3 -m sutra analyze --qualys qualys.csv --tenable tenable.csv --cmdb cmdb.csv --org "Plant name" --out out/
```

`--qualys` and `--tenable` can repeat. The CMDB columns are in `sutra/synth.py` (`CMDB_COLS`); without a CMDB the
grouping still works but rupee impact falls back to a flat default. Only use public or synthetic data until the
plan's IP and employment checks are done.

## Synthetic data

`python3 -m sutra synth --seed 7` builds a fictional power company: an HQ with RHEL, Ubuntu Kubernetes and Windows
server fleets and 80 laptops, internet-facing NetScaler gateways, a thermal plant with Windows 7 HMIs, engineering
workstations and Siemens S7-1500 PLCs, plus 9 hosts missing from the CMDB and 12 registered assets that are never
scanned. The organisation, hostnames, IPs, QIDs, plugin IDs and advisory numbers are invented; CVE IDs are real so the
threat-intel lookup behaves as it would on real data.

## Assumptions to argue with

All risk assumptions are in `ASSUMPTIONS` in `sutra/risk.py`, and the exploitation states in
`sutra/data/threat_intel.json` are a small sample snapshot, not a live CISA KEV or EPSS feed. The rupee figures are
hypotheses for demos, not calibrated loss data. The CEA windows come from a vendor summary quoted in the plan and need
checking against the gazette text.

## Tests

```
python3 -m unittest -v
```
