# Sutra Scan

Sutra's own vulnerability scanner for Linux hosts. It does not probe the network and does not use any commercial
scanner's code or data. It does two plain things:

1. **Inventory**: lists the packages a host has installed, from the package databases the system itself keeps
   (dpkg, apk, rpm), together with the operating system release.
2. **Match**: compares that list with open advisory data, using each system's own version ordering, and writes a
   Sutra rows file that **Import data** reads like a Qualys or Tenable export.

Matching reads only a local snapshot file, so it works on an air-gapped plant: build the snapshot where there is
internet, carry the file across, and match there. The collector needs nothing but Python 3.10+ (no third-party
packages), and rpm hosts need the `rpm` command they already have.

## Supported systems

| Family | Releases (as published in the feed) | Advisory source (via OSV) | Package name the advisory uses |
| --- | --- | --- | --- |
| Debian | 11, 12, 13 | Debian Security Tracker, DSA/DLA | source package |
| Ubuntu | LTS and interim releases | Ubuntu Security Notices and CVE tracker | source package |
| Alpine | v3.x | Alpine secdb | origin (source) package |
| AlmaLinux | 8, 9, 10 | AlmaLinux errata (ALSA) | binary package |
| Rocky Linux | 8, 9, 10 | Rocky Linux errata (RLSA, RXSA) | binary package |
| Red Hat Enterprise Linux | 6 to 10 (standard channels) | Red Hat Security Data, errata (RHSA) | binary package |

Not covered, and said so rather than guessed at: **RHEL Extended Update Support, E4S, AUS and TUS streams** (the
standard-channel data is matched, so a host held on an older minor release can show fixes it will never receive),
**Ubuntu Pro / ESM** fixes, **SUSE**, **Windows** (planned), language packages
(PyPI, npm and so on), and anything installed outside the package manager. On an unsupported system `sutra-scan`
stops with an error; it never reports an unknown system as clean.

## Use

```
pip install -e ./scan                      # or ship it as a zipapp: python -m zipapp scan/src -m "sutra_scan.cli:main"

# 1. Where there is internet: download the advisories and build the snapshot (about 5 minutes, 50-250 MB per release)
sutra-scan feed fetch ./osv -e Debian:12 -e Ubuntu:22.04:LTS -e Alpine:v3.19 -e "Red Hat:enterprise_linux:9::*"
sutra-scan feed build sutra-feed.db ./osv/*.zip -e Debian:12 -e Ubuntu:22.04:LTS -e Alpine:v3.19 -e "Red Hat:enterprise_linux:9::*"
sutra-scan feed info sutra-feed.db         # build date, newest advisory, SHA-256 of every source file

# 2. On each host (no network needed): list what is installed
sutra-scan inventory -o "$(hostname).json"

# 3. On the Sutra server (no network needed): match, and write the file Sutra imports
sutra-scan match *.json --feed sutra-feed.db -o sutra-scan.rows
sutra-scan match web01.json --feed sutra-feed.db --fail-on high   # exit code 3 for a CI gate

# Or in one step on a host that has the snapshot, or on a mounted image
sutra-scan scan --feed sutra-feed.db
sutra-scan scan --feed sutra-feed.db --root /mnt/image
```

Upload the `.rows` file under **Import data** (VM analyst or admin). Each host gets one "Host assessed by Sutra
Scan" row, which is what lets a fully patched host count as scanned so that fixes can be verified, and one row per
vulnerable package. Hosts are matched to the asset register by host name and IP address, as for every other scanner.
Re-run the inventory regularly (cron or a systemd timer) and import again: a package that has been upgraded
disappears from the next file, and Sutra's rescan check closes the job.

## What a finding says

Each row names the package, the installed version, the fixed version, the advisory ID and its CVEs, a severity, and
an evidence line such as

> libc6 (source package glibc) 2.36-9+deb12u1 is affected by DSA-5514-1; fixed in 2.36-9+deb12u3. Severity high
> (CVSS 7.8). Matched against Debian:12 advisories from OSV, newest advisory in the snapshot 2026-10-13, snapshot
> digest 5b977616a2ea. https://osv.dev/vulnerability/DSA-5514-1

(Real output for the `debian:bookworm-20230904` image.)

**Severity** is the CVSS v3 base score computed from the advisory's vector. When an advisory has none, the
distribution's own rating is used and the evidence says so ("distribution urgency", "distribution rating",
"distribution priority"); with no rating at all it is `medium` and marked "unrated". **Records with no fixed version
are not reported** unless you pass `--include-unfixed`, because there is nothing to patch.

## How the matching is done (and where it is approximate)

- **Version comparison** is a port of each system's own algorithm (`dpkg` `verrevcmp`, rpm `rpmvercmp`, apk
  `version.c`), checked in CI against the real `dpkg`, `rpm` and `apk` binaries on random inputs and against the
  published test vectors.
- **Debian, Ubuntu and Alpine** advisories name the source package, so the inventory records each binary package's
  source name and source version (a binNMU such as `2.38.1-5+b1` is judged by its source version `2.38.1-5`).
- **AlmaLinux, Rocky Linux and RHEL** errata often list several fixed builds of one package, one per module stream or minor
  release. A package is judged against the fixes of its own stream (same epoch and first version component, else all
  fixes, taking the lowest). This is a heuristic: a stale build that sorts between two fixes of the *same* stream can
  be missed. The AlmaLinux and Rocky images in the CI tests cover the common case.
- A Debian/Ubuntu CVE record and a distribution advisory (DSA, USN) for the same package and fix are reported once,
  under the distribution advisory, with the higher CVSS of the two.
- **Completeness is the feed's**: Rocky Linux's OSV data starts later than AlmaLinux's, so an old Rocky image shows
  fewer findings than the same AlmaLinux image. Sutra Scan reports what the feed says; it adds nothing of its own.
- Findings only mean the installed *package* is older than the distribution's fix. A backported fix keeps the
  upstream version number, and that is handled because the comparison uses the distribution's own version.
  Packages built from source, vendored libraries and containers inside the host are not inspected.

## Keeping the snapshot fresh

`sutra-scan feed info` and every match report the newest advisory date inside the snapshot, and a match warns when it
is more than 14 days old. For an air-gapped plant: rebuild the snapshot weekly on a connected machine and carry
`sutra-feed.db` over. The file carries the SHA-256 of every source download, so what was matched against can be
reproduced; it is **not signed** yet, so protect it like any other input (a forged snapshot could hide findings).

## Tests

```
pip install -e "./scan[test]" && pytest scan                  # unit tests on real OSV records, offline
SUTRA_SCAN_CONTAINERS=1 pytest scan/tests/test_containers.py  # real images + live feeds (internet; CI job "containers")
```

The container tests pull these exact images (pinned by digest) and check specific, historic findings: Debian
`bookworm-20230904` (glibc, CVE-2023-4911), Ubuntu `jammy-20230126`, Alpine `3.19.0`, AlmaLinux `9.2`, Rocky Linux `9.2` and Red Hat's UBI 9.2 (RHEL userland). In CI they also compare the collector's package list with `dpkg-query`, `apk info` and `rpm -qa` run inside the
image. The advisory fixtures in `tests/fixtures/osv` are real OSV records (trimmed); the hand-built inventories in
`test_match.py` are labelled as constructed.

## Limits

- Linux only so far. A Windows collector (installed programs and KBs against Microsoft's advisories) is not built.
- No agent daemon: the inventory is a command you schedule yourself.
- The snapshot is unsigned (see above) and the fetch step trusts the OSV bucket over HTTPS.
- Not yet wired into the web application's scheduled pulls; use the rows file import.
