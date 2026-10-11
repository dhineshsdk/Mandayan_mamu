# sutra-connectors

Read-only API connectors that pull vulnerability findings and host data from the scanners and endpoint agents Sutra's
customers already run, so nobody has to export a file:

| Connector | Product | Findings from | Hosts from |
| --- | --- | --- | --- |
| `QualysConnector` | Qualys VMDR | Host List Detection `/api/6.0/fo/asset/host/vm/detection/`, enriched from the KnowledgeBase `/api/4.0/fo/knowledge_base/vuln/` | Host List `/api/6.0/fo/asset/host/` |
| `TenableVMConnector` | Tenable Vulnerability Management (Tenable.io) | Vulnerability export `/vulns/export` | Asset export `/assets/export` |
| `TenableSCConnector` | Tenable Security Center (Tenable.sc) | `/rest/analysis`, tool `vulndetails` | `/rest/analysis`, tool `sumip` |
| `CrowdStrikeConnector` | CrowdStrike Falcon Spotlight | `/spotlight/combined/vulnerabilities/v1` | `/devices/queries/devices/v1` and `/devices/entities/devices/v2` |
| `AwsInspectorConnector` | Amazon Inspector (one region) | `POST /findings/list` | `POST /coverage/list` |
| `AzureDefenderConnector` | Microsoft Defender for Cloud (servers) | `GET /{scope}/providers/Microsoft.Security/subAssessments` | `GET /{scope}/providers/Microsoft.Security/assessments` |
| `NozomiConnector` | Nozomi Networks Guardian or CMC (OT) | `GET /api/open/query/do`, `node_cves` | `GET /api/open/query/do`, `assets` |

It also collects firewall and switch configurations, read-only, with every password, key and SNMP community masked
before the configuration leaves the collector (`src/sutra_connectors/netdevices.py`; research notes in
`docs/api-notes/network-devices.md`):

| Collector | Devices | Reads |
| --- | --- | --- |
| `FortiGateCollector` | Fortinet FortiGate (FortiOS REST API, API token) | `GET /api/v2/monitor/system/status`, `GET /api/v2/monitor/system/config/backup?scope=global` |
| `PanOsCollector` | Palo Alto Networks firewalls (PAN-OS XML API, API key) | `show system info`, running configuration (`type=config&action=show`) |
| `CiscoIosCollector` | Cisco IOS and IOS-XE switches and routers (SSH) | `show version`, `show running-config`, `show ip arp`, `show mac address-table` |

SSH host keys are pinned: the first key a device presents is recorded, and a different key later raises
`HostKeyError`. The SSH session can send only those four commands and the two that switch off paging.

This is a plain Python library. Scheduling, credential storage and wiring into the Sutra app come with the app's
database milestone; nothing here touches the app server, auth or database.

## Install and test

```
cd connectors
python -m pip install -e ".[test]"
ruff check .
PYTHONPATH=.. pytest
```

Python 3.10+. Runtime dependencies: `httpx`, `defusedxml` and `paramiko` (SSH to network devices). With the repository root on `PYTHONPATH`, the adapter
tests also check that connector rows match the rows Sutra's own file importers build; without the `sutra` package
they are skipped.

## Use

```python
from sutra_connectors import QualysConnector, TenableSCConnector, TenableVMConnector
from sutra_connectors.state import JsonFileCheckpointStore, sync
from sutra_connectors.sutra_rows import to_sutra_rows

qualys = QualysConnector("https://qualysapi.qg1.apps.qualys.in", username, password)  # India platform IN1
tvm = TenableVMConnector(access_key, secret_key)  # https://cloud.tenable.com by default
tsc = TenableSCConnector("https://sc.plant.example.in", access_key, secret_key, verify="/etc/ssl/plant-ca.pem")

store = JsonFileCheckpointStore("workspace/connector-checkpoints.json")
findings, hosts = [], []
report = sync(qualys, store, findings.append, hosts.append)  # first run: full pull; later runs: changes only
rows = list(to_sutra_rows(findings))  # same row dicts as sutra.ingest's file loaders
```

Each connector yields `ScannerFinding` and `ScannerHost` records (`src/sutra_connectors/models.py`). A finding carries
what the file importers read (IP, host, OS, title, severity, CVSS, CVEs, port, evidence, solution, first and last
seen) plus the API-only facts: the vendor's IDs, a stable `record_id`, and the detection state (`open`, `reopened`,
`fixed`) with the fix time. The receipt Sutra shows for an API finding is `source` (for example
`qualys-api:qualysapi.qg1.apps.qualys.in`) and `record_id`, in place of a file name and row.

## How each pull works

`sync()` records when a pull started and saves it only after every record has been handed over, so a pull that fails
half-way is repeated next time. Incremental pulls go back one extra hour (`overlap`) because scanners index results
after a scan ends; repeats share a `record_id`.

| | Full pull | Incremental pull |
| --- | --- | --- |
| Qualys | `status=New,Active,Re-Opened` | `vm_processed_after=<since>`, `status=New,Active,Re-Opened,Fixed` |
| Tenable VM | `since` = now − `full_lookback` (365 days), state OPEN, REOPENED | `since=<since>`, state OPEN, REOPENED, FIXED |
| Tenable SC | `cumulative`, all open | `cumulative` with `lastSeen` `0:<days>`, plus `patched` with `lastMitigated` `0:<days>` |

Tenable VM needs a time filter on a full pull: without one, Tenable exports only what was "found or fixed within the
last 30 days". Tenable SC filters take whole days, so its window is rounded up.

Informational findings are left out by default (`severities` on the Tenable connectors; Qualys excludes information
gathered unless `show_igs` is set, which this connector never sends).

## Safety

- **Read-only, enforced.** Each connector has an allowlist of method and path, and for Qualys the `action=list`
  parameter. Anything else raises `ReadOnlyViolation` before a request is sent. The only POSTs are the vendors' own
  read APIs (Qualys list calls, Tenable export requests, Security Center analysis queries) and cancelling a Tenable
  export job this library started, when it times out.
- **HTTPS only**, certificates verified by default. `verify` takes a CA bundle path for consoles with an internal CA.
  `verify=False` works for Security Center but logs a warning every time.
- **No redirects followed**, so credentials are never sent to another host.
- **XML parsed with defusedxml**: no entity expansion, no external entities.
- **Secrets stay out of logs, errors and `repr()`.** Checkpoint files are written atomically with mode 0600 and hold
  only timestamps and counts.

## Limits and retries

- HTTP 429 and 5xx are retried with exponential backoff and jitter (six attempts). A `Retry-After` header is honoured
  as given, up to 15 minutes.
- Qualys: rate-limit code 1965 waits `X-RateLimit-ToWait-Sec`; concurrency code 1960 waits 30 seconds; code 1981 ("try
  this same request again later") waits `busy_wait`. When `X-RateLimit-Remaining` reaches 0 the connector waits out
  the window before its next call. Requests are sequential, so a pull uses one of the subscription's concurrent slots.
- Tenable VM: one export at a time, as Tenable asks ("Do not multi-thread your requests"); a 409 for a duplicate
  export reuses the running job (`active_job_id`). An export that reports failed chunks fails the pull, rather than
  silently skipping findings.
- Tenable SC: pages of 2,000 rows (Tenable recommends 2,000 to 10,000), one at a time.

## Sources and documentation gaps

Every endpoint, parameter and field used here comes from the vendors' published documentation, cited at the top of each
connector module. `docs/api-notes/` holds the research notes with quotes and links, including points where the docs
are unclear or disagree. The gaps that affect behaviour, and how the code handles them:

- **Qualys `/api/6.0` response schema could not be read.** Qualys names 6.0 as the recommended path (Host List 2.0-4.0
  reach end of life in December 2026). The parser uses the element names from the published 2.0 samples, matches tags
  case-insensitively and ignores new elements. API versions are settings (`detection_api_version`,
  `host_api_version`, `kb_api_version`) if a tenant needs another.
- **Qualys `STATUS` strings for fixed and reopened detections** are not given verbatim; matching ignores case, hyphens
  and spaces.
- **Qualys KnowledgeBase paging** is not documented; QIDs are requested in batches of 500 with `ids=`.
- **Tenable VM asset export**: `/assets/v2/export` supersedes v1 with a nested record model; v1 is used because its
  fields could be verified. Deleted and terminated assets are not pulled.
- **Tenable VM**: some reference pages refuse automated reading; request and record schemas were cross-checked with
  Tenable's pyTenable SDK and a published copy of Tenable's OpenAPI spec. Chunk expiry is given as both 24 hours and 3
  days; chunks are downloaded as soon as they are listed.
- **Tenable SC**: the API reference puts `startOffset`/`endOffset` at the body root while the query reference, the
  integration guide and pyTenable put them inside `query`; this library follows the latter. Multiple CVEs in `cve`
  are split on commas and spaces. `lastMitigated` is read from patched results when present. No rate limits are
  documented.
- **Not yet checked against a live tenant.** All tests run on mocked responses built from the documented shapes. The
  first design-partner connection should be watched, starting with `check()` on Security Center and a small Qualys
  `truncation_limit`.
