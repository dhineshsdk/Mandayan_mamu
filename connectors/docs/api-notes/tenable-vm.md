# Tenable Vulnerability Management (Tenable.io) API: research notes for a read-only connector

Research date: 2026-10-11. WebFetch summarizes pages with a small model and caps quotes at about 125 characters, so the "verbatim" quotes below are short fragments.

Sources, in order of trust:
- [OFF]: official developer.tenable.com / docs.tenable.com pages. Several reference pages (for example exports-vulns-request-export, exports-vulns-cancel, exports-assets-request-export, vulnerability-export-guidelines-and-limitations, export-limits) are robots-blocked. Other reference pages only partly rendered.
- [OAS]: a third-party mirror of Tenable's OpenAPI specs (api-evangelist). It closely matches the official reference text, but it is not first-party:
  - https://raw.githubusercontent.com/api-evangelist/tenable/refs/heads/main/openapi/tenable-exports-vulnerabilities-api-openapi.yml
  - https://raw.githubusercontent.com/api-evangelist/tenable/refs/heads/main/openapi/tenable-exports-assets-api-openapi.yml
- [PYT]: pyTenable source, the official SDK. https://raw.githubusercontent.com/tenable/pyTenable/master/...

---
## 1. Base URL, auth, User-Agent

- **Base URL:** `https://cloud.tenable.com`.
  - [OFF] https://developer.tenable.com/docs/authorization: the curl example targets "https://cloud.tenable.com/scans".
  - [PYT] tenable/io/__init__.py: `_url = 'https://cloud.tenable.com'`.
  - [PYT docs] https://pytenable.readthedocs.io/en/stable/api/io/index.html: "The default is `https://cloud.tenable.com`".
  - FedRAMP and other regional base URLs: NOT DOCUMENTED in the pages read. The connector should make the base URL configurable.
- **Auth header** ([OFF] https://developer.tenable.com/docs/authorization):
  `X-ApiKeys: accessKey=ACCESS_KEY; secretKey=SECRET_KEY;`
  - The same page notes that the Tenable Enclave Security APIs use `x-apikey` instead. That does not apply to cloud.tenable.com.
  - [PYT] env vars: `TIO_ACCESS_KEY`, `TIO_SECRET_KEY`.
- **User-Agent** ([OFF] https://developer.tenable.com/docs/user-agent-header):
  - Required format: `Integration/1.0 (VENDOR; PRODUCT; Build/VERSION)`
  - curl example: `--header 'User-Agent: Integration/1.0 (ACME Industries; Fancyintegration; Build/1.0)'`
  - pyTenable output example: `Integration/1.0 (SMC Industries; Fancypants; Build/1.0) pyTenable/0.3.28 (pyTenable/0.3.28; Python/3.7.3; Darwin/x86_64)`
- **Rate-limit identity** ([OFF] https://developer.tenable.com/docs/rate-limiting): "Always use a unique user account for each API integration you enable or create."
- **Permissions** ([OFF] exports-vulns-request-export summary): "Users need at least BASIC [16] user permissions and the Can View access control permission for the asset objects they want to export." Also: "ADMINISTRATOR [64] users can export without the explicit Can View access control permissions."

## 2. POST /vulns/export (request)

Sources:
- [OFF] https://developer.tenable.com/reference/exports-vulnerabilities, partly rendered
- [OFF] https://developer.tenable.com/docs/retrieve-vulnerability-data-from-tenableio
- [OFF] https://developer.tenable.com/docs/refine-vulnerability-export-requests
- [OAS] the vulns export spec

**Body parameters**

- `num_assets` (int32): default **50**, range **50 to 5000**. "Specifies the number of assets used to chunk the vulnerabilities."
  - Out-of-range values are clamped: "If you specify a value outside this range, the system uses the upper or lower-bound value." [OFF reference + OAS]
  - [PYT] defaults to 500.
  - [OFF retrieve page]: "Tenable does not recommend using a chunk size larger than 5000".
- `include_unlicensed` (bool): default **false**. "The default is false when no parameter is specified." [OFF reference]
  - Also: "exported vulnerability data includes licensed assets only" by default. [OFF retrieve page]
  - [PYT] defaults this to True, so pyTenable sends it explicitly. Don't copy that by accident.
- `include_software_vulns` (bool): default false. Adds a `software_vulns` array. [OAS; the OFF page shows the description but not the name]
- Plugin output toggle (bool): default true. "Specifies whether to include plugin output in each vulnerability record in the export." The exact parameter name is NOT CONFIRMED; the OFF page did not render it.
- `filters` (object): described below.

**Default time window** [OFF reference]: "By default, vulnerability exports will only include accepted and non-accepted vulnerabilities" "found or fixed within the last 30 days if no time-based filters are submitted with the request."
- The retrieve page lists the time-based filters as indexed_at, last_fixed, last_found, and first_found.

**Filters.** All timestamps are int64 **Unix seconds**. [OAS] says "10-digit Unix timestamp in seconds" for indexed_at and last_fixed. The [OFF] refine page example uses `"since": 1546300800` = Jan 1, 2019.

- `since`: "The start date for the range of data you want to export." [OAS]
  - It is interpreted together with `state`: last-seen dates for OPEN and REOPENED, fix dates for FIXED.
  - It **cannot be combined** with first_found, first_seen, last_found, last_seen, or last_fixed. [OAS]
  - [OFF refine]: "the export includes data for OPEN and REOPENED vulnerabilities that were seen on or after the since date you specify".
- `state`: array, enum `OPEN`, `REOPENED`, `FIXED`. [OAS] says case-insensitive; the [OFF] examples use uppercase.
  - It is **required** when first_found, last_found, or last_fixed is used.
  - If omitted, it defaults to OPEN and REOPENED. [OAS]
  - [OFF refine]: "The API uses different terms for vulnerability states than the user interface."
- `severity`: array, enum `info`, `low`, `medium`, `high`, `critical`, all lowercase. Default is all levels. [OAS; PYT; OFF examples use lowercase]
- `first_found` (alias `first_seen`): "Returns vulnerabilities first discovered on or after the specified date." [OAS]
- `last_found` (alias `last_seen`): "Returns vulnerabilities last found on or after the specified date." [OAS]
- `last_fixed`: "Returns vulnerabilities that were last fixed between the specified date and the present." [OAS]
- `indexed_at`: "Returns vulnerabilities that were indexed in Tenable Vulnerability Management on the specified date." [OAS]
  - Whether it means "on" or "on or after" is unclear from the wording.
- `plugin_id`: array of ints. [OAS]
- `tag.<category>`: array of values. [OFF refine examples, e.g. `"tag.Location": ["Austin","Dallas","Fort Worth"]`]
- Others in [PYT]: `severity_modification_type` (`NONE`, `ACCEPTED`, `RECASTED`), and `vpr_score`.
  - [OFF] deprecation notice: "update all integrations to use the vpr_score filter parameter"; `vpr_v2_score` is deprecated as of July 1, 2026.

**Responses** [OAS; OFF reference shows 400 and 403]

| Code | Meaning |
|------|---------|
| 200 | `{"export_uuid": "..."}`. "Returned if a vulnerability export request was queued successfully." |
| 400 | Invalid parameters or improperly formatted request. |
| 403 | "Returned if you do not have permission to export vulnerabilities." |
| 409 | Duplicate of an export already in progress. The body includes `active_job_id` and `failure_reason`. |
| 429 | Rate or concurrency limit. |

- [OFF retrieve]: "Vulnerability Management rejects any concurrent request with identical filters from the same user account" while the original is PROCESSING and fewer than three days have passed. The OFF page does not name the status code; 409 comes from [OAS] and [PYT].
- [PYT] api.py: on 409 with `adopt_existing=True` (the default), pyTenable reads `active_job_id` from the response body, reuses that job, and logs `failure_reason`.
- Other OFF notes:
  - "You cannot export vulnerabilities detected by PCI scans."
  - "Output for an individual plugin is limited to 1,024 KB (1 MB)."

## 3. Vuln export status and chunks

**GET /vulns/export/{export_uuid}/status** [OAS schema `Export_Vulnerabilities_response-vulns-export-status`]

- `uuid` (string)
- `status` (string, UPPERCASE): `QUEUED`, `PROCESSING`, `FINISHED`, `CANCELLED`, `ERROR`
  - FINISHED: "Tenable Vulnerability Management has completed processing the export request. All chunks are available."
  - CANCELLED: "An administrator has cancelled the export request."
  - ERROR: "An error occurred while processing the export request. Retry the request."
- `reason` (string): present only when status is ERROR, or FINISHED with failed chunks. Example values:
  - "The export request timed out. Try again."
  - "{N} of {M} chunks failed to process. The remaining chunks are available for download."
- `chunks_available` (int32[]): "A list of completed chunks available for download."
- `chunks_failed` (int32[])
- `chunks_cancelled` (int32[]): a failed chunk causes all later queued chunks in the same request to be cancelled automatically.
- `total_chunks` (int)
- `chunks_available_count` (int)
- `empty_chunks_count` (int)
- `finished_chunks` (int)
- `filters` (object)
- `num_assets_per_chunk` (int)
- `created` (int64, Unix timestamp)

Notes:
- [OFF] exports-vulns-export-status: "Tenable Vulnerability Management processes the chunks in parallel so the chunks may not complete in order."
- Chunks can be downloaded while the status is PROCESSING. [PYT] iterator.py pops `chunks_available` as they appear and loops until status == FINISHED.
- **GET /vulns/export/status** lists jobs. The array is under `exports` [PYT]. Each item has the same fields minus the three chunk lists [OAS].

**GET /vulns/export/{export_uuid}/chunks/{chunk_id}** [OFF] https://developer.tenable.com/reference/exports-vulns-download-chunk

- Accept defaults to `application/octet-stream`. The body is a JSON array of vulnerability objects.
- 400: includes the case where "the vulnerabilities chunk was not ready for download".
- 403: no permission.
- 404: not found, or "the chunk with the specified UUID has expired".
- **Expiry conflict:**
  - [OFF retrieve page]: "You can download completed export chunks for three days after completion."
  - [OAS] download-chunk description: up to 24 hours after creation.
  - [OAS] cancel description: completed chunks stay downloadable for three days after cancellation.
  - Treat the window as **24 hours** to be safe; the sources are unclear.
- [PYT] download_chunk retries 3 times when the body is not valid JSON, and warns on empty chunks. Empty chunks exist; see `empty_chunks_count`.

## 4. Vulnerability object fields

Source: [OAS] chunk schema. Not verified against a live response.

**Top level**

| Field | Type |
|-------|------|
| `output` | string |
| `severity` | string. The value set is not enumerated in the schema; it likely matches the filter enum info/low/medium/high/critical (unverified). |
| `severity_id` | int32. The 0 to 4 mapping is NOT DOCUMENTED in what I read. |
| `severity_default_id` | int32 |
| `severity_modification_type` | string |
| `state` | string. API values are OPEN, REOPENED, FIXED (from the filter enum; casing in records is not stated). |
| `first_found` | **string, ISO-8601 timestamp** (no `format` declared) |
| `last_found` | **string, ISO-8601 timestamp** |
| `last_fixed` | **string, ISO-8601 timestamp** |
| `indexed` | **int64 Unix time**. The schema has `indexed`, not `indexed_at`. `indexed_at` is only a filter name. |
| `finding_id` | uuid string |
| `source` | string |
| `resurfaced_date` | string |
| `time_taken_to_fix` | int64 |
| `recast_reason` | string |
| `recast_rule_uuid` | string |
| `software_vulns` | array |

**`asset.*`**

| Field | Type |
|-------|------|
| `uuid` | string |
| `hostname` | string |
| `fqdn` | string |
| `ipv4` | string (single value) |
| `ipv6` | string |
| `netbios_name` | string |
| `operating_system` | **array of string** |
| `mac_address` | string |
| `agent_uuid`, `bios_uuid`, `device_type`, `network_id`, `netbios_workgroup`, `serial_number` | string |
| `tracked` | bool |
| `last_authenticated_results`, `last_unauthenticated_results` | string |

**`plugin.*`**

| Field | Type |
|-------|------|
| `id` | int |
| `name` | string |
| `cve` | **array of string** |
| `cvss_base_score` | float |
| `cvss3_base_score` | float |
| `solution`, `synopsis`, `description` | string |
| `family`, `risk_factor`, `see_also`, `vpr`, `epss_score`, `has_patch`, `exploit_available`, `cvss3_vector`, `cvss4_base_score`, `publication_date`, `patch_publication_date`, ... | various |

**`port.*`**: `port` (int), `protocol` (string), `service` (string).

**`scan.*`**: `uuid`, `schedule_uuid`, `started_at` (ISO string), `last_scan_target`.

Treat every field as optional or nullable.

## 5. Asset export

Sources: [OAS] assets spec; [OFF] https://developer.tenable.com/docs/vm-retrieve-data. The [OFF] reference page exports-assets-request-export is robots-blocked.

**POST /assets/export (v1)**

- `chunk_size` (int, **required**): "Specifies the number of assets per exported chunk. The range is 100-10000."
  - The OAS example is 5000. The limit drops to 1000 with `include_resource_tags`.
  - [OFF]: "Tenable does not recommend using a chunk size larger than 5000".
  - [PYT] defaults to 1000.
- `include_open_ports` (bool, default false), `include_resource_tags` (bool, default false).
- `filters`:
  - Timestamp filters, int64 Unix, "later than" the given date: `created_at`, `updated_at`, `terminated_at`, `deleted_at`, `first_scan_time`, `last_authenticated_scan_time`, `last_assessed`.
  - Booleans: `is_terminated`, `is_deleted`, `is_licensed`, `has_plugin_results`, `servicenow_sysid`.
  - Other: `last_scan_id`, `network_id`, `sources[]`, `tag.<category>[]`.
  - Omitting all filters returns all current assets.
  - [OFF]: deleted and terminated assets come only through the `terminated_at` and `deleted_at` filters.
  - [OFF]: "use the id attribute from the asset export response message, instead of any other single asset identifier".

**POST /assets/v2/export (exists)** [OAS; PYT `assets_v2()`, which posts to `assets/v2/export` but uses `assets/export/...` for status and chunks]

- Supersedes v1 and adds WAS web-app assets.
- New filters: `since` (int64; assets updated, deleted, or terminated since), and `types` (`host` | `webapp`, default `host`).
- Drops `tag.<category>`.
- Different (nested) record model:
  - Timestamps move into `timestamps{}`.
  - Network data moves into `network{}`: ipv4s, ipv6s, fqdns, hostnames, netbios_names, mac_addresses, open_ports, and more.
  - Also nested: `cloud{}`, `third_party_ids{}`, `scan{}`.
  - Adds `is_licensed`, `types`, `is_public`, `custom_attributes`.
  - Removes `acr_score`, `exposure_score`, `serial_number`.

**Status and chunks** (shared by v1 and v2)

- `GET /assets/export/{uuid}/status` → `status` (`QUEUED|PROCESSING|FINISHED|CANCELLED|ERROR`), `chunks_available` (int[]), `reason` (when ERROR).
  - The full asset status field list (whether it has chunks_failed or total_chunks) is not fully confirmed.
- `GET /assets/export/status` lists jobs: "the 1,000 most recent". Job items have uuid, status, reason, total_chunks, filters, finished_chunks, num_assets_per_chunk, created.
- `GET /assets/export/{uuid}/chunks/{chunk_id}` → JSON array of asset records.
  - [OFF] https://developer.tenable.com/reference/exports-assets-download-chunk: "Chunks are available for download for up to 24 hours after they have been created." Expired chunks return 404.
  - [OFF vm-retrieve-data]: "You can download completed export chunks for 24 hours after completion."
- `POST /assets/export/{uuid}/cancel`.
- **Duplicate-request conflict:**
  - [OAS]: 409 when "your export request is identical to a request already in progress".
  - [OFF vm-retrieve-data] says both "Vulnerability Management rejects any concurrent request with identical filters from the same user account" and, for duplicate filters, "the old export is canceled and a new export is submitted."
  - The docs contradict each other. Handle both a 409 (reuse `active_job_id` if present) and a silently cancelled earlier job.

**v1 asset record fields** [OAS]

- Strings: `id`, `agent_uuid`, `bios_uuid`, `network_id`, `network_name`, `serial_number`, `last_scan_id`, ...
- Timestamps, **ISO-8601 strings**: `created_at`, `updated_at`, `deleted_at`, `terminated_at`, `first_seen`, `last_seen`, `first_scan_time`, `last_scan_time`, `last_authenticated_scan_date`, `last_licensed_scan_date`.
- **Arrays of string**: `ipv4s`, `ipv6s`, `fqdns`, `hostnames`, `netbios_names`, `operating_systems`, `mac_addresses`, `agent_names`, `installed_software`, `system_types`, `ssh_fingerprints`.
- Booleans: `has_agent`, `has_plugin_results`. One example shows `has_plugin_results` as null.
- `sources[]`: `{name, first_seen, last_seen}`.
- `tags[]`: `{uuid, key, value, added_by, added_at}`.
- `network_interfaces[]`, `open_ports[]`, plus cloud fields (`aws_*`, `azure_*`, `gcp_*`).

## 6. Rate limiting and concurrency

- [OFF] https://developer.tenable.com/docs/rate-limiting:
  - The request limit is computed "from a single user per minute" based on "current processing load". No fixed number is published.
  - When it is exceeded, the API returns "429 (Too Many Requests)". "The response also includes a retry-after" "header element that specifies the number of seconds to wait before retrying." Example: `retry-after:30`.
  - Guidance: "Do not multi-thread your requests."; "Use the exports endpoints to retrieve data".
- [OFF] https://developer.tenable.com/docs/concurrency-limiting:
  - Exports: "10 concurrent exports per container", and duplicate exports (same filters) are prevented from running concurrently.
  - "3 concurrent requests per customer instance" (subject to change). The page does not say precisely what this applies to.
  - Over the limit, the API returns 429 with retry-after.
- [OFF] https://docs.tenable.com/other/service-description-guide/Content/cloudplatform/performance-and-fair-use.htm:
  - "Users are allowed a maximum of 10 active concurrent export requests per customer container, depending on the endpoint."
  - Export job file storage is limited to "500 MB or 50 GB, depending on your license".
- 5xx handling, [OFF] https://developer.tenable.com/docs/common-tio-api-errors:
  - 503: "Wait a moment and retry your request."
  - 500: no retry guidance.
  - Export status ERROR: "Retry the request" [OAS].
  - No official backoff algorithm is DOCUMENTED.
- [PYT] defaults: retries=5. On 429 without Retry-After, the backoff is 1 second ("If a 429 response is returned, how much do we want to backoff if the response didn't send a Retry-After header. The default backoff is `1` second.").
  - On retry pyTenable sends the `X-Tio-Last-Request-Uuid` (taken from the response header of the same name) and `X-Tio-Retry-Count` headers.
  - It polls status with a linear backoff of 1, 2, 3 ... seconds, capped at 30.
  - It downloads chunks with 2 threads by default.
  - The exact list of retried status codes lives in the restfly library, which I could not fetch: NOT CONFIRMED.

## 7. Cancel

- `POST /vulns/export/{export_uuid}/cancel` [OAS; PYT `cancel()` → `{job_path}/{uuid}/cancel`]
  - The OFF page https://developer.tenable.com/reference/exports-vulns-cancel is robots-blocked.
  - The job finishes chunks already processing, stops unprocessed chunks, and sets the status to CANCELLED.
  - Response 200: `{"status": "CANCELLED"}`.
  - 400: invalid request, or the job could not be cancelled.
  - 404: job not found.
- `POST /assets/export/{export_uuid}/cancel` works the same way.

## Open / unclear items

- Chunk expiry for vulnerability exports: 3 days ([OFF] guide) or 24 hours ([OAS] reference).
- Asset duplicate export: 409 or cancel-and-replace ([OFF] page says both).
- The `severity_id` numeric mapping, and the casing of `state` and `severity` values inside records: not confirmed.
- The exact JSON name of the "include plugin output" flag.
- What "3 concurrent requests per customer instance" applies to.
- Region and FedRAMP base URLs.
