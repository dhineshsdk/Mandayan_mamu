# CrowdStrike Falcon Spotlight API: research notes for a read-only connector

Research date: 2026-10-11. CrowdStrike's API reference and swagger are only visible after signing in to a Falcon
console, so they were not read. Two public sources were used instead.

Sources, in order of trust:
- [FPY]: FalconPy 1.6.6, CrowdStrike's official Python SDK (PyPI `crowdstrike-falconpy`, source distribution). Its
  `src/falconpy/_endpoint/*.py` files are generated from CrowdStrike's swagger and list each operation's method, path
  and parameters with their descriptions.
- [ELA]: Elastic's CrowdStrike integration, `elastic/integrations` on GitHub, `packages/crowdstrike/data_stream/`
  `vulnerability` and `host`: the CEL programs that call the API (`agent/stream/cel.yml.hbs`) and the pipeline test
  records (`_dev/test/pipeline/test-*.log`). The test records have the API's shape but some values are edited
  (for example `local_ip: 1.128.0.0`).

## Auth

- `POST /oauth2/token`, form fields `client_id`, `client_secret`, and optionally `member_cid` ("For MSSP Master CIDs,
  optionally lock the token to act on behalf of this member CID") [FPY `_oauth2.py`].
- Tokens have "a standard 30-minute lifespan" [FPY `oauth2RevokeToken` description]. The response is read as a
  standard OAuth 2.0 token response (`access_token`, `expires_in`); the connector renews a minute early and once
  after any 401.
- Base URLs [FPY `_enum/_base_url.py`]: US1 `api.crowdstrike.com`, US2 `api.us-2.crowdstrike.com`, US3
  `api.us-3.crowdstrike.com`, EU1 `api.eu-1.crowdstrike.com`, USGOV1 `api.laggar.gcw.crowdstrike.com`.
- API client scopes needed: Vulnerabilities (read) and Hosts (read). (Scope names as shown in the Falcon console's
  API client screen; to confirm when a design partner creates the client.)

## Vulnerabilities

`GET /spotlight/combined/vulnerabilities/v1` [FPY `combinedQueryVulnerabilities`]:
- `filter` (required, FQL). Exact-match fields include `aid`, `status`, `cve.id`, `cve.severity`,
  `host_info.platform_name`, `suppression_info.is_suppressed`; range fields are `created_timestamp`,
  `closed_timestamp`, `updated_timestamp`, `cve.base_score`.
- `limit` "default: 100, max: 5000"; `after` paging token ("On your first request, don't provide an after token");
  `sort` such as `updated_timestamp|asc`; `facet`, repeated, from `host_info`, `remediation`, `cve`, `evaluation_logic`.
- Response: `resources`, `errors`, `meta.pagination.after` (empty when done) [ELA vulnerability CEL]. Elastic filters
  incremental pulls with `updated_timestamp:>='<RFC 3339>'` and sorts ascending by `updated_timestamp`.
- Record fields used [ELA test records]: `id`, `aid`, `vulnerability_id`, `status`, `created_timestamp`,
  `updated_timestamp`, `closed_timestamp`, `app.product_name_normalized`, `app.product_name_version`,
  `apps[].remediation_info.recommended_id`, `cve.id`, `cve.severity` (upper case, e.g. `MEDIUM`), `cve.base_score`,
  `host_info.hostname`, `host_info.local_ip`, `host_info.machine_domain`, `host_info.os_version`,
  `host_info.host_last_seen_timestamp`, `remediation.entities[]` with `id`, `reference` (fixed version or KB),
  `action`, `data_providers[].ports`.

DOC GAP: the values of `status`. The samples only show `open`. `reopen`, `closed` and `expired` are taken from
CrowdStrike's Spotlight documentation as remembered, not from a source read for this connector. A full pull asks for
`status:['open','reopen']`; check both values, and the FQL list syntax, on a real tenant before go-live.

## Hosts

- `GET /devices/queries/devices/v1` with `offset` and `limit` returns device IDs; `meta.pagination.total` says when to
  stop [ELA host CEL, which also notes that `/devices/combined/devices/v1` is not available in GovCloud].
- `POST /devices/entities/devices/v2` with JSON `{"ids": [...]}` returns device records [FPY `PostDeviceDetailsV2`,
  ELA host CEL]. Fields used [ELA test records]: `device_id`, `hostname`, `local_ip`, `os_version`, `first_seen`,
  `last_seen`. DOC GAP: the maximum number of IDs per request; the connector sends 100.
- Spotlight assesses hosts continuously through the sensor, so a host whose sensor reported recently counts as
  assessed. Hosts not seen within `host_window` (30 days by default) are left out.
