# Nozomi Networks Open API: research notes for a read-only connector

Research date: 2026-10-11. Nozomi Networks' API documentation sits behind its customer portal and was not read. One
public source was used:

- [ELA]: Elastic's Nozomi Networks integration, `elastic/integrations` on GitHub, `packages/nozomi_networks`: the
  manifest (URL, username and password settings), the CEL pollers for `node_cve` and `asset`
  (`data_stream/*/agent/stream/cel.yml.hbs`), and the pipeline test records and sample events. The records are
  Elastic's test data, with edited values; one mixes an iPad's fields with a PLC's `node_*` fields.

## Request

- `GET {guardian or CMC}/api/open/query/do` with HTTP Basic authentication [ELA pollers].
- Parameters [ELA]: `query` (N2QL), `page` (from 1), `count` (page size), `skip_total_count=true`,
  `default_filters=false`.
- Response [ELA]: `result` (list of records) and `error` (set when the query is rejected). A page shorter than
  `count` is the last.
- Queries used, in the forms Elastic uses: `node_cves | where time > <ms> | sort time asc` and
  `assets | where last_activity_time > <ms> | sort last_activity_time asc`. The full pull drops the `where` and
  filters `resolved` in the connector, so it relies on no N2QL syntax beyond Elastic's.

DOC GAP: Nozomi Vantage (the SaaS console) uses API keys rather than a local user, and was not covered by the source.

## Vulnerability records (`node_cves`)

Fields read [ELA records and sample event]: `id`, `cve` (also `CVE-EOL` for an end-of-life product, which is kept but
carries no CVE), `cve_score`, `cve_summary`, `cwe_name`, `time` and `record_created_at` (Unix milliseconds),
`resolved`, `probability` and `likelihood`, `nodes` (addresses; may include `localhost` and `0.0.0.0`), `name`,
`type`, `vendor`, `product_name`, `firmware_version`, `os`, `zones`, `minimum_hotfix`, `asset_id`, and on CMC records
`node_label`, `node_type`, `node_vendor`, `node_product_name`, `node_firmware_version`, `node_os`, `node_id`.

There is no severity field; the connector rates by `cve_score` with the CVSS v3.1 bands. There is no fixed firmware
version; `minimum_hotfix` (a KB number on Windows-based assets) is used when present.

## Asset records (`assets`)

Fields read [ELA]: `id`, `ip` (list), `name`, `os`, `type`, `level`, `last_activity_time` and `created_at` (Unix
milliseconds, sometimes as strings). Nozomi sees assets passively, from traffic, so an asset active within the host
window (30 days) counts as assessed.
