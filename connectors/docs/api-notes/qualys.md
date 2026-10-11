# Qualys VMDR (VM) API research for a read-only connector

Researched 2026-10-11. Sources were fetched with WebFetch, which summarizes pages through a small model. Short quoted strings are verbatim as returned. Anything that could not be confirmed is marked **NOT DOCUMENTED / unclear**.

Main limitation: on docs.qualys.com, the multi-version API pages put each version in its own tab. WebFetch only reached the V2.0 and V3.0 tabs, so **the V4.0, V5.0 and V6.0 tabs for Host List Detection and Host List could not be read.** The facts below about V6.0 come from the versioning page and the release notes.

---

## 0. VERSIONING: which path is current (read this first)

Source: "API Life Cycle - EOS/EOL", page says "Last updated: September, 2026". https://docs.qualys.com/en/vm/qweb-all-api/get_started/api_versioning_standards.htm

The latest version for each API, from the "New API Path (Recommended)" column:

| API | Old path | Recommended path | EOS | EOL |
|---|---|---|---|---|
| VM Detection (Host List Detection) | /api/2.0, 3.0, 4.0 `/fo/asset/host/vm/detection/index.php` | **/api/6.0/fo/asset/host/vm/detection/index.php** | December 2025 | **June 2027** |
| VM Detection | /api/5.0/fo/asset/host/vm/detection/index.php | /api/6.0/... | February 2027 | August 2027 |
| Asset Host (Host List) | /api/2.0, 3.0, 4.0 `/fo/asset/host/index.php` | **/api/6.0/fo/asset/host/index.php** | December 2025 | **December 2026** (imminent) |
| Asset Host | /api/5.0/fo/asset/host/index.php | /api/6.0/... | February 2027 | August 2027 |
| KnowledgeBase Vuln | /api/2.0/fo/knowledge_base/vuln/index.php | **/api/4.0/fo/knowledge_base/vuln/index.php** | December 2025 | December 2026 (imminent) |
| KnowledgeBase Vuln | /api/3.0/fo/knowledge_base/vuln/index.php | /api/4.0/... | August 2026 | February 2027 |

Verbatim row: "/api/2.0/fo/asset/host/vm/detection/index.php /api/6.0/fo/asset/host/vm/detection/index.php December 2025 June 2027"

Policy, verbatim: "For API endpoints supporting versioning standards, customers get an overall 12 months to shift to the latest versions." and "End of Support (EOS): Six months after the latest deployment for your respective POD."

Cross-checks in the release notes:
- 10.38.3: "we have extended the End of Life (EOL) dates for VM detection API from June 2026 to June 2027" for /api/2.0, 3.0 and 4.0 detection. https://docs.qualys.com/en/vm/release-notes/qweb/release_10_38_3_api.htm
- **10.39.2 introduced /api/6.0** for both Host List and Host List Detection, adding OCI cloud metadata. Host List gained CLOUD_PROVIDER, CLOUD_SERVICE and CLOUD_RESOURCE_ID. Host List sample note: "<EC2_INSTANCE_ID> tag has been deprecated. Please refer to <CLOUD_RESOURCE_ID> tag for the same information". DTDs were added. /api/5.0 has EOS February 2027 and EOL August 2027. https://docs.qualys.com/en/vm/release-notes/qweb/release_10_39_2_api.htm
- 10.36.1: /api/5.0/fo/asset/host/vm/detection/ "supports GET and POST", with no DTD change. /api/4.0 detection had "EOS Timeline: December 2025" and "EOL Timeline: June 2026" (later extended to June 2027). It added HIGHEST_CONTRIBUTING_CVE under QDS_FACTORS. Also: "Currently, the EOS message is shown only in XML response format." https://docs.qualys.com/en/vm/release-notes/qweb/release_10_36_1_api.htm
- 10.33: /api/4.0 detection added MITRE_TACTIC_NAME, MITRE_TECHNIQUE_NAME, MITRE_TACTIC_ID and MITRE_TECHNIQUE_ID, and added a DTD. https://docs.qualys.com/en/vm/release-notes/qweb/release_10_33_api.htm
- 10.34: /api/5.0/fo/asset/host added VM_AUTH_INSUFFICIENT_PRIVILEGE. https://docs.qualys.com/en/vm/release-notes/qweb/release_10_34_api.htm
- 10.39: /api/4.0 KnowledgeBase added CVSS_V4 and a DTD. https://docs.qualys.com/en/vm/release-notes/qweb/release_10_39_api.htm
- 10.38.2: fixed a CSV column bug on /api/5.0 detection.
- 10.37.2: fixed "inconsistencies ... in the responses when the detection_updated_since parameter was used" across HLD versions.
- 10.37.1: "EASM hosts are now excluded from the VMDR Host Detection API output".

The versioned paths take the same parameters, and each version mainly adds response elements. **The exact V6.0 HLD parameter list and response DTD could not be read: NOT VERIFIED.** The DTD is said to be published per version, for example `<platform API server>/api/2.0/fo/asset/host/vm/detection/dtd/output.dtd` for v2.0. A WebFetch of that URL returned binary or unreadable content, so the v6.0 DTD path is unverified.

The host_list.htm page summary says the V3.0 Host List samples "return lowercase XML tags (for example, `<host_list_output>`, `<host>`)". **This is unclear and unverified, and could be a documentation artifact.** A parser should match element names case-insensitively, or this should be verified against a live tenant.

A beta JSON API also exists: "Host Detection List - API JSON", `POST /vmrs/api/1.0/host/list/detections`, in "Limited Customer Release Notes" 10.39.1 (July 22, 2026). The page is marked Draft/Beta and uses page-number and requestId pagination. It is not GA and is not recommended for production. https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/New_host_list_detection_api.htm

---

## 1. API server URLs per platform

Source: https://www.qualys.com/platform-identification/

| Platform | API Server URL | Platform (UI) URL |
|---|---|---|
| US1 | https://qualysapi.qualys.com | https://qualysguard.qualys.com |
| US2 | https://qualysapi.qg2.apps.qualys.com | https://qualysguard.qg2.apps.qualys.com |
| US3 | https://qualysapi.qg3.apps.qualys.com | https://qualysguard.qg3.apps.qualys.com |
| US4 | https://qualysapi.qg4.apps.qualys.com | https://qualysguard.qg4.apps.qualys.com |
| GOV1 | https://qualysapi.gov1.qualys.us | https://qualysguard.gov1.qualys.us/ |
| EU1 | https://qualysapi.qualys.eu | https://qualysguard.qualys.eu |
| EU2 | https://qualysapi.qg2.apps.qualys.eu | https://qualysguard.qg2.apps.qualys.eu |
| EU3 | https://qualysapi.qg3.apps.qualys.it | https://qualysguard.qg3.apps.qualys.it |
| **IN1 (India)** | **https://qualysapi.qg1.apps.qualys.in** | https://qualysguard.qg1.apps.qualys.in |
| CA1 | https://qualysapi.qg1.apps.qualys.ca | https://qualysguard.qg1.apps.qualys.ca |
| AE1 | https://qualysapi.qg1.apps.qualys.ae | https://qualysguard.qg1.apps.qualys.ae |
| UK1 | https://qualysapi.qg1.apps.qualys.co.uk | https://qualysguard.qg1.apps.qualys.co.uk |
| AU1 | https://qualysapi.qg1.apps.qualys.com.au | https://qualysguard.qg1.apps.qualys.com.au |
| KSA1 | https://qualysapi.qg1.apps.qualysksa.com | https://qualysguard.qg1.apps.qualysksa.com |
| Private | `https://qualysapi.<customer_base_url>` | |

The page lists only one India platform (IN1). The base URL should be configurable, with private platforms allowed.

---

## 2. Authentication

Source: https://docs.qualys.com/en/vm/qweb-all-api/get_started/authentication.htm

- Basic, verbatim: "Qualys account credentials are transmitted using the “Basic Authentication Scheme” over HTTPS for each API call."
- Header, verbatim: "The "X-Requested-With" header parameter must be included in all API v2 calls using basic HTTP authentication". The page says it helps protect against CSRF and also applies to session auth. Any value is accepted. Docs use `X-Requested-With: Curl Sample`, and qualysapi uses "Parag Baxi QualysAPI (python) v…".
- Sample: `curl -H "X-Requested-With: Curl Sample" -u "acme_ab12:passwd" "https://qualys_base_url/api/2.0/fo/asset/host/?action=list"`
- Session alternative: "APIs with request URL containing /2.0/ support session based authentication." Login is `POST /api/2.0/fo/session/` with `action=login&username=..&password=..`, and the "request returns a session ID in the Set-Cookie HTTP header". Send the cookie `QualysSession=<id>`. Logout is `action=logout`. Warning: "Access may be denied if a user makes too many session login requests without closing sessions properly". **Whether session auth works on /api/3.0 through /api/6.0 paths is NOT DOCUMENTED / unclear**, because the doc says /2.0/. Recommendation: use Basic auth.
- OAuth or token for these VM APIs: NOT DOCUMENTED.

---

## 3. Host List Detection API

Source (multi-version page): https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm. Also https://docs.qualys.com/en/vm/api/assets/host_lists/host_detection.htm, which is the v2.0 single page, marked Draft.

- Path: `/api/{2.0|3.0|4.0|5.0|6.0}/fo/asset/host/vm/detection/?action=list`, with GET or POST. The page's version tabs read "V2.0|V3.0|V4.0|V5.0|V6.0". Recommended: **6.0** (see section 0).
- GET vs POST: the docs list both. qualysapi sends every v2 request as POST, with the code comment "All API v2 requests are POST methods" (https://raw.githubusercontent.com/paragbaxi/qualysapi/master/qualysapi/connector.py). Using POST with form-encoded params avoids URL-length limits. Qualys's own preference between the two: NOT DOCUMENTED. Error 1908 exists: "Request method (GET or POST) is incompatible with specified parameter(s)".

Parameters, verbatim or near-verbatim from the docs (v2.0 and v3.0 tabs):
- `action=list`: "Specify action=list to list host detection."
- `echo_request`: "Specify 1 to view input parameters in the XML output."
- `truncation_limit`: "When not specified, the truncation limit is set to 1000 host records." "You may specify a value less than the default (1-999) or greater than the default (1001-1000000)." "Specify 0 for no truncation limit." The limit counts hosts, not detections.
- `show_results`: "When not specified, results are included in the output. Specify show_results=0 to exclude the results."
- `status`: "Show only hosts with one or more of these status values: New, Active, Re-Opened, Fixed." "If this parameter is not passed to the API, by default, the output contains detections with New, Active or Re-Opened". **Fixed detections must be requested explicitly.**
- `show_igs`: "Specify 0 (default) to hide information gathered."
- `include_vuln_type`: "Use to download vulnerability information based on their type, confirmed or potential." Samples use `confirmed` and `potential`.
- `qids`, `severities`: comma-separated values and ranges are allowed.
- `filter_superseded_qids`: "When unspecified or set to 0, the XML output includes all QIDs even if they've been superseded."
- `vm_scan_since`, `vm_processed_after`, `vm_processed_before`: format YYYY-MM-DD[THH:MM:SSZ] (UTC).
- `detection_updated_since`: "Show only detections whose detection status changed after a certain date and time." `detection_updated_before` is the counterpart. `detection_processed_after` is "Show detections with vulnerability scan results processed after a certain date and time." The examples "2017-02-15" and "2017-02-15T23:15:00Z" show the format YYYY-MM-DD[THH:MM:SSZ].
- `ids`, `id_min` ("Show only hosts which have a minimum host ID value."), `id_max`.
- `output_format`: "Valid values are: XML, CSV or CSV_NO_METADATA, CSV_NO_METADATA_MS_EXCEL and CSV_MS_EXCEL". XML is the default. JSON is not supported on the fo API.
- `show_qds`: "Specify 1 to show the QDS value in the output for each detection record." `show_qds_factors` exists. `qds_min` "can only be specified when show_qds=1".
- `show_tags` (1 adds asset tags), `show_asset_id` (default 0), `host_metadata` (all, ec2, google, azure), `arf_kernel_filter` ("active_kernels_only is deprecated ... use arf_kernel_filter instead"), `compliance_enabled`, `os_pattern` (PCRE, URL-encoded).
- V3.0 adds `arf_filter_keys` and `show_arf_data`.
- V6.0-specific parameters: NOT VERIFIED (tab unreadable).

Qualys guidance from the blog (https://blog.qualys.com/product-tech/2021/07/09/qualys-api-best-practices-host-list-detection): "scoping the extract to brief time intervals via vm_processed_after date". The blog drives HLD from a queue of host IDs with "spawning of concurrently running jobs through a multiprocessing facility". It gives no numbers.

---

## 4. Pagination (truncation WARNING)

Source: the host_detection.htm page, verbatim sample. The URL line is wrapped here.

```xml
<WARNING>
<CODE>1980</CODE>
<TEXT>100 record limit exceeded. Use URL to get next batch of results.</TEXT>
<URL><![CDATA[https://<qualys_base_url>/api/2.0/fo/asset/host/vm/detection/?action=list&truncation_limit=100&id_min=5641289]]></URL>
</WARNING>
```

Verbatim: "then the XML output includes the <WARNING> element and the URL for making another request for the next batch of host records."

`WARNING` is a child of `RESPONSE`, a sibling of `HOST_LIST`. To paginate, follow WARNING/URL, or extract `id_min` from it and resend with the same parameters, until no WARNING appears. Code 1980 is not listed in Appendix D.

Separately, EOS deprecation warnings appear in XML responses. Their exact XML element and code are NOT DOCUMENTED. A parser must not treat every WARNING as a pagination marker: it should check `CODE == 1980` and the presence of a URL.

---

## 5. Response XML structure (HLD)

Sources: the v2.0 doc samples, plus GitHub sample https://github.com/QualysAPI/Qualys-API-Doc-Center/blob/master/Host%20List%20Detection%20API%20samples/Sample%20%201%20-%20Host%20List%20Detection%20XML%20Output. Both agree.

```
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "<base>/api/2.0/fo/asset/host/vm/detection/dtd/output.dtd">
HOST_LIST_VM_DETECTION_OUTPUT
  RESPONSE
    DATETIME            2018-04-26T11:25:58Z
    HOST_LIST
      HOST
        ID              6506432
        (ASSET_ID)      when show_asset_id=1
        IP              10.10.10.11
        (IPV6)          NOT seen in samples, unverified
        TRACKING_METHOD IP
        OS              Windows 2008 R2 Enterprise Service Pack 1
        DNS             2k8r2-u-10-11.sample.qualys.com
        DNS_DATA
          HOSTNAME      2k8r2-u-10-11
          DOMAIN        sample.qualys.com
          FQDN          2k8r2-u-10-11.sample.qualys.com
        NETBIOS         2K8R2-U-10-11
        LAST_SCAN_DATETIME        2018-04-13T03:49:05Z
        LAST_VM_SCANNED_DATE      2018-04-13T03:48:50Z
        LAST_VM_SCANNED_DURATION  352
        LAST_PC_SCANNED_DATE      (some samples)
        (TAGS, METADATA)          with show_tags / host_metadata; no sample seen
        DETECTION_LIST
          DETECTION
            UNIQUE_VULN_ID          52664
            QID                     38170
            TYPE                    Confirmed | Potential (Info when show_igs=1, not seen in samples)
            SEVERITY                2
            PORT                    3389      (optional)
            PROTOCOL                tcp       (optional)
            SSL                     1
            RESULTS                 CDATA text (omitted with show_results=0)
            STATUS                  New | Active | Fixed | Re-Opened (see note)
            FIRST_FOUND_DATETIME    2018-01-26T04:45:50Z
            LAST_FOUND_DATETIME     2018-04-13T03:48:50Z
            TIMES_FOUND             111
            LAST_TEST_DATETIME      2018-04-13T03:48:50Z
            LAST_UPDATE_DATETIME    2018-04-13T03:49:05Z
            LAST_FIXED_DATETIME     2019-08-27T22:48:04Z (optional)
            IS_IGNORED              0
            IS_DISABLED             0
            LAST_PROCESSED_DATETIME 2018-04-13T03:49:05Z
            QDS severity="LOW"      5  (with show_qds=1)
            QDS_FACTORS/QDS_FACTOR name="..."  (with show_qds_factors=1)
            MITRE_* (v4.0+)
    WARNING (CODE/TEXT/URL)   pagination
```

- Date format: ISO-8601 UTC with a `Z` suffix, `YYYY-MM-DDTHH:MM:SSZ`.
- STATUS output strings: samples show `New` and `Active`, and the request parameter uses `Re-Opened` and `Fixed`. **The exact output strings for Fixed and Re-Opened are NOT DOCUMENTED / unclear.** Normalize case-insensitively.
- TYPE value `Info` for information gathered: NOT confirmed in docs (inferred, unverified).
- ID vs QG_HOSTID, IPV6, ASSET_ID: present on the host list pages. They are NOT confirmed in HLD samples, so all such fields should be treated as optional.

---

## 6. KnowledgeBase API

Source: https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase.htm

- Path: GET or POST `/api/{2.0|3.0|4.0}/fo/knowledge_base/vuln/?action=list`. Recommended: **4.0** (v2.0 EOL Dec 2026, v3.0 EOL Feb 2027).
- DTD: `<qualys_base_url>/api/4.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd`
- Parameters:
  - `details`: "A valid value is: Basic (default), All, or None."
  - `ids`: comma-separated QIDs and ranges. For large ranges the doc recommends `id_min`/`id_max`.
  - `id_min`, `id_max`
  - `last_modified_after`, `last_modified_before`, `published_after`, `published_before` (YYYY-MM-DD[THH:MM:SSZ])
  - `is_patchable`, `discovery_method`, `show_supported_modules_info`, `show_pci_reasons`, `show_disabled_flag`, `show_qid_change_log`
  - `cloud_agent_scan_type` (v4.0)
  - `echo_request`
- Pagination or truncation for KB: **NOT DOCUMENTED / unclear**. No WARNING or truncation is described. Fetch in chunks of `ids` (QIDs collected from detections).
- Structure: `KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/(DATETIME, VULN_LIST/VULN)`.
- VULN children seen: QID, VULN_TYPE, SEVERITY_LEVEL, TITLE, CATEGORY, LAST_SERVICE_MODIFICATION_DATETIME, PUBLISHED_DATETIME, CODE_MODIFIED_DATETIME, PATCHABLE, PATCH_PUBLISHED_DATE, SOFTWARE_LIST/SOFTWARE/(PRODUCT,VENDOR), VENDOR_REFERENCE_LIST/VENDOR_REFERENCE/(ID,URL), **CVE_LIST/CVE/(ID,URL)**, BUGTRAQ_LIST, **DIAGNOSIS, CONSEQUENCE, SOLUTION** (HTML in CDATA), **CVSS/(BASE,TEMPORAL)**, CORRELATION/EXPLOITS..., PCI_FLAG, THREAT_INTELLIGENCE/THREAT_INTEL, DISCOVERY/(REMOTE, AUTH_TYPE_LIST, ADDITIONAL_INFO).
- CVSS_V3 DTD, verbatim from 10.39 release notes: "CVSS_V3 (BASE?, TEMPORAL?, VECTOR_STRING?, CVSS3_VERSION?, ATTACK?, IMPACT?," ... "PRIVILEGES_REQUIRED?, USER_INTERACTION?, SCOPE?, EXPLOIT_CODE_MATURITY?, REMEDIATION_LEVEL?, REPORT_CONFIDENCE?)>". CVSS_V4 is new in v4.0 (BASE, VECTOR_STRING e.g. "CVSS:4.0/AV:N/...", CVSS4_VERSION). https://docs.qualys.com/en/vm/release-notes/qweb/release_10_39_api.htm
- Some CVSS BASE elements may carry attributes; this is unverified, so the parser should take the element text.
- VULN_TYPE values in samples: "Vulnerability", "Potential Vulnerability", "Vulnerability or Potential Vulnerability". The docs give no formal list. SEVERITY_LEVEL is 1-5. Per the docs, "Basic includes CVSS Base and Temporal scores". details=All is needed for DIAGNOSIS, SOLUTION and so on (unverified exact split).
- Cross-check: the Elastic qualys_vmdr integration maps `knowledge_base.cvss.base`, `knowledge_base.cvss_v3.base` and `knowledge_base.cve_list`. Its changelog says "Update knowledge base API to v4" and "Implement X-RateLimit header handling". https://www.elastic.co/docs/reference/integrations/qualys_vmdr

---

## 7. Host List API (asset inventory)

Source: https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_list.htm

- Path: GET or POST `/api/{2.0..6.0}/fo/asset/host/?action=list`. Recommended **6.0**. v2.0 through v4.0 reach EOL **December 2026**, and v5.0 EOL is August 2027.
- `details`: "Basic" (default), "Basic/AGs", "All", "All/AGs", "None". "All" adds the last VM and compliance scan dates.
- `truncation_limit`: default 1000, range 1-1000000, 0 for none. Pagination uses the same WARNING CODE 1980 / URL / id_min pattern.
- `id_min`, `vm_processed_after` (YYYY-MM-DD[THH:MM:SSZ] UTC), `vm_scan_since`, `show_asset_id` (default 0), `show_tags`, `show_cloud_tags`, `host_metadata`.
- Structure: `HOST_LIST_OUTPUT/RESPONSE/(DATETIME, HOST_LIST/HOST, WARNING)`.
- HOST fields: ID, ASSET_ID, IP, TRACKING_METHOD, NETWORK_ID, DNS, DNS_DATA/(HOSTNAME, DOMAIN, FQDN), NETBIOS, OS, QG_HOSTID, FIRST_FOUND_DATE, LAST_BOOT, LAST_ACTIVITY, AGENT_STATUS, CLOUD_AGENT_RUNNING_ON, ASSET_RISK_SCORE, TRURISK_SCORE, ASSET_CRITICALITY_SCORE, TRURISK_SCORE_FACTORS, METADATA, LAST_VULN_SCAN_DATETIME / LAST_VM_SCANNED_DATE etc. (LAST_VM_*), LAST_COMPLIANCE_SCAN_DATETIME, VM_AUTH_INSUFFICIENT_PRIVILEGE (v5.0+), CLOUD_PROVIDER/CLOUD_SERVICE/CLOUD_RESOURCE_ID (v6.0).
- Exact LAST_VM_* names other than those listed above: unverified.

---

## 8. Rate and concurrency limits

Sources: https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/get_started/get_started.htm, https://docs.qualys.com/en/vm/api/pc/get_started/http_headers.htm and https://cdn2.qualys.com/docs/qualys-api-limits.pdf

Response headers, verbatim:
- X-RateLimit-Limit: "Maximum number of API calls allowed in any given time period of <number-seconds> seconds"
- X-RateLimit-Window-Sec: "Time period (in seconds) during which up to <numberlimit> API calls are allowed"
- X-RateLimit-Remaining: "Number of API calls you can make right now before reaching the rate limit"
- X-RateLimit-ToWait-Sec: "The wait period (in seconds) before you can make the next API call without being blocked by the rate limiting rule."
- X-Concurrency-Limit-Limit: "Number of API calls you are allowed to run concurrently."
- X-Concurrency-Limit-Running: "Number of API calls that are running right now (including the one identified in the current HTTP response header)."

When exceeded: "The HTTP status code "Conflict" (example: "HTTP/1.1 409 Conflict") is returned for API calls that were blocked."

Default limits from the limits PDF (per API, per subscription; may be customized):

| Service level | Concurrency | Rate |
|---|---|---|
| Express/Consultant | 1 | 50 per day |
| Standard | 2 | 300 per hour |
| Enterprise | 5 | 750 per hour |
| Premium | 10 | 2000 per hour |

Error codes for v2-style APIs, from the PDF:
- **1960** (concurrency), TEXT: "This API cannot be run again until 1 currently running API instance has finished."
- **1965** (rate), TEXT like: "This API cannot be run again for another 23 hours, 57 minutes and 54 seconds."
- Appendix D lists 1920 as a legacy code to be replaced by 1960 or 1965. It lists 1960 with status 409 and 1965 with "HTTP/1.1 400 Conflict", which looks like a doc typo. Treat both 409 and 1965 as rate-limited.
- Per the users API_limits page, "the concurrency limit error takes precedence over the rate limit error".

The qualysapi client (secondary source) cross-checks this: it matches `<CODE>1965</CODE>` and sleeps `x-ratelimit-towait-sec`, and on `<CODE>1960</CODE>` it sleeps 30s and retries up to 10 times.

Concurrency is per subscription per API, so parallel HLD workers must stay at or below X-Concurrency-Limit-Limit.

---

## 9. Error response format and HTTP status codes

Format: `SIMPLE_RETURN/RESPONSE/(DATETIME, CODE?, TEXT, ITEM_LIST/ITEM/(KEY,VALUE)?)`, with DOCTYPE pointing to `<base>/api/<ver>/simple_return.dtd`. The structure is seen in the 10.37.1 sample (a success case without CODE) and in qualysapi's matching on `<CODE>`/`<TEXT>`. **No verbatim error SIMPLE_RETURN sample could be retrieved.**

Appendix D, https://docs.qualys.com/en/vm/qweb-all-api/appendix/appendix_d.htm:

| HTTP | CODE | TEXT |
|---|---|---|
| 400 | 1901 | "Unrecognized parameter(s):..." |
| 400 | 1903 | "Missing required parameter(s):..." |
| 400 | 1904 | "Please specify only one of these parameters:..." |
| 400 | 1905 | "parameter ... has invalid value ..." |
| 400 | 1907 | "The following combination of key=value pairs is not supported:..." |
| 400 | 1908 | "Request method (GET or POST) is incompatible with specified parameter(s):..." |
| 409 | 1920 | "The requested operation is blocked by one or more existing Business Objects" (legacy) |
| 409 | 1960 | same text (concurrency) |
| 400 (doc says "400 Conflict") | 1965 | same text (rate) |
| 400 | 1922 | "Please specify at least one of the following parameters:..." |
| 202 | 1981 | "Your request is being processed. Please try this same request again later." |
| 400 / 501 | 999 | "Internal Error" |
| 503 | 1999 | "We are performing scheduled maintenance on our System. ..." |
| 401 | 2000 | "Bad Login/Password" |
| 403 | 2002 | "User account is inactive." |
| 409 | 2003 | "Registration must be completed before API requests will be served for this account" |
| 409 | 2011 | "SecureID authentication is required for this account, so API access is blocked." |
| 403 | 2012 | "User license is not authorized to run this API." |

Appendix D says the error TEXT for 1960 and 1965 is the generic "Business Objects" text, while the limits PDF shows "This API cannot be run again ..." text. The two disagree, so retry logic should key on CODE and HTTP 409, not on TEXT.

---

## Items NOT DOCUMENTED / unclear (summary)
- Exact V6.0 HLD and Host List parameter lists and DTD (tabs unreadable). Response element names are assumed to be uppercase like v2.0; the V3.0 lowercase-tag claim is unverified.
- Session auth on /api/3.0 and later paths.
- KB pagination or truncation.
- Exact STATUS output strings for Fixed and Re-Opened, and TYPE "Info".
- IPV6, ASSET_ID and QG_HOSTID presence in HLD output.
- XML form and code of the EOS deprecation warning.
- A verbatim SIMPLE_RETURN error sample.
- Qualys's own GET vs POST preference.
