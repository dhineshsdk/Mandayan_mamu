# Tenable Security Center (Tenable.sc) REST API: research notes for a read-only connector

Researched 2026-10-11. Pages were fetched through a summarizing tool, so the "quotes" below are verbatim excerpts the tool returned. Each excerpt is 125 characters or shorter, so long JSON examples were reconstructed from field-level quotes. Wherever the docs are silent, these notes say **NOT DOCUMENTED / unclear**.

Sources:
- A. https://docs.tenable.com/security-center/api/index.htm (API overview)
- B. https://docs.tenable.com/security-center/best-practices/api/Content/APIKeyAuthorization.htm
- C. https://docs.tenable.com/security-center/Content/APIKeyAuthentication.htm
- D. https://docs.tenable.com/security-center/api/Token.htm
- E. https://docs.tenable.com/security-center/api/Analysis.htm
- F. https://docs.tenable.com/security-center/api/Query.htm
- G. https://docs.tenable.com/security-center/best-practices/api/Content/RetrieveVulnerabilityDataForSpecificTimeRange.htm
- H. https://developer.tenable.com/docs/sc-integrations (Tenable's integration guide for SC, the most practical source)
- I. https://docs.tenable.com/security-center/api/Hosts.htm
- J. https://docs.tenable.com/security-center/api/Changelog.htm
- K. https://docs.tenable.com/security-center/best-practices/large-enterprise-deployment/Content/API.htm
- P1. https://raw.githubusercontent.com/tenable/pyTenable/master/tenable/sc/__init__.py
- P2. https://raw.githubusercontent.com/tenable/pyTenable/master/tenable/sc/analysis.py
- P3. https://raw.githubusercontent.com/tenable/pyTenable/master/tenable/sc/base.py
- P4. https://raw.githubusercontent.com/tenable/pyTenable/master/tenable/sc/hosts.py

---

## 1. Base path and authentication

### Base path
- A: "http://host:port/rest/resource-name". In practice the URL is `https://<host>[:port]/rest/<resource>`, for example `/rest/analysis`.
- P1: `_base_path: str = 'rest'`

### API key header
- A and B: `x-apikey: accesskey=ACCESS_KEY; secretkey=SECRET_KEY;`
- B: "API key authorization requires Tenable Security Center 5.13.x or later."
- A: "The 'x-apikey' header element is used to pass your API keys in HTTP request messages."
- C: an administrator must enable the "**Allow API Keys** toggle in your Security Settings". C also says "You can only perform actions allowed by the privileges granted to the user account associated with the API keys."
- P1 (pyTenable) sends it as `{'X-APIKey': f'accessKey={access_key}; secretKey={secret_key}'}`. pyTenable uses camelCase `accessKey`/`secretKey` with no trailing `;`, while the official docs use lowercase with a trailing `;`. HTTP header names are case-insensitive. Whether the server matches the value keys case-insensitively is **NOT DOCUMENTED / unclear**, though both forms appear to be accepted because pyTenable is the official SDK. **Recommendation: send exactly the documented form `accesskey=...; secretkey=...;`.**
- B's example uses `curl -X GET -k --header ... /rest/currentUser`. `GET /rest/currentUser` is therefore a reasonable connectivity and auth test call.

### Session/token alternative (for versions before 5.13, or username/password)
- D: `POST /rest/token` with body `{"username": ..., "password": ..., "releaseSession": <boolean> DEFAULT false}`. The response holds `"token" : 123456789`.
- D: the client "should set the token as the value of the "X-SecurityCenter" HTTP header field".
- P1 also keeps the session cookie: `'X-SecurityCenter': str(resp.json()['response']['token'])` and `'TNS_SESSIONID': str(resp.headers['Set-Cookie'])[14:46]`. The cookie requirement is not in the official docs.
- D: `DELETE /rest/token` "Deletes the token associated with the logged in User."
- D: "On response if releaseSession returns "true", the user has reached its maximum login limit."

---

## 2. POST /rest/analysis, type "vuln"

### Body shape, official API reference (E)
```
"type" : "vuln",
"query" : { (valid query object) },
"sortDir" : <string> "ASC" | "DESC" OPTIONAL
"sortField" : <string> (any valid field returned in the results entry for the corresponding tool) [Some restrictions apply.] Must accompany sortDir.
"sourceType" : <string> "individual" | "cumulative" | "patched",
"wasVuln" : <string> "onlyWas" | "excludeWas" | "includeWas" OPTIONAL
"startOffset" : <number>,
"endOffset" : <number>,
```
- `individual` additionally needs `"scanID" : <number>` and `"view" : "all" | "new" | "patched"` at the root.
- E: "The results are inclusive of the startOffset parameter value and exclusive of the endOffset parameter value."

### Placement of startOffset/endOffset: the sources disagree
- E (API reference) shows them at the **root**.
- F (Query reference, vuln query object): `"startOffset" : <number> OPTIONAL ... Must be explicitly supplied for tools "vulndetails" and "listvuln"`, and the same for `endOffset`. These sit **inside `query`**.
- G and H (Tenable's worked examples) put `tool`, `type`, `filters`, `startOffset` and `endOffset` **inside `query`**. `sourceType` sits at the root, and G also repeats it inside `query`.
- P2 (pyTenable): `payload['query']['startOffset'] = offset` and `payload['query']['endOffset'] = limit + offset`. These go **inside `query`**.
- J (changelog 5.17.x): "The /analysis endpoint now supports a "startOffset" and "endOffset" for "vuln" type requests."
- **Recommendation:** put them inside `query`, where both the official SDK and Tenable's integration guide put them. Putting them at the root as well is harmless if you want to cover both readings, but no source says this is required.

### Recommended request (assembled from H, G and P2)
```json
{
  "type": "vuln",
  "sourceType": "cumulative",
  "query": {
    "type": "vuln",
    "tool": "vulndetails",
    "startOffset": 0,
    "endOffset": 2000,
    "filters": [
      {"filterName": "lastSeen", "operator": "=", "value": "0:1"}
    ]
  }
}
```
P2 also adds the filter `('wasVuln', '=', 'excludeWas')` by default in some code paths. Root-level `"wasVuln": "excludeWas"` (from E) is the documented way to exclude Web App Scanning findings.

### sourceType
- E: `"individual" | "cumulative" | "patched"`
- P2: "Allowed sources are ``cumulative`` and ``patched``. Defaults to ``cumulative``."
- H: "cumulative—For current active vulnerability data (stateful)." and "patched—For fixed or remediated vulnerability data (stateful)."
- G: "`patched`—Retrieves vulnerabilities from the mitigated database."

### Query object and filters (F)
- `"filters" : [ ... ] DEFAULT []`. Each filter has the form `{"filterName": <string>, "operator": <string>, "value": (Format depends on filter's "filterName" parameter)}`.
- F example: `"filterName" : "ip", "operator" : "=", "value" : "192.168.1.100"`

### Valid vuln tools
F (official):
`"iplist" | "listmailclients" | "listos" | "listservices" | "listsoftware" | "listsshservers" | "listvuln" | "listwebclients" | "listwebservers" | "remediationdetail" | "sumasset" | "sumcce" | "sumclassa" | "sumclassb" | "sumclassc" | "sumcve" | "sumdnsname" | "sumfamily" | "sumiavm" | "sumid" | "sumip" | "summsbulletin" | "sumport" | "sumprotocol" | "sumremediation" | "sumseverity" | "sumuserresponsibility" | "vulndetails" | "vulnipdetail" | "vulnipsummary"`

P2 additionally lists `cceipdetail`, `cveipdetail`, `iavmipdetail`, `trend`, `sumwasurl`, `wasvulndetail` and `waslistvuln`. `vulndetails` is pyTenable's default (`kw['tool'] = 'vulndetails'`).

---

## 3. Filters for incremental pulls

### Date filters (firstSeen, lastSeen, lastMitigated, daysMitigated, pluginModified, pluginPublished, vulnPublished)
F (official):
- `"operator": <string> "=" (relative with custom format),`
- `"value" : <string> "<minDaysBack>:<maxDaysBack>" (Both minDaysBack and maxDaysBack are provided in the number of days ago.`
- `"value" : <string> "<minDaysBack>:all" (A value "all" indicates to return all results before minDaysBack)`
- `"value" : <string> "currentMonth" | "lastMonth" | "currentQuarter" (i.e. the current fiscal quarter) | "lastQuarter"`
- `patchPublished` is different: `"<endDay>:<startDay>" | "<endDay>:all"`

H (Tenable developer integration guide) also documents an **absolute epoch form**:
- "The format is NUM:NUM where each number represents the number of calendar days in the past."
- "The format is NUM-NUM (note the dash instead of a colon) where each number is a Unix timestamp."
- Applies to: "lastSeen (temporal, source: cumulative)" and "lastMitigated (temporal, source: patched)".
- H's examples use only `"value": "0:1"`. None of its examples uses the epoch form, and F (Query.htm) does not mention the epoch form. **The epoch "start-end" form is documented in one official source (H) only. Verify it against the target SC version before relying on it, and fall back to day ranges (`0:N`) if it fails.**

G:
- "A code in the format `#:#` specifying a date range relative to the current day."
- "To set this filter to a single date, use the same number for both elements." and "a value of `0:0` retrieves all vulnerabilities first discovered today."
- lastSeen: "Requires that the `sourceType` parameter is `cumulative`."
- lastMitigated: "Requires that the `sourceType` parameter is `patched`."

### Severity (F)
- `"operator": <string> "=" | "!=",`
- `"value" : <string> (comma-separated or newline-separated list of integers)`. The page also shows an array form `[ {"id" : <number> (integer)} ]`.
- P2: "Severities are in level of criticality, from 0 (informational) to 4 (critical)." Example: `{"filterName":"severity","operator":"=","value":"1,2,3,4"}`.

### Other potentially useful filters (F)
- pluginID: operators `"=" | "!=" | "<=" | ">="`. The value is a comma- or newline-separated list of integers or dash ranges, "with each value between 0 and 8388607".
- repository: `"operator": "="` with `"value" : { "id" : <number> }`. The format of `repositoryIDs` is not documented on F.
- Full vuln filterName list (F): acceptRiskStatus, asset, assetCriticalityRating, assetID, auditFile, auditFileID, baseCVSSScore, benchmarkName, cceID, cpe, cveID, cvssV3BaseScore, cvssV3Vector, cvssVector, dataFormat, daysMitigated, daysToMitigated, dnsName, exploitAvailable, exploitFrameworks, family, familyID, firstSeen, iavmID, ip, lastMitigated, lastSeen, mitigatedStatus, msbulletinID, outputAssets, patchPublished, pluginID, pluginModified, pluginName, pluginPublished, pluginText, pluginType, policy, policyID, port, protocol, recastRiskStatus, repository, repositoryIDs, responsibleUser, responsibleUserIDs, severity, solutionID, stigSeverity, tcpport, udpport, uuid, vprScore, vulnPublished, xref, epssScore, cvssV4BaseScore, cvssV4ThreatScore, cvssV4Vector, cvssV4ThreatVector, cvssV4Supplemental.

### Sync strategy (H)
- "it's recommended to first perform an initial sync of the data and then to export temporal deltas thereafter."

---

## 4. Response envelope (E, I)
```
"type": "regular",
"response": {
  "totalRecords": "1",            <- STRING
  "returnedRecords": 1,           <- NUMBER
  "startOffset": "0",             <- STRING
  "endOffset": "50",              <- STRING
  "matchingDataElementCount": "-1",
  "results": [ ... ]
},
"error_code": 0,
"error_msg": "",
"warnings": [],
"timestamp": 1765404982
```
- Parse `totalRecords`, `startOffset` and `endOffset` as int(string). `returnedRecords` is a number in the example.
- P2: `total_records = resp['response'].get('totalRecords')`, with the code comment "sadly the totalRecords attribute isn't always returned". **Do not depend on totalRecords.** Stop paging when a page returns fewer records than requested, which is what P3 does.
- Non-zero `error_code` meanings: **NOT DOCUMENTED** on E. P1 treats any non-zero value as an error: `if data['error_code']: raise APIError(response)`.
- HTTP status codes on errors: **NOT DOCUMENTED** in the official API reference. P1 maps only `_error_map = {403: APIError}`. Treat any non-2xx status as an error, and also check `error_code != 0` on 200 responses.

---

## 5. vulndetails result fields

All scalar values are **strings**, including numbers and timestamps (E, H examples).

E (Universal repository example), complete key list:
pluginID, severity {id, name, description}, hasBeenMitigated, acceptRisk, recastRisk, ip, uuid, port, protocol, pluginName, firstSeen, lastSeen, exploitAvailable, exploitEase, exploitFrameworks, synopsis, description, solution, seeAlso, riskFactor, stigSeverity, vprScore, vprContext, baseScore, temporalScore, cvssVector, cvssV3BaseScore, cvssV3TemporalScore, cvssV3Vector, cvssV4BaseScore, cvssV4Vector, cvssV4ThreatScore, cvssV4ThreatVector, cvssV4Supplemental, cpe, vulnPubDate, patchPubDate, pluginPubDate, pluginModDate, checkType, version, cve, bid, xref, seolDate, epssScore, pluginText, dnsName, macAddress, netbiosName, operatingSystem, ips, recastRiskRuleComment, acceptRiskRuleComment, hostUniqueness, hostUUID, acrScore, keyDrivers, assetExposureScore, vulnUniqueness, vulnUUID, cgiScanEnabled, thoroughScanEnabled, paranoidScanEnabled, attachment, uniqueness, family {id, name, type}, repository {id, name, description, dataFormat}, pluginInfo.

Example values:
- `"pluginID": "98120"`
- `"severity": {"id": "4", "name": "Critical", "description": "Critical Severity"}`. This is an object, and its id is a string.
- `"baseScore": "10.0"`, `"cvssV3BaseScore": "9.8"`, `"cvssVector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"`
- `"firstSeen": "1744728630"`, `"lastSeen": "1751396645"`. These are epoch-seconds strings. H: lastSeen is "The Unix timestamp when this vulnerability finding was last observed from any scan."
- `"port": "8080"`, `"protocol": "TCP"`, `"ip": "172.26.48.75"`, `"netbiosName": "TARGET\\WINDOW7X64"`, `"dnsName": ""`, `"uuid": ""`. Empty strings are common, so treat `""` as null.
- `"operatingSystem": "Linux Kernel 5.15.0-1056-aws on CentOS Linux release 7.6.1810 (Core)"` (H)
- `"pluginText": "<plugin_output>fake output</plugin_output>"`
- `"hostUUID": "02ebb260-30ed-4bf8-9e2c-92a8614cda1a"`
- `"repository": {"id": "1", "name": "Live", "description": "", "dataFormat": "IPv4"}`. `dataFormat` may also be "universal".
- `"cve": "CVE-2018-14618"` (H). Neither source documents the format when there are multiple CVEs. H says of xref: "If multiple third-party references exist, they are returned as a comma-separated list within the string value." That makes a comma-separated cve very likely, but it is **unclear / not documented explicitly**. Split on commas and strip whitespace defensively.
- `hasBeenMitigated` (H): "Indicates whether the vulnerability was previously fixed in the past and then reopened (1) or not (0)."
- Unique finding key (H): "The attributes from hostUniqueness in combination with the port, protocol, and pluginID attributes define a unique finding." H also says hostUniqueness is "The field names that Tenable Security Center used to determine that the host is unique." Example uniqueness value: `"repositoryID,ip,dnsName"`.
- `lastMitigated` as a result field for `sourceType: patched`: **NOT DOCUMENTED / unclear**. The docs document it only as a filter name. G's patched example uses tool `listvuln`, not vulndetails.

---

## 6. Host/asset data

### Option A: /analysis with tool "sumip" (H)
- H: "To export asset data, you can use the built-in sumip tool to query the Tenable Security Center API for asset details."
- H's example: `"sourceType": "cumulative"` with `"query": {"tool": "sumip", "filters": [], "startOffset": 0, "endOffset": 5000}` (plus `"type": "vuln"`).
- sumip result keys (H): ip, uuid, dnsName, netbiosName, macAddress, osCPE, lastAuthRun, lastUnauthRun, score, total, severityCritical, severityHigh, severityInfo, severityLow, severityMedium, repository {dataFormat, description, id, name}, hostUniqueness, hostUUID, policyName, pluginSet, biosGUID, mcafeeGUID, acrScore, assetExposureScore, keyDrivers, tpmID, uniqueness.
  - The only OS field is `osCPE` (for example `"cpe:/o:Arista:EOS"`). sumip has **no** `operatingSystem`, `firstSeen` or `lastSeen`. H: lastAuthRun is "The Unix timestamp of the last authenticated scan". Example: `"lastUnauthRun": "1663044810"`.
  - The vulndetails `operatingSystem` field gives a human-readable OS string per finding.

### Option B: /rest/hosts (I)
- `GET /hosts`: "Gets the list of Hosts identified from all scan results that are on" the SC instance. The other host endpoints are `GET /hosts/{uuid}`, `POST /hosts/search`, `POST /hosts/download` (CSV) and `PATCH /hosts/{uuid}/acr` (a write call that a read-only connector does not need).
- Query parameters: `?fields=<field>,...`, `?limit=<number>`, `?startOffset=<number>`, `?endOffset=<number>`. The pagination flag is inconsistent in the docs: the text says "pagination" but the syntax shows `?paginated=<boolean>`. pyTenable (P4) sends a `pagination` parameter as the lowercase string "true"/"false". The correct parameter name is **unclear**.
- Fields: always returned are "id, uuid, tenableUUID, name, ipAddress, os, firstSeen, lastSeen". "source, repID, acr, aes" are returned when no field list is given. Other allowed fields are "macAddress, netBios, netBiosWorkgroup, systemType, createdTime, modifiedTime".
- pyTenable's default field list (P4): id, uuid, tenableUUID, name, ipAddress, os, firstSeen, lastSeen, macAddress, source, repID, netBios, netBiosWorkgroup, createdTime, modifiedTime, acr, aes.
- Response shape: for `GET /hosts`, `"response"` is a **plain array** of host objects in the I example. `/hosts/search` wraps its results in `totalRecords`, `returnedRecords`, `startOffset`, `endOffset` and `results`. Example host: `"id": "154", "uuid": "...", "tenableUUID": "...", "name": "Aerified", "ipAddress": "201.22.196.102", "os": "Linux", "firstSeen": "1770798", "lastSeen": "1685038"`. All values are strings, and the example timestamps are obviously fake.
- Search body (I): `{"filters": {"and": [{"property": "systemType", "operator": "eq", "value": ...}]}}`. Example properties include ip, repositoryAll, assetCriticalityRating, assetExposureScore, sourceType and hostid.
- Limits: "The limit parameter should be an integer greater than 0." No maximum or default is documented. pyTenable's signature default is `limit: int = 10000`, but its docstring says 1000.
- Version: the changelog (J) shows /hosts existing by 5.22.x ("Added **aes** as a valid field for the /hosts::GET endpoint"). 5.23.x added /hosts/download, 6.2.x added the hostid filter on search, and 6.4.x added systemType. **The version that first introduced /hosts was not found.** /hosts probably requires the Tenable One / ACR-AES ("Exposure" / Lumin) features to populate acr and aes. This is unclear.

### Which to use
- Tenable's integration guide (H) recommends **sumip** for asset export, and sumip works on all versions that support /analysis paging (5.17+).
- /hosts gives first-seen and last-seen per host plus `os`, but its documentation is thin and inconsistent (the pagination parameter name, the array vs. paged envelope).
- Suggested approach: use sumip as the primary source, optionally enrich with /hosts when it is available (feature-detect by calling it and handling 403/404), and get the OS string from vulndetails `operatingSystem` when needed. This combination is a recommendation, not a documented Tenable practice.

---

## 7. Pagination, rate limiting, retries, TLS
- Page size (H): "Tenable recommends a page size between 2000 to 10000 for the pagination of export data from Security Center." Also from H: "If the page size is too large the Security Center console might not be able to field the request".
- H: "The analysis API is a synchronous, paginated API that pulls data from the underlying data repositories." H adds that "you should be careful how you extract data from the platform since it's possible to significantly impact the performance of the Security Center console."
- Concurrency (K): "Tenable does not recommend multi-threading API calls to speed up access." **Page sequentially.**
- Data source (K): "Tenable generally recommends pulling data from the /analysis endpoint instead of parsing individual results" (as opposed to /scanResult).
- Frequency (K): "Consider the frequency that data is likely to change when setting the frequency for an API call."
- Paging in pyTenable: P2's default is `limit = 1000`, though its docstring says "Default is 200". The offset advances with `self._offset += self._limit`. P3 estimates the total and stops when a page returns fewer rows than the limit.
- Rate limiting: **NOT DOCUMENTED** for Tenable Security Center. No rate-limit headers or limits are published. pyTenable's docstring describes generic client behaviour: a default of "``5``" retries, and for HTTP 429 a backoff of "``1`` second" when no Retry-After header is sent. That is pyTenable client behaviour, not a documented SC server limit.
- Timeouts: P1 uses `_timeout = 300` seconds by default. Large /analysis pages can be slow, so use a generous read timeout.
- User-Agent (H): "Ensure that all API calls from your integration use a standard User-Agent string as outlined in the User-Agent Header guide." The format itself is in a separate guide that was not fetched: **NOT VERIFIED**.
- TLS: no official guidance. B's curl example uses `-k`, which skips certificate verification and reflects how often on-prem SC uses self-signed certificates. P1 defaults to `_ssl_verify = False` ("Default is False"). **Recommendation:** verify certificates by default, and allow a custom CA bundle path plus an explicit, logged opt-out for insecure TLS.
