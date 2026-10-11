# Amazon Inspector (Inspector2) API: research notes for a read-only connector

Research date: 2026-10-11. AWS's online API reference (docs.aws.amazon.com) was not read for this connector. Two
sources were used instead.

Sources, in order of trust:
- [MOD]: the Inspector2 service model in botocore 1.43.111 (PyPI wheel), `botocore/data/inspector2/2020-06-08/`
  `service-2.json`, `paginators-1.json` and `endpoint-rule-set-1.json`. AWS generates its SDKs from these models, so
  paths, methods, field names, limits and enum values are taken from here.
- [ELA]: Elastic's AWS integration, `elastic/integrations` on GitHub, `packages/aws/data_stream/inspector`: the
  poller configuration (`agent/stream/httpjson.yml.hbs`) and pipeline test records
  (`_dev/test/pipeline/test-inspector.log`). Account IDs and addresses in those records are edited; three records
  are marked by their text as made up (`EXAMPLE-2025-0001`, `EXAMPLE-2025-0002` and the first record, which the
  connector tests leave out).

## Protocol and auth

- Protocol `rest-json`, signature version 4, signing name `inspector2` [MOD metadata].
- Endpoint `https://inspector2.{Region}.{dnsSuffix}`; FIPS endpoints are `inspector2-fips.` [MOD endpoint rules].
  `dnsSuffix` is `amazonaws.com`, or `amazonaws.com.cn` in the China partition.
- Timestamps in bodies are Unix seconds, with a fraction [ELA records, for example `1749795895.486`].
- The connector signs requests itself; `tests/test_aws_inspector.py` checks its `Authorization` header against
  botocore's `SigV4Auth` for the same request, with and without a session token.

## Findings

`ListFindings`: `POST /findings/list` [MOD]:
- Body: `maxResults` (1-100), `nextToken`, `filterCriteria`, `sortCriteria` (`field`, `sortOrder`).
- `filterCriteria` fields used: `findingType` and `findingStatus` (string filters: `comparison` EQUALS, PREFIX or
  NOT_EQUALS, and `value`), and `updatedAt` (date filter: `startInclusive`, `endInclusive`).
- Response: `findings`, `nextToken` (absent on the last page) [MOD, paginator].
- `FindingType`: NETWORK_REACHABILITY, PACKAGE_VULNERABILITY, CODE_VULNERABILITY. `FindingStatus`: ACTIVE,
  SUPPRESSED, CLOSED. `Severity`: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL, UNTRIAGED.
- Fields read: `findingArn`, `awsAccountId`, `type`, `status`, `severity`, `title`, `description`,
  `firstObservedAt`, `lastObservedAt`, `updatedAt`, `remediation.recommendation.text`, `resources[]` (`id`, `type`,
  `region`, `tags`, `details.awsEc2Instance` with `ipV4Addresses` and `platform`, `details.awsEcrContainerImage` with
  `registry`, `repositoryName`, `imageTags`, `imageHash`, `platform`, `details.vm` for other clouds),
  `packageVulnerabilityDetails` (`vulnerabilityId`, `relatedVulnerabilities`, `cvss[]` with `baseScore` and
  `version`, `vulnerablePackages[]` with `name`, `version`, `release`, `epoch`, `fixedInVersion`, `remediation`,
  `filePath`).
- Elastic polls on `updatedAt` because a status change to CLOSED or SUPPRESSED moves `updatedAt` but not
  `lastObservedAt` [ELA]. The connector's incremental mode does the same.

DOC GAP: `fixedInVersion` when no fix exists. The records seen all carry a version. The connector treats an empty
value and `NotAvailable` (the value AWS's documentation uses, as remembered, not read) as "no fix".

## Coverage (hosts)

`ListCoverage`: `POST /coverage/list` [MOD]:
- Body: `maxResults` (1-200), `nextToken`, `filterCriteria` with `scanStatusCode` (ACTIVE, INACTIVE) and `scanType`
  (NETWORK, PACKAGE, CODE).
- Response: `coveredResources[]` with `resourceId`, `resourceType`, `accountId`, `scanStatus` (`statusCode`,
  `reason`), `lastScannedAt`, `resourceMetadata.ec2` (`tags`, `amiId`, `platform`).
- Coverage records carry no IP address. The connector names a resource from its findings when it had any, else by its
  `Name` tag, else by its resource ID. Resources not scanned within `host_window` (30 days) are left out.

## Permissions

Only `inspector2:ListFindings` and `inspector2:ListCoverage` (the IAM action names follow the operation names).

DOC GAP: that Inspector's delegated administrator account in an AWS Organization lists its member accounts' findings
and coverage is from AWS's documentation as remembered, not read. Confirm with the design partner's AWS team.

DOC GAP: an ECR image is named by its pull URI, `<registry>.dkr.ecr.<region>.amazonaws.com/<repository>:<tag>`. The
URI pattern is ECR's well-known format but was not read from a source for this connector.
