# Microsoft Defender for Cloud API: research notes for a read-only connector

Research date: 2026-10-11. Microsoft's online REST reference (learn.microsoft.com) could not be reached from the
build environment, so it was not read. Two sources were used instead.

Sources, in order of trust:
- [SDK]: `azure-mgmt-security` 7.0.0 (PyPI wheel), Microsoft's Python SDK generated from the Azure REST API
  specifications: `v2019_01_01_preview/operations/_sub_assessments_operations.py`,
  `v2021_06_01/operations/_assessments_operations.py` and the matching `models/_models_py3.py`.
- [ELA]: Elastic's Microsoft Defender for Cloud integration, `elastic/integrations` on GitHub,
  `packages/microsoft_defender_cloud/data_stream/assessment`: the CEL program that calls the API
  (`agent/stream/cel.yml.hbs`) and pipeline test records (`_dev/test/pipeline/test-assessment.log`). IDs in the
  records are edited (for example subscription `5abcdef6-1234-5678-8912-e1234abcdef1`).

## Auth

- Entra ID client credentials: `POST {login}/{tenant}/oauth2/v2.0/token`, scope `https://management.azure.com/.default`
  [ELA manifest: `login_url`, `tenant_id`, `token_scopes`; the same flow `sutra.app.directory` uses for Graph].
- Role: Security Reader on each subscription or management group read. (Role name from Azure's built-in roles as
  remembered; to confirm when a design partner grants it.)

## Sub-assessments (findings)

`GET /{scope}/providers/Microsoft.Security/subAssessments?api-version=2019-01-01-preview` [SDK `list_all`: "Get
security sub-assessments on all your scanned resources inside a subscription scope"]. `scope` is
`/subscriptions/{id}` or `/providers/Microsoft.Management/managementGroups/{name}` [SDK]. Pages: `value`, `nextLink`
[ELA].

Fields used (`properties.`): `id`, `displayName`, `status.code` (Healthy, Unhealthy, NotApplicable),
`status.severity`, `remediation`, `timeGenerated`, `resourceDetails.id`, `additionalData` [SDK `SecuritySubAssessment`].

`additionalData.assessedResourceType` `ServerVulnerabilityTvm` (Defender Vulnerability Management on a machine)
carries [ELA]: `softwareVendor`, `softwareName` (for example `libxml2_for_linux`), `softwareVersion`,
`recommendedVersion` (empty in the sample), `cvssV30Score`, `source`, and `cve[]` with `title` (the CVE ID),
`cvssScore`, `severity`, exploit flags and dates.

DOC GAP: the SDK's models predate `ServerVulnerabilityTvm` (they know `ServerVulnerability`, the retired Qualys-based
scanner). Its fields are known only from one Elastic record. Whether healthy (fixed) sub-assessments are listed at all
is not shown; the connector reads Healthy as fixed if they appear.

Not read yet: `AzureRuntimeImageVulnerability` (container images) and `ManagedAggregatedServerVulnerabilityTvm` (AKS
node pools, with `affectedNodes`).

## Assessments (hosts)

`GET /{scope}/providers/Microsoft.Security/assessments?api-version=2021-06-01` [SDK `list`]. Fields:
`properties.displayName`, `properties.resourceDetails` (`Id`, `ResourceName`), `properties.status` (`code`,
`firstEvaluationDate`, `statusChangeDate`) [SDK `SecurityAssessmentResponse`, `AssessmentStatusResponse`].

- A machine with the assessment "Machines should have vulnerability findings resolved" in Healthy or Unhealthy state
  has a current vulnerability assessment, so it counts as assessed at the time of the pull.
- DOC GAP: the built-in assessment's key (its `name`) is edited in the Elastic records, so the connector matches the
  display name. Confirm the key on a live subscription and switch to it.
- `statusChangeDate` is when the verdict last changed, not when the machine was last scanned, so it is not used as a
  scan date.

## Hosts and addresses

Neither operation returns IP addresses. Findings and hosts are named by the virtual machine's name (the last segment
of its resource ID), so the asset register should use the same host names.
