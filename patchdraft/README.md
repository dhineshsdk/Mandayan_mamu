# sutra-patchdraft: patch-job drafting

Given one root cause, the hosts it touches and their findings, this library drafts the patch job a team sends for
approval: target hosts, rollout rings, steps, pre-checks, rollback and maintenance window. IT drafts describe a job a
patch tool can run after approval. OT drafts are staged plans a plant engineer carries out by hand, with OEM approval,
a compensating control until the shutdown, and backups first.

Drafts come from Claude when an API key is set, and from rule-based templates otherwise. Both kinds pass the same
checks before anyone sees them, and neither carries an approval route: who approves comes from the rules engine in
the app, so a draft cannot lower its own approval level.

It is a plain Python library (3.10+, no required dependencies) with no web server, database or workflow. The app
calls it when a team raises a patch job.

## Use

```python
from sutra_patchdraft import MaintenancePolicy, PatchDrafter, from_sutra

drafter = PatchDrafter()                       # reads SUTRA_AI_* and ANTHROPIC_API_KEY from the environment
inp = from_sutra(rc, team_hosts, team_findings, as_of,
                 policy=MaintenancePolicy(ot_shutdown=next_shutdown))   # optional; weekly Saturday window by default
draft = drafter.draft(inp)

draft.source            # "ai" or "template"
draft.fallback_reason   # why the template was used, if it was
draft.to_dict()         # everything, with citations to findings, hosts and changes
draft.to_legacy_dict()  # the keys the current patch-job screen reads (targets, rings, playbook, ...)
```

`from_sutra` reads the app's `RootCause`, `Asset` and `Finding` objects by attribute name, so this package does not
import the app. Pass only the hosts and findings in the job's scope (for example, one team's share of a root cause).
Or build `DraftInput` from `RootCauseInput`, `HostInput` and `FindingInput` directly.

`draft()` does not raise for model problems. API errors, refusals, cut-off or invalid replies, and drafts that fail
the checks twice all end in a template draft, with the reason in `fallback_reason`. Bad input (a finding on a host
that is not in the job, no hosts, an unknown SSVC value) raises `InputError`.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`) | unset | Without one, every draft comes from the templates. |
| `SUTRA_AI_DRAFTING` | `on` | `off` forces templates, for air-gapped sites. |
| `SUTRA_AI_MODEL` | `claude-opus-5-5` | Any Claude model that supports structured outputs. |
| `SUTRA_AI_EFFORT` | `high` | `low` to `max`, or `none` to leave it out for models without effort. |
| `SUTRA_AI_ADAPTIVE_THINKING` | `on` | Turn off for models that do not take adaptive thinking. |
| `SUTRA_AI_SERVER_FALLBACKS` | `on` | On a safety decline, the API re-runs the request on its recommended fallback model (`fallbacks: "default"`). Turn off on Bedrock, Vertex AI or Foundry, which do not offer it. |
| `SUTRA_AI_ATTEMPTS` | `2` | Model drafts tried before the template takes over; the second try is told why the first was rejected. |
| `SUTRA_AI_MAX_TOKENS`, `SUTRA_AI_TIMEOUT` | `16000`, `300` | Per request. |

Install with `pip install -e "./patchdraft[ai]"` for AI drafting. API keys belong in the deployment's environment or
secret store, never in this repository.

`PatchDrafter(client=...)` accepts any object with the `anthropic.Anthropic` messages interface, which is how the
tests run and how a different endpoint could be plugged in later.

## How a model draft is kept honest

1. **Untrusted input stays data.** Scanner and asset text is cleaned (control and bidi characters removed, length
   capped) and sent as JSON inside a `<scan_data>` block, with `<`, `>` and `&` escaped so no value can close the
   block. The system prompt, which holds the rules, never contains input text. Finding `evidence` is not sent at all,
   since it can hold credentials.
2. **Refs, not values.** Every host, finding and change gets a short ID (`H3`, `F12`, `C1`, and `R1` for the root
   cause). The model places host refs in rings and names change refs in steps; the renderer fills in hostnames,
   package versions and KB numbers from the input. A step cannot name a version the scan did not report.
3. **A fixed schema per lane.** Structured outputs constrain the reply to the lane's JSON schema. Steps use a fixed
   verb list; the OT list has no deploy, reboot or image steps and the OT schema has no `tool` field. No schema has a
   field for approvers, route or urgency.
4. **Checks the schema cannot express** (`grounding.validate`): every ref exists; each host is in exactly one ring
   or excluded with a reason; every change reaches every ring holding one of its hosts, through a step whose verb fits
   the change; verification follows the last change; OT plans request OEM approval and hold a compensating control.
   Free text may not contain a version, KB number, CVE, advisory ID, IP address or URL that is absent from the input,
   OT text may not name patch tools or scripts, and no text may talk about skipping approvals or emergency status.
5. **Windows from policy.** Maintenance windows come from `MaintenancePolicy`, one weekly window per ring. OT plans
   use the shutdown date operations has named; with none, the draft says the slot is not set rather than guessing.

The template drafter produces the same raw shape and goes through the same checks, and its text uses only fixed
wording and input values.

Known limit: the grounding check accepts any value that appears somewhere in the input, including a finding's free
text. A version planted in a scanner title could therefore appear in a step's prose. The change a step applies still
comes from the finding's structured package and fixed-version fields, and every step cites the findings it relies on.

## Tests

```
cd patchdraft
pip install -e ".[ai,test]"
python -m pytest -q
```

The tests use a fake client that records each request and replays scripted replies; no test calls the API.
