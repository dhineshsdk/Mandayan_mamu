# sutra-explain: AI explanations that cite their evidence and cannot act

Sutra's AI writes in two places: explanations on root-cause pages and the quarterly board briefing. (Patch-job drafts
are in `../patchdraft`.) This package is the safe way to do it. It is a plain Python library with no required
dependencies and no web server; the app calls it.

## What it guarantees

1. **No attacker text reaches the writer.** Scanner titles, hostnames, banners and ticket comments never go to the
   model that writes explanations. A `Node` holds only numbers, booleans, members of a fixed vocabulary, and strings
   that match a strict pattern (CVE ID, date, rupee label); `Node()` raises `UnsafeField` for anything else. Names
   and titles are node *labels*, which people see and models do not.
2. **A reader that cannot do anything.** The only component that touches raw finding text is the reader. It has no
   tools and answers with one word from a fixed list (`remote-code-execution`, `weak-credential`, …). Text that
   looks like an instruction to an AI is counted (`injection_suspects`) and shown as a reason for concern. It is
   never obeyed, and words after an instruction-like phrase do not choose the category. `RuleReader` needs no model;
   `ModelReader` uses one and falls back to the rules on anything but a clean answer.
3. **Every claim cites nodes.** A claim is `{text, cites, role, action}`. It is shown only if every cited ref
   exists, every number in it is a number on a cited node, names appear only as `{ref}` placeholders that Sutra
   fills in, and strong words (exploited, internet, safety, plant, overdue) are backed by a cited field (or, if the
   sentence denies the thing, by the opposite field). Roles let a claim be evidence *against* or an uncertainty; "not
   enough evidence" is a valid answer.
4. **The ratchet.** Wording about ignoring, closing, lowering, skipping or accepting is refused, and the only
   actions a claim can propose are `open_ticket`, `open_pull_request`, `stage_change`, `notify` and
   `request_rescan` (OT: no pull request). `PolicyGate` is plain code: lowering anything needs a second independent
   source and a named person, and the gate puts that to a person rather than doing it. An explanation can make Sutra
   louder, never quieter. It never changes an SSVC decision, a risk number or an approval route.
5. **Rules when the model fails.** If no model is configured, it is unreachable or declines, or two answers in a row
   fail the checks, the explanation is written from fixed rules and passes the same checks. The result says
   `source: "template"` and why.

These tests are mechanical. They do not prove a sentence is true. The app shows the cited nodes beside every claim so
a person can check.

## Models

| Variable | Meaning |
| --- | --- |
| `SUTRA_AI_PROVIDER` | `auto` (default), `anthropic`, `local`, `off`. `auto` uses a local model if `SUTRA_AI_LOCAL_URL` is set, else Claude if `ANTHROPIC_API_KEY` is set, else none. |
| `SUTRA_AI_LOCAL_URL`, `SUTRA_AI_LOCAL_MODEL`, `SUTRA_AI_LOCAL_KEY` | Any OpenAI-compatible chat endpoint inside the customer's network (vLLM, llama.cpp server, Ollama, LM Studio). Redirects are refused. With a local model no prompt leaves the box. |
| `SUTRA_AI_EXPLAIN_MODEL`, `SUTRA_AI_EXPLAIN_EFFORT` | Claude model (default `claude-sonnet-5-5`) and effort (`none` leaves it out). |
| `SUTRA_AI_ATTEMPTS`, `SUTRA_AI_TIMEOUT` | Model answers tried before the rules take over (2); seconds per request (300). |
| `SUTRA_AI_EXPLAIN=off` | Rule-written explanations only. |

`MessagesShim(LocalClient(...))` gives `sutra_patchdraft.PatchDrafter` the same local model for patch-job drafts.
The local model must support JSON-schema constrained output (`response_format: json_schema`); Sutra's checks run on
whatever comes back either way. Which local models are good enough is measured in Sutra Range, not assumed here.

## Use

```python
from sutra_explain import Explainer, ExplainConfig, board_facts, root_cause_facts

explainer = Explainer.from_config(ExplainConfig.from_env())
facts = root_cause_facts(payload, "RC-004")          # payload is sutra.views.payload(...)
result = explainer.explain_root_cause(facts)
result.to_dict(facts)       # claims with rendered text, role, action and the cited nodes (ref, id, type, label)
briefing = explainer.brief_board(board_facts(payload, unowned=3))
```

## Tests

```
pip install -e ".[test]" && python -m pytest -q
```

No test calls a model API. A fake client replays scripted answers, including hostile ones, and a stub HTTP server
stands in for a local model. Install `../patchdraft[ai]` as well to run the local-drafting test.
