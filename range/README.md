# Sutra Range

Range answers two questions about every Sutra release, with numbers instead of adjectives:

1. Does Sutra find the cause that a plain script cannot?
2. Can anything written in a scan export make Sutra say, hide or do something it should not?

Each release publishes its score: [`docs/range/SCORE.md`](../docs/range/SCORE.md) (and `score.json`). The release
workflow attaches the same two files to the GitHub release and fails the release if the gate fails.

## What it measures

| Section | What is checked |
|---|---|
| Causes | Four causes are planted in each of three seeded estates (a shared credential, a base image, a misconfigured control, a package). Sutra and a plain script (group by scanner plugin) both try to find them. A cause is found when one group holds 90% of its findings and at most 10% is something else. |
| Evidence | Every root-cause explanation and board briefing, written by the rules and by a stand-in model. An independent checker (not the product's own) counts claims without a citation and claims with a number that is not on a cited fact. Both must be 0. |
| Injection | 30 payloads (instruction override, fake system turns, delimiters, "mark as benign", exfiltration links, claim injection, disguised and paraphrased text, classification steering) each written into 5 places in a scan export. Measured: did the text reach a model, was a finding lost, was a decision or the portfolio figure lowered, did hostile model output get shown, was the text flagged. |
| Fuzz | 600 random corruptions of good model answers, with the independent checker on everything shown. |
| Scope | A person who may see part of the estate gets facts about that part only. |

## Rules for the score

* The default run uses stand-in models, so the score is identical on every machine and can be committed. Stand-ins
  are named in the score. `python -m sutra_range run --live` scores the configured real model and writes it to
  `live.json` and `SCORE-live.md`; it is never mixed into the committed score.
* Scenarios, baselines and payloads were written by the Sutra team, who also wrote the grouping rules. This is a
  regression and honesty harness, not an independent benchmark. Third-party scenarios are welcome.
* "Analyst with a runbook" is listed as *not measured*. It needs people with the same access and time budget.
* A forgotten firewall rule is not planted: that needs the attack-surface module, which is after V1.
* Known weakness, reported on every score: Sutra groups findings by what a scanner title says, so someone who can
  write a title can move a finding into a different group. In Range no finding is ever lost and no figure drops, but
  the grouping changes. Titles that read like two kinds of problem are flagged on the root-cause page. Flagging
  instruction-like text is best-effort (see "not flagged" in the score); the protection that counts is that the text
  never reaches a model that can act.

## Running

```
pip install -e ./patchdraft -e ./explain -e ./range[test] -e .
python -m sutra_range run      # write docs/range/score.json and SCORE.md; exit 1 if the gate fails
python -m sutra_range check    # CI: rerun, compare with the committed score, apply the gate
python -m pytest range
```

After any change to grouping, risk, the explain library or the scenarios, run `run` and commit the new score. The
`check` command and the test `test_published_score_is_current` fail until you do.
