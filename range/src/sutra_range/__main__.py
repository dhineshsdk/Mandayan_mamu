"""``python -m sutra_range run | check``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import runner
from .report import failures, markdown

DEFAULT_OUT = Path("docs/range")


def _live():
    from sutra_explain import ExplainConfig, Explainer

    ex = Explainer.from_config(ExplainConfig.from_env())
    if ex.client is None:
        sys.exit(f"--live needs a model: {ex.unavailable}")
    return ex.client


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sutra-range", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run Range and write score.json and SCORE.md")
    r.add_argument("--out", type=Path, default=DEFAULT_OUT)
    r.add_argument("--live", action="store_true", help="also score the configured model (never written to the "
                                                       "deterministic score file)")
    c = sub.add_parser("check", help="run Range, compare with the committed score, and apply the release gate")
    c.add_argument("--out", type=Path, default=DEFAULT_OUT)
    a = ap.parse_args(argv)

    if a.cmd == "run":
        live = _live() if a.live else None
        score = runner.run(live=live)
        a.out.mkdir(parents=True, exist_ok=True)
        stem = "live" if live else "score"
        (a.out / f"{stem}.json").write_text(json.dumps(score, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        (a.out / ("SCORE-live.md" if live else "SCORE.md")).write_text(markdown(score), encoding="utf-8")
        bad = failures(score)
        print(markdown(score))
        return 1 if bad else 0

    score = runner.run()
    bad = failures(score)
    published = a.out / "score.json"
    if not published.exists():
        bad.append(f"no published score at {published}; run `python -m sutra_range run`")
    elif runner.deterministic(json.loads(published.read_text(encoding="utf-8"))) != runner.deterministic(score):
        bad.append(f"{published} is out of date; run `python -m sutra_range run` and commit the result")
    for line in bad:
        print("FAIL:", line)
    print("Range gate:", "FAIL" if bad else "PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
