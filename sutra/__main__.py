"""Command line: python -m sutra {synth,analyze,demo}."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import pipeline, report, synth


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="sutra", description="Root-cause and rupee-risk prototype for scanner exports.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("synth", help="generate synthetic Qualys, Tenable and CMDB files")
    s.add_argument("--out", type=Path, default=Path("data/synthetic"))
    s.add_argument("--seed", type=int, default=7)

    a = sub.add_parser("analyze", help="group findings by root cause and write the board summary")
    a.add_argument("--qualys", type=Path, action="append", default=[], help="Qualys VM CSV export (repeatable)")
    a.add_argument("--tenable", type=Path, action="append", default=[], help="Tenable.sc/.io CSV export (repeatable)")
    a.add_argument("--cmdb", type=Path, help="asset register CSV (optional but needed for rupee impact)")
    a.add_argument("--intel", type=Path, help="threat intel JSON (defaults to the bundled sample snapshot)")
    a.add_argument("--org", default="")
    a.add_argument("--out", type=Path, default=Path("out"))

    d = sub.add_parser("demo", help="synth + analyze in one go")
    d.add_argument("--data", type=Path, default=Path("data/synthetic"))
    d.add_argument("--out", type=Path, default=Path("out"))
    d.add_argument("--seed", type=int, default=7)

    args = ap.parse_args(argv)
    if args.cmd == "synth":
        paths = synth.generate(args.out, args.seed)
        for k, p in paths.items():
            print(f"{k:8} {p}")
        return

    if args.cmd == "demo":
        paths = synth.generate(args.data, args.seed)
        res = pipeline.run([paths["qualys"]], [paths["tenable"]], paths["cmdb"], org=synth.ORG)
        out = args.out
    else:
        if not args.qualys and not args.tenable:
            ap.error("give at least one --qualys or --tenable export")
        res = pipeline.run(args.qualys, args.tenable, args.cmdb, org=args.org, intel_path=args.intel)
        out = args.out

    board = report.write_all(res, out)
    print(report.console_summary(res))
    print(f"\nBoard summary: {board}\nReceipts:      {out / 'receipts.json'}, {out / 'root_causes.csv'}, "
          f"{out / 'findings.csv'}")


if __name__ == "__main__":
    main()
