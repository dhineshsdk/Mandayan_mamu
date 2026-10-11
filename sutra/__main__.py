"""Command line: python -m sutra {synth,analyze,demo,serve}."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import pipeline, report, synth


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="sutra", description="Root-cause and rupee-risk prototype for scanner exports.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("synth", help="generate a synthetic estate's Qualys, Tenable, .nessus and CMDB files")
    s.add_argument("--profile", choices=sorted(synth.PROFILES), default="power")
    s.add_argument("--out", type=Path, default=Path("data/synthetic"))
    s.add_argument("--seed", type=int, default=7)

    a = sub.add_parser("analyze", help="group findings by root cause and write the board summary")
    a.add_argument("files", type=Path, nargs="*", help="Qualys CSV, Tenable CSV or .nessus exports (auto-detected)")
    a.add_argument("--qualys", type=Path, action="append", default=[], help=argparse.SUPPRESS)
    a.add_argument("--tenable", type=Path, action="append", default=[], help=argparse.SUPPRESS)
    a.add_argument("--cmdb", type=Path, help="asset register CSV (optional but needed for rupee impact)")
    a.add_argument("--intel", type=Path, help="threat intel JSON (defaults to the bundled sample snapshot)")
    a.add_argument("--org", default="")
    a.add_argument("--out", type=Path, default=Path("out"))

    d = sub.add_parser("demo", help="synth + analyze in one go")
    d.add_argument("--profile", choices=sorted(synth.PROFILES), default="power")
    d.add_argument("--data", type=Path, default=Path("data/synthetic"))
    d.add_argument("--out", type=Path, default=Path("out"))
    d.add_argument("--seed", type=int, default=7)

    w = sub.add_parser("serve", help="run the web app on this machine")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument("--workspace", type=Path, default=Path("workspace"))
    w.add_argument("--no-demo", action="store_true", help="start empty instead of loading the power demo")
    w.add_argument("--no-browser", action="store_true", help="do not open a browser tab")

    args = ap.parse_args(argv)
    if args.cmd == "serve":
        from .web.server import serve
        serve(args.host, args.port, args.workspace, preload=not args.no_demo, open_browser=not args.no_browser)
        return

    if args.cmd == "synth":
        paths = synth.generate(args.out, args.seed, args.profile)
        for k, p in paths.items():
            print(f"{k:16} {p}")
        return

    if args.cmd == "demo":
        data = args.data / args.profile
        paths = synth.generate(data, args.seed, args.profile)
        files = [p for k, p in paths.items() if k != "cmdb"]
        res = pipeline.run(files, paths["cmdb"], org=synth.PROFILES[args.profile]["org"])
        out = args.out
    else:
        files = args.files + args.qualys + args.tenable
        if not files:
            ap.error("give at least one scanner export")
        res = pipeline.run(files, args.cmdb, org=args.org, intel_path=args.intel)
        out = args.out

    board = report.write_all(res, out)
    print(report.console_summary(res))
    print(f"\nBoard summary: {board}\nReceipts:      {out / 'receipts.json'}, {out / 'root_causes.csv'}, "
          f"{out / 'findings.csv'}")


if __name__ == "__main__":
    main()
