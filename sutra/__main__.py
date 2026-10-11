"""Command line: python -m sutra {synth,analyze,demo,serve,db-upgrade,create-admin,demo-users}."""

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
    s.add_argument("--month", type=int, default=0, help="the same estate this many 30-day months later")

    a = sub.add_parser("analyze", help="group findings by root cause and write the board summary")
    a.add_argument("files", type=Path, nargs="*",
                   help="Qualys CSV, Tenable CSV, .nessus, Trivy JSON or Grype JSON (auto-detected)")
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

    w = sub.add_parser("serve", help="run the web application")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument("--workspace", type=Path, help="data folder (default: $SUTRA_WORKSPACE or ./workspace)")

    u = sub.add_parser("db-upgrade", help="create or upgrade the database schema")
    u.add_argument("--workspace", type=Path)

    c = sub.add_parser("create-admin", help="create the first administrator account")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--workspace", type=Path)

    m = sub.add_parser("demo-users", help="load a SYNTHETIC demo company and create one account per role "
                                          "(random passwords, printed once)")
    m.add_argument("--profile", choices=sorted(synth.PROFILES), default="power")
    m.add_argument("--months", type=int, default=2, help="monthly imports to load, 30 days apart (default 2)")
    m.add_argument("--workspace", type=Path)

    args = ap.parse_args(argv)
    if args.cmd in ("serve", "db-upgrade", "create-admin", "demo-users"):
        from .app import cli
        from .app.config import Settings

        settings = Settings(workspace=args.workspace) if args.workspace else Settings()
        if args.cmd == "serve":
            cli.serve(settings, args.host, args.port)
        elif args.cmd == "db-upgrade":
            cli.db_upgrade(settings)
        elif args.cmd == "create-admin":
            cli.create_admin(settings, args.email, args.name)
        else:
            made = cli.demo_users(settings, args.profile, args.months)
            print(f"Loaded the synthetic {synth.PROFILES[args.profile]['org']} and set up {len(made)} accounts.")
            print("Passwords are shown once. These accounts are for synthetic demo data only.\n")
            width = max(len(e) for e, _, _ in made)
            for email, password, roles in made:
                print(f"{email:<{width}}  {password}  {roles}")
        return

    if args.cmd == "synth":
        paths = synth.generate(args.out, args.seed, args.profile, args.month)
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
