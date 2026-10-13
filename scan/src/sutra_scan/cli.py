"""``sutra-scan`` command line: ``inventory``, ``feed fetch|build|info``, ``match`` and ``scan``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, feed, rows
from .inventory import Inventory, InventoryError, collect
from .match import MatchResult, UnsupportedOs, match

SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sutra-scan", description=__doc__)
    p.add_argument("--version", action="version", version=f"sutra-scan {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    inv = sub.add_parser("inventory", help="list installed packages as JSON (run this on the host)")
    inv.add_argument("--root", default="/", help="inspect a mounted or extracted image instead of this host")
    inv.add_argument("--hostname", default="", help="name to record (default: this host's name)")
    inv.add_argument("-o", "--output", help="write here instead of standard output")

    fd = sub.add_parser("feed", help="manage the advisory snapshot").add_subparsers(dest="feed_cmd", required=True)
    fetch = fd.add_parser("fetch", help="download OSV bulk files (needs the internet)")
    fetch.add_argument("directory")
    default = ", ".join(feed.DEFAULT_ECOSYSTEMS)
    fetch.add_argument("-e", "--ecosystem", action="append", help=f"repeatable; default: {default}")
    build = fd.add_parser("build", help="build the snapshot file from OSV zips, folders or JSON files (offline)")
    build.add_argument("snapshot")
    build.add_argument("sources", nargs="+")
    build.add_argument("-e", "--ecosystem", action="append")
    info = fd.add_parser("info", help="show what a snapshot contains")
    info.add_argument("snapshot")

    for name, text in (("match", "match inventory files against a snapshot"),
                       ("scan", "inventory this host (or --root) and match it in one step")):
        m = sub.add_parser(name, help=text)
        m.add_argument("--feed", required=True, help="snapshot file")
        m.add_argument("-o", "--output", help="write a Sutra rows file (import it under Import data)")
        m.add_argument("--json", action="store_true", help="print detections as JSON")
        m.add_argument("--include-unfixed", action="store_true", help="also report advisories with no fix yet")
        m.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 3 if any detection is at least this severe")
        if name == "match":
            m.add_argument("inventories", nargs="+")
        else:
            m.add_argument("--root", default="/")
            m.add_argument("--hostname", default="")
    return p


def _print_table(inv: Inventory, res: MatchResult, out) -> None:
    print(f"{inv.hostname or 'host'}: {inv.os.pretty_name or inv.os.id} - {res.packages_checked} packages, "
          f"{len(res.detections)} vulnerabilities ({res.ecosystem}, advisories to {res.feed['data_as_of'][:10]})",
          file=out)
    for d in sorted(res.detections, key=lambda d: (-SEVERITY_ORDER.index(d.severity), d.package)):
        cves = ",".join(d.cves[:3])
        print(f"  {d.severity:<8} {d.package} {d.installed} -> {d.fixed or 'no fix'}  {d.advisory} {cves}", file=out)
    for w in res.warnings:
        print(f"  warning: {w}", file=out)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except BrokenPipeError:  # `sutra-scan ... | head`
        return 0
    except (InventoryError, feed.FeedError, UnsupportedOs, OSError) as exc:
        print(f"sutra-scan: {exc}", file=sys.stderr)
        return 2


def _run(args) -> int:
    if args.cmd == "inventory":
        inv = collect(args.root, hostname=args.hostname)
        text = inv.to_json()
        if args.output:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return 0
    if args.cmd == "feed":
        if args.feed_cmd == "fetch":
            for p in feed.fetch(args.directory, args.ecosystem or feed.DEFAULT_ECOSYSTEMS):
                print(p)
            return 0
        if args.feed_cmd == "build":
            info = feed.build(args.snapshot, args.sources, args.ecosystem or feed.DEFAULT_ECOSYSTEMS)
            if info["missing_ecosystems"]:
                print(f"warning: no advisories found for {', '.join(info['missing_ecosystems'])}", file=sys.stderr)
        else:
            info = feed.Feed(args.snapshot).info()
        print(json.dumps(info, indent=1))
        return 0

    snapshot = feed.Feed(args.feed)
    if args.cmd == "match":
        invs = [Inventory.from_json(Path(p).read_text(encoding="utf-8")) for p in args.inventories]
    else:
        invs = [collect(args.root, hostname=args.hostname)]
    all_rows, worst, payload = [], -1, []
    for inv in invs:
        res = match(inv, snapshot, include_unfixed=args.include_unfixed)
        all_rows += rows.to_rows(inv, res)
        worst = max([worst, *(SEVERITY_ORDER.index(d.severity) for d in res.detections)])
        if args.json:
            payload.append({"host": inv.hostname, "os": inv.os.pretty_name, "feed": res.feed, "warnings": res.warnings,
                            "detections": [{**d.__dict__, "url": d.url} for d in res.detections]})
        else:
            _print_table(inv, res, sys.stdout)
    if args.json:
        print(json.dumps(payload, indent=1))
    if args.output:
        n = rows.write(args.output, all_rows, "sutra-scan")
        print(f"wrote {n} rows to {args.output}", file=sys.stderr)
    if args.fail_on and worst >= SEVERITY_ORDER.index(args.fail_on):
        return 3
    return 0
