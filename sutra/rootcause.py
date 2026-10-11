"""Group deduplicated findings by the one thing that, once fixed, closes them all.

Four root-cause types from the plan, tried in this order for every finding:

1. Shared credential: the same credential fingerprint accepted on several hosts.
2. Config template: the same misconfiguration on hosts built from the same template (GPO, Ansible role,
   switch baseline).
3. Base image: a package flaw present on most hosts built from the same golden image or VM template.
   Hosts missing from the CMDB are matched to an image by their package fingerprint.
4. Package: the same package below the same fixed version across hosts that share no image.

Anything left becomes a fleet-wide misconfiguration (same control, no template) or a single finding.
"""

from __future__ import annotations

from collections import defaultdict

from .ingest.normalize import ACCOUNT
from .model import SEVERITY_ORDER, Asset, Finding, RootCause

WINDOWS_PATCH = "Microsoft Windows OS patch"
IMAGE_SHARE = 0.5  # a package flaw is the image's fault if at least this share of its hosts carry it
INFER_MATCH = 0.6  # Jaccard similarity needed to assign an image to a host missing from the CMDB


def infer_images(assets: dict[str, Asset], findings: list[Finding]) -> None:
    pkgs_by_asset: dict[str, set] = defaultdict(set)
    for f in findings:
        if f.kind == "package":
            pkgs_by_asset[f.asset_id].add((f.package, f.installed))
    members: dict[str, list[str]] = defaultdict(list)
    for a in assets.values():
        if a.image and a.scanned_by:
            members[a.image].append(a.asset_id)
    signatures = {}
    for image, ids in members.items():
        counts: dict[tuple, int] = defaultdict(int)
        for aid in ids:
            for p in pkgs_by_asset[aid]:
                counts[p] += 1
        sig = {p for p, c in counts.items() if c / len(ids) >= IMAGE_SHARE}
        if sig:
            signatures[image] = sig
    for a in assets.values():
        if a.image or not pkgs_by_asset.get(a.asset_id):
            continue
        mine = pkgs_by_asset[a.asset_id]
        best, score = "", 0.0
        for image, sig in signatures.items():
            j = len(mine & sig) / len(mine | sig)
            if j > score:
                best, score = image, j
        if score >= INFER_MATCH:
            a.image, a.image_source = best, f"inferred (package match {score:.2f})"


def _finish(rc: RootCause, members: list[Finding], assets: dict[str, Asset]) -> RootCause:
    rc.finding_ids = [f.finding_id for f in members]
    rc.asset_ids = sorted({f.asset_id for f in members})
    rc.cves = sorted({c for f in members for c in f.cves})
    rc.max_severity = max((f.severity for f in members), key=SEVERITY_ORDER.get)
    rc.max_cvss = max((f.cvss or 0.0 for f in members), default=0.0)
    rc.is_ot = any(assets[a].is_ot for a in rc.asset_ids)
    rc.executor = ("Human-executed plan: OEM approval, planned outage, compensating control meanwhile"
                   if rc.is_ot else "Can run automatically after approval")
    for f in members:
        f.root_cause_id = rc.rc_id
    return rc


def _package_labels(members: list[Finding]) -> list[str]:
    """Package names, with missing Windows updates shown by KB number."""
    labels = {f.package for f in members if f.package != WINDOWS_PATCH}
    kbs = sorted({f.fixed for f in members if f.package == WINDOWS_PATCH})
    if kbs:
        labels.add(f"Windows updates ({', '.join(kbs)})")
    return sorted(labels)


def group(assets: dict[str, Asset], findings: list[Finding]) -> list[RootCause]:
    infer_images(assets, findings)
    rcs: list[RootCause] = []
    claimed: set[str] = set()

    def new(kind, key, title, fix, members):
        rc = RootCause(rc_id=f"tmp-{len(rcs)}", kind=kind, key=key, title=title, fix=fix)
        rcs.append(_finish(rc, members, assets))
        claimed.update(f.finding_id for f in members)

    def n_hosts(members):
        return len({f.asset_id for f in members})

    # 1. Shared credentials
    by_cred: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.kind == "credential":
            by_cred[f.credential_fp].append(f)
    for fp, members in by_cred.items():
        if n_hosts(members) >= 2:
            m = ACCOUNT.search(members[0].evidence)
            who = f"account '{m[1]}'" if m else fp
            new("shared-credential", fp, f"One shared credential ({who}) logs in to {n_hosts(members)} hosts",
                members[0].solution or "Rotate the credential and give each host its own.", members)

    # 2. Config templates
    by_tpl: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        tpl = assets[f.asset_id].config_template
        if f.kind == "config" and tpl and f.finding_id not in claimed:
            by_tpl[(tpl, f.control)].append(f)
    for (tpl, control), members in by_tpl.items():
        if n_hosts(members) >= 2:
            new("config-template", f"{tpl}|{control}", f"Template {tpl} sets: {control}",
                f"Fix {tpl} once and re-apply it to {n_hosts(members)} hosts. {members[0].solution}", members)

    # 3. Base images
    image_hosts: dict[str, set] = defaultdict(set)
    for a in assets.values():
        if a.image and a.scanned_by:
            image_hosts[a.image].add(a.asset_id)
    by_img_pkg: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        img = assets[f.asset_id].image
        if f.kind == "package" and img and f.finding_id not in claimed:
            by_img_pkg[(img, f.package, f.fixed)].append(f)
    image_members: dict[str, list[Finding]] = defaultdict(list)
    for (img, _pkg, _fixed), members in by_img_pkg.items():
        if n_hosts(members) >= 2 and n_hosts(members) / len(image_hosts[img]) >= IMAGE_SHARE:
            image_members[img].extend(members)
    for img, members in image_members.items():
        pkgs = _package_labels(members)
        ot = any(assets[f.asset_id].is_ot for f in members)
        fix = ("Staged plan: get OEM approval, apply at the next planned outage, and keep a compensating control "
               "in place until then." if ot else
               f"Patch the image once, rebuild, and redeploy or patch the {n_hosts(members)} hosts built from it.")
        new("base-image", img, f"Golden image {img} needs fixes: {', '.join(pkgs)}", fix, members)

    # 4. Packages across the fleet
    by_pkg: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.kind == "package" and f.finding_id not in claimed:
            by_pkg[(f.package, f.fixed)].append(f)
    for (pkg, fixed), members in by_pkg.items():
        if n_hosts(members) >= 2:
            new("package", f"{pkg}|{fixed}", f"{pkg} below {fixed} on {n_hosts(members)} hosts",
                members[0].solution or f"Upgrade {pkg} to {fixed} or later.", members)

    # 5. Fleet-wide controls with no template, then everything else
    by_rest: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.finding_id not in claimed:
            key = ("config", f.control) if f.kind == "config" else ("other", f.package or f.title)
            by_rest[key].append(f)
    for (kind, key), members in by_rest.items():
        if kind == "config" and n_hosts(members) >= 2:
            new("fleet-config", key, f"{key} on {n_hosts(members)} hosts (no shared template)",
                members[0].solution or f"Fix {key}.", members)
        elif n_hosts(members) >= 2:
            new("fleet", key, f"{members[0].title} on {n_hosts(members)} hosts",
                members[0].solution or "Remediate per vendor guidance.", members)
        else:
            for f in members:
                host = assets[f.asset_id].hostname or f.asset_id
                new("single", f.finding_id, f"{f.title} on {host}", f.solution or "Remediate per vendor guidance.",
                    [f])
    return rcs
