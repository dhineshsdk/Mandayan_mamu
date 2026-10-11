"""Load the role and module catalogue (sutra/data/access_catalog.json) into the database."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Module, Role, RolePermission, Setting

CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "access_catalog.json"

DEFAULT_APPROVAL_RULES = {
    # Step 3 (vertical head) is needed for these SSVC decisions...
    "vertical_head_for_ssvc": ["Act", "Attend", "Track*"],
    # ...and for any job touching an asset at or above this criticality (5 = crown jewel).
    "crown_jewel_min_criticality": 5,
    # The vertical head may approve an Act job as an emergency change.
    "emergency_fast_track_for_act": True,
}
# Rules no setting can loosen: manager and VM analyst always sign, and every OT plan needs the vertical head.
FIXED_RULES = {"manager_always": True, "vm_analyst_always": True, "ot_always_vertical_head": True}


def load_catalog(path: Path = CATALOG_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    actions, scopes = set(data["actions"]), set(data["scope_types"])
    module_keys = {m["key"] for m in data["modules"]}
    for r in data["roles"]:
        if r["scope"] not in scopes:
            raise ValueError(f"role {r['key']}: unknown scope {r['scope']}")
        for mod, acts in r["permissions"].items():
            if mod not in module_keys:
                raise ValueError(f"role {r['key']}: unknown module {mod}")
            if not set(acts) <= actions:
                raise ValueError(f"role {r['key']}: unknown action in {acts}")
    return data


def sync_catalog(db: Session, path: Path = CATALOG_PATH) -> None:
    """Make the roles, modules and permissions tables match the catalogue file. Licences are kept."""
    data = load_catalog(path)
    existing = {m.key: m for m in db.scalars(select(Module))}
    for m in data["modules"]:
        row = existing.get(m["key"])
        if row is None:
            db.add(Module(key=m["key"], name=m["name"], built=m["built"], licensed=True))
        else:
            row.name, row.built = m["name"], m["built"]
    db.flush()
    roles = {r.key: r for r in db.scalars(select(Role))}
    for r in data["roles"]:
        row = roles.get(r["key"])
        if row is None:
            row = Role(key=r["key"])
            db.add(row)
        row.name, row.description, row.scope_type = r["name"], r.get("description", ""), r["scope"]
        row.time_limited = bool(r.get("time_limited"))
        row.permissions = [RolePermission(role_key=r["key"], module_key=mod, action=a)
                           for mod, acts in r["permissions"].items() for a in acts]
    if db.get(Setting, "approval_rules") is None:
        db.add(Setting(key="approval_rules", value=dict(DEFAULT_APPROVAL_RULES)))
    db.commit()
