"""Who may do what, where: module x action x scope, decided on the server for every request."""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..model import Asset
from .models import Module, OwnershipTeam, Role, User, utcnow

ORG = "org"


@dataclass(frozen=True)
class Scope:
    type: str  # org | vertical | site | team
    value: str = ""

    def label(self) -> str:
        return "Whole organisation" if self.type == ORG else f"{self.type.title()}: {self.value}"


@dataclass
class Principal:
    user: User
    roles: list[tuple[str, Scope]]
    perms: dict[tuple[str, str], set[Scope]] = field(default_factory=dict)
    team_vertical: dict[str, str] = field(default_factory=dict)

    @property
    def role_keys(self) -> set[str]:
        return {r for r, _ in self.roles}

    def can(self, module: str, action: str) -> bool:
        return bool(self.perms.get((module, action)))

    def scopes(self, module: str, action: str) -> set[Scope]:
        return self.perms.get((module, action), set())

    def modules(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for (m, a), scopes in self.perms.items():
            if scopes:
                out.setdefault(m, []).append(a)
        return {m: sorted(a) for m, a in out.items()}

    # ----- scope checks -----
    def _match(self, scope: Scope, team: str, site: str) -> bool:
        if scope.type == ORG:
            return True
        if scope.type == "team":
            return team == scope.value
        if scope.type == "vertical":
            return self.team_vertical.get(team) == scope.value
        if scope.type == "site":
            return site == scope.value
        return False

    def asset_allowed(self, asset: Asset, module: str, action: str = "view") -> bool:
        team = asset.owner or ""
        return any(self._match(s, team, asset.site) for s in self.scopes(module, action))

    def asset_ids(self, assets: dict[str, Asset], module: str, action: str = "view") -> set[str]:
        scopes = self.scopes(module, action)
        if any(s.type == ORG for s in scopes):
            return set(assets)
        return {k for k, a in assets.items() if any(self._match(s, a.owner or "", a.site) for s in scopes)}

    def allowed(self, module: str, action: str, team: str, site: str) -> bool:
        """Whether a record owned by ``team`` at ``site`` is inside this person's scope for the module action."""
        return any(self._match(s, team, site) for s in self.scopes(module, action))

    def team_allowed(self, team: str, module: str, action: str) -> bool:
        return any(self._match(s, team, "") for s in self.scopes(module, action) if s.type != "site")

    def is_org_wide(self, module: str, action: str = "view") -> bool:
        return any(s.type == ORG for s in self.scopes(module, action))


def account_usable(user: User | None) -> bool:
    if user is None or not user.is_active:
        return False
    return not (user.expires_at and user.expires_at <= utcnow())


def build_principal(db: Session, user: User) -> Principal:
    licensed = {m.key for m in db.scalars(select(Module)) if m.licensed and m.built}
    roles = {r.key: r for r in db.scalars(select(Role))}
    p = Principal(user=user, roles=[])
    p.team_vertical = {t.team: t.vertical for t in db.scalars(select(OwnershipTeam))}

    def add(module: str, action: str, scope: Scope):
        if module in licensed:
            p.perms.setdefault((module, action), set()).add(scope)

    for ur in user.roles:
        role = roles.get(ur.role_key)
        if role is None:
            continue
        scope = Scope(ORG) if ur.scope_type == ORG else Scope(ur.scope_type, ur.scope_value)
        p.roles.append((ur.role_key, scope))
        for perm in role.permissions:
            add(perm.module_key, perm.action, scope)
    for g in user.grants:
        if g.effect == "allow":
            add(g.module_key, g.action, Scope(ORG) if g.scope_type == ORG else Scope(g.scope_type, g.scope_value))
    for g in user.grants:
        if g.effect == "deny":
            for key in [k for k in p.perms if k[0] == g.module_key and (g.action == "*" or k[1] == g.action)]:
                del p.perms[key]
    return p
