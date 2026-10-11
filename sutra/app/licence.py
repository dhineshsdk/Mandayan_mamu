"""Licence keys: which modules a customer has bought, checked offline.

A key is one line of text, ``SUTRA1.<payload>.<signature>``. The payload is JSON (customer, licence id, issue and
expiry dates, module keys) and the signature is Ed25519 over those exact bytes. Sutra holds only the vendor's PUBLIC
key, so a customer cannot make or change a key, and nothing is sent anywhere to check it: it works on an air-gapped
server. A key is not tied to a machine, so it can be copied to a second install; that is a contract matter, and the
customer name on the Licences tab and in the audit log is what makes it visible.

What a licence does:

* only modules named in the key can be switched on; ``M-ADM`` (Administration) is always allowed so a lapsed licence can
  always be replaced;
* the existing per-module switch (``Module.licensed``) still lets an administrator turn a bought module off, but never
  turn on one that is not in the key;
* after the expiry date there is a grace period (``GRACE_DAYS``) with a warning on the Licences tab; after that only
  Administration stays on, until a new key is installed. Data is never deleted or hidden from export.

Without a key Sutra runs every built module, labelled "No licence installed (evaluation)", unless
``SUTRA_REQUIRE_LICENCE=1`` is set (the installer sets it), in which case only Administration runs until a key is
installed. The vendor's public key is read from ``SUTRA_LICENCE_PUBLIC_KEY`` (a PEM file) or
``sutra/data/licence_public.pem``. This repository ships without one: the vendor generates the pair with
``python -m sutra licence keygen``, keeps the private half offline and builds the public half into the release.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Module, Setting, utcnow

PREFIX = "SUTRA1"
GRACE_DAYS = 30
ALWAYS = "M-ADM"
SETTING = "licence"
BUNDLED_KEY = Path(__file__).resolve().parent.parent / "data" / "licence_public.pem"


class LicenceError(ValueError):
    """The key is not valid. The message says why, in words an administrator can act on."""


@dataclass(frozen=True)
class Licence:
    id: str
    customer: str
    issued: date
    expires: date
    modules: tuple[str, ...]  # module keys, or ("*",) for every module

    def grants(self, key: str) -> bool:
        return key == ALWAYS or "*" in self.modules or key in self.modules

    def as_dict(self) -> dict:
        return {"id": self.id, "customer": self.customer, "issued": self.issued.isoformat(),
                "expires": self.expires.isoformat(), "modules": list(self.modules)}


@dataclass
class Entitlement:
    """What the installed key allows right now. ``keys`` is None when nothing restricts the modules."""

    state: str  # open | none | valid | grace | expired | invalid | no_vendor_key
    message: str
    licence: Licence | None = None
    keys: set[str] | None = None
    days_left: int | None = None
    warnings: list[str] = field(default_factory=list)

    def allows(self, module: str) -> bool:
        return self.keys is None or module in self.keys or module == ALWAYS

    def as_dict(self) -> dict:
        return {"state": self.state, "message": self.message,
                "licence": self.licence.as_dict() if self.licence else None, "days_left": self.days_left,
                "grace_days": GRACE_DAYS, "warnings": self.warnings}


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as e:
        raise LicenceError("The key is damaged: it is not complete. Copy the whole line.") from e


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# ----- vendor side -----
def generate_keypair() -> tuple[bytes, bytes]:
    """(private PEM, public PEM). The private key signs licences; keep it offline and never ship it."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, public


def issue(private_pem: bytes, customer: str, modules: list[str], expires: date, licence_id: str,
          issued: date | None = None) -> str:
    customer = customer.strip()
    if not customer or not licence_id.strip():
        raise LicenceError("A customer name and a licence id are required.")
    if not modules:
        raise LicenceError("List at least one module (or * for all).")
    try:
        key = serialization.load_pem_private_key(private_pem, password=None)
    except ValueError as e:
        raise LicenceError("That is not a private key file.") from e
    if not isinstance(key, Ed25519PrivateKey):
        raise LicenceError("The signing key must be an Ed25519 key (made by `licence keygen`).")
    issued = issued or date.today()
    if expires <= issued:
        raise LicenceError("The expiry date must be after the issue date.")
    payload = {"v": 1, "id": licence_id.strip(), "customer": customer, "issued": issued.isoformat(),
               "expires": expires.isoformat(), "modules": sorted(set(modules))}
    body = _canonical(payload)
    return f"{PREFIX}.{_b64(body)}.{_b64(key.sign(body))}"


# ----- customer side -----
def load_public_key(path: str | os.PathLike | None = None) -> Ed25519PublicKey | None:
    """The vendor's public key, or None when this build has none."""
    chosen = Path(path) if path else Path(os.environ["SUTRA_LICENCE_PUBLIC_KEY"]) if os.environ.get(
        "SUTRA_LICENCE_PUBLIC_KEY") else BUNDLED_KEY
    if not chosen.exists():
        return None
    try:
        key = serialization.load_pem_public_key(chosen.read_bytes())
    except ValueError as e:
        raise LicenceError(f"{chosen} is not a public key file.") from e
    if not isinstance(key, Ed25519PublicKey):
        raise LicenceError(f"{chosen} is not an Ed25519 public key.")
    return key


def verify(token: str, public_key: Ed25519PublicKey) -> Licence:
    """Check the signature and shape. Does not look at the date: expiry is a state, not a parse error."""
    parts = "".join(token.split()).split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise LicenceError("That is not a Sutra licence key. It should start with SUTRA1.")
    body, sig = _unb64(parts[1]), _unb64(parts[2])
    try:
        public_key.verify(sig, body)
    except InvalidSignature as e:
        raise LicenceError("The signature does not match. The key was changed, is incomplete, or was not issued "
                           "for this version of Sutra.") from e
    try:
        p = json.loads(body)
        mods = p["modules"]
        if p["v"] != 1 or not isinstance(mods, list) or not mods or not all(isinstance(m, str) for m in mods):
            raise ValueError
        return Licence(id=str(p["id"]), customer=str(p["customer"]), issued=date.fromisoformat(p["issued"]),
                       expires=date.fromisoformat(p["expires"]), modules=tuple(mods))
    except (ValueError, KeyError, TypeError) as e:
        raise LicenceError("The key is signed but its contents are not in a form this version understands.") from e


def evaluate(licence: Licence, built: set[str], today: date) -> Entitlement:
    unknown = sorted(m for m in licence.modules if m != "*" and m not in built and m != ALWAYS)
    keys = built if "*" in licence.modules else {m for m in licence.modules if m in built}
    keys = keys | {ALWAYS}
    left = (licence.expires - today).days
    warn = [f"The key lists modules this version does not have: {', '.join(unknown)}."] if unknown else []
    if left >= 0:
        if left <= 30:
            warn.append(f"The licence expires in {left} day{'s' if left != 1 else ''} ({licence.expires}).")
        return Entitlement("valid", f"Licensed to {licence.customer} until {licence.expires}.", licence, keys, left,
                           warn)
    if -left <= GRACE_DAYS:
        end = licence.expires + timedelta(days=GRACE_DAYS)
        return Entitlement("grace", f"The licence expired on {licence.expires}. Modules stay on until {end}; install "
                                    f"a new key before then.", licence, keys, left,
                           warn + [f"Expired {-left} day{'s' if -left != 1 else ''} ago."])
    return Entitlement("expired", f"The licence expired on {licence.expires} and the grace period has ended. Only "
                                  f"Administration is on until a new key is installed.", licence, {ALWAYS}, left, warn)


class LicenceService:
    """Reads the installed key on each request (cheap: one row and one signature check)."""

    def __init__(self, require_licence: bool = False, public_key_path: str | os.PathLike | None = None,
                 today: Callable[[], date] = date.today):
        self.require = require_licence
        self.path = public_key_path
        self.today = today

    def public_key(self) -> Ed25519PublicKey | None:
        return load_public_key(self.path)

    def installed_token(self, db: Session) -> str:
        row = db.get(Setting, SETTING)
        return (row.value or {}).get("token", "") if row else ""

    def entitlement(self, db: Session) -> Entitlement:
        token = self.installed_token(db)
        if not token:
            if self.require:
                return Entitlement("none", "No licence key is installed. Only Administration is on. Install the key "
                                           "from your Sutra contract on this screen.", keys={ALWAYS})
            return Entitlement("open", "No licence installed (evaluation): every built module is available.")
        try:
            pub = self.public_key()
        except LicenceError as e:
            return Entitlement("invalid", f"The vendor key file is unusable: {e}", keys={ALWAYS})
        if pub is None:
            return Entitlement("no_vendor_key", "A licence is stored but this build has no vendor public key, so it "
                                                "cannot be checked. Only Administration is on.", keys={ALWAYS})
        try:
            lic = verify(token, pub)
        except LicenceError as e:
            return Entitlement("invalid", f"The installed key is not valid: {e} Only Administration is on.",
                               keys={ALWAYS})
        built = {m.key for m in db.scalars(select(Module)) if m.built}
        return evaluate(lic, built, self.today())

    def install(self, db: Session, token: str, user_id: int | None) -> Entitlement:
        pub = self.public_key()
        if pub is None:
            raise LicenceError("This build has no vendor public key, so keys cannot be checked. Ask your Sutra "
                               "contact for a release that includes it.")
        token = "".join(token.split())
        lic = verify(token, pub)
        built = {m.key for m in db.scalars(select(Module)) if m.built}
        ent = evaluate(lic, built, self.today())
        if ent.state == "expired":
            raise LicenceError(f"That key expired on {lic.expires}, more than {GRACE_DAYS} days ago. Ask for a "
                               f"current one.")
        row = db.get(Setting, SETTING)
        value = {"token": token, "installed_at": utcnow().isoformat(timespec="seconds"), **lic.as_dict()}
        if row is None:
            db.add(Setting(key=SETTING, value=value, updated_by=user_id))
        else:
            row.value, row.updated_by, row.updated_at = value, user_id, utcnow()
        return ent
