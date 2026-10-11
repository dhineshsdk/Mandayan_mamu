"""Encrypts the scanner credentials Sutra stores (Fernet: AES-128-CBC with HMAC-SHA256).

The key is derived with HKDF-SHA256 from the server's secret key (``SUTRA_SECRET_KEY``, or the one generated in the
workspace). If that secret changes, stored credentials can no longer be read and must be entered again; Sutra says
so rather than failing silently.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CannotDecrypt(Exception):
    """The stored secret was encrypted under a different server secret key."""


def _fernet(secret_key: str) -> Fernet:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sutra-vault-v1",
               info=b"scanner connection credentials").derive(secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def seal(secret_key: str, plain: str) -> str:
    return _fernet(secret_key).encrypt(plain.encode()).decode()


def open_(secret_key: str, sealed: str) -> str:
    try:
        return _fernet(secret_key).decrypt(sealed.encode()).decode()
    except InvalidToken as e:
        raise CannotDecrypt("The stored credential cannot be decrypted with this server's secret key. "
                            "Enter it again.") from e
