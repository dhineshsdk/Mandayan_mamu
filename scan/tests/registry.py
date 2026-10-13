"""Pull the file system of a real image from Docker Hub without a Docker daemon, for the container tests.

Anonymous pull of ``library/<name>`` (or ``<org>/<name>``) images through the registry HTTP API v2: token, manifest
(an index is resolved to linux/amd64), then each layer blob, applied in order with whiteouts honoured. Layers are
untrusted downloads, so extraction refuses absolute paths, ``..``, devices and links that point outside the target.
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
# Docker Hub rate-limits anonymous pulls per address; Google's public mirror serves the same library images.
DEFAULT_REGISTRY = os.environ.get("SUTRA_SCAN_REGISTRY", "mirror.gcr.io")


class Registry:
    """Anonymous client for one registry; follows the 401 challenge to fetch a pull token when it asks for one."""

    def __init__(self, host: str):
        self.host = host
        self.tokens: dict[str, str] = {}

    def get(self, repo: str, path: str) -> bytes:
        url = f"https://{self.host}/v2/{repo}/{path}"
        headers = {"Accept": ACCEPT}
        if repo in self.tokens:
            headers["Authorization"] = f"Bearer {self.tokens[repo]}"
        try:
            return self._open(url, headers)
        except urllib.error.HTTPError as exc:
            challenge = exc.headers.get("WWW-Authenticate", "")
            if exc.code != 401 or not challenge.lower().startswith("bearer "):
                raise
            fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
            query = urllib.parse.urlencode({"service": fields.get("service", ""), "scope": f"repository:{repo}:pull"})
            token = json.loads(self._open(f"{fields['realm']}?{query}", {}))
            self.tokens[repo] = token.get("token") or token["access_token"]
            headers["Authorization"] = f"Bearer {self.tokens[repo]}"
            return self._open(url, headers)

    @staticmethod
    def _open(url: str, headers: dict) -> bytes:
        req = urllib.request.Request(url, headers=headers)  # noqa: S310 - https registry URL built above
        with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310
            return resp.read()


def _repo(image: str) -> tuple[str, str]:
    if "@" in image:
        name, _, ref = image.partition("@")
    else:
        name, _, ref = image.partition(":")
        ref = ref or "latest"
    return (name if "/" in name else f"library/{name}"), ref


def pull(image: str, dest: Path, platform: str = "amd64", registry: str = DEFAULT_REGISTRY) -> str:
    """Extract ``image`` into the directory ``dest``; returns the manifest digest that was pulled."""
    reg = Registry(registry)
    repo, ref = _repo(image)
    manifest = json.loads(reg.get(repo, f"manifests/{ref}"))
    if "manifests" in manifest:
        pick = next(m for m in manifest["manifests"]
                    if m["platform"].get("architecture") == platform and m["platform"].get("os") == "linux"
                    and not m["platform"].get("variant"))
        ref = pick["digest"]
        manifest = json.loads(reg.get(repo, f"manifests/{ref}"))
    dest.mkdir(parents=True, exist_ok=True)
    for layer in manifest["layers"]:
        _apply(reg.get(repo, f"blobs/{layer['digest']}"), dest)
    return ref


def _safe(dest: Path, name: str) -> Path | None:
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        return None
    target = (dest / p).resolve()
    return target if dest.resolve() in (target, *target.parents) else None


def _apply(blob: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for m in tf:
            target = _safe(dest, m.name)
            if target is None:
                continue
            base = PurePosixPath(m.name).name
            if base == ".wh..wh..opq":
                for child in target.parent.iterdir() if target.parent.is_dir() else ():
                    _remove(child)
                continue
            if base.startswith(".wh."):
                _remove(target.parent / base[4:])
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif m.isreg():
                target.parent.mkdir(parents=True, exist_ok=True)
                _remove(target)
                src = tf.extractfile(m)
                target.write_bytes(src.read() if src else b"")
            elif m.issym() or m.islnk():
                # Links are recreated only when they stay inside dest; the package databases are plain files.
                link = PurePosixPath(m.linkname)
                dest_ok = _safe(dest, str(PurePosixPath(m.name).parent / link)) if not link.is_absolute() else None
                if m.issym() and dest_ok is not None:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    _remove(target)
                    target.symlink_to(link)
                elif m.islnk() and _safe(dest, m.linkname) is not None:
                    source = _safe(dest, m.linkname)
                    if source and source.is_file():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        _remove(target)
                        target.write_bytes(source.read_bytes())


def _remove(p: Path) -> None:
    if p.is_symlink() or p.is_file():
        p.unlink()
    elif p.is_dir():
        for c in p.iterdir():
            _remove(c)
        p.rmdir()
