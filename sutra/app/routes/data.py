"""Data import: upload scanner exports, an asset register and an ownership chart, then analyse them."""

from __future__ import annotations

import re
import secrets
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import ingest, synth
from ..access import Principal
from ..deps import client_ip, get_db, require
from ..models import Dataset, User
from ..security import audit

router = APIRouter(prefix="/api/data")
CHUNK = 1024 * 1024


class AnalyzeIn(BaseModel):
    org: str = Field(default="", max_length=200)


class DemoIn(BaseModel):
    profile: str = Field(max_length=40)
    month: int = Field(default=0, ge=0, le=12)  # 0 = the base scan; n = the same estate n x 30 days later


def staging(request: Request) -> Path:
    return request.app.state.settings.workspace / "staging"


def safe_name(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name or "upload").name)[:120] or "upload"
    return "_" + name if name.startswith(".") else name


def staged_files(request: Request) -> list[dict]:
    files = []
    root = staging(request)
    if root.exists():
        for p in sorted(root.iterdir()):
            try:
                fmt = ingest.detect_format(p)
            except ValueError:
                fmt = "unknown"
            files.append({"name": p.name, "format": fmt, "bytes": p.stat().st_size})
    return files


@router.get("/uploads")
def list_uploads(request: Request, p: Principal = Depends(require("M-DAT", "view"))):
    return {"files": staged_files(request), "profiles": {k: v["org"] for k, v in synth.PROFILES.items()}}


@router.post("/uploads", status_code=201)
async def upload(file: UploadFile, request: Request, p: Principal = Depends(require("M-DAT", "act")),
                 db: Session = Depends(get_db)):
    limit = request.app.state.settings.max_upload_bytes
    root = staging(request)
    root.mkdir(parents=True, exist_ok=True)
    name = safe_name(file.filename or "")
    dest = root / name
    size = 0
    with dest.open("wb") as out:
        while chunk := await file.read(CHUNK):
            size += len(chunk)
            if size > limit:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"{name} is larger than {limit // (1024 * 1024)} MB.")
            out.write(chunk)
    try:
        fmt = ingest.detect_format(dest)
    except ValueError as e:
        dest.unlink(missing_ok=True)
        raise ValueError(f"{name}: {e}") from None
    audit(db, "data.upload", p.user, "file", name, client_ip(request), format=fmt, bytes=size)
    db.commit()
    return {"name": name, "format": fmt, "bytes": size}


@router.delete("/uploads")
def clear_uploads(request: Request, p: Principal = Depends(require("M-DAT", "act")), db: Session = Depends(get_db)):
    shutil.rmtree(staging(request), ignore_errors=True)
    audit(db, "data.uploads_cleared", p.user, "file", "", client_ip(request))
    db.commit()
    return {"ok": True}


def _dataset_dir(request: Request, label: str) -> Path:
    d = request.app.state.settings.workspace / "datasets" / f"{label}-{secrets.token_hex(4)}"
    d.mkdir(parents=True)
    return d


@router.post("/analyze")
def analyze(body: AnalyzeIn, request: Request, p: Principal = Depends(require("M-DAT", "act")),
            db: Session = Depends(get_db)):
    staged = [f for f in staged_files(request) if f["format"] != "unknown"]
    if not any(f["format"] in ingest.LOADERS for f in staged):
        raise ValueError("Upload at least one scanner file: a Qualys CSV, Tenable CSV, .nessus file, or Trivy or "
                         "Grype JSON report.")
    dest = _dataset_dir(request, "upload")
    files = []
    for f in staged:
        target = dest / f["name"]
        shutil.move(staging(request) / f["name"], target)
        files.append({"path": str(target), "name": f["name"], "format": f["format"]})
    store = request.app.state.analysis
    try:
        ds = store.activate(db, files, body.org.strip(), "upload", p.user.id)
    except Exception:
        for f in files:  # put the files back so the person can fix the problem and retry
            shutil.move(f["path"], staging(request) / f["name"])
        shutil.rmtree(dest, ignore_errors=True)
        raise
    audit(db, "data.analyze", p.user, "dataset", ds.id, client_ip(request), org=ds.org_name,
          files=[f["name"] for f in files])
    db.commit()
    return {"ok": True, "dataset": ds.id}


@router.post("/demo")
def demo(body: DemoIn, request: Request, p: Principal = Depends(require("M-DAT", "act")),
         db: Session = Depends(get_db)):
    if body.profile not in synth.PROFILES:
        raise ValueError(f"Unknown demo profile {body.profile!r}.")
    ds = load_demo(request.app, db, body.profile, p.user.id, body.month)
    audit(db, "data.demo", p.user, "dataset", ds.id, client_ip(request), profile=body.profile, month=body.month)
    db.commit()
    return {"ok": True, "dataset": ds.id}


def load_demo(app, db: Session, profile: str, user_id: int | None, month: int = 0) -> Dataset:
    """Generate a synthetic estate (clearly labelled SYNTHETIC) and make it the current import."""
    d = app.state.settings.workspace / "datasets" / f"demo-{profile}-m{month}-{secrets.token_hex(4)}"
    paths = synth.generate(d, profile=profile, month=month)
    files = [{"path": str(p), "name": p.name, "format": ingest.detect_format(p)} for p in paths.values()]
    return app.state.analysis.activate(db, files, synth.PROFILES[profile]["org"], "demo", user_id)


@router.get("/datasets")
def datasets(p: Principal = Depends(require("M-DAT", "view")), db: Session = Depends(get_db)):
    users = {u.id: u.display_name for u in db.scalars(select(User))}
    rows = db.scalars(select(Dataset).order_by(Dataset.id.desc()).limit(50))
    return [{"id": d.id, "org": d.org_name, "kind": d.kind, "current": d.is_current,
             "as_of": d.as_of.isoformat() if d.as_of else None, "summary": d.summary or {},
             "files": [{"name": f["name"], "format": f["format"]} for f in d.files],
             "by": users.get(d.created_by, "system"), "at": d.created_at.isoformat(timespec="seconds")} for d in rows]
