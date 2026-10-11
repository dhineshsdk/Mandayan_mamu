"""A small local web server for the Sutra app. Standard library only; binds to localhost by default.

Routes
  GET  /                      the single-page app
  GET  /api/state             current analysis (or {"loaded": false}) plus uploaded files
  POST /api/demo              {"profile": "power" | "manufacturing"}: generate and analyse a synthetic estate
  POST /api/upload?name=...   raw file body; stored in the workspace, format detected from content
  DELETE /api/upload          forget uploaded files
  POST /api/analyze           {"org": "..."}: analyse the uploaded files
  POST /api/headline          {"query": "CVE-2023-4966"}: are we exposed?
  GET  /api/board             printable one-page board summary
  GET  /api/download/<file>   receipts.json, root_causes.csv or findings.csv
"""

from __future__ import annotations

import json
import re
import shutil
import threading
import webbrowser
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import ingest, pipeline, report, risk, synth, views

STATIC = Path(__file__).parent / "static"
MAX_UPLOAD = 300 * 1024 * 1024
DOWNLOADS = {"receipts.json": "application/json", "root_causes.csv": "text/csv", "findings.csv": "text/csv"}


class State:
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.uploads = workspace / "uploads"
        self.out = workspace / "out"
        self.lock = threading.Lock()
        self.result = None
        self.payload = None
        self.dataset = {}
        self.intel = risk.load_intel()

    def uploaded(self) -> list[dict]:
        files = []
        if self.uploads.exists():
            for p in sorted(self.uploads.iterdir()):
                try:
                    fmt = ingest.detect_format(p)
                except ValueError:
                    fmt = "unknown"
                files.append({"name": p.name, "format": fmt, "bytes": p.stat().st_size})
        return files

    def analyse(self, files: list[Path], cmdb: Path | None, org: str, dataset: dict) -> None:
        res = pipeline.run(files, cmdb, org=org)
        report.write_all(res, self.out)
        self.result, self.payload, self.dataset = res, views.payload(res, self.intel), dataset

    def load_demo(self, profile: str) -> None:
        if profile not in synth.PROFILES:
            raise ValueError(f"unknown demo profile {profile!r}")
        paths = synth.generate(self.workspace / "demo" / profile, profile=profile)
        files = [p for k, p in paths.items() if k != "cmdb"]
        self.analyse(files, paths["cmdb"], synth.PROFILES[profile]["org"],
                     {"kind": "demo", "profile": profile,
                      "files": [{"name": p.name, "format": ingest.detect_format(p)} for p in paths.values()]})


def make_handler(state: State):
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(STATIC), **kw)

        def log_message(self, fmt, *args):  # keep the console quiet during demos
            pass

        def _json(self, obj, status=HTTPStatus.OK):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, msg, status=HTTPStatus.BAD_REQUEST):
            self._json({"error": msg}, status)

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_UPLOAD:
                raise ValueError("file too large")
            return self.rfile.read(n) if n else b""

        def _same_origin(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or urlparse(origin).netloc == self.headers.get("Host")

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/api/state":
                with state.lock:
                    return self._json({"loaded": state.payload is not None, "dataset": state.dataset,
                                       "uploads": state.uploaded(), "profiles": {
                                           k: v["org"] for k, v in synth.PROFILES.items()},
                                       "data": state.payload})
            if url.path == "/api/board":
                if state.result is None:
                    return self._error("nothing analysed yet", HTTPStatus.NOT_FOUND)
                body = report.render_board_html(state.result).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if url.path.startswith("/api/download/"):
                name = url.path.rsplit("/", 1)[-1]
                path = state.out / name
                if name not in DOWNLOADS or not path.exists():
                    return self._error("not found", HTTPStatus.NOT_FOUND)
                body = path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", DOWNLOADS[name])
                self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if url.path.startswith("/api/"):
                return self._error("not found", HTTPStatus.NOT_FOUND)
            if url.path != "/" and not (STATIC / url.path.lstrip("/")).is_file():
                self.path = "/"
            return super().do_GET()

        def do_POST(self):
            if not self._same_origin():
                return self._error("cross-origin request refused", HTTPStatus.FORBIDDEN)
            url = urlparse(self.path)
            try:
                if url.path == "/api/upload":
                    name = parse_qs(url.query).get("name", [""])[0]
                    name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)[:120] or "upload"
                    if name.startswith("."):
                        name = "_" + name
                    state.uploads.mkdir(parents=True, exist_ok=True)
                    dest = state.uploads / name
                    dest.write_bytes(self._body())
                    try:
                        fmt = ingest.detect_format(dest)
                    except ValueError as e:
                        dest.unlink()
                        return self._error(str(e))
                    return self._json({"name": name, "format": fmt})
                body = json.loads(self._body() or b"{}")
                if url.path == "/api/demo":
                    with state.lock:
                        state.load_demo(body.get("profile", "power"))
                    return self._json({"ok": True})
                if url.path == "/api/analyze":
                    with state.lock:
                        files = state.uploaded()
                        scans = [state.uploads / f["name"] for f in files if f["format"] in ingest.LOADERS]
                        cmdbs = [state.uploads / f["name"] for f in files if f["format"] == "cmdb"]
                        if not scans:
                            return self._error("upload at least one Qualys CSV, Tenable CSV or .nessus file")
                        state.analyse(scans, cmdbs[0] if cmdbs else None, body.get("org", "").strip(),
                                      {"kind": "upload", "files": files})
                    return self._json({"ok": True})
                if url.path == "/api/headline":
                    if state.result is None:
                        return self._error("nothing analysed yet")
                    return self._json(views.headline_check(state.result, str(body.get("query", "")), state.intel))
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                return self._error(str(e))
            except SystemExit as e:
                return self._error(str(e))
            return self._error("not found", HTTPStatus.NOT_FOUND)

        def do_DELETE(self):
            if not self._same_origin():
                return self._error("cross-origin request refused", HTTPStatus.FORBIDDEN)
            if urlparse(self.path).path == "/api/upload":
                shutil.rmtree(state.uploads, ignore_errors=True)
                return self._json({"ok": True})
            return self._error("not found", HTTPStatus.NOT_FOUND)

    return Handler


def serve(host: str, port: int, workspace: Path, preload: bool = True, open_browser: bool = True) -> None:
    state = State(workspace)
    if preload:
        state.load_demo("power")
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    url = f"http://{host}:{port}/"
    print(f"Sutra is running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
