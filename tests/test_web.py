import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from sutra import synth
from sutra.web.server import State, make_handler


class WebApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.state = State(Path(cls.tmp.name))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.state))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()

    def call(self, path, body=None, method=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())

    def test_demo_upload_analyse_and_headline(self):
        self.assertFalse(self.call("/api/state")["loaded"])
        self.call("/api/demo", {"profile": "manufacturing"})
        state = self.call("/api/state")
        self.assertTrue(state["loaded"])
        self.assertEqual(state["data"]["org"], synth.PROFILES["manufacturing"]["org"])

        paths = synth.generate(Path(self.tmp.name) / "src", profile="power")
        for p in paths.values():
            r = self.call(f"/api/upload?name={p.name}", raw=p.read_bytes(), method="POST")
            self.assertNotEqual(r["format"], "unknown")
        self.call("/api/analyze", {"org": "Uploaded"})
        data = self.call("/api/state")["data"]
        self.assertEqual(data["org"], "Uploaded")
        self.assertEqual(len(data["coverage"]["unscanned"]), 12)

        hit = self.call("/api/headline", {"query": "CVE-2023-4966"})
        self.assertTrue(hit["exposed"])
        self.assertEqual(hit["internet_hosts"], 2)

        with urllib.request.urlopen(self.base + "/api/board") as r:
            self.assertIn("board summary", r.read().decode())
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertIn("Sutra", r.read().decode())


if __name__ == "__main__":
    unittest.main()
