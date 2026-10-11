import json
import tempfile
import threading
import unittest
import urllib.error
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


    def test_patch_job_routes_by_criticality_and_walks_the_chain(self):
        self.call("/api/demo", {"profile": "power"})
        state = self.call("/api/state")
        rcs = {r["key"]: r for r in state["data"]["root_causes"]}
        org = state["org"]

        hmi = rcs["hmi-win7e-vendor-2016"]
        job = self.call("/api/jobs", {"rc_id": hmi["id"], "team": "C&I - Unit 2", "mode": "patch",
                                      "actor": "C&I - Unit 2 team"})
        self.assertEqual(job["route"]["type"], "staged-plan")
        self.assertEqual([s["role"] for s in job["steps"]], ["manager", "vm_analyst", "vertical_head"])
        self.assertEqual(job["draft"]["oem_approval"], "Pending")
        self.assertTrue(job["jira"].startswith("CIU2-"))

        with self.assertRaises(urllib.error.HTTPError):  # the analyst cannot jump the manager
            self.call(f"/api/jobs/{job['id']}/decision", {"action": "approve", "actor": org["vm_analyst"]})
        for step in job["steps"]:
            job = self.call(f"/api/jobs/{job['id']}/decision", {"action": "approve", "actor": step["who"]})
        self.assertEqual(job["status"], "approved")
        self.assertEqual(len(job["audit"]), 4)

        laptops = rcs["win11-corp-2024q2"]  # Attend on IT: needs the vertical head too
        job = self.call("/api/jobs", {"rc_id": laptops["id"], "team": "End-user Computing", "mode": "patch"})
        self.assertIn("vertical_head", [s["role"] for s in job["steps"]])
        track = next(r for r in rcs.values() if r["ssvc"] == "Track" and not r["is_ot"]
                     and r["key"].startswith("switch-baseline"))
        job = self.call("/api/jobs", {"rc_id": track["id"], "team": "Network Operations", "mode": "patch"})
        self.assertEqual([s["role"] for s in job["steps"]], ["manager", "vm_analyst"])
        manual = self.call("/api/jobs", {"rc_id": rcs["Apache Tomcat|9.0.83"]["id"], "team": "IT Infra - Linux",
                                         "mode": "manual", "ticket": "CHG0012345"})
        self.assertEqual(manual["status"], "fixing-manually")


if __name__ == "__main__":
    unittest.main()
