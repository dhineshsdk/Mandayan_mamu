import json
import tempfile
import unittest
from pathlib import Path

from sutra import pipeline, report, synth
from sutra.money import inr


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        paths = synth.generate(root / "data", seed=7)
        cls.res = pipeline.run([paths["qualys"]], [paths["tenable"]], paths["cmdb"], org=synth.ORG)
        cls.board = report.write_all(cls.res, root / "out")
        cls.out = root / "out"
        cls.rc = {r.key: r for r in cls.res.root_causes}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_finding_has_exactly_one_root_cause(self):
        ids = [fid for r in self.res.root_causes for fid in r.finding_ids]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), {f.finding_id for f in self.res.findings})

    def test_cross_scanner_duplicates_are_merged(self):
        self.assertLess(len(self.res.findings), self.res.raw_rows)
        self.assertGreater(self.res.coverage["multi_scanner_findings"], 100)

    def test_groups_by_base_image_package_template_and_credential(self):
        kinds = {r.kind for r in self.res.root_causes}
        self.assertTrue({"base-image", "package", "config-template", "shared-credential"} <= kinds)
        self.assertGreaterEqual(len(self.rc["rhel8-base-v3"].asset_ids), 40)
        self.assertEqual(len(self.rc["Apache Log4j|2.17.1"].asset_ids), 6)
        self.assertEqual(len(self.rc["vendor-default:engineer"].asset_ids), 14)

    def test_hosts_missing_from_cmdb_are_matched_to_their_image(self):
        inferred = self.res.coverage["inferred_images"]
        self.assertGreaterEqual(len(inferred), 5)
        self.assertTrue(all(a.image == "rhel8-base-v3" for a in inferred))

    def test_ot_and_exploited_work_is_triaged(self):
        hmi = self.rc["hmi-win7e-vendor-2016"]
        self.assertTrue(hmi.is_ot)
        self.assertEqual(hmi.ssvc, "Act")
        self.assertIn("OEM", hmi.executor)
        self.assertEqual(self.rc["Citrix NetScaler ADC|13.1-49.15"].ssvc, "Act")

    def test_blind_spots_are_counted(self):
        self.assertEqual(len(self.res.coverage["unscanned"]), 12)
        self.assertEqual(len(self.res.coverage["unknown"]), 9)

    def test_outputs_and_receipts(self):
        html = self.board.read_text(encoding="utf-8")
        self.assertIn("₹", html)
        self.assertIn("RC-001", html)
        receipts = json.loads((self.out / "receipts.json").read_text(encoding="utf-8"))
        first = receipts["root_causes"][0]["findings"][0]["sources"][0]
        self.assertTrue({"scanner", "scanner_ref", "source_file", "source_row"} <= first.keys())

    def test_rupee_risk_is_deterministic_and_ranked(self):
        rcs = self.res.root_causes
        self.assertEqual([r.ale_mean for r in rcs], sorted((r.ale_mean for r in rcs), reverse=True))
        again = pipeline.run(*self._paths_again())
        self.assertAlmostEqual(again.portfolio["ale_mean"], self.res.portfolio["ale_mean"])

    def _paths_again(self):
        d = Path(self.tmp.name) / "data"
        return [d / "qualys_vm_export.csv"], [d / "tenable_sc_export.csv"], d / "cmdb_assets.csv"


class Money(unittest.TestCase):
    def test_lakh_and_crore(self):
        self.assertEqual(inr(45_000), "₹45,000")
        self.assertEqual(inr(1_850_000), "₹18.5 lakh")
        self.assertEqual(inr(42_000_000), "₹4.2 crore")


if __name__ == "__main__":
    unittest.main()
