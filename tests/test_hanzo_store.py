import tempfile
import unittest
from pathlib import Path

from hanzo_store import HanzoStore


class HanzoStoreTests(unittest.TestCase):
    def test_records_and_reads_workflow_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store = HanzoStore(Path(directory))
            run_id = store.record(
                "http://10.20.39.11", "profile", "completed", False,
                {"steps": [{"adapter": "hexstrike_profile"}]},
            )
            rows = store.recent(1)
            self.assertEqual(rows[0]["id"], run_id)
            self.assertEqual(rows[0]["asset"], "http://10.20.39.11")
            self.assertFalse(rows[0]["authorized"])
            self.assertEqual(rows[0]["result"]["steps"][0]["adapter"], "hexstrike_profile")


if __name__ == "__main__":
    unittest.main()
