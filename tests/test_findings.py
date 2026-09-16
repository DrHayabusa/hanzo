import unittest
from unittest.mock import patch

import findings
from hexstrike_server import app

GOBUSTER = """
/.env                 (Status: 200) [Size: 262]
/admin                (Status: 403) [Size: 2665]
/backups              (Status: 308) [Size: 247] [--> http://127.0.0.1:5005/backups/]
/about                (Status: 200) [Size: 3484]
"""
KATANA = (
    '{"request":{"endpoint":"http://127.0.0.1:5005/portal/login"},"response":{"status_code":200}}\n'
    '{"request":{"endpoint":"http://127.0.0.1:5005/api/v1/shipments/"},"response":{"status_code":404}}\n'
)
NUCLEI = "[tech-detect:flask] [http] [info] http://127.0.0.1:5005\n"


class ExtractionTests(unittest.TestCase):
    def test_gobuster_lines_become_structured_findings(self):
        results = findings.from_gobuster(GOBUSTER)
        self.assertEqual(len(results), 4)
        env = next(item for item in results if item["path"] == "/.env")
        self.assertEqual((env["status"], env["size"]), (200, 262))
        self.assertIn("credentials", env["note"])

    def test_redirect_target_is_preserved(self):
        backups = next(item for item in findings.from_gobuster(GOBUSTER) if item["path"] == "/backups")
        self.assertEqual(backups["status"], 308)
        self.assertIn("/backups/", backups["redirect"])

    def test_an_ordinary_page_carries_no_invented_note(self):
        about = next(item for item in findings.from_gobuster(GOBUSTER) if item["path"] == "/about")
        self.assertIsNone(about["note"])

    def test_katana_results_are_marked_as_references_not_confirmations(self):
        results = findings.from_katana(KATANA)
        self.assertEqual(len(results), 2)
        for item in results:
            self.assertEqual(item["evidence"], "referenced by the application")

    def test_nuclei_severity_is_carried_through(self):
        result = findings.from_nuclei(NUCLEI)[0]
        self.assertEqual(result["severity"], "info")
        self.assertEqual(result["source"], "nuclei")

    def test_ansi_colour_codes_do_not_corrupt_paths(self):
        coloured = "\x1b[32m/admin\x1b[0m                (Status: 200) [Size: 10]"
        self.assertEqual(findings.from_gobuster(coloured)[0]["path"], "/admin")

    def test_an_unknown_tool_yields_nothing_rather_than_guessing(self):
        self.assertEqual(findings.extract("some-tool", GOBUSTER), [])

    def test_empty_output_is_not_a_finding(self):
        self.assertEqual(findings.extract("gobuster", ""), [])


class CollectionTests(unittest.TestCase):
    EVIDENCE = {"steps": [
        {"tool": "gobuster", "return_code": 0, "stdout": GOBUSTER},
        {"tool": "katana", "return_code": 0, "stdout": KATANA},
        {"tool": "nikto", "return_code": 1, "stdout": ""},
    ]}

    def test_every_tool_that_ran_is_reported_including_silent_ones(self):
        collected = findings.collect(self.EVIDENCE)
        names = {entry["tool"]: entry for entry in collected["tools"]}
        self.assertFalse(names["nikto"]["produced_output"])
        self.assertEqual(names["gobuster"]["findings"], 4)

    def test_counts_match_the_extracted_findings(self):
        collected = findings.collect(self.EVIDENCE)
        self.assertEqual(collected["counts"]["total"], len(collected["findings"]))
        self.assertEqual(collected["counts"]["by_source"]["gobuster"], 4)

    def test_facts_list_only_what_was_extracted(self):
        collected = findings.collect(self.EVIDENCE)
        facts = findings.as_facts("http://127.0.0.1:5005", collected)
        self.assertIn("/.env", facts)
        self.assertIn("nikto", facts)
        self.assertNotIn("SQL injection", facts)

    def test_a_run_with_no_output_says_so(self):
        collected = findings.collect({"steps": [{"tool": "gobuster", "stdout": ""}]})
        facts = findings.as_facts("http://x", collected)
        self.assertIn("No paths or findings were extracted", facts)


class NarrativeRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        created = self.client.post("/api/redteam/workflows", json={
            "asset": "http://127.0.0.1:5005", "phase": "web", "status": "completed",
            "authorization_confirmed": True,
            "result": {"steps": [{"tool": "gobuster", "return_code": 0, "stdout": GOBUSTER}]}})
        self.run_id = created.get_json()["run_id"]
        self.addCleanup(self.client.delete, f"/api/redteam/workflows/{self.run_id}")

    def test_missing_run_id_is_a_client_error(self):
        self.assertEqual(self.client.post("/api/reports/narrative", json={}).status_code, 400)

    def test_unknown_run_is_not_found(self):
        response = self.client.post("/api/reports/narrative", json={"run_id": "nope"})
        self.assertEqual(response.status_code, 404)

    def test_findings_are_returned_even_when_the_model_is_unreachable(self):
        import requests
        with patch("hexstrike_server.requests.post", side_effect=requests.RequestException("down")):
            payload = self.client.post("/api/reports/narrative", json={"run_id": self.run_id}).get_json()
        self.assertEqual(payload["narrative_status"], "model_unavailable")
        self.assertIsNone(payload["narrative"])
        self.assertEqual(len(payload["findings"]), 4)

    def test_invented_paths_in_the_prose_are_flagged(self):
        class Reply:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {"message": {"content": "We found /.env and also /secret-console here."}}
        with patch("hexstrike_server.requests.post", return_value=Reply()):
            payload = self.client.post("/api/reports/narrative", json={"run_id": self.run_id}).get_json()
        self.assertEqual(payload["narrative_status"], "drafted")
        self.assertIn("/secret-console", payload["unverified_paths"])
        self.assertIn("should not", payload["message"])

    def test_a_faithful_narrative_flags_nothing(self):
        class Reply:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {"message": {"content": "The scan reported /.env and /admin on the host."}}
        with patch("hexstrike_server.requests.post", return_value=Reply()):
            payload = self.client.post("/api/reports/narrative", json={"run_id": self.run_id}).get_json()
        self.assertEqual(payload["unverified_paths"], [])

    def test_a_full_url_in_the_prose_is_not_mistaken_for_a_path(self):
        class Reply:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {"message": {"content": "The target http://127.0.0.1:5005 exposed /.env."}}
        with patch("hexstrike_server.requests.post", return_value=Reply()):
            payload = self.client.post("/api/reports/narrative", json={"run_id": self.run_id}).get_json()
        self.assertEqual(payload["unverified_paths"], [])


if __name__ == "__main__":
    unittest.main()
