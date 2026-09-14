import socket
import threading
import unittest
from contextlib import closing

import assessment_preflight as preflight
from hexstrike_server import app

CATALOG = {"categories": [{"id": "network", "commands": [
    {"id": "nmap", "installed": True}, {"id": "rustscan", "installed": False},
    {"id": "masscan", "installed": False}, {"id": "subfinder", "installed": True},
    {"id": "amass", "installed": False}, {"id": "httpx", "installed": True},
    {"id": "katana", "installed": False}, {"id": "gobuster", "installed": True},
    {"id": "ffuf", "installed": False}, {"id": "feroxbuster", "installed": False},
    {"id": "nuclei", "installed": True}, {"id": "nikto", "installed": False},
    {"id": "sqlmap", "installed": False}, {"id": "wpscan", "installed": False},
    {"id": "dalfox", "installed": False}]}]}


class ClassifyTests(unittest.TestCase):
    def test_target_kinds(self):
        self.assertEqual(preflight.classify("CVE-2021-44228"), "cve")
        self.assertEqual(preflight.classify("cve-2021-4428"), "cve")
        self.assertEqual(preflight.classify("http://10.20.39.11:8080"), "url")
        self.assertEqual(preflight.classify("https://lab.local/app"), "url")
        self.assertEqual(preflight.classify("10.20.39.11"), "ip")
        self.assertEqual(preflight.classify("lab.local"), "hostname")


class ReachabilityTests(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.addCleanup(self.server.close)

    def accept_once(self):
        thread = threading.Thread(target=lambda: closing(self.server.accept()[0]).__enter__(), daemon=True)
        thread.start()
        return thread

    def test_open_port_is_reachable(self):
        self.accept_once()
        result = preflight.check_reachable(f"127.0.0.1:{self.port}", "hostname", timeout=2)
        self.assertTrue(result["reachable"])
        self.assertEqual(result["port"], self.port)

    def test_closed_port_reports_unreachable_with_actionable_detail(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        result = preflight.check_reachable(f"127.0.0.1:{closed_port}", "hostname", timeout=2)
        self.assertFalse(result["reachable"])
        self.assertIn("No TCP connection", result["detail"])

    def test_cve_target_is_never_contacted(self):
        result = preflight.check_reachable("CVE-2021-44228", "cve")
        self.assertFalse(result["checked"])
        self.assertIsNone(result["reachable"])


class StageReadinessTests(unittest.TestCase):
    def test_recon_reports_installed_and_missing_adapters(self):
        readiness = preflight.stage_readiness("recon", CATALOG)
        self.assertTrue(readiness["applicable"])
        self.assertIn("nmap", readiness["ready"])
        self.assertIn("rustscan", readiness["missing"])

    def test_non_executing_stage_is_not_applicable(self):
        for stage in ("profile", "bughunter", "cve_triage"):
            self.assertFalse(preflight.stage_readiness(stage, CATALOG)["applicable"])

    def test_stage_with_nothing_installed_says_so(self):
        empty = {"categories": [{"id": "network", "commands": [
            {"id": name, "installed": False} for name in preflight.STAGE_TOOLS["validate"]]}]}
        readiness = preflight.stage_readiness("validate", empty)
        self.assertEqual(readiness["ready"], [])
        self.assertIn("No adapter", readiness["detail"])


class PreflightTests(unittest.TestCase):
    def test_invalid_target_is_rejected_without_contacting_anything(self):
        result = preflight.preflight("http://host/a b", "recon", CATALOG)
        self.assertFalse(result["valid"])
        self.assertFalse(result["reachability"]["checked"])
        self.assertFalse(result["ready_to_run"])

    def test_unreachable_target_blocks_and_explains(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        result = preflight.preflight(f"127.0.0.1:{closed}", "recon", CATALOG, timeout=2)
        self.assertTrue(result["valid"])
        self.assertFalse(result["ready_to_run"])
        self.assertIn("not reachable", result["message"])

    def test_cve_stage_passes_without_touching_an_asset(self):
        result = preflight.preflight("CVE-2021-44228", "cve_triage", CATALOG)
        self.assertTrue(result["ready_to_run"])
        self.assertFalse(result["reachability"]["checked"])

    def test_preflight_never_claims_a_scanner_will_succeed(self):
        result = preflight.preflight("CVE-2021-44228", "cve_triage", CATALOG)
        self.assertNotIn("guarantee that a scanner will succeed", result["message"].replace("not a guarantee", ""))
        self.assertIn("not a guarantee", result["message"])


class PreflightRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_missing_target_is_a_client_error(self):
        self.assertEqual(self.client.post("/api/assessment/preflight", json={}).status_code, 400)

    def test_route_returns_classification_and_readiness(self):
        response = self.client.post("/api/assessment/preflight",
                                    json={"target": "CVE-2021-44228", "stage": "cve_triage"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["kind"], "cve")
        self.assertIn("readiness", payload)


class NoHttpResponseTests(unittest.TestCase):
    """A port that accepts TCP but never speaks HTTP is what scanners hang on."""

    def setUp(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.addCleanup(self.server.close)

    def test_silent_port_blocks_an_http_target(self):
        result = preflight.preflight(f"http://127.0.0.1:{self.port}", "recon", CATALOG, timeout=2)
        self.assertTrue(result["reachability"]["reachable"])
        self.assertIsNone(result["reachability"]["http_status"])
        self.assertFalse(result["ready_to_run"])
        self.assertIn("no HTTP response", result["message"])

if __name__ == "__main__":
    unittest.main()
