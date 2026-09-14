import json
import unittest
from unittest.mock import Mock, patch

from hexstrike_server import app


class VaptAgentGuiTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_gui_is_served(self):
        response = self.client.get("/")
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"HANZO", response.data)
            self.assertIn(b"Test a target", response.data)
            self.assertIn(b"Detection lab map", response.data)
        finally:
            response.close()

    def test_static_assets_are_served(self):
        css = self.client.get("/static/styles.css")
        js = self.client.get("/static/app.js")
        logo = self.client.get("/static/hanzo-emblem.svg")
        try:
            self.assertEqual(css.status_code, 200)
            self.assertEqual(js.status_code, 200)
            self.assertEqual(logo.status_code, 200)
            self.assertIn("image/svg+xml", logo.content_type)
            self.assertIn(b"--red", css.data)
            self.assertIn(b"runAutomatedWorkflow", js.data)
            self.assertIn(b"validateStack", js.data)
            self.assertIn(b"renderLab", js.data)
            self.assertIn(b"HANZO gold shinobi system", css.data)
        finally:
            css.close()
            js.close()
            logo.close()

    def test_health_exposes_hanzo_and_lab_identity(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["agent_name"], "Hanzo")
        self.assertEqual(body["lab_cidr"], "10.20.39.0/24")
        self.assertIn("tool_categories", body)
        exposed = {tool for tools in body["tool_categories"].values() for tool in tools}
        self.assertEqual(exposed, set(body["tools_status"]))

    def test_analysis_validates_target(self):
        response = self.client.post("/api/intelligence/analyze-target", json={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Target is required")

    def test_smart_scan_requires_explicit_authorization(self):
        response = self.client.post("/api/intelligence/smart-scan", json={"target": "lab.local"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("authorization", response.get_json()["error"].lower())

    def test_lab_topology_matches_configured_range_without_probing(self):
        response = self.client.get("/api/lab/topology?probe=false")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["cidr"], "10.20.39.0/24")
        self.assertEqual(len(body["nodes"]), 7)
        self.assertEqual(body["host"]["memory"], "32 GB")
        self.assertEqual(body["host"]["disk"], "1 TB")
        nodes = {node["id"]: node for node in body["nodes"]}
        self.assertEqual(nodes["windows"]["ip"], "10.20.39.11")
        self.assertEqual(nodes["splunk"]["ip"], "10.20.39.13")
        self.assertEqual(nodes["kali"]["status"], "current")

    def test_llm_chat_validates_message(self):
        response = self.client.post("/api/llm/chat", json={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Message is required")

    def test_llm_providers_do_not_expose_keys(self):
        response = self.client.get("/api/llm/providers")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIn("openrouter", [item["id"] for item in body["providers"]])
        self.assertNotIn("key_env", json.dumps(body))
        for provider in body["providers"]:
            self.assertNotIn("key", provider)
            self.assertNotIn("token", provider)

    @patch("hexstrike_server.requests.post")
    def test_openai_compatible_provider(self, mock_post):
        upstream = Mock()
        upstream.raise_for_status.return_value = None
        upstream.json.return_value = {"choices": [{"message": {"content": "cloud ready"}}]}
        mock_post.return_value = upstream
        response = self.client.post("/api/llm/chat", json={
            "message": "hello",
            "provider": "compatible",
            "model": "lab-model",
            "base_url": "https://llm.lab.invalid/v1",
            "api_key": "temporary-test-key",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["reply"], "cloud ready")
        self.assertEqual(mock_post.call_args.args[0], "https://llm.lab.invalid/v1/chat/completions")

    @patch("hexstrike_server.requests.get")
    def test_llm_status_reports_local_model(self, mock_get):
        upstream = Mock()
        upstream.raise_for_status.return_value = None
        upstream.json.return_value = {"models": [{"name": "qwen3:1.7b"}]}
        mock_get.return_value = upstream
        response = self.client.get("/api/llm/status")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["model_available"])


if __name__ == "__main__":
    unittest.main()
