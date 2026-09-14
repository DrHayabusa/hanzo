import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from hexstrike_server import app, redteam_hub
from redteam_hub import RedTeamHub


class RedTeamHubUnitTests(unittest.TestCase):
    def setUp(self):
        self.hub = RedTeamHub(Path(__file__).parents[1])

    def test_registry_has_all_documented_integrations(self):
        body = self.hub.inspect(probe_services=False)
        ids = {item["id"] for item in body["integrations"]}
        self.assertTrue({
            "hexstrike", "cve_mcp", "burp_mcp", "claude_bughunter", "strix",
            "pentagi", "pentestgpt", "cai", "decepticon", "shannon",
        }.issubset(ids))
        self.assertNotIn("key_env", json.dumps(body))
        self.assertEqual(body["summary"]["total"], len(body["integrations"]))

    def test_plan_rejects_missing_authorization_gate(self):
        plan, status = self.hub.create_plan({"target": "lab.local"})
        self.assertEqual(status, 400)
        self.assertEqual(plan["status"], "blocked")
        self.assertFalse(plan["execution_started"])
        self.assertGreaterEqual(len(plan["blockers"]), 4)

    def test_plan_is_non_executing_when_gate_is_complete(self):
        plan, status = self.hub.create_plan({
            "target": "http://lab.local",
            "scope": ["http://lab.local"],
            "approval_name": "LAB-123 / Test Owner",
            "testing_window": "2026-09-14T09:00/2026-09-14T17:00",
            "authorization_confirmed": True,
        })
        self.assertEqual(status, 200)
        self.assertEqual(plan["status"], "ready_for_human_approval")
        self.assertFalse(plan["execution_started"])
        self.assertEqual(plan["approval_checkpoint"]["required_before"], "validate")

    def test_mcp_config_uses_absolute_paths_and_no_secrets(self):
        config = self.hub.mcp_config()
        gateway = config["mcpServers"]["vapt-redteam-hub"]
        self.assertTrue(Path(gateway["command"]).is_absolute())
        self.assertTrue(Path(gateway["args"][0]).is_absolute())
        self.assertEqual(gateway["alwaysAllow"], [])
        self.assertNotIn("api_key", json.dumps(config).lower())


class RedTeamHubApiTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_integrations_api(self):
        response = self.client.get("/api/redteam/integrations?probe=false")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["integrations"][0]["status"], "online")

    def test_plan_api_enforces_scope_gate(self):
        response = self.client.post("/api/redteam/plan", json={"target": "lab.local"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "blocked")

    def test_mcp_config_rejects_invalid_server_url(self):
        response = self.client.get("/api/redteam/mcp-config?server=not-a-url")
        self.assertEqual(response.status_code, 400)

    @patch("hexstrike_server.requests.get")
    def test_validation_reports_real_llm_state(self, mock_get):
        upstream = Mock()
        upstream.raise_for_status.return_value = None
        upstream.json.return_value = {"models": [{"name": "qwen3:1.7b"}]}
        mock_get.return_value = upstream
        runtime = {
            "cve_mcp": {"status": "online", "ready": True, "tool_count": 28},
            "claude_bughunter": {"status": "ready", "ready": True, "skill_count": 83},
        }
        with patch.object(redteam_hub.runtime, "snapshot", return_value=runtime):
            response = self.client.post("/api/redteam/validate", json={})
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["status"], "ready")
        self.assertTrue(body["checks"]["local_llm_model_available"])
        self.assertFalse(body["active_testing_performed"])

    def test_cve_triage_validates_identifier_before_runtime_call(self):
        response = self.client.post("/api/redteam/cve/triage", json={"cve_id": "not-a-cve"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("valid CVE ID", response.get_json()["error"])

    def test_bughunter_classification_uses_runtime_adapter(self):
        expected = {"success": True, "asset": "http://10.20.39.11", "output": "idor"}
        with patch.object(redteam_hub.runtime, "classify_asset", return_value=expected):
            response = self.client.post(
                "/api/redteam/bughunter/classify", json={"asset": "10.20.39.11"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), expected)

    def test_workflow_evidence_validates_phase(self):
        response = self.client.post("/api/redteam/workflows", json={
            "asset": "10.20.39.11", "phase": "destroy", "result": {},
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Unsupported workflow phase")


if __name__ == "__main__":
    unittest.main()
