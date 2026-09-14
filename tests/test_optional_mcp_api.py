import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from flask import Flask
from hanzo_store import HanzoStore
from optional_mcp_api import create_optional_mcp_blueprint


class OptionalApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = HanzoStore(Path(self.temp.name))
        self.registry = Mock()
        app = Flask(__name__)
        with patch("optional_mcp_api.OptionalMCPRegistry", return_value=self.registry):
            app.register_blueprint(create_optional_mcp_blueprint(Path(self.temp.name), self.store))
        self.client = app.test_client()

    def test_inventory_does_not_probe(self):
        self.registry.snapshot.return_value = {"configured":False,"servers":[]}
        self.assertEqual(self.client.get("/api/mcp/optional").status_code, 200)
        self.registry.probe.assert_not_called()

    def test_call_confirmation_required(self):
        self.assertEqual(self.client.post("/api/mcp/optional/test/call",json={"tool":"echo"}).status_code,403)
        self.registry.call.assert_not_called()

    def test_call_persists_returned_evidence(self):
        self.registry.call.return_value = {"success":True,"result":{"text":"hello"}}
        response = self.client.post("/api/mcp/optional/test/call",json={"tool":"echo","arguments":{"text":"hello"},"authorization_confirmed":True})
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.get_json()["evidence_id"])
        self.assertEqual(self.store.recent()[0]["phase"],"mcp")

    def test_allowlist_failure_is_forbidden(self):
        self.registry.call.side_effect = PermissionError("do not leak")
        response = self.client.post("/api/mcp/optional/test/call",json={"authorization_confirmed":True})
        self.assertEqual(response.status_code,403)
        self.assertNotIn(b"do not leak",response.data)

    def test_unexpected_errors_are_redacted(self):
        self.registry.probe.side_effect = RuntimeError("secret-token")
        response = self.client.post("/api/mcp/optional/test/probe",json={})
        self.assertEqual(response.status_code,503)
        self.assertNotIn(b"secret-token",response.data)
