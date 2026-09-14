"""Release regression tests. No live IIS, Splunk, target, or cloud calls."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import requests
from hexstrike_server import app, LLM_PROVIDERS
from hanzo_store import HanzoStore, redact_evidence
from lab_exercises import LabExerciseRunner, SplunkTelemetry, validate_target, origin, markdown_report


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_cross_origin_control_requests_rejected(self):
        response = self.client.post("/api/command", json={"command": "never execute"},
                                    headers={"Origin": "https://untrusted.invalid"})
        self.assertEqual(response.status_code, 403)

    def test_cross_site_request_rejected(self):
        self.assertEqual(self.client.get("/health", headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)

    def test_bad_json_shape_rejected(self):
        for body in ([], ["bad"], "text", 3):
            self.assertEqual(self.client.post("/api/llm/chat", json=body).status_code, 400)

    def test_invalid_history_rejected(self):
        self.assertEqual(self.client.post("/api/llm/chat", json={"message": "hi", "history": "invalid"}).status_code, 400)

    @patch("hexstrike_server.requests.post")
    def test_fixed_provider_cannot_redirect_key(self, post):
        post.return_value = Mock()
        post.return_value.json.return_value = {"choices": [{"message": {"content": "ready"}}]}
        response = self.client.post("/api/llm/chat", json={"message": "hi", "provider": "groq", "api_key": "test-only",
                                                        "base_url": "https://untrusted.invalid"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(post.call_args.args[0], "https://api.groq.com/openai/v1/chat/completions")
        self.assertFalse(post.call_args.kwargs["allow_redirects"])

    @patch.dict(os.environ, {"LLM_API_KEY": "server-test-only"})
    @patch("hexstrike_server.requests.post")
    def test_generic_server_key_stays_on_configured_endpoint(self, post):
        response = self.client.post("/api/llm/chat", json={"message":"hi", "provider":"compatible", "model":"test",
                                                        "base_url":"https://untrusted.invalid/v1"})
        self.assertEqual(response.status_code, 400)
        post.assert_not_called()

    @patch("hexstrike_server.requests.post", side_effect=requests.RequestException("secret-do-not-echo"))
    def test_provider_errors_hide_upstream_details(self, post):
        response = self.client.post("/api/llm/chat", json={"message":"hello"})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"secret-do-not-echo", response.data)

    def test_exercise_catalog_never_probes_lab(self):
        with patch("lab_exercises.requests.Session") as client:
            result = self.client.get("/api/lab/exercises")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(result.get_json()["exercises"]), 8)
        client.assert_not_called()

    def test_exercises_require_authorization(self):
        self.assertEqual(self.client.post("/api/lab/exercises/run", json={"exercise_id":"full_suite"}).status_code, 403)

    def test_telemetry_not_configured_is_honest(self):
        with patch.dict(os.environ, {}, clear=True):
            result = self.client.get("/api/lab/telemetry/status").get_json()
        self.assertFalse(result["configured"])
        self.assertFalse(result["detection_verified"])

    def test_unknown_report_and_limit(self):
        self.assertEqual(self.client.get("/api/lab/exercises/missing/report").status_code, 404)
        self.assertEqual(self.client.get("/api/lab/exercises/history?limit=no").status_code, 400)

    def test_evidence_redaction(self):
        evidence = redact_evidence({"api_key":"secret", "nested":{"password":"s", "text":"Bearer abc.def"}})
        self.assertEqual(evidence["api_key"], "[redacted]")
        self.assertEqual(evidence["nested"]["text"], "Bearer [redacted]")

    def test_origin_rejects_credentials_and_paths(self):
        for url in ("http://a:b@localhost", "http://localhost/path", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                origin(url)

    @patch.dict(os.environ, {"HANZO_LAB_TARGET":"http://10.20.39.11:8080"})
    def test_scope_mismatch_fails_before_dns(self):
        with patch("lab_exercises.socket.getaddrinfo") as lookup:
            with self.assertRaises(ValueError):
                validate_target("http://10.20.39.12:8080")
        lookup.assert_not_called()

    def test_exercise_synthetic_transport_and_persistence(self):
        with tempfile.TemporaryDirectory() as folder:
            store = HanzoStore(Path(folder))
            telemetry = Mock()
            telemetry.send.return_value = {"status":"not_configured", "accepted":False}
            runner = LabExerciseRunner(store, telemetry)
            responses = [
                {"status_code":200,"body":{"lab_mode":True},"headers":{"X-Lab-Only":"OWASP training target - never expose publicly"},"text":"","path":"/health","method":"GET","duration_ms":1},
                {"status_code":200,"body":{},"headers":{},"text":"demo","path":"/","method":"GET","duration_ms":1},
            ]
            with patch("lab_exercises.validate_target", return_value="http://127.0.0.1:5005"), patch.object(runner, "_request", side_effect=responses):
                result = runner.run("recon_headers", "http://127.0.0.1:5005", True)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["request_count"], 2)
            self.assertFalse(result["detection_verified"])
            self.assertEqual(store.exercise_run(result["id"])["id"], result["id"])
            self.assertIn("not been independently verified", markdown_report(result))


if __name__ == "__main__":
    unittest.main()
