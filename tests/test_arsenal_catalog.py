import unittest
from pathlib import Path
from unittest.mock import patch
from arsenal_catalog import build_catalog
from scan_scope import validate_scan_target
from hexstrike_server import app


class ArsenalTests(unittest.TestCase):
    def setUp(self):
        self.catalog = build_catalog(Path(__file__).resolve().parents[1])
        self.commands = {item["endpoint"]:item for cat in self.catalog["categories"] for item in cat["commands"]}

    def test_every_existing_tool_post_route_is_in_catalog(self):
        routes = {rule.rule for rule in app.url_map.iter_rules() if rule.rule.startswith("/api/tools/") and "POST" in rule.methods}
        self.assertEqual(set(self.commands), routes)
        self.assertEqual(len(routes), 90)

    def test_no_generic_shell_route(self):
        self.assertNotIn("/api/command", self.commands)
        self.assertEqual(self.catalog["category_count"], 10)

    def test_nmap_fields_and_types(self):
        fields = {f["name"]:f for f in self.commands["/api/tools/nmap"]["fields"]}
        self.assertTrue(fields["target"]["required"])
        self.assertEqual(fields["scan_type"]["default"], "-sCV")
        self.assertEqual(fields["use_recovery"]["type"], "bool")
        self.assertIn("additional_args", fields)

    def test_api_structured_fields(self):
        fields = {f["name"]:f for f in self.commands["/api/tools/api_fuzzer"]["fields"]}
        self.assertEqual(fields["endpoints"]["type"], "array")

    def test_presence_never_invented(self):
        with patch("arsenal_catalog.shutil.which", return_value=None):
            catalog = build_catalog(Path(__file__).resolve().parents[1])
        for cat in catalog["categories"]:
            for tool in cat["commands"]:
                self.assertIsNot(tool["installed"], True)

    def test_get_is_read_only_and_serves_launcher(self):
        with patch("hexstrike_server.execute_command") as execute:
            client = app.test_client()
            self.assertEqual(client.get("/api/arsenal/catalog").get_json()["command_count"], 90)
            response = client.get("/static/arsenal.js")
            self.assertEqual(response.status_code, 200)
            response.close()
        execute.assert_not_called()

    def test_scan_target_rejects_shell_and_option_injection(self):
        for value in ("127.0.0.1;id", "$(id)", "`id`", "-iL", "a b", "http://a/?x=1&x=2", "http://a/'", "file:///tmp/a", "http://a:bad", None):
            with self.subTest(value=value), self.assertRaises(ValueError): validate_scan_target(value)
        for value in ("127.0.0.1", "lab.local", "http://10.20.39.11:8080", "https://lab.local/path", "http://[::1]:8080"):
            self.assertEqual(validate_scan_target(value), value)

    def test_bad_max_tools_cannot_start_scan(self):
        with patch("hexstrike_server.decision_engine.analyze_target") as analyze:
            for count in (0, -1, 9, "3", True):
                result = app.test_client().post("/api/intelligence/smart-scan", json={"target":"127.0.0.1", "max_tools":count, "authorization_confirmed":True})
                self.assertEqual(result.status_code, 400)
        analyze.assert_not_called()

    def test_missing_scanners_explained_without_execution(self):
        with patch("hexstrike_server.decision_engine.analyze_target"), patch("hexstrike_server.decision_engine.select_optimal_tools", return_value=["nmap"]), patch("hexstrike_server.shutil.which", return_value=None), patch("hexstrike_server.execute_command") as execute:
            result = app.test_client().post("/api/intelligence/smart-scan", json={"target":"127.0.0.1", "authorization_confirmed":True})
            self.assertEqual(result.status_code, 409)
            self.assertFalse(result.get_json()["success"])
        execute.assert_not_called()
