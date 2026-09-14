import asyncio
import unittest
from pathlib import Path
from unittest.mock import patch

import arsenal_mcp
import redteam_mcp
from arsenal_catalog import build_catalog

PROJECT = Path(__file__).resolve().parents[1]


class NameAndSchemaTests(unittest.TestCase):
    def setUp(self):
        self.catalog = build_catalog(PROJECT)
        self.commands = arsenal_mcp.commands_from_catalog(self.catalog)

    def test_every_catalog_command_becomes_a_unique_tool_name(self):
        names = [arsenal_mcp.tool_name(c["id"]) for c in self.commands]
        self.assertEqual(len(names), 90)
        self.assertEqual(len(set(names)), 90)
        for name in names:
            self.assertTrue(name.isidentifier(), name)
            self.assertTrue(name.startswith("run_"), name)

    def test_dashed_ids_are_sanitized(self):
        self.assertEqual(arsenal_mcp.tool_name("arp-scan"), "run_arp_scan")
        self.assertEqual(arsenal_mcp.tool_name("docker-bench-security"), "run_docker_bench_security")

    def test_generated_signature_exposes_typed_arguments(self):
        nmap = next(c for c in self.commands if c["id"] == "nmap")
        tool = arsenal_mcp.make_tool(nmap, lambda command, payload: payload, lambda _id: True)
        params = tool.__signature__.parameters
        self.assertEqual(params["target"].annotation, str)
        self.assertEqual(params["use_recovery"].annotation, bool)
        self.assertEqual(params["scan_type"].default, "-sCV")
        self.assertIn("authorization_confirmed", params)
        self.assertIs(params["authorization_confirmed"].default, False)

    def test_reserved_names_are_never_taken_from_the_catalog(self):
        command = {"id": "x", "endpoint": "/api/tools/x",
                   "fields": [{"name": "authorization_confirmed", "type": "bool", "default": True},
                              {"name": "target", "type": "str", "default": ""},
                              {"name": "target", "type": "str", "default": ""}]}
        fields = [f["name"] for f in arsenal_mcp.usable_fields(command)]
        self.assertEqual(fields, ["target"])


class ExecutionContractTests(unittest.TestCase):
    def setUp(self):
        self.command = {"id": "nmap", "tool": "nmap", "endpoint": "/api/tools/nmap", "category": "network",
                        "description": "Execute nmap", "fields": [
                            {"name": "target", "type": "str", "default": "", "required": True},
                            {"name": "ports", "type": "str", "default": "", "required": False},
                            {"name": "use_recovery", "type": "bool", "default": True, "required": False}]}
        self.calls = []

    def tool(self, installed=True):
        def invoke(command, payload):
            self.calls.append((command["endpoint"], payload))
            return {"success": True}
        return arsenal_mcp.make_tool(self.command, invoke, lambda _id: installed)

    def test_missing_authorization_refuses_and_never_calls_the_worker(self):
        with self.assertRaises(RuntimeError) as error:
            self.tool()(target="127.0.0.1")
        self.assertIn("authorization", str(error.exception).lower())
        self.assertEqual(self.calls, [])

    def test_missing_executable_refuses_and_never_calls_the_worker(self):
        with self.assertRaises(RuntimeError) as error:
            self.tool(installed=False)(target="127.0.0.1", authorization_confirmed=True)
        self.assertIn("not installed", str(error.exception))
        self.assertEqual(self.calls, [])

    def test_runtime_dependent_adapter_is_not_blocked(self):
        self.tool(installed=None)(target="127.0.0.1", authorization_confirmed=True)
        self.assertEqual(len(self.calls), 1)

    def test_authorized_call_sends_confirmation_and_typed_values(self):
        self.tool()(target="127.0.0.1", use_recovery=False, authorization_confirmed=True)
        endpoint, payload = self.calls[0]
        self.assertEqual(endpoint, "/api/tools/nmap")
        self.assertEqual(payload["target"], "127.0.0.1")
        self.assertIs(payload["use_recovery"], False)
        self.assertIs(payload["authorization_confirmed"], True)

    def test_blank_optional_text_is_omitted_like_the_browser_launcher(self):
        self.tool()(target="127.0.0.1", ports="   ", authorization_confirmed=True)
        self.assertNotIn("ports", self.calls[0][1])

    def test_blank_required_field_is_rejected(self):
        with self.assertRaises(ValueError):
            self.tool()(target="  ", authorization_confirmed=True)
        self.assertEqual(self.calls, [])


class RegistrationTests(unittest.TestCase):
    def test_register_adds_one_tool_per_command(self):
        class Recorder:
            def __init__(self):
                self.added = []

            def add_tool(self, fn):
                self.added.append(fn.__name__)

        recorder = Recorder()
        catalog = build_catalog(PROJECT)
        names = arsenal_mcp.register(recorder, catalog, lambda c, p: {}, lambda _id: True)
        self.assertEqual(len(names), 90)
        self.assertEqual(recorder.added, names)
        self.assertIn("run_nuclei", names)
        self.assertIn("run_gobuster", names)


class ArsenalCatalogSourceTests(unittest.TestCase):
    def test_worker_api_catalog_is_preferred(self):
        arsenal = redteam_mcp.Arsenal(lambda method, path, payload=None: {"categories": [
            {"id": "network", "commands": [{"id": "nmap", "endpoint": "/api/tools/nmap", "installed": True}]}]})
        arsenal.load()
        self.assertEqual(arsenal.source, "worker_api")
        self.assertIs(arsenal.readiness("nmap"), True)

    def test_offline_worker_falls_back_to_local_source_without_raising(self):
        def unavailable(method, path, payload=None):
            raise RuntimeError("connection refused")

        arsenal = redteam_mcp.Arsenal(unavailable, PROJECT)
        arsenal.load()
        self.assertEqual(arsenal.source, "local_source")
        self.assertEqual(arsenal.status()["command_count"], 90)
        self.assertIn("Worker API unavailable", arsenal.error)

    def test_readiness_is_never_invented_for_unknown_commands(self):
        arsenal = redteam_mcp.Arsenal(lambda *a, **k: {"categories": []})
        arsenal.load()
        self.assertIsNone(arsenal.readiness("does-not-exist"))

    def test_status_counts_match_the_catalog(self):
        arsenal = redteam_mcp.Arsenal(lambda *a, **k: {"categories": [{"id": "n", "commands": [
            {"id": "a", "endpoint": "/api/tools/a", "installed": True},
            {"id": "b", "endpoint": "/api/tools/b", "installed": False},
            {"id": "c", "endpoint": "/api/tools/c", "installed": None}]}]})
        arsenal.load()
        status = arsenal.status()
        self.assertEqual((status["executable_present"], status["not_installed"],
                          status["runtime_check_required"]), (1, 1, 1))


class ServerWiringTests(unittest.TestCase):
    def build(self):
        catalog = build_catalog(PROJECT)
        with patch.object(redteam_mcp.Arsenal, "load", autospec=True) as load:
            def fake(self):
                self.catalog, self.source, self.error = catalog, "worker_api", None
                return catalog

            load.side_effect = fake
            return redteam_mcp.build_server("http://127.0.0.1:8888")

    def test_server_exposes_control_plane_and_every_tool_adapter(self):
        tools = asyncio.run(self.build().list_tools())
        names = {tool.name for tool in tools}
        self.assertEqual(len(names), len(tools))
        for control in ("list_integrations", "triage_cve", "run_authorized_smart_scan",
                        "arsenal_status", "list_security_tools", "refresh_arsenal_catalog",
                        "run_security_tool"):
            self.assertIn(control, names)
        generated = {n for n in names if n.startswith("run_")} - {"run_authorized_smart_scan", "run_security_tool"}
        self.assertEqual(len(generated), 90)

    def test_generated_tools_publish_real_json_schemas(self):
        tools = {tool.name: tool for tool in asyncio.run(self.build().list_tools())}
        schema = tools["run_nmap"].inputSchema["properties"]
        self.assertEqual(schema["target"]["type"], "string")
        self.assertEqual(schema["use_recovery"]["type"], "boolean")
        self.assertEqual(schema["authorization_confirmed"]["type"], "boolean")
        self.assertIn("Readiness:", tools["run_nmap"].description)


if __name__ == "__main__":
    unittest.main()
