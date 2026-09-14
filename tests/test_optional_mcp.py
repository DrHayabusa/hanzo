import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from mcp.types import CallToolResult, TextContent

from optional_mcp import OptionalMCPRegistry


FIXTURE_SERVER = '''from mcp.server.fastmcp import FastMCP
server = FastMCP("HANZO harmless protocol fixture")
@server.tool()
def echo(value: str) -> str:
    """Return a supplied string without network or filesystem access."""
    return value
if __name__ == "__main__":
    server.run(transport="stdio")
'''


class OptionalMCPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "mcp.json"
        self.registry = OptionalMCPRegistry(self.root, self.config)

    def tearDown(self):
        self.temp.cleanup()

    def configure(self, **values):
        spec = {"transport": "stdio", "command": sys.executable, **values}
        self.config.write_text(json.dumps({"version": 1, "servers": {"fixture": spec}}))
        return spec

    @staticmethod
    def fake_session(pages=None):
        session = AsyncMock()
        session.initialize.return_value = SimpleNamespace(protocolVersion="2025-03-26")
        session.list_tools.side_effect = pages or [SimpleNamespace(tools=[SimpleNamespace(name="echo", description="Echo", inputSchema={"type": "object"})], nextCursor=None)]
        session.__aenter__.return_value = session
        return session

    def test_unconfigured_is_not_online(self):
        self.assertEqual(self.registry.snapshot()["status"], "unconfigured")
        self.assertEqual(self.registry.snapshot()["servers"], [])

    def test_configured_does_not_launch_or_leak_settings(self):
        self.configure(env={"SECRET": "hidden-value"}, args=["sensitive-arg"])
        with patch("optional_mcp.stdio_client") as transport:
            data = self.registry.snapshot()
        transport.assert_not_called()
        rendered = json.dumps(data)
        self.assertNotIn("hidden-value", rendered)
        self.assertNotIn("sensitive-arg", rendered)
        self.assertNotIn("SECRET", rendered)
        self.assertNotIn(sys.executable, rendered)
        self.assertFalse(data["servers"][0]["ready"])
        self.assertTrue(data["servers"][0]["discovery_only"])

    def test_invalid_json_is_redacted_configuration_error(self):
        self.config.write_text("not-json hidden-value")
        data = self.registry.snapshot()
        self.assertEqual(data["status"], "configuration_error")
        self.assertNotIn("hidden-value", json.dumps(data))

    def test_configuration_size_is_bounded(self):
        self.config.write_text(" " * 256001)
        self.assertEqual(self.registry.snapshot()["status"], "configuration_error")

    def test_version_required(self):
        self.config.write_text(json.dumps({"servers": {}}))
        self.assertEqual(self.registry.snapshot()["status"], "configuration_error")

    def test_url_credentials_and_query_rejected(self):
        for url in ["http://user:pass@localhost/mcp", "http://localhost/mcp?token=secret", "file:///secret", "http://localhost:0/mcp"]:
            self.configure(transport="sse", url=url)
            self.assertEqual(self.registry.snapshot()["status"], "configuration_error")

    def test_wildcards_not_accepted(self):
        self.configure(allowed_tools=["*"])
        self.assertEqual(self.registry.snapshot()["status"], "configuration_error")

    def test_unknown_and_disabled_never_launch(self):
        self.configure(enabled=False)
        with patch("optional_mcp.stdio_client") as transport:
            with self.assertRaises(ValueError):
                self.registry.probe("other")
            with self.assertRaises(ValueError):
                self.registry.probe("fixture")
        transport.assert_not_called()

    def test_only_explicit_environment_is_forwarded(self):
        spec = self.configure(env_from=["HANZO_TEST_SECRET"], env={"CUSTOM": "setting"})
        with patch.dict(os.environ, {"HANZO_TEST_SECRET": "secret", "CLOUD_API_KEY": "not-forwarded"}):
            parameters = self.registry._stdio_parameters(spec)
        self.assertEqual(parameters.env["HANZO_TEST_SECRET"], "secret")
        self.assertEqual(parameters.env["CUSTOM"], "setting")
        self.assertNotIn("CLOUD_API_KEY", parameters.env)

    def test_missing_environment_is_not_silently_omitted(self):
        spec = self.configure(env_from=["UNSET_HANZO_TEST_VALUE"])
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                self.registry._stdio_parameters(spec)

    def test_sse_initialize_list_and_pagination(self):
        self.configure(transport="sse", url="http://127.0.0.1:9876/sse", headers_from={"Authorization": "HANZO_TEST_AUTH"}, allowed_tools=["echo"])
        pages = [SimpleNamespace(tools=[SimpleNamespace(name="echo", inputSchema={"type": "object"})], nextCursor="page2"), SimpleNamespace(tools=[SimpleNamespace(name="history", inputSchema={"type": "object"})], nextCursor=None)]
        session = self.fake_session(pages)
        seen = {}
        @asynccontextmanager
        async def transport(url, **kwargs):
            seen.update(url=url, **kwargs)
            yield ("read", "write")
        with patch.dict(os.environ, {"HANZO_TEST_AUTH": "Bearer test-secret"}), patch("optional_mcp.sse_client", transport), patch("optional_mcp.ClientSession", return_value=session):
            result = self.registry.probe("fixture")
        self.assertEqual(result["status"], "online")
        self.assertEqual(result["tools"], ["echo", "history"])
        self.assertTrue(result["tool_details"][0]["allowlisted"])
        self.assertFalse(result["tool_details"][1]["allowlisted"])
        self.assertEqual(seen["headers"], {"Authorization": "Bearer test-secret"})
        self.assertNotIn("test-secret", json.dumps(result))
        session.initialize.assert_awaited_once()
        session.call_tool.assert_not_awaited()
        self.assertEqual(self.registry.snapshot()["servers"][0]["status"], "online")

    def test_streamable_http_ignores_session_id_callback(self):
        self.configure(transport="streamable_http", url="http://127.0.0.1:9090/mcp")
        session = self.fake_session()
        @asynccontextmanager
        async def transport(*args, **kwargs):
            yield ("read", "write", lambda: "session-id")
        with patch("optional_mcp.streamablehttp_client", transport), patch("optional_mcp.ClientSession", return_value=session) as constructor:
            result = self.registry.probe("fixture")
        constructor.assert_called_once_with("read", "write")
        self.assertTrue(result["ready"])

    def test_repeated_cursor_does_not_claim_online(self):
        self.configure()
        page = SimpleNamespace(tools=[], nextCursor="repeated")
        session = self.fake_session([page, page])
        @asynccontextmanager
        async def transport(*args, **kwargs):
            yield ("read", "write")
        with patch("optional_mcp.stdio_client", transport), patch("optional_mcp.ClientSession", return_value=session):
            result = self.registry.probe("fixture")
        self.assertFalse(result["ready"])
        self.assertEqual(session.list_tools.await_count, 2)

    def test_oversized_schema_is_omitted(self):
        self.configure()
        session = self.fake_session([SimpleNamespace(tools=[SimpleNamespace(name="echo", inputSchema={"description": "x" * 20000})], nextCursor=None)])
        @asynccontextmanager
        async def transport(*args, **kwargs):
            yield ("read", "write")
        with patch("optional_mcp.stdio_client", transport), patch("optional_mcp.ClientSession", return_value=session):
            result = self.registry.probe("fixture")
        self.assertTrue(result["ready"])
        self.assertIsNone(result["tool_details"][0]["inputSchema"])
        self.assertTrue(result["tool_details"][0]["schema_omitted"])

    def test_config_change_invalidates_cached_readiness(self):
        self.configure()
        with patch.object(self.registry, "_discover", new=AsyncMock(return_value={"status": "online", "ready": True})):
            self.registry.probe("fixture")
        self.configure(args=["different.py"])
        self.assertEqual(self.registry.snapshot()["servers"][0]["status"], "configured")

    def test_connection_errors_do_not_leak_exception_text(self):
        self.configure()
        with patch.object(self.registry, "_discover", new=AsyncMock(side_effect=RuntimeError("secret-from-remote"))):
            result = self.registry.probe("fixture")
        self.assertFalse(result["ready"])
        self.assertNotIn("secret-from-remote", json.dumps(result))

    def test_timeout_is_bounded_and_reported(self):
        self.configure()
        async def slow(*args):
            await asyncio.sleep(1)
        with patch.object(self.registry, "_discover", new=slow):
            result = self.registry.probe("fixture", timeout=.01)
        self.assertFalse(result["ready"])
        self.assertIn("timed out", result["message"])

    def test_calls_require_exact_allowlist_and_true_confirmation(self):
        self.configure(allowed_tools=["echo"])
        for tool, confirmed in [("echo", False), ("echo", "true"), ("other", True)]:
            with self.assertRaises(ValueError):
                self.registry.call("fixture", tool, {}, authorization_confirmed=confirmed)

    def test_call_arguments_and_timeout_are_bounded(self):
        self.configure(allowed_tools=["echo"])
        for arguments in [[], {"value": "a" * 16384}, {"value": float("nan")}]:
            with self.assertRaises(ValueError):
                self.registry.call("fixture", "echo", arguments, True)
        for timeout in [0, 31, True, float("nan")]:
            with self.assertRaises(ValueError):
                self.registry.call("fixture", "echo", {}, True, timeout)

    def test_call_errors_do_not_leak_remote_error(self):
        self.configure(allowed_tools=["echo"])
        with patch.object(self.registry, "_call", new=AsyncMock(side_effect=RuntimeError("secret-value"))):
            result = self.registry.call("fixture", "echo", {}, True)
        self.assertFalse(result["success"])
        self.assertNotIn("secret-value", json.dumps(result))

    def test_redacts_known_secrets_from_nested_result(self):
        spec = self.configure(env={"SECRET": "secret-value"})
        self.assertEqual(self.registry._redact({"text": ["prefix secret-value suffix"]}, spec), {"text": ["prefix [REDACTED] suffix"]})

    def test_result_truncation_redacts_before_json_escaping(self):
        self.configure(allowed_tools=["echo"], env={"SECRET": "hidden\nvalue"})
        session = self.fake_session()
        session.call_tool.return_value = CallToolResult(content=[TextContent(type="text", text="hidden\nvalue " + "z" * 300000)])
        @asynccontextmanager
        async def transport(*args, **kwargs):
            yield ("read", "write")
        with patch("optional_mcp.stdio_client", transport), patch("optional_mcp.ClientSession", return_value=session):
            result = self.registry.call("fixture", "echo", {}, True)
        self.assertTrue(result["success"])
        self.assertTrue(result["truncated"])
        self.assertIn("[REDACTED]", result["result"]["preview"])
        self.assertNotIn("hidden", result["result"]["preview"])
        self.assertLessEqual(len(result["result"]["preview"].encode()), 262144)

    def test_allowlisted_but_unadvertised_tool_is_not_called(self):
        self.configure(allowed_tools=["missing"])
        session = self.fake_session()
        @asynccontextmanager
        async def transport(*args, **kwargs):
            yield ("read", "write")
        with patch("optional_mcp.stdio_client", transport), patch("optional_mcp.ClientSession", return_value=session):
            result = self.registry.call("fixture", "missing", {}, True)
        self.assertFalse(result["success"])
        session.call_tool.assert_not_awaited()

    def test_real_stdio_initialize_list_and_harmless_call(self):
        fixture = self.root / "server.py"
        fixture.write_text(FIXTURE_SERVER)
        self.configure(args=[str(fixture)], allowed_tools=["echo"])
        discovered = self.registry.probe("fixture")
        self.assertTrue(discovered["ready"], discovered)
        self.assertEqual(discovered["tools"], ["echo"])
        self.assertEqual(discovered["tool_details"][0]["inputSchema"]["type"], "object")
        result = self.registry.call("fixture", "echo", {"value": "HANZO protocol test passed"}, True)
        self.assertTrue(result["success"], result)
        self.assertIn("HANZO protocol test passed", json.dumps(result["result"]))
        self.assertFalse(result["truncated"])


if __name__ == "__main__":
    unittest.main()
