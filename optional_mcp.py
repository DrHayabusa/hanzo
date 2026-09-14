"""Explicitly allowlisted MCP bridge for operator-configured lab services.

Discovery sends initialize and tools/list. Calls additionally require a local
operator allowlist and per-call confirmation. Configuring a stdio server
authorizes launching that program, so configuration must remain operator-owned.
Browser requests select existing IDs; they never supply connection settings.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import threading
from typing import Any
from urllib.parse import urlsplit

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client


_SERVER_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
_ENV_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_TRANSPORTS = {"stdio", "sse", "streamable_http"}
_MAX_CONFIG_BYTES = 256_000
_MAX_TOOLS = 1024
_MAX_PAGES = 64
_MAX_ARGUMENT_BYTES = 16_384
_MAX_RESULT_BYTES = 262_144
_MAX_SCHEMA_BYTES = 16_384


def _string(value: Any, field: str, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
        raise ValueError(f"Invalid MCP configuration field: {field}")
    return value


def _mapping(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 64:
        raise ValueError(f"Invalid MCP configuration field: {field}")
    for key, item in value.items():
        _string(key, field, 256)
        _string(item, field, 16384)
    return value


class OptionalMCPRegistry:
    """Read trusted disk config and maintain truthful in-process probe results."""

    def __init__(self, project_dir: Path, config_path: Path | None = None):
        self.project_dir = Path(project_dir).resolve()
        configured = config_path or os.environ.get("HANZO_MCP_CONFIG")
        self.config_path = Path(configured).expanduser() if configured else self.project_dir / ".hanzo-data" / "mcp-servers.json"
        if not self.config_path.is_absolute():
            self.config_path = self.project_dir / self.config_path
        self._results: dict[str, tuple[str, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.config_path.exists():
            return {}
        try:
            # Bounded reads also protect against a concurrently growing config.
            with self.config_path.open("rb") as handle:
                raw = handle.read(_MAX_CONFIG_BYTES + 1)
            if len(raw) > _MAX_CONFIG_BYTES:
                raise ValueError("MCP configuration exceeds 256 KB")
            document = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Cannot read valid MCP configuration JSON") from exc
        if not isinstance(document, dict) or document.get("version") != 1:
            raise ValueError("MCP configuration requires version 1")
        servers = document.get("servers")
        if not isinstance(servers, dict) or len(servers) > 32:
            raise ValueError("MCP configuration requires up to 32 named servers")
        for server_id, spec in servers.items():
            if not isinstance(server_id, str) or not _SERVER_ID.fullmatch(server_id):
                raise ValueError("Invalid MCP server ID")
            self._validate(spec)
        return servers

    def _validate(self, spec: Any) -> None:
        if not isinstance(spec, dict) or spec.get("transport") not in _TRANSPORTS:
            raise ValueError("MCP transport must be stdio, sse, or streamable_http")
        if "enabled" in spec and not isinstance(spec["enabled"], bool):
            raise ValueError("MCP enabled must be a boolean")
        if "name" in spec:
            _string(spec["name"], "name", 128)
        allowed = spec.get("allowed_tools", [])
        if not isinstance(allowed, list) or len(allowed) > 128:
            raise ValueError("MCP allowed_tools must be an array of exact tool names")
        for name in allowed:
            _string(name, "allowed_tools", 256)
            if "*" in name or "?" in name:
                raise ValueError("MCP allowed_tools does not accept wildcards")
        if spec["transport"] == "stdio":
            _string(spec.get("command"), "command")
            args = spec.get("args", [])
            if not isinstance(args, list) or len(args) > 128:
                raise ValueError("MCP args must be an array with at most 128 strings")
            for arg in args:
                _string(arg, "args", 16384)
            if "cwd" in spec:
                _string(spec["cwd"], "cwd")
            env = _mapping(spec.get("env", {}), "env")
            env_from = spec.get("env_from", [])
            if not isinstance(env_from, list) or len(env_from) > 64:
                raise ValueError("MCP env_from must be an array")
            for key in [*env.keys(), *env_from]:
                if not isinstance(key, str) or not _ENV_NAME.fullmatch(key):
                    raise ValueError("Invalid MCP environment name")
        else:
            url = _string(spec.get("url"), "url")
            try:
                parsed = urlsplit(url)
                port = parsed.port
            except ValueError as exc:
                raise ValueError("Invalid MCP endpoint URL") from exc
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("MCP URL must use HTTP(S), without credentials, query, or fragment")
            if port is not None and port < 1:
                raise ValueError("Invalid MCP endpoint port")
            headers = _mapping(spec.get("headers", {}), "headers")
            headers_from = _mapping(spec.get("headers_from", {}), "headers_from")
            for key, value in {**headers, **headers_from}.items():
                if "\r" in key + value or "\n" in key + value:
                    raise ValueError("Invalid MCP header")
            for value in headers_from.values():
                if not _ENV_NAME.fullmatch(value):
                    raise ValueError("Invalid MCP header environment name")

    @staticmethod
    def _fingerprint(spec: dict[str, Any]) -> str:
        # Kept exclusively in memory; never returned from a public method.
        import hashlib
        return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()

    def _metadata(self, server_id: str, spec: dict[str, Any]) -> dict[str, Any]:
        enabled = spec.get("enabled", True)
        result = {
            "id": server_id, "name": spec.get("name", server_id),
            "transport": spec["transport"], "status": "configured" if enabled else "disabled",
            "ready": False, "tool_count": 0, "tools": [], "last_checked": None,
            "tool_details": [], "allowed_tools": spec.get("allowed_tools", []),
            "discovery_only": not bool(spec.get("allowed_tools")),
            "message": "Configured; run a connection test" if enabled else "Disabled by operator configuration",
        }
        with self._lock:
            cached = self._results.get(server_id)
            if enabled and cached and cached[0] == self._fingerprint(spec):
                result.update(cached[1])
        return result

    def snapshot(self) -> dict[str, Any]:
        try:
            servers = self._load()
        except ValueError as exc:
            return {"configured": False, "servers": [], "status": "configuration_error", "message": str(exc)}
        return {
            "configured": bool(servers), "status": "configured" if servers else "unconfigured",
            "servers": [self._metadata(key, value) for key, value in servers.items()],
            "message": "Connection status is the last probe result, not a continuous heartbeat. Calls require an exact operator allowlist and explicit confirmation."
            if servers else "Optional services are not configured. See docs/OPTIONAL_MCP.md.",
        }

    def _stdio_parameters(self, spec: dict[str, Any]) -> StdioServerParameters:
        # Never inherit cloud API keys or the entire host environment implicitly.
        env = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ}
        for key in spec.get("env_from", []):
            if key not in os.environ:
                raise ValueError("A configured MCP environment variable is missing")
            env[key] = os.environ[key]
        env.update(spec.get("env", {}))
        cwd = Path(spec.get("cwd", str(self.project_dir))).expanduser()
        if not cwd.is_absolute():
            cwd = self.project_dir / cwd
        return StdioServerParameters(command=spec["command"], args=spec.get("args", []), cwd=str(cwd), env=env)

    @staticmethod
    def _headers(spec: dict[str, Any]) -> dict[str, str]:
        headers = dict(spec.get("headers", {}))
        for key, env_name in spec.get("headers_from", {}).items():
            value = os.environ.get(env_name)
            if not value:
                raise ValueError("A configured MCP header environment variable is missing")
            if "\r" in value or "\n" in value:
                raise ValueError("Invalid MCP header environment value")
            headers[key] = value
        return headers

    @asynccontextmanager
    async def _streams(self, spec: dict[str, Any], timeout: float):
        if spec["transport"] == "stdio":
            # A child server may print credentials on stderr; never forward it to
            # HANZO HTTP responses or logs. Operators can run it manually to debug.
            with open(os.devnull, "w") as errlog:
                async with stdio_client(self._stdio_parameters(spec), errlog=errlog) as streams:
                    yield streams
        elif spec["transport"] == "sse":
            async with sse_client(spec["url"], headers=self._headers(spec), timeout=timeout, sse_read_timeout=timeout) as streams:
                yield streams
        else:
            async with streamablehttp_client(spec["url"], headers=self._headers(spec), timeout=timeout, sse_read_timeout=timeout) as streams:
                yield streams[:2]

    async def _list_tools(self, session: ClientSession, spec: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]], bool]:
        names: list[str] = []
        details: list[dict[str, Any]] = []
        seen_cursors: set[str] = set()
        cursor = None
        truncated = False
        schema_budget = 1_048_576
        for _ in range(_MAX_PAGES):
            response = await session.list_tools(cursor=cursor)
            for tool in response.tools:
                if len(names) >= _MAX_TOOLS:
                    truncated = True
                    break
                name = str(tool.name)
                if not name or len(name) > 256:
                    truncated = True
                    continue
                names.append(name)
                schema = getattr(tool, "inputSchema", None)
                try:
                    encoded = json.dumps(schema, allow_nan=False)
                    schema_size = len(encoded.encode())
                    safe_schema = schema if isinstance(schema, dict) and schema_size <= _MAX_SCHEMA_BYTES and schema_size <= schema_budget else None
                except (TypeError, ValueError, RecursionError):
                    safe_schema = None
                if safe_schema is not None:
                    schema_budget -= schema_size
                details.append({
                    "name": name, "description": str(getattr(tool, "description", "") or "")[:512],
                    "inputSchema": safe_schema, "schema_omitted": safe_schema is None,
                    "allowlisted": name in spec.get("allowed_tools", []),
                })
            cursor = getattr(response, "nextCursor", None)
            if truncated or not cursor:
                break
            if cursor in seen_cursors:
                raise ValueError("MCP server returned a repeated pagination cursor")
            seen_cursors.add(cursor)
        else:
            truncated = bool(cursor)
        return names, details, truncated

    async def _discover(self, spec: dict[str, Any], timeout: float) -> dict[str, Any]:
        async with self._streams(spec, timeout) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                names, details, truncated = await self._list_tools(session, spec)
                return {
                    "status": "online", "ready": True, "tools": names, "tool_count": len(names),
                    "tool_details": details, "tools_truncated": truncated,
                    "protocol_version": str(initialized.protocolVersion)[:64],
                    "message": "Real MCP initialize and tools/list passed. Calls require an exact operator allowlist and explicit confirmation.",
                }

    @staticmethod
    def _redact(value: Any, spec: dict[str, Any]) -> Any:
        secrets = list(spec.get("env", {}).values()) + list(spec.get("headers", {}).values())
        secrets += [os.environ.get(key, "") for key in spec.get("env_from", [])]
        secrets += [os.environ.get(key, "") for key in spec.get("headers_from", {}).values()]
        secrets = sorted({secret for secret in secrets if secret}, key=len, reverse=True)
        def clean(item: Any) -> Any:
            if isinstance(item, str):
                for secret in secrets:
                    item = item.replace(secret, "[REDACTED]")
                return item
            if isinstance(item, list):
                return [clean(part) for part in item]
            if isinstance(item, dict):
                return {clean(key): clean(part) for key, part in item.items()}
            return item
        return clean(value)

    async def _call(self, spec: dict[str, Any], tool_name: str, arguments: dict[str, Any], timeout: float) -> dict[str, Any]:
        async with self._streams(spec, timeout) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names, _, _ = await self._list_tools(session, spec)
                if tool_name not in names:
                    raise ValueError("Configured tool was not discovered on this MCP server")
                result = await session.call_tool(tool_name, arguments)
                payload = self._redact(result.model_dump(mode="json", exclude_none=True), spec)
                encoded = json.dumps(payload, allow_nan=False)
                truncated = len(encoded.encode()) > _MAX_RESULT_BYTES
                if truncated:
                    payload = {"preview": encoded.encode()[:_MAX_RESULT_BYTES].decode("utf-8", errors="ignore"), "note": "Result exceeded 256 KB; preview only."}
                return {"success": not bool(getattr(result, "isError", False)), "result": payload, "truncated": truncated}

    def call(self, server_id: str, tool_name: str, arguments: dict[str, Any], authorization_confirmed: bool = False, timeout: float = 30) -> dict[str, Any]:
        if authorization_confirmed is not True:
            raise ValueError("Explicit authorization confirmation is required for each MCP call")
        if not isinstance(server_id, str) or not _SERVER_ID.fullmatch(server_id):
            raise ValueError("Invalid MCP server ID")
        servers = self._load()
        if server_id not in servers:
            raise ValueError("Unknown MCP server ID; configure it on the HANZO host first")
        spec = servers[server_id]
        if not spec.get("enabled", True):
            raise ValueError("MCP server is disabled by operator configuration")
        if not isinstance(tool_name, str) or tool_name not in spec.get("allowed_tools", []):
            raise ValueError("Tool is not in this server's operator-configured allowed_tools list")
        if not isinstance(arguments, dict) or any(not isinstance(key, str) for key in arguments):
            raise ValueError("MCP arguments must be a JSON object")
        try:
            encoded = json.dumps(arguments, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("MCP arguments must be finite JSON values") from exc
        if len(encoded.encode()) > _MAX_ARGUMENT_BYTES:
            raise ValueError("MCP arguments exceed 16 KB")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError("MCP call timeout must be between 0 and 30 seconds")
        try:
            outcome = asyncio.run(asyncio.wait_for(self._call(spec, tool_name, arguments, timeout), timeout=timeout))
        except TimeoutError:
            outcome = {"success": False, "result": None, "truncated": False, "message": "MCP call timed out. Remote execution may have started; do not retry a state-changing action without checking its server."}
        except Exception:
            outcome = {"success": False, "result": None, "truncated": False, "message": "MCP call failed. Verify the advertised tool, arguments, credentials, and server logs. Execution outcome may be unknown."}
        outcome.update(server_id=server_id, tool=tool_name)
        outcome.setdefault("message", "MCP tool returned an error" if not outcome["success"] else "Allowlisted MCP call completed; review the returned evidence.")
        return outcome

    def probe(self, server_id: str, timeout: float = 15) -> dict[str, Any]:
        if not isinstance(server_id, str) or not _SERVER_ID.fullmatch(server_id):
            raise ValueError("Invalid MCP server ID")
        servers = self._load()
        if server_id not in servers:
            raise ValueError("Unknown MCP server ID; configure it on the HANZO host first")
        spec = servers[server_id]
        if not spec.get("enabled", True):
            raise ValueError("MCP server is disabled by operator configuration")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError("MCP probe timeout must be between 0 and 30 seconds")
        try:
            outcome = asyncio.run(asyncio.wait_for(self._discover(spec, timeout), timeout=timeout))
            outcome = self._redact(outcome, spec)
        except TimeoutError:
            outcome = {"status": "error", "ready": False, "tool_count": 0, "tools": [], "message": "MCP connection timed out. Check the server process, transport, and endpoint."}
        except Exception:
            # Exception strings may contain access tokens, command arguments, or
            # upstream response bodies. Do not expose them to the web client.
            outcome = {"status": "error", "ready": False, "tool_count": 0, "tools": [], "message": "MCP handshake failed. Check the operator configuration, credentials, dependencies, and server logs."}
        outcome["last_checked"] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._results[server_id] = (self._fingerprint(spec), outcome)
        return self._metadata(server_id, spec)
