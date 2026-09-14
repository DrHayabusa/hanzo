#!/usr/bin/env python3
"""MCP facade for the VAPT Agent centralized red-team control plane.

Exposes the control-plane operations plus one typed MCP tool for every bundled
HexStrike /api/tools adapter, generated from the same catalog the browser uses.
"""

import argparse
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from mcp.server.fastmcp import FastMCP

import arsenal_mcp

PROJECT_DIR = Path(__file__).resolve().parent


class Arsenal:
    """Catalog holder for the generated tool adapters.

    The worker API is authoritative because its readiness reflects the host that
    actually runs the commands. Local AST parsing is a fallback so the MCP server
    still starts (and still lists real routes) while the worker is down.
    """

    def __init__(self, call, project_dir: Path = PROJECT_DIR):
        self._call = call
        self._project_dir = project_dir
        self.catalog: Dict[str, Any] = {"categories": []}
        self.source = "unavailable"
        self.error: Optional[str] = None

    def load(self) -> Dict[str, Any]:
        try:
            self.catalog = self._call("GET", "/api/arsenal/catalog")
            self.source, self.error = "worker_api", None
        except Exception as api_error:  # noqa: BLE001 - fall back, never fail startup
            try:
                from arsenal_catalog import build_catalog

                self.catalog = build_catalog(self._project_dir)
                self.source = "local_source"
                self.error = f"Worker API unavailable ({api_error}); readiness reflects this host."
            except Exception as local_error:  # noqa: BLE001
                self.catalog = {"categories": []}
                self.source, self.error = "unavailable", f"{api_error}; local catalog failed: {local_error}"
        return self.catalog

    def commands(self) -> Dict[str, Dict[str, Any]]:
        return {str(c.get("id")): c for c in arsenal_mcp.commands_from_catalog(self.catalog)}

    def readiness(self, command_id: str) -> Optional[bool]:
        command = self.commands().get(str(command_id))
        return None if command is None else command.get("installed")

    def status(self) -> Dict[str, Any]:
        commands = self.commands().values()
        return {
            "catalog_source": self.source,
            "catalog_note": self.error,
            "command_count": len(commands),
            "category_count": len(self.catalog.get("categories") or []),
            "executable_present": sum(1 for c in commands if c.get("installed") is True),
            "not_installed": sum(1 for c in commands if c.get("installed") is False),
            "runtime_check_required": sum(1 for c in commands if c.get("installed") is None),
            "message": "Readiness is executable presence only; it is not proof of a working command.",
        }


def build_server(api_url: str) -> FastMCP:
    api_url = api_url.rstrip("/")
    mcp = FastMCP("hanzo")

    def call(method: str, path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        response = requests.request(method, f"{api_url}{path}", json=payload, timeout=300)
        result = response.json()
        if not response.ok:
            raise RuntimeError(result.get("error") or result.get("blockers") or f"HTTP {response.status_code}")
        return result

    arsenal = Arsenal(call)
    arsenal.load()

    def invoke(command: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
        endpoint = str(command.get("endpoint", ""))
        if not re.fullmatch(r"/api/tools/[A-Za-z0-9_/-]+", endpoint):
            raise RuntimeError(f"Refusing to call an unexpected route: {endpoint!r}")
        return call("POST", endpoint, payload)

    registered = arsenal_mcp.register(mcp, arsenal.catalog, invoke, arsenal.readiness)

    @mcp.tool()
    def list_integrations(probe_services: bool = True) -> Dict[str, Any]:
        """List every registered security/MCP integration and its verified status."""
        suffix = "true" if probe_services else "false"
        return call("GET", f"/api/redteam/integrations?probe={suffix}")

    @mcp.tool()
    def validate_control_plane() -> Dict[str, Any]:
        """Validate the central API, registered integrations and configured local LLM."""
        return call("POST", "/api/redteam/validate", {})

    @mcp.tool()
    def create_scoped_plan(
        target: str,
        scope: List[str],
        approval_name: str,
        testing_window: str,
        objective: str = "web_application",
        authorization_confirmed: bool = False,
    ) -> Dict[str, Any]:
        """Create a non-executing engagement plan. Authorization and scope are mandatory."""
        return call("POST", "/api/redteam/plan", {
            "target": target,
            "scope": scope,
            "approval_name": approval_name,
            "testing_window": testing_window,
            "objective": objective,
            "authorization_confirmed": authorization_confirmed,
        })

    @mcp.tool()
    def local_llm_status() -> Dict[str, Any]:
        """Check Ollama connectivity and whether the configured Qwen model is present."""
        return call("GET", "/api/llm/status")

    @mcp.tool()
    def analyze_target(target: str, analysis_type: str = "web_application") -> Dict[str, Any]:
        """Profile an authorized target and recommend tools without launching a smart scan."""
        return call("POST", "/api/intelligence/analyze-target", {
            "target": target,
            "analysis_type": analysis_type,
        })

    @mcp.tool()
    def run_authorized_smart_scan(
        target: str,
        objective: str = "web_application",
        max_tools: int = 3,
        authorization_confirmed: bool = False,
    ) -> Dict[str, Any]:
        """Run a bounded native scan only after explicit authorization confirmation."""
        if authorization_confirmed is not True:
            raise RuntimeError("Explicit authorization confirmation is required before active scanning")
        if max_tools < 1 or max_tools > 8:
            raise RuntimeError("max_tools must be between 1 and 8")
        return call("POST", "/api/intelligence/smart-scan", {
            "target": target,
            "objective": objective,
            "max_tools": max_tools,
            "authorization_confirmed": True,
        })

    @mcp.tool()
    def list_active_processes() -> Dict[str, Any]:
        """List scanner processes managed by the VAPT Agent control plane."""
        return call("GET", "/api/processes/list")

    @mcp.tool()
    def cve_intelligence_status() -> Dict[str, Any]:
        """Run a real stdio handshake and list the CVE intelligence MCP readiness."""
        return call("GET", "/api/redteam/cve/status?deep=true")

    @mcp.tool()
    def triage_cve(cve_id: str, depth: str = "quick") -> Dict[str, Any]:
        """Correlate CVE, EPSS, CISA KEV and related defensive intelligence."""
        return call("POST", "/api/redteam/cve/triage", {"cve_id": cve_id, "depth": depth})

    @mcp.tool()
    def classify_with_bughunter(asset: str) -> Dict[str, Any]:
        """Map an authorized URL or asset to installed Claude-BugHunter playbooks."""
        return call("POST", "/api/redteam/bughunter/classify", {"asset": asset})

    @mcp.tool()
    def workflow_history(limit: int = 20) -> Dict[str, Any]:
        """Read recent Hanzo workflow evidence from the local SQLite store."""
        safe_limit = min(max(limit, 1), 100)
        return call("GET", f"/api/redteam/workflows?limit={safe_limit}")

    @mcp.tool()
    def list_lab_exercises() -> Dict[str, Any]:
        """List fixed HELPAG exercises; this does not contact the lab target."""
        return call("GET", "/api/lab/exercises")

    @mcp.tool()
    def lab_exercise_history(limit: int = 20) -> Dict[str, Any]:
        """Read local exercise evidence without contacting Splunk or IIS."""
        return call("GET", f"/api/lab/exercises/history?limit={min(max(limit, 1), 100)}")

    @mcp.tool()
    def list_optional_mcp_servers() -> Dict[str, Any]:
        """Read operator-configured MCP status without contacting external servers."""
        return call("GET", "/api/mcp/optional")

    @mcp.tool()
    def probe_optional_mcp_server(server_id: str) -> Dict[str, Any]:
        """Initialize and list tools on a server already configured by the operator."""
        from urllib.parse import quote
        return call("POST", f"/api/mcp/optional/{quote(server_id, safe='')}/probe", {})

    @mcp.tool()
    def call_optional_mcp_tool(server_id: str, tool: str, arguments: Dict[str, Any],
                               authorization_confirmed: bool = False) -> Dict[str, Any]:
        """Call an exact server-side allowlisted MCP tool after operator confirmation."""
        from urllib.parse import quote
        return call("POST", f"/api/mcp/optional/{quote(server_id, safe='')}/call", {
            "tool": tool, "arguments": arguments, "authorization_confirmed": authorization_confirmed,
        })

    @mcp.tool()
    def arsenal_status() -> Dict[str, Any]:
        """Summarize how many bundled tool adapters are registered and actually installed."""
        return {**arsenal.status(), "registered_mcp_tools": len(registered)}

    @mcp.tool()
    def list_security_tools(category: str = "", installed_only: bool = False) -> Dict[str, Any]:
        """List bundled tool adapters, their MCP tool names, arguments and readiness."""
        categories = []
        for group in arsenal.catalog.get("categories") or []:
            if category and str(group.get("id")) != category:
                continue
            commands = []
            for command in group.get("commands") or []:
                if installed_only and command.get("installed") is not True:
                    continue
                commands.append({
                    "command_id": command.get("id"),
                    "mcp_tool": arsenal_mcp.tool_name(command.get("id")),
                    "endpoint": command.get("endpoint"),
                    "executable": command.get("tool"),
                    "installed": command.get("installed"),
                    "readiness": command.get("readiness"),
                    "arguments": [{"name": f["name"], "type": f.get("type"), "required": bool(f.get("required")),
                                   "default": f.get("default")} for f in arsenal_mcp.usable_fields(command)],
                })
            if commands:
                categories.append({"id": group.get("id"), "label": group.get("label"), "commands": commands})
        return {"catalog_source": arsenal.source, "categories": categories,
                "command_count": sum(len(c["commands"]) for c in categories),
                "message": "Each command is also registered as its own MCP tool named run_<command_id>."}

    @mcp.tool()
    def list_wordlists(group: str = "", contains: str = "", limit: int = 50) -> Dict[str, Any]:
        """List wordlists that exist on this worker, for any tool taking a wordlist path."""
        catalog = call("GET", "/api/arsenal/wordlists")
        needle, capped = contains.strip().lower(), min(max(int(limit), 1), 500)
        groups = []
        for entry in catalog.get("groups") or []:
            if group and str(entry.get("id")) != group:
                continue
            items = [w for w in entry.get("wordlists") or []
                     if not needle or needle in str(w.get("path", "")).lower()]
            if items:
                groups.append({"id": entry.get("id"), "label": entry.get("label"),
                               "total": len(items), "wordlists": items[:capped]})
        return {"groups": groups, "total_available": catalog.get("count", 0),
                "installed": catalog.get("installed", False),
                "install_hint": catalog.get("install_hint"),
                "message": catalog.get("message")}

    @mcp.tool()
    def check_wordlist(path: str) -> Dict[str, Any]:
        """Confirm a wordlist path exists and is readable before running a tool with it."""
        return call("POST", "/api/arsenal/wordlists/resolve", {"path": path})

    @mcp.tool()
    def delete_report(run_id: str, confirm: bool = False) -> Dict[str, Any]:
        """Permanently delete one stored report. Requires confirm=true."""
        if confirm is not True:
            raise RuntimeError("Deletion is permanent. Call again with confirm=true to delete this report.")
        from urllib.parse import quote
        return call("DELETE", f"/api/redteam/workflows/{quote(str(run_id), safe='')}")

    @mcp.tool()
    def refresh_arsenal_catalog() -> Dict[str, Any]:
        """Re-read the catalog so newly installed executables stop reporting as missing."""
        arsenal.load()
        return arsenal.status()

    @mcp.tool()
    def run_security_tool(command_id: str, arguments: Dict[str, Any],
                          authorization_confirmed: bool = False) -> Dict[str, Any]:
        """Run any bundled adapter by catalog id. Equivalent to its generated run_<id> tool."""
        command = arsenal.commands().get(str(command_id))
        if command is None:
            raise RuntimeError(f"Unknown command id {command_id!r}. Call list_security_tools for valid ids.")
        if authorization_confirmed is not True:
            raise RuntimeError(f"Explicit authorization is required before running {command_id}.")
        if command.get("installed") is False:
            raise RuntimeError(f"{command.get('tool') or command_id} is not installed on this worker. "
                               f"Install it, then call refresh_arsenal_catalog.")
        supplied = {k: v for k, v in (arguments or {}).items() if k != "authorization_confirmed"}
        return invoke(command, arsenal_mcp.build_arguments(command, supplied))

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="VAPT Agent centralized red-team MCP gateway")
    parser.add_argument("--server", default="http://127.0.0.1:8888")
    args = parser.parse_args()
    build_server(args.server).run()


if __name__ == "__main__":
    main()
