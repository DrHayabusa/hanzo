#!/usr/bin/env python3
"""MCP facade for the VAPT Agent centralized red-team control plane."""

import argparse
from typing import Any, Dict, List

import requests
from mcp.server.fastmcp import FastMCP


def build_server(api_url: str) -> FastMCP:
    api_url = api_url.rstrip("/")
    mcp = FastMCP("hanzo")

    def call(method: str, path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        response = requests.request(method, f"{api_url}{path}", json=payload, timeout=300)
        result = response.json()
        if not response.ok:
            raise RuntimeError(result.get("error") or result.get("blockers") or f"HTTP {response.status_code}")
        return result

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

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="VAPT Agent centralized red-team MCP gateway")
    parser.add_argument("--server", default="http://127.0.0.1:8888")
    args = parser.parse_args()
    build_server(args.server).run()


if __name__ == "__main__":
    main()
