"""Runtime bridges for on-demand third-party Hanzo integrations.

The bridges intentionally keep third-party projects in isolated virtual
environments.  Hanzo talks to CVE MCP over the real stdio protocol and invokes
Claude-BugHunter through its deterministic CLI without shell interpolation.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
ALLOWED_CVE_TOOLS = {
    "triage_cve",
    "lookup_cve",
    "search_cves",
    "get_epss_score",
    "check_kev",
    "parse_cvss",
    "get_cve_summary",
    "check_exploit_availability",
    "get_attack_mapping",
    "calculate_risk_score",
    "generate_vuln_report",
}


class IntegrationRuntime:
    def __init__(self, project_dir: Path):
        self.project_dir = Path(project_dir).resolve()
        self.root = Path(os.environ.get("HANZO_INTEGRATIONS_DIR", self.project_dir / ".integrations")).expanduser().resolve()
        self.cve_dir = Path(os.environ.get(
            "CVE_MCP_DIR", self.root / "cve-mcp-server"
        )).expanduser().resolve()
        self.bughunter_dir = Path(os.environ.get(
            "CLAUDE_BUGHUNTER_DIR", self.root / "claude-bughunter"
        )).expanduser().resolve()

    @staticmethod
    def _executable(path: Path) -> bool:
        return path.is_file() and os.access(path, os.X_OK)

    def cve_python(self) -> Path | None:
        override = os.environ.get("CVE_MCP_PYTHON", "").strip()
        candidates = [
            Path(override).expanduser() if override else None,
            self.cve_dir / ".venv" / "bin" / "python",
            self.cve_dir / ".venv" / "Scripts" / "python.exe",
        ]
        for candidate in candidates:
            if candidate and self._executable(candidate):
                return candidate.absolute()
        return None

    def bughunter_command(self) -> Path | None:
        override = os.environ.get("CLAUDE_BUGHUNTER_COMMAND", "").strip()
        candidates = [
            Path(override).expanduser() if override else None,
            self.bughunter_dir / ".venv" / "bin" / "cbh",
            self.bughunter_dir / ".venv" / "Scripts" / "cbh.exe",
        ]
        for candidate in candidates:
            if candidate and self._executable(candidate):
                return candidate.absolute()
        found = shutil.which("cbh")
        return Path(found).resolve() if found else None

    def cve_server_parameters(self) -> StdioServerParameters:
        python = self.cve_python()
        if not python:
            raise RuntimeError("CVE MCP is not installed. Run scripts/install_integrations.sh --core")
        return StdioServerParameters(
            command=str(python),
            args=["-m", "cve_mcp.server"],
            cwd=str(self.cve_dir),
            env={
                key: value for key, value in os.environ.items()
                if key in {
                    "PATH", "HOME", "NVD_API_KEY", "GITHUB_TOKEN",
                    "ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "GREYNOISE_API_KEY",
                    "SHODAN_KEY", "URLSCAN_KEY", "CIRCL_PDNS_USER",
                    "CIRCL_PDNS_PASS", "REQUEST_TIMEOUT", "MAX_RETRIES",
                }
            },
        )

    async def _cve_list_tools(self) -> list[str]:
        async with stdio_client(self.cve_server_parameters()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                response = await session.list_tools()
                return [tool.name for tool in response.tools]

    async def _cve_call(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        async with stdio_client(self.cve_server_parameters()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments)
                blocks = []
                for block in result.content:
                    text = getattr(block, "text", None)
                    if text is not None:
                        blocks.append(text)
                rendered = "\n".join(blocks)
                try:
                    parsed: Any = json.loads(rendered)
                except (TypeError, ValueError):
                    parsed = rendered
                return {
                    "success": not bool(getattr(result, "isError", False)),
                    "tool": tool,
                    "result": parsed,
                }

    def probe_cve(self, timeout: float = 30) -> Dict[str, Any]:
        python = self.cve_python()
        if not python:
            return {
                "status": "not_installed", "ready": False, "transport": "stdio",
                "message": "Run scripts/install_integrations.sh --core",
            }
        try:
            tools = asyncio.run(asyncio.wait_for(self._cve_list_tools(), timeout=timeout))
            return {
                "status": "online", "ready": True, "transport": "stdio / on demand",
                "tool_count": len(tools), "tools": tools,
                "command": str(python),
                "message": f"Real MCP handshake passed; {len(tools)} tools discovered",
            }
        except Exception as exc:
            return {
                "status": "error", "ready": False, "transport": "stdio",
                "command": str(python), "message": str(exc)[:500],
            }

    def call_cve(self, tool: str, arguments: Dict[str, Any], timeout: float = 120) -> Dict[str, Any]:
        if tool not in ALLOWED_CVE_TOOLS:
            raise ValueError(f"Unsupported CVE tool: {tool}")
        return asyncio.run(asyncio.wait_for(self._cve_call(tool, arguments), timeout=timeout))

    def triage_cve(self, cve_id: str, depth: str = "quick") -> Dict[str, Any]:
        normalized = cve_id.strip().upper()
        if not CVE_ID.fullmatch(normalized):
            raise ValueError("A valid CVE ID such as CVE-2021-44228 is required")
        if depth not in {"quick", "standard", "deep"}:
            raise ValueError("depth must be quick, standard, or deep")
        return self.call_cve("triage_cve", {"cve_id": normalized, "depth": depth})

    def bughunter_status(self, deep: bool = False) -> Dict[str, Any]:
        command = self.bughunter_command()
        skills = list((self.bughunter_dir / "skills").glob("*/SKILL.md"))
        commands = list((self.bughunter_dir / "commands").glob("*.md"))
        if not command:
            state = "source_ready" if self.bughunter_dir.is_dir() else "not_installed"
            return {
                "status": state, "ready": False, "transport": "CLI / skills",
                "skill_count": len(skills), "command_count": len(commands),
                "message": "Source cloned; install the cbh CLI" if skills else "Run scripts/install_integrations.sh --core",
            }
        result = {
            "status": "ready", "ready": True, "transport": "CLI / skills",
            "skill_count": len(skills), "command_count": len(commands),
            "command": str(command),
            "message": f"CLI ready with {len(skills)} skills and {len(commands)} commands",
        }
        if deep:
            try:
                completed = subprocess.run(
                    [str(command), "--help"], cwd=self.bughunter_dir,
                    text=True, capture_output=True, timeout=20, check=False,
                )
                result["self_test"] = completed.returncode == 0
                if completed.returncode != 0:
                    result.update(status="error", ready=False, message=completed.stderr[-500:])
            except (OSError, subprocess.SubprocessError) as exc:
                result.update(status="error", ready=False, self_test=False, message=str(exc)[:500])
        return result

    def classify_asset(self, asset: str) -> Dict[str, Any]:
        value = asset.strip()
        if not value or len(value) > 2048:
            raise ValueError("A URL or target asset is required")
        if not value.startswith(("http://", "https://")):
            value = f"http://{value}"
        command = self.bughunter_command()
        if not command:
            raise RuntimeError("Claude-BugHunter CLI is not installed")
        completed = subprocess.run(
            [str(command), "classify", value], cwd=self.bughunter_dir,
            text=True, capture_output=True, timeout=30, check=False,
        )
        if completed.returncode == 1 and "No high-confidence matches." in completed.stdout:
            return {"success": True, "matched": False, "asset": value,
                    "message": "Classification completed with no high-confidence playbook matches.",
                    "output": completed.stdout}
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout)[-1000:])
        return {"success": True, "matched": True, "asset": value, "output": completed.stdout}

    def snapshot(self, deep: bool = False) -> Dict[str, Dict[str, Any]]:
        cve = self.probe_cve() if deep else {
            "status": "ready" if self.cve_python() else "not_installed",
            "ready": bool(self.cve_python()), "transport": "stdio / on demand",
            "command": str(self.cve_python()) if self.cve_python() else None,
            "message": "Installed; run validation for a real MCP handshake" if self.cve_python()
            else "Run scripts/install_integrations.sh --core",
        }
        return {
            "cve_mcp": cve,
            "claude_bughunter": self.bughunter_status(deep=deep),
        }
