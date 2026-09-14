"""Central integration registry and safe engagement planner for VAPT Agent.

This module deliberately does not auto-install or auto-launch third-party offensive
frameworks.  It provides one auditable control plane that reports what is really
available, exports MCP wiring, and requires an explicit scope gate before planning
active validation.
"""

from __future__ import annotations

import os
import shutil
import socket
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from integration_runtime import IntegrationRuntime


@dataclass(frozen=True)
class Integration:
    id: str
    label: str
    role: str
    kind: str
    repo: str
    phases: tuple[str, ...]
    command_candidates: tuple[str, ...] = ()
    url_env: Optional[str] = None
    default_url: Optional[str] = None
    notes: str = ""
    checkout: Optional[str] = None


INTEGRATIONS: tuple[Integration, ...] = (
    Integration(
        "hexstrike", "HexStrike AI", "Native scanner and tool execution plane", "native",
        "https://github.com/0x4m4/hexstrike-ai", ("recon", "validate"),
        notes="Embedded in this project and exposed through the existing HexStrike MCP server.",
    ),
    Integration(
        "cve_mcp", "CVE MCP Server", "CVE, EPSS, KEV, OSV and threat-intelligence triage", "mcp_stdio",
        "https://github.com/mukul975/cve-mcp-server", ("triage",),
        ("cve-mcp",), notes="On-demand stdio MCP; no listening port is required.",
        checkout="cve-mcp-server",
    ),
    Integration(
        "burp_mcp", "Burp Suite MCP", "Human-guided HTTP interception and validation", "mcp_sse",
        "https://portswigger.net/bappstore/9954d105bc1b45b2b1cbcc044b2b7b9a", ("validate",),
        (), "BURP_MCP_URL", "http://127.0.0.1:9876",
        "Requires Burp Suite with the MCP Server extension; keep human approval enabled.",
    ),
    Integration(
        "claude_bughunter", "Claude-BugHunter", "Scope workflow, playbooks and report templates", "cli",
        "https://github.com/elementalsouls/Claude-BugHunter", ("recon", "validate", "report"),
        ("cbh",), notes="Skill bundle and deterministic CLI; it does not run as a daemon.",
        checkout="claude-bughunter",
    ),
    Integration(
        "strix", "Strix", "Sandboxed autonomous application validation", "cli",
        "https://github.com/usestrix/strix", ("validate", "report"), ("strix",),
        notes="Run only in an isolated lab and require a human approval checkpoint.", checkout="strix",
    ),
    Integration(
        "pentagi", "PentAGI", "Containerized multi-agent validation and knowledge graph", "http",
        "https://github.com/vxcontrol/pentagi", ("recon", "validate", "report"),
        (), "PENTAGI_URL", "https://127.0.0.1:8443",
        "The service is normally deployed separately with Docker/Podman.", checkout="pentagi",
    ),
    Integration(
        "pentestgpt", "PentestGPT", "Structured multi-stage pentest reasoning", "cli",
        "https://github.com/GreyDGL/PentestGPT", ("recon", "validate", "report"),
        ("pentestgpt-legacy",), checkout="pentestgpt",
    ),
    Integration(
        "cai", "CAI", "Extensible cybersecurity agent and MCP client", "cli",
        "https://github.com/aliasrobotics/CAI", ("recon", "triage", "validate", "report"), ("cai",),
        checkout="cai",
    ),
    Integration(
        "decepticon", "Decepticon MCP", "LangGraph red-team orchestration plane", "mcp_stdio",
        "https://github.com/PurpleAILAB/Decepticon", ("recon", "validate", "report"),
        ("decepticon-mcp", "decepticon-cli"), notes="Requires Python 3.13 and its management/sandbox services.",
        checkout="decepticon",
    ),
    Integration(
        "shannon", "Shannon", "White-box web/API validation with proof-oriented reports", "cli",
        "https://github.com/KeygraphHQ/shannon", ("validate", "report"),
        ("shannon",), notes="Requires target source and a container runtime.", checkout="shannon",
    ),
)


PHASES = (
    ("scope", "Lock scope, dates, credentials, stop conditions and evidence handling."),
    ("recon", "Use passive/native discovery and preserve raw evidence."),
    ("triage", "Correlate CVE, EPSS and KEV intelligence; prioritize likely impact."),
    ("validate", "Run bounded validation only after the human approval checkpoint."),
    ("report", "Deduplicate findings and publish evidence, remediation and retest status."),
)


class RedTeamHub:
    def __init__(self, project_dir: Path):
        self.project_dir = Path(project_dir).resolve()
        self.runtime = IntegrationRuntime(self.project_dir)

    @staticmethod
    def _first_command(candidates: Iterable[str]) -> Optional[str]:
        for command in candidates:
            path = shutil.which(command)
            if path:
                return path
        return None

    @staticmethod
    def _tcp_probe(url: str, timeout: float = 0.35) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            with socket.create_connection((parsed.hostname, port), timeout=timeout):
                return True
        except OSError:
            return False

    def inspect(self, probe_services: bool = True) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        runtime_states = self.runtime.snapshot(deep=probe_services)
        for spec in INTEGRATIONS:
            command = self._first_command(spec.command_candidates)
            endpoint = os.environ.get(spec.url_env, spec.default_url) if spec.url_env else None
            explicitly_configured = bool(spec.url_env and os.environ.get(spec.url_env))
            configured = bool(command or explicitly_configured or spec.kind == "native")
            reachable = bool(endpoint and probe_services and self._tcp_probe(endpoint))
            source_path = self.runtime.root / spec.checkout if spec.checkout else None
            source_cloned = bool(source_path and source_path.is_dir())
            if spec.kind == "native":
                status = "online"
                installed = True
            elif reachable:
                status = "reachable"
                installed = bool(command)
            elif command:
                status = "installed"
                installed = True
            elif source_cloned:
                status = "source_ready"
                installed = False
            elif explicitly_configured:
                status = "needs_config"
                installed = False
            else:
                status = "not_installed"
                installed = False
            item = asdict(spec)
            item.update({
                "phases": list(spec.phases),
                "status": status,
                "installed": installed,
                "configured": configured,
                "reachable": reachable,
                "command": command,
                "endpoint": endpoint,
                "source_cloned": source_cloned,
                "source_path": (str(source_path.relative_to(self.project_dir)) if source_path.is_relative_to(self.project_dir) else str(source_path)) if source_cloned else None,
                "execution_integrated": spec.id in {"hexstrike", "cve_mcp", "claude_bughunter"},
                "verification": "native runtime" if spec.kind == "native" else ("TCP only, protocol unverified" if reachable else "installation inventory"),
            })
            if source_cloned and status == "source_ready":
                item["message"] = (
                    f"Source cloned at {item['source_path']}; install and configure its runtime to enable calls"
                )
            runtime = runtime_states.get(spec.id)
            if runtime:
                item.update(runtime)
                item["installed"] = bool(runtime.get("ready"))
                item["configured"] = bool(runtime.get("ready") or source_cloned)
            item.pop("command_candidates", None)
            item.pop("url_env", None)
            item.pop("default_url", None)
            results.append(item)
        return {
            "integrations": results,
            "summary": {
                "total": len(results),
                "online": sum(item["status"] == "online" for item in results),
                "installed": sum(item["installed"] for item in results),
                "configured": sum(item["configured"] for item in results),
                "ready": sum(item["status"] in {"online", "ready"} for item in results),
                "source_cloned": sum(item.get("source_cloned", False) for item in results),
            },
        }

    def mcp_config(self, server_url: str = "http://127.0.0.1:8888") -> Dict[str, Any]:
        """Return a secret-free MCP client configuration for the central gateway."""
        return {
            "mcpServers": {
                "vapt-redteam-hub": {
                    "command": str(self.project_dir / ".venv311" / "bin" / "python"),
                    "args": [str(self.project_dir / "redteam_mcp.py"), "--server", server_url],
                    "description": "Central scoped red-team control plane; active steps require operator approval.",
                    "timeout": 300,
                    "alwaysAllow": [],
                }
            }
        }

    def create_plan(self, payload: Dict[str, Any]) -> tuple[Dict[str, Any], int]:
        target = str(payload.get("target", "")).strip()
        scope = [str(item).strip() for item in payload.get("scope", []) if str(item).strip()]
        approval = str(payload.get("approval_name", "")).strip()
        window = str(payload.get("testing_window", "")).strip()
        authorized = payload.get("authorization_confirmed") is True
        blockers = []
        if not target:
            blockers.append("A target is required.")
        if not scope:
            blockers.append("At least one in-scope host, URL or CIDR is required.")
        if not authorized:
            blockers.append("Explicit ownership or written authorization confirmation is required.")
        if not approval:
            blockers.append("Record the approving operator or engagement owner.")
        if not window:
            blockers.append("Record the approved testing window.")

        objective = str(payload.get("objective", "web_application")).strip() or "web_application"
        stop_conditions = payload.get("stop_conditions") or [
            "Unexpected service instability", "Evidence of production data access", "Scope ambiguity"
        ]
        plan = {
            "status": "blocked" if blockers else "ready_for_human_approval",
            "target": target,
            "scope": scope,
            "objective": objective,
            "approval_name": approval,
            "testing_window": window,
            "stop_conditions": stop_conditions,
            "blockers": blockers,
            "execution_started": False,
            "phases": [
                {"id": phase, "description": description,
                 "integrations": [i.id for i in INTEGRATIONS if phase in i.phases]}
                for phase, description in PHASES
            ],
            "approval_checkpoint": {
                "required_before": "validate",
                "message": "Review recon/triage evidence and approve the bounded validation plan manually.",
            },
        }
        return plan, (400 if blockers else 200)
