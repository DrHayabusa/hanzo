"""Configured lab topology with bounded, truthful service reachability probes."""

from __future__ import annotations

import os
import socket
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class LabNode:
    id: str
    label: str
    role: str
    ip: Optional[str]
    probe_port: Optional[int]
    cpu: Optional[str]
    memory: Optional[str]
    disk: Optional[str]
    icon: str
    current_agent: bool = False
    cloud: bool = False


class LabTopology:
    def __init__(self) -> None:
        self.name = os.environ.get("VAPT_LAB_NAME", "Detection Engineering Lab")
        self.cidr = os.environ.get("VAPT_LAB_CIDR", "10.20.39.0/24")
        self.network_mode = os.environ.get("VAPT_LAB_NETWORK", "VMware host-only / isolated")
        self.host = {
            "platform": os.environ.get("VAPT_LAB_HOST_OS", "Windows"),
            "cpu": os.environ.get("VAPT_LAB_HOST_CPU", "16 cores"),
            "memory": os.environ.get("VAPT_LAB_HOST_MEMORY", "32 GB"),
            "disk": os.environ.get("VAPT_LAB_HOST_DISK", "1 TB"),
        }

    @staticmethod
    def _env_ip(name: str, fallback: str) -> str:
        return os.environ.get(name, fallback).strip()

    @staticmethod
    def _env_port(name: str, fallback: int) -> int:
        try:
            return int(os.environ.get(name, fallback))
        except (TypeError, ValueError):
            return fallback

    def nodes(self) -> tuple[LabNode, ...]:
        return (
            LabNode("ad", "AD + DHCP", "Identity, DNS, DHCP, GPO, LDAP/Kerberos",
                    self._env_ip("VAPT_LAB_AD_IP", "10.20.39.10"), self._env_port("VAPT_LAB_AD_PORT", 389),
                    None, None, None, "AD"),
            LabNode("azure", "Azure AD", "Cloud identities, MFA and sign-in telemetry",
                    None, None, None, None, None, "AZ", cloud=True),
            LabNode("windows", "Windows / IIS", "HELPAG web target, Sysmon and Windows events",
                    self._env_ip("VAPT_LAB_WINDOWS_IP", "10.20.39.11"), self._env_port("VAPT_LAB_IIS_PORT", 8080),
                    "2 vCPU", "4 GB", "60 GB thin", "WS"),
            LabNode("linux", "Linux server", "SSH, CRUD services, Nginx/Apache and audit logs",
                    self._env_ip("VAPT_LAB_LINUX_IP", "10.20.39.12"), self._env_port("VAPT_LAB_LINUX_PORT", 22),
                    "2 vCPU", "2 GB", "30 GB thin", "LX"),
            LabNode("splunk", "Splunk server", "Indexing, detections, alerts and MITRE mapping",
                    self._env_ip("VAPT_LAB_SPLUNK_IP", "10.20.39.13"), self._env_port("VAPT_LAB_SPLUNK_PORT", 8000),
                    "6 vCPU", "12 GB", "150 GB thin", "SP"),
            LabNode("kali", "Kali + Hanzo", "Authorized VAPT orchestration and local tools",
                    self._env_ip("VAPT_LAB_KALI_IP", "10.20.39.14"), self._env_port("VAPT_PORT", 8888),
                    "2 vCPU", "4 GB", "40 GB", "KA", current_agent=True),
            LabNode("pfsense", "pfSense", "Controlled routing and traffic observation",
                    self._env_ip("VAPT_LAB_PFSENSE_IP", "10.20.39.15"), self._env_port("VAPT_LAB_PFSENSE_PORT", 443),
                    "2 vCPU", "4 GB", "20 GB", "FW"),
        )

    @staticmethod
    def _probe(ip: str, port: int, timeout: float = 0.35) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            return False

    def snapshot(self, probe: bool = True) -> Dict[str, Any]:
        rendered = []
        for node in self.nodes():
            item = asdict(node)
            if node.current_agent:
                status = "current"
                reachable = True
            elif node.cloud:
                status = "cloud"
                reachable = None
            elif probe and node.ip and node.probe_port:
                reachable = self._probe(node.ip, node.probe_port)
                status = "online" if reachable else "offline"
            else:
                reachable = None
                status = "not_probed"
            item.update({"status": status, "reachable": reachable})
            rendered.append(item)

        return {
            "name": self.name,
            "cidr": self.cidr,
            "network_mode": self.network_mode,
            "host": self.host,
            "nodes": rendered,
            "links": {
                "iis_site": f"http://{self._env_ip('VAPT_LAB_WINDOWS_IP', '10.20.39.11')}:{self._env_port('VAPT_LAB_IIS_PORT', 8080)}",
                "splunk": f"http://{self._env_ip('VAPT_LAB_SPLUNK_IP', '10.20.39.13')}:{self._env_port('VAPT_LAB_SPLUNK_PORT', 8000)}",
                "ollama": os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
            },
            "flow": [
                {"step": "01", "label": "Authorized activity", "detail": "Hanzo on Kali runs bounded assessments."},
                {"step": "02", "label": "Telemetry generation", "detail": "IIS, Windows, Linux, AD and pfSense produce lab logs."},
                {"step": "03", "label": "Collection", "detail": "Forwarders and HEC move events to Splunk."},
                {"step": "04", "label": "Detection", "detail": "Splunk searches, correlates and maps activity."},
                {"step": "05", "label": "Validate + improve", "detail": "Compare test evidence, tune detections and retest."},
            ],
            "resource_guidance": [
                "Keep the lab on an isolated VMware host-only network.",
                "Kali has 4 GB RAM: use qwen3:1.7b locally or a hosted provider; avoid larger local models.",
                "Do not expose IIS, Splunk, Ollama, or the agent directly to the public Internet.",
            ],
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "probe_type": "single configured TCP service per node" if probe else "disabled",
        }
