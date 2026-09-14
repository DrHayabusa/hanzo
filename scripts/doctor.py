#!/usr/bin/env python3
"""Read-only worker inventory. Does not start services, scan targets or print secrets."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
from sync_integrations import load_manifest, sync_one  # noqa: E402

CORE_PACKAGES = (
    "flask", "requests", "psutil", "fastmcp", "mcp", "beautifulsoup4",
    "selenium", "webdriver-manager", "aiohttp", "mitmproxy",
)
WORKER_TOOLS = (
    "git", "curl", "nmap", "nikto", "sqlmap", "nuclei", "ffuf", "gobuster",
    "httpx", "katana", "subfinder", "whatweb", "tcpdump", "tshark",
    "docker", "node", "npm", "uv", "ollama", "cbh", "strix", "pentestgpt", "cai",
)
VERSION_ARGS = {"git": ["--version"], "curl": ["--version"], "nmap": ["--version"],
                "node": ["--version"], "uv": ["--version"]}


def inventory(project: Path = PROJECT, versions: bool = False) -> dict:
    """Report presence separately from verified runtime connectivity."""
    project = Path(project).resolve()
    search_path = os.pathsep.join((str(project / "tools/bin"), str(project / ".venv311/bin"), os.environ.get("PATH", "")))
    packages = []
    for package in CORE_PACKAGES:
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            version = None
        packages.append({"name": package, "installed": version is not None, "version": version})
    binaries = []
    for name in WORKER_TOOLS:
        path = shutil.which(name, path=search_path)
        if not path and name == "ollama":
            bundled = project / "tools/ollama/ollama"
            if bundled.is_file() and os.access(bundled, os.X_OK):
                path = str(bundled)
        row = {"name": name, "found": bool(path), "path": path, "runtime_verified": False}
        if versions and path and name in VERSION_ARGS:
            try:
                result = subprocess.run([path, *VERSION_ARGS[name]], capture_output=True, text=True, timeout=5)
                row["version"] = result.stdout.splitlines()[0][:160] if result.returncode == 0 and result.stdout else "version check failed"
            except (OSError, subprocess.SubprocessError):
                row["version"] = "version check failed"
        binaries.append(row)
    destination = Path(os.environ.get("HANZO_INTEGRATIONS_DIR", project / ".integrations")).expanduser()
    sources = []
    try:
        locked = load_manifest(project / "integrations.lock.json")
        for item in locked:
            try:
                row = sync_one(item, destination, check_only=True)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                row = {"directory": item["directory"], "status": "error", "message": str(exc) if isinstance(exc, ValueError) else "Git inspection failed"}
            row["profile"] = item["profile"]
            row["runtime_verified"] = False
            sources.append(row)
    except (OSError, ValueError, TypeError):
        sources = [{"directory": "source lock", "profile": "core", "status": "error", "message": "Missing or invalid integrations.lock.json"}]
    adapters = []
    for name, env, suffix in (("cve-mcp-server", "CVE_MCP_DIR", ".venv/bin/python"),
                              ("claude-bughunter", "CLAUDE_BUGHUNTER_DIR", ".venv/bin/cbh")):
        path = Path(os.environ.get(env, destination / name)).expanduser() / suffix
        adapters.append({"name": name, "executable_present": path.is_file() and os.access(path, os.X_OK), "runtime_verified": False})
    problems = []
    if sys.version_info[:2] != (3, 11):
        problems.append("Run doctor with .venv311/bin/python (Python 3.11).")
    if any(not item["installed"] for item in packages):
        problems.append("Install core dependencies: .venv311/bin/python -m pip install -r requirements-core.txt")
    mcp = next((item["version"] for item in packages if item["name"] == "mcp"), None)
    if mcp and not mcp.startswith("1."):
        problems.append("Core MCP must remain >=1.7,<2; reinstall requirements-core.txt and run pip check.")
    if any(item["status"] != "pinned" for item in sources if item["profile"] == "core") or any(not item["executable_present"] for item in adapters):
        problems.append("Install/repair core adapters: bash scripts/install_integrations.sh --core; preserve modified source checkouts first.")
    return {
        "mode": "read_only", "platform": platform.system(), "python": platform.python_version(),
        "interpreter": sys.executable, "core_inventory_ready": not problems,
        "packages": packages, "binaries": binaries, "sources": sources, "adapters": adapters,
        "configuration": {
            "ollama_url_configured": bool(os.environ.get("OLLAMA_URL")),
            "cloud_credentials_present": {name: bool(os.environ.get(name)) for name in ("GROQ_API_KEY", "OPENROUTER_API_KEY", "LLM_API_KEY")},
            "splunk_hec_configured": bool(os.environ.get("HANZO_SPLUNK_HEC_URL") and os.environ.get("HANZO_SPLUNK_HEC_TOKEN")),
            "lab_target_configured": bool(os.environ.get("HANZO_LAB_TARGET")),
        },
        "problems": problems,
        "next_checks": [
            ".venv311/bin/python -m pip check",
            ".venv311/bin/python scripts/validate_integrations.py",
            "bash scripts/install_kali_arsenal.sh --core --dry-run (on Kali)",
            "Start HANZO, then use MCP servers → Validate core and AI assistant → Test model connectivity.",
        ],
        "note": "Source and executable presence is not tool execution, model connectivity, or detection validation. No target or service was contacted.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--versions", action="store_true", help="Run safe version commands for git/curl/nmap/node/uv only")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if required core inventory is missing")
    args = parser.parse_args(argv)
    report = inventory(versions=args.versions)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"HANZO doctor — {report['platform']} / Python {report['python']}")
        print(f"Core inventory: {'present (connectivity unverified)' if report['core_inventory_ready'] else 'needs attention'}")
        for row in report["binaries"]:
            print(f"  {'FOUND' if row['found'] else 'MISSING':8} {row['name']}")
        for row in report["sources"]:
            print(f"  {row['status'].upper():18} {row['directory']}")
        for problem in report["problems"]:
            print(f"ACTION: {problem}")
        print(report["note"])
        print("Next checks:")
        for command in report["next_checks"]:
            print(f"  {command}")
    return 1 if args.strict and not report["core_inventory_ready"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
