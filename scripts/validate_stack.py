#!/usr/bin/env python3
"""Repeatable post-deployment validation for the VAPT Agent control plane."""

import argparse
import json
import sys

import requests


def request_json(method: str, url: str, **kwargs):
    response = requests.request(method, url, timeout=180, **kwargs)
    response.raise_for_status()
    return response.json()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8888")
    parser.add_argument("--inference", action="store_true", help="Also run a small real LLM generation")
    args = parser.parse_args()
    base = args.server.rstrip("/")

    report = {"server": base, "checks": {}, "passed": True}
    try:
        health = request_json("GET", f"{base}/health")
        report["checks"]["api"] = health.get("status") == "healthy"

        stack = request_json("POST", f"{base}/api/redteam/validate", json={})
        report["checks"].update(stack.get("checks", {}))

        mcp = request_json("GET", f"{base}/api/redteam/mcp-config")
        report["checks"]["mcp_config"] = "vapt-redteam-hub" in mcp.get("mcpServers", {})

        blocked = requests.post(
            f"{base}/api/intelligence/smart-scan",
            json={"target": "127.0.0.1"}, timeout=10,
        )
        report["checks"]["active_scan_scope_gate"] = blocked.status_code == 403

        if args.inference:
            reply = request_json("POST", f"{base}/api/llm/chat", json={
                "provider": "ollama",
                "message": "Connectivity test. Reply with exactly: CENTRAL RED TEAM LLM READY",
            })
            report["checks"]["llm_inference"] = reply.get("reply", "").strip() == "CENTRAL RED TEAM LLM READY"
            report["llm_reply"] = reply.get("reply")
    except (requests.RequestException, ValueError) as exc:
        report["error"] = str(exc)
        report["passed"] = False

    report["passed"] = report["passed"] and all(report["checks"].values())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
