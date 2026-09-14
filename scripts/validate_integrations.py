#!/usr/bin/env python3
"""Validate Hanzo's real CVE MCP and Claude-BugHunter bridges."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from integration_runtime import IntegrationRuntime  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--live-cve", default="", metavar="CVE-ID",
        help="Also perform a real zero-key quick CVE triage lookup",
    )
    args = parser.parse_args()

    runtime = IntegrationRuntime(PROJECT_DIR)
    report = {
        "cve_mcp": runtime.probe_cve(),
        "claude_bughunter": runtime.bughunter_status(deep=True),
    }
    try:
        report["bughunter_classification"] = runtime.classify_asset(
            "http://10.20.39.11:8080/account?id=42&next=https://example.com"
        )
    except Exception as exc:
        report["bughunter_classification"] = {"success": False, "error": str(exc)}
    if args.live_cve:
        try:
            report["live_cve"] = runtime.triage_cve(args.live_cve, "quick")
        except Exception as exc:
            report["live_cve"] = {"success": False, "error": str(exc)}

    report["passed"] = bool(
        report["cve_mcp"].get("ready")
        and report["claude_bughunter"].get("ready")
        and report["claude_bughunter"].get("self_test")
        and report["bughunter_classification"].get("success")
        and (not args.live_cve or report.get("live_cve", {}).get("success"))
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
