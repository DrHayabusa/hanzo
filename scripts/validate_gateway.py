#!/usr/bin/env python3
"""Real MCP protocol smoke test of HANZO's gateway; no lab target requests."""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def validate(server_url):
    root = Path(__file__).resolve().parents[1]
    params = StdioServerParameters(command=sys.executable,
                                  args=[str(root / "redteam_mcp.py"), "--server", server_url],
                                  cwd=str(root),
                                  env={key: value for key, value in os.environ.items()
                                       if key in {"PATH", "HOME", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"}})
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [tool.name for tool in tools.tools]
            response = await session.call_tool("list_lab_exercises", {})
            passed = not response.isError and "triage_cve" in names and "run_authorized_smart_scan" in names
            return {"passed": passed, "transport": "stdio", "tool_count": len(names),
                    "tools": names, "catalog_call_passed": not response.isError,
                    "target_requests_performed": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8888")
    args = parser.parse_args()
    try:
        report = asyncio.run(asyncio.wait_for(validate(args.server), timeout=40))
    except Exception:
        report = {"passed": False, "error": "MCP gateway handshake/call failed. Verify environment and HTTP server."}
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
