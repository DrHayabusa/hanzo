# API and MCP architecture

HANZO's browser talks to a loopback Flask API. HexStrike supplies tool adapters; the worker supplies binaries. CVE intelligence is a real stdio MCP subprocess in an isolated virtual environment. BugHunter is a separate deterministic CLI. Ollama/cloud inference explains evidence. SQLite stores records.

## Operator APIs
| API | Purpose |
| --- | --- |
| GET /health | Worker/tool inventory and runtime metrics |
| GET /api/redteam/integrations?probe=true | Core MCP/CLI checks and optional source/service inventory |
| POST /api/redteam/validate | Core validation, no target scan |
| GET /api/redteam/mcp-config | Absolute-path client configuration for this clone |
| POST /api/redteam/cve/triage | CVE intelligence; JSON cve_id and optional depth |
| POST /api/redteam/bughunter/classify | CLI classification; JSON asset |
| GET/POST /api/redteam/workflows | Local workflow evidence |
| GET /api/llm/providers | Secret-free provider metadata |
| GET /api/llm/status | Ollama model discovery |
| POST /api/llm/chat | provider, model, message; optional key/history/context |
| GET /api/lab/exercises | Fixed exercise catalog, no target contact |
| POST /api/lab/exercises/run | Explicitly authorized fixed companion requests |
| GET /api/lab/exercises/history | Local exercise records |
| GET /api/lab/exercises/ID/report?format=md | Markdown export |
| GET /api/lab/telemetry/status | Configuration / last delivery, not Splunk search |
| POST /api/lab/telemetry/test | Benign HEC connectivity event |

## MCP clients

The central facade exports 113 tools: 23 control-plane tools plus one generated tool per bundled adapter, so every command the GUI can run is reachable over MCP as `run_<command_id>`. Generated tools take their arguments, types and defaults from GET /api/arsenal/catalog, the same read-only catalog the command launcher uses; categories and fields are extracted from bundled source without execution. Each generated tool requires authorization_confirmed and refuses when the executable is absent. `list_security_tools` enumerates them, `run_security_tool` dispatches by catalog id, and `refresh_arsenal_catalog` re-reads readiness after you install a tool. The optional MCP bridge adds GET /api/mcp/optional, POST /api/mcp/optional/<id>/probe and POST /api/mcp/optional/<id>/call. It reads private server configuration and requires exact allowlisting plus confirmation for calls. See OPTIONAL_MCP.md.
With the HTTP server running, obtain GET /api/redteam/mcp-config and put the resulting mcpServers entry in your MCP client's configuration. Paths are generated from the actual clone rather than the laptop's directories. The facade is redteam_mcp.py; the original full HexStrike adapter is hexstrike_mcp.py. Keep active calls operator-approved.

Example gateway launch:
```bash
.venv311/bin/python redteam_mcp.py --server http://127.0.0.1:8888
```
This is a stdio server for an MCP client, not a web URL to open in a browser.

## Security and limits
Upstream command/file APIs are privileged and are not a general authenticated Internet service. Run unprivileged, bind loopback, use SSH, and isolate the worker. Browser cross-origin requests are rejected; that is defense in depth, not a substitute for host/network controls.

The model never chooses and executes arbitrary shell commands from chat. Test workflows are operator-selected. Exercise payloads are fixed and limited to the configured companion. No detection is marked verified because HEC accepted a request. Reports retain the distinction between fixture observation, delivery, and actual SIEM detection.

Credential-like fields are redacted before SQLite persistence; this is best-effort, not guaranteed removal of secrets from arbitrary prose. Review evidence before export or cloud analysis.
