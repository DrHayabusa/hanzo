# Optional MCP servers: configure, connect, and call explicitly allowed tools

HANZO includes a real MCP client for **stdio**, **SSE**, and **Streamable HTTP**.
It initializes the server, follows `tools/list` pagination, displays tool input
schemas, and invokes only exact tool names the host operator has allowlisted.
Each invocation also requires explicit confirmation in HANZO. An empty
allowlist permits discovery only. There is no wildcard or browser-supplied
command, environment, endpoint, or connection-configuration API.

This does not install Burp Suite or provision Decepticon's sandbox services.
An optional service is **online only after a real handshake**; a cloned source
directory or saved config is not an online connection. Status is the timestamped
last probe result, not a continuous heartbeat. This bridge does not feed tools
to the LLM for autonomous execution.

## Operator-owned configuration

Create `.hanzo-data/mcp-servers.json` in your HANZO checkout using a text editor.
This directory is gitignored. Keep this file writable only by your lab operator
and restrict its permissions (`chmod 600 .hanzo-data/mcp-servers.json` on Kali).
Alternatively set `HANZO_MCP_CONFIG` to a private absolute JSON path before
starting HANZO. A relative path is resolved inside the HANZO checkout.

Start with the following **disabled examples**. Replace paths, transports, and
endpoints with values from your installed server before setting `enabled: true`.
Do not enable a stdio entry until you have reviewed its executable and startup
behavior: probing it launches the configured program.

```json
{
  "version": 1,
  "servers": {
    "burp_mcp": {
      "name": "Burp Suite MCP",
      "enabled": false,
      "transport": "sse",
      "url": "http://127.0.0.1:9876/sse",
      "allowed_tools": []
    },
    "decepticon": {
      "name": "Decepticon MCP",
      "enabled": false,
      "transport": "stdio",
      "command": "/absolute/path/to/decepticon/.venv/bin/decepticon-mcp",
      "args": [],
      "cwd": "/absolute/path/to/decepticon",
      "env_from": [],
      "allowed_tools": []
    },
    "custom_lab": {
      "name": "My lab MCP service",
      "enabled": false,
      "transport": "streamable_http",
      "url": "http://127.0.0.1:9090/mcp",
      "headers_from": {"Authorization": "HANZO_LAB_MCP_AUTH"},
      "allowed_tools": []
    }
  }
}
```

`headers_from` maps a header name to an environment-variable name. Its value
must be the complete header value expected by that server, for example
`Bearer ...`. For stdio, `env_from` explicitly forwards named variables from
HANZO's environment. `env` and `headers` also accept literal string maps, but
environment references are preferred for secrets. Unrelated cloud credentials
are not automatically forwarded to child processes. Do not commit secrets.

## Burp workflow

1. Install and enable the official [PortSwigger MCP Server extension](https://portswigger.net/bappstore/9954d105bc1b45b2b1cbcc044b2b7b9a) in your lab Burp installation.
2. Check the actual listener address and transport in the extension. The JSON
   above is an example, not proof your installed version uses that endpoint.
   Run Burp and keep its human-approval controls enabled.
3. Configure the matching URL and transport; enable the entry. Bind the
   extension to loopback when HANZO and Burp run on the same Kali machine.
4. In HANZO's **MCP servers** page, test the connection. The response must say
   `online`, include a timestamp, and show the actual tool list.
5. Review the discovered tool descriptions and schemas. For a first connection,
   choose a read-only history or status tool supplied by your extension.
   Copy its **exact** name into `allowed_tools` in the private config; never
   guess names from another version. Retest the connection.
6. Select that tool in HANZO, supply its schema-matching JSON arguments, review
   the scope and effect, confirm the action, and run it. Inspect returned
   evidence. Start with reading your captured lab requests, not issuing scans.

The bridge cannot infer whether a tool truly is read-only from its name or MCP
annotations. The allowlist is the operator's trust decision. Target requests,
credentials, and possible side effects are governed by the selected server and
its tool arguments; HANZO's general target form does not rewrite those arguments.

## Decepticon and custom servers

Install the selected release following its own documentation; the cloned
[Decepticon source](https://github.com/PurpleAILAB/Decepticon) requires its own
runtime and supporting services. Confirm the installed MCP entry point, startup
arguments, required environment variables, and working directory. Configure the
absolute executable path rather than relying on an interactive shell profile.
Do not point the stdio transport at a normal interactive CLI: it must speak MCP
JSON-RPC over stdin/stdout. Use the same discovery-first, allowlist-second flow.

A remote MCP listener should remain on your isolated lab network, behind an
appropriate firewall and authentication. Use HTTPS for secrets across machines.
URLs with embedded credentials or query tokens are rejected; use headers.

## What is not an MCP server

| Project | Role in this build | What is required to use it |
|---|---|---|
| HexStrike | Native HANZO execution engine, also exported through MCP | Install the underlying worker executables on Kali |
| CVE MCP | Dedicated stdio intelligence adapter | Core integration installer and network access for its data providers |
| Claude-BugHunter | Skills/playbooks and deterministic CLI adapter | Its CLI environment; a skill bundle is not a listening daemon |
| Burp MCP | Optional extension-hosted MCP service | Running Burp extension plus matching configuration |
| Decepticon | Optional MCP-capable orchestration runtime | Its independent runtime, services, and connection config |
| Strix, PentestGPT, CAI, Shannon | Independent CLI/agent frameworks, not interchangeable MCP daemons | Their own dependencies, credentials, and documented launch workflow |
| PentAGI | Independent containerized application | Separate container deployment; an HTTP website is not automatically MCP |

HANZO does not pretend that every cloned framework is an executable adapter.
Use each independent framework through its supported workflow unless it exposes
an actual compatible MCP server that you configure here. See the project
integration and Kali deployment guides for source installation.

## API and limits

- `GET /api/mcp/optional`: operator-configured service metadata and last results.
- `POST /api/mcp/optional/<id>/probe`: real initialize and tool discovery.
- `POST /api/mcp/optional/<id>/call`: exact allowlisted tool call. The body
  contains `tool`, `arguments` (object), and `authorization_confirmed: true`.
  No connection settings can be supplied through these routes.
- At most 32 configured servers; a 256 KB config file; 1,024 discovered tool
  names; 64 discovery pages; 16 KB arguments; 256 KB rendered result preview;
  each input schema is limited to 16 KB with a 1 MB aggregate schema budget.
- A probe defaults to 15 seconds and a call to 30 seconds, with a hard maximum
  requested timeout of 30 seconds. Cleanup can add a short transport shutdown
  delay. A timed-out call may have already started remotely; do not blindly
  retry a state-changing tool.
- API metadata never includes commands, arguments, headers, or environment
  configuration. Errors do not expose raw upstream exception strings. Known
  configured secret values are redacted from call output; this is not a general
  DLP scanner. Returned target data may still be sensitive. Review before export.
- Tool names, descriptions, schemas, and results are untrusted external data,
  not instructions to HANZO or your LLM.

## Reproducible verification

```bash
.venv311/bin/python -m unittest discover -s tests -p 'test_optional_mcp.py' -v
```

The test suite launches a harmless temporary FastMCP subprocess, completes a
real stdio handshake, discovers its `echo` schema, and calls that tool. It also
tests SSE and Streamable HTTP adapter wiring with mocked transports, pagination,
config validation, missing secrets, timeout handling, redaction, and allowlist
enforcement. It does **not** claim a live Burp or Decepticon deployment was
tested on this laptop. Run their connection tests after configuring your lab.
