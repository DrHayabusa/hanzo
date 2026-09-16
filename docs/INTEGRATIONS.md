# What is integrated, and how

Every number here was measured on the development worker on 2026-09-16 by calling
the running API, not asserted from configuration. Reproduce them with:

```bash
curl -s http://127.0.0.1:8888/api/system/stats | python3 -m json.tool
```

## Summary

| Capability | Count | Source of truth |
| --- | --- | --- |
| Tool adapters exposed | **90** across 10 categories | `GET /api/arsenal/catalog` |
| Adapters ready on this worker | **49** (48 distinct executables) | same, `installed: true` |
| Engagement stages | **19** in 8 groups | `GET /api/assessment/stages` |
| MCP tools published by HANZO | **113** (90 generated + 23 control) | `list_tools` over stdio |
| Wordlists discovered | **429** | `GET /api/arsenal/wordlists` |
| Pinned upstream repositories | **8** | `integrations.lock.json` |
| Registered integrations | **10** (3 callable, 7 source or external) | `GET /api/redteam/integrations` |

"Ready" means the executable was found on this worker's PATH. It is not a claim
that the command, its credentials, or its network access work.

## The ten integrations

Three are callable from HANZO today. The rest are pinned source or external
runtimes: HANZO knows their revision and reports their state honestly rather than
pretending they are wired in.

### Callable from HANZO

**HexStrike AI** — `native` — https://github.com/0x4m4/hexstrike-ai
The scanner execution plane, embedded in this repository as `hexstrike_server.py`.
It provides the 90 `/api/tools/<name>` adapters, the target-profiling engine, the
smart-scan attack-pattern selector and the process manager. HANZO calls its Flask
routes in-process. Everything in the Security tools page and every `run_<tool>`
MCP tool resolves to one of these routes. *Onboarded: all 90 adapters, 10
categories, the attack patterns behind all 16 executing stages.*

**CVE MCP Server** — `mcp_stdio` — https://github.com/mukul975/cve-mcp-server
Pinned at `d666bac37435`. Spoken to over stdio MCP: the process starts per call
and holds no port. A real `initialize`/`list_tools` handshake discovers **28
tools** covering CVE lookup, EPSS scoring, KEV membership and OSV data. HANZO
exposes it through `/api/redteam/cve/triage` and the `triage_cve` MCP tool, and it
backs the CVE intelligence stage. *Onboarded: 28 MCP tools, verified by handshake
at startup.*

**Claude-BugHunter** — `cli` — https://github.com/elementalsouls/Claude-BugHunter
Pinned at `ef108a26e46c`. Installed into its own virtualenv at
`.integrations/claude-bughunter/.venv` and invoked as the `cbh` command. Its
self-test passes and reports **83 skills and 15 commands**. HANZO calls it through
`/api/redteam/bughunter/classify` and the `classify_with_bughunter` MCP tool; it
backs the Vulnerability classification stage. Classification is advisory — it
suggests where to look and never scans the asset. *Onboarded: 83 skills, 15
commands, self-test verified.*

### Pinned source, external runtime

These are cloned at reviewed revisions so the code you audit is the code you run,
but they need their own runtime and are reported as `source_ready`, never as
online. HANZO will not claim an integration it cannot reach.

| Integration | Kind | Revision | Why it is not callable yet |
| --- | --- | --- | --- |
| **Strix** — https://github.com/usestrix/strix | cli | `84f4108195fb` | Sandboxed autonomous validation. Needs an isolated lab and a human approval checkpoint before it may act. |
| **PentAGI** — https://github.com/vxcontrol/pentagi | http | `ea665308baaf` | Containerized multi-agent platform; deployed separately with Docker and reached at `PENTAGI_URL`. |
| **PentestGPT** — https://github.com/GreyDGL/PentestGPT | cli | `e8b1bb77d1ac` | Multi-stage pentest reasoning; needs its own model credentials. |
| **CAI** — https://github.com/aliasrobotics/CAI | cli | `6dc79257777f` | Cybersecurity agent and MCP client with its own runtime and model configuration. |
| **Decepticon** — https://github.com/PurpleAILAB/Decepticon | mcp_stdio | `31e1c8e786c8` | LangGraph red-team orchestration; requires Python 3.13 plus its management and sandbox services. |
| **Shannon** — https://github.com/KeygraphHQ/shannon | cli | `25b90b0611f1` | White-box web/API validation; requires the target's source and a container runtime. |

**Burp Suite MCP** — `mcp_sse` — is registered but has no pinned checkout: it is a
commercial product. Install Burp and its MCP Server extension, set `BURP_MCP_URL`,
and the optional-MCP bridge will probe it over SSE with human approval kept on.

## How a tool call actually travels

```
Browser (Security tools)            MCP client (Claude, Codex, …)
        |                                    |
        |  POST /api/tools/<name>            |  run_<name>  (one per adapter)
        v                                    v
   hexstrike_server.py  <-------------  redteam_mcp.py
        |                     reads the same read-only catalog
        v
   execute_command()  ->  the real binary on PATH
        |
        v
   SQLite evidence (.hanzo-data/hanzo.db)
```

Both paths are generated from one catalog (`arsenal_catalog.py`), so the browser
and an MCP client always see the same tools, arguments and readiness. Every
executing path requires `authorization_confirmed`, and an adapter whose executable
is missing refuses with an install instruction instead of a confusing tool error.

## What HANZO adds on top

- **`pentest_stages.py`** — 19 engagement stages in 8 groups, each bound to its
  adapters and to a HexStrike attack-pattern objective. One catalog feeds the
  console, the pre-flight check and the evidence store.
- **`arsenal_mcp.py`** — generates one typed MCP tool per adapter, with
  authorization and readiness gating.
- **`wordlists.py`** — discovers the wordlists that exist, ranks them against each
  adapter's default, and never invents a path.
- **`assessment_preflight.py`** — validates a target, confirms it is reachable and
  reports stage readiness before anything is launched.
- **`hanzo_store.py`** — local SQLite evidence with credential redaction, explicit
  deletion and retention.

## The 19 stages

| Group | Stages |
| --- | --- |
| Intelligence | Target profiling · CVE intelligence · Vulnerability classification |
| Discovery | Reconnaissance and attack surface · Network discovery and service enumeration · Comprehensive network penetration test |
| Application testing | Web application testing · API and parameter analysis · Vulnerability validation |
| Cloud and infrastructure | AWS · Kubernetes · Container image · Infrastructure as code |
| Credentials | Credential and password auditing |
| Binary and forensics | Binary analysis and exploitation · Forensics and file analysis |
| Bug bounty | Bug bounty reconnaissance · Bug bounty vulnerability hunting |
| Comprehensive | Full assessment |

The three Intelligence stages never contact the asset and need no authorization.
The other 16 can launch scanners and require explicit confirmation.

## Adapter readiness by category

Measured on the development Mac. Kali is the intended worker and will score higher.

| Category | Ready |
| --- | --- |
| Reconnaissance & discovery | 8 / 10 |
| Data utilities | 3 / 3 |
| Cloud, containers & IaC | 8 / 12 |
| Password auditing | 3 / 4 |
| Binary analysis & debugging | 7 / 16 |
| Web application testing | 11 / 21 |
| Network & infrastructure | 6 / 13 |
| Forensics & file analysis | 3 / 5 |
| API & token analysis | 0 / 4 |
| Advanced lab simulation | 0 / 2 |

Install more with `bash scripts/install_macos_arsenal.sh --full` on macOS or
`bash scripts/install_kali_arsenal.sh --full` on Kali, then use **Refresh catalog**.

## The reporting workflow

This is the recommended path from a target to a readable report.

1. **Pre-flight** — Test target page, *Check target readiness*. Confirms the
   target resolves and responds, and lists which adapters the chosen stage has.
   One TCP connect plus an HTTP HEAD; never a scan.
2. **Run a stage** — pick one of the 19 stages and confirm authorization. HexStrike
   selects its attack pattern from the stage's objective and runs the installed
   adapters.
3. **Evidence is stored** — raw stdout, exit codes and timings go to SQLite with
   credential redaction (`hanzo_store.py`).
4. **Findings are extracted in Python** — `findings.py` parses gobuster,
   feroxbuster, dirsearch, katana, httpx and nuclei output into structured rows:
   path, status, size, redirect, severity, and which tool saw it. Paths matching
   known-sensitive patterns are categorised (environment file, backup location,
   upload location, API surface, and so on).
5. **The local model narrates only those findings** — `POST /api/reports/narrative`
   sends the extracted facts, never raw tool output, with instructions not to add
   anything. The response always returns the findings next to the prose.
6. **The prose is checked against the facts** — every path the model mentions is
   compared to the extracted findings. Anything it names that was not found is
   returned in `unverified_paths` and shown in the interface as unsupported.
7. **Export** — *Download report (Markdown)* writes the narrative, the findings
   table and the list of tools that ran, including tools that produced no output.

Why this shape: a language model is good at prose and bad at not inventing
details. Keeping extraction deterministic means the model cannot add a path, a
status code or a vulnerability, and the verification step catches it if it tries.
If Ollama is unreachable the endpoint still returns the complete findings and says
the narrative could not be written, rather than failing the report.

## What is deliberately not integrated

Metasploit, OWASP ZAP, Ghidra, Burp, and the Linux-oriented SMB/AD tooling
(NetExec, enum4linux, Responder) are reported as not installed on macOS rather
than wired to a stub. `scripts/install_macos_arsenal.sh` names each one and how to
obtain it. The autonomous LLM-driven scanning loop is **not built**: the assistant
is advisory, stages are operator-selected, and each executing stage requires
explicit authorization.
