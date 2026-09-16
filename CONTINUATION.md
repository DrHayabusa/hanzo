# HANZO continuation handoff
Updated 2026-09-15 (Asia/Dubai). Start here before editing.

## User intent and priority
The user wants HANZO: a personal, authorized lab pentesting workspace deployed by git clone on Kali. It combines a usable GUI, HexStrike commands, CVE intelligence, practical MCP connections, local/cloud LLM analysis and evidence. Deliver working code and truthful status, not fake “all online” badges.

**Tool first. The CTF/IIS companion website is deferred.** The user already owns the lab and will deploy/test Windows IIS and Splunk there. Do not install those systems or scan their network from the development laptop as part of bootstrap.

Public repo: https://github.com/DrHayabusa/hanzo
Original development repo: https://github.com/DrHayabusa/VAPT-Agent
Upstream engine: https://github.com/0x4m4/hexstrike-ai

The hanzo repo is a clean source snapshot, not the old development history. Preserve the upstream LICENSE and attribution. Models, binaries, third-party clones, evidence, logs and credentials are intentionally gitignored.

## Read next
README.md; docs/PROGRESS.md; PROJECT_PLAN.md; docs/VALIDATION_REPORT.md; docs/CENTRAL_REDTEAM_HUB.md; docs/PAGE_GUIDE.md; docs/LAB_DEPLOYMENT.md; docs/OPTIONAL_MCP.md; integrations.lock.json.

## Product decisions
- Name HANZO only; use “MCP servers,” never “Stack Nexus.”
- Black, warm gold, restrained red; compact flat ninja emblem, subtle round moon/katana/Japanese silhouettes. Do not revert to a huge 3D robot mask or oval moon.
- Existing Flask + vanilla JS project, not React/Sites. Preserve frontend IDs.
- Nine pages: Overview, Test target, Lab exercises, Reports, Lab network, MCP servers, Security tools, Running jobs, AI assistant.
- Scope accepts URL, hostname, IP, or CVE in the appropriate stage. Active actions remain explicit.
- SQLite WAL is the local database; no database service necessary.
- Python 3.11 is intentional because the upstream proxy dependencies are not compatible with arbitrary newer Python releases.
- Chat is advisory. “Full workflow” is a fixed adapter sequence, not autonomous closed-loop LLM execution.
- Cloned source, executable presence, TCP reachability, MCP handshake and successful tool calls are different states. Never fake wrappers or green status.

## Code map
| File | Responsibility |
| --- | --- |
| hexstrike_server.py | Upstream Flask engine, 90 tool POST adapters, health/LLM/HANZO routes |
| arsenal_catalog.py | Read-only AST catalog of every bundled tool route and its parameter defaults |
| static/arsenal.js | Category/command dropdown, typed arguments, exact request preview, confirmation and saved evidence |
| static/app.js | Workflows, local/cloud assistant, reports, topology, exercise UI |
| static/optional-mcp.js | Configured MCP discovery, schemas and explicit invocation |
| static/index.html / styles.css / hanzo-emblem.svg | Current visual system |
| integration_runtime.py | Isolated CVE stdio MCP client and cbh classification |
| redteam_hub.py | Integration registry, source/service status, plans and client config |
| redteam_mcp.py | Central MCP facade: 23 control tools + one generated tool per bundled adapter (113 total) |
| arsenal_mcp.py | Builds typed MCP tools from the arsenal catalog; authorization and readiness gating |
| wordlists.py | Discovers wordlists that actually exist; classifies and validates operator paths |
| assessment_preflight.py | Validates, reaches and reports stage readiness for a target before any scanner runs |
| pentest_stages.py | The engagement stage catalog: 19 stages, their adapters, objectives and proper names |
| findings.py | Deterministic extraction of structured findings from raw scanner output |
| static/refinements.css | Visual layer over styles.css; removable without breaking any view |
| optional_mcp.py / optional_mcp_api.py | stdio/SSE/Streamable HTTP bridge, allowlists, limits, redaction, routes |
| hanzo_store.py | SQLite workflow/exercise evidence and credential-field redaction |
| scan_scope.py | Conservative single-target validation for automated smart scan |
| lab_exercises.py / lab_topology.py | Fixed companion checks, optional HEC and supplied lab configuration |
| scripts/setup_kali.sh | Python 3.11 bootstrap and core checks |
| scripts/install_integrations.sh / sync_integrations.py | Locked source revisions and isolated core environments |
| scripts/install_kali_arsenal.sh | Kali packages with per-package failure logs and nonzero error status |
| scripts/doctor.py | Read-only preflight, distinct presence/runtime states |
| .github/workflows/tests.yml | Linux/Python 3.11 unit, dependency, shell and JS validation |

## Measured integration state
- HexStrike: embedded and all **90 tool POST routes in 10 categories** exposed in the GUI **and as individual MCP tools**. Inventory contains 124 unique names; only 12 binaries detected on development Mac. Installing Kali packages remains destination work.
- CVE MCP: real initialize/list (28 tools) and intelligence calls passed. Dedicated bridge uses a restricted intelligence tool allowlist.
- BugHunter: real CLI self-test, 83 skills/15 commands and classification passed. No-match is a valid completed outcome. It is not a daemon.
- Ollama: qwen3:1.7b discovery and real generation passed.
- Cloud: Groq/OpenRouter/compatible API implemented and mock-tested; real API keys/model availability needed for live validation.
- Optional MCP: actual harmless stdio echo fixture passes; SSE/HTTP wiring mocked. Real Burp/Decepticon need actual service configuration and a real first call.
- Strix/PentAGI/PentestGPT/CAI/Decepticon/Shannon: locked source inventory, not universally callable native integrations. Do not treat their websites/CLIs as MCP daemons.
- Lab exercises and HEC: locally tested with synthetic transports; no actual IIS deployment, Splunk indexing, or alert validation claimed.

## Setup and verification
```bash
git clone https://github.com/DrHayabusa/hanzo.git
cd hanzo
bash scripts/setup_kali.sh --all-sources
bash scripts/install_kali_arsenal.sh --core
bash start_vapt_agent.sh
```
Keep the terminal open. Browse http://127.0.0.1:8888 . Read LAB_DEPLOYMENT for prerequisites and SSH tunneling. Never run the control plane as root or expose it publicly.

```bash
.venv311/bin/python -m unittest discover -s tests -v
node --test tests/test_*ui.js
.venv311/bin/pip check
.venv311/bin/python scripts/doctor.py --json --strict
.venv311/bin/python scripts/sync_integrations.py --check
.venv311/bin/python scripts/validate_integrations.py
.venv311/bin/python scripts/validate_stack.py --inference
.venv311/bin/python scripts/validate_gateway.py
```
Last two require the API; inference also needs Ollama/model. CVE upstream requests can be rate-limited.

.env.example is documentation, not automatically sourced. Export config before startup. Variables: VAPT_HOST/VAPT_PORT/VAPT_PYTHON, OLLAMA_URL/OLLAMA_MODEL/HANZO_SKIP_OLLAMA, HANZO_INTEGRATIONS_DIR, CVE_MCP_DIR/CVE_MCP_PYTHON, CLAUDE_BUGHUNTER_DIR/CLAUDE_BUGHUNTER_COMMAND, HANZO_MCP_CONFIG/HANZO_DB_PATH, GROQ_API_KEY, OPENROUTER_API_KEY, LLM_API_BASE/LLM_API_MODEL/LLM_API_KEY, HANZO_LAB_TARGET and HANZO_SPLUNK_HEC_URL/HANZO_SPLUNK_HEC_TOKEN/HANZO_SPLUNK_INDEX.

Optional MCP: private .hanzo-data/mcp-servers.json, exact allowed_tools, host-owned config only. Probe, review schemas, allowlist, explicitly invoke. Do not guess Burp ports or tool names.

## Supplied lab
Windows host: 16 cores, 32 GB RAM, 1 TB disk; isolated 10.20.39.0/24.
| Role | IP | CPU / RAM / disk |
| --- | --- | --- |
| AD + DHCP | 10.20.39.10 | Not specified |
| Windows / IIS | 10.20.39.11 | 2 / 4 GB / 60 GB |
| Linux | 10.20.39.12 | 2 / 2 GB / 30 GB |
| Splunk | 10.20.39.13 | 6 / 12 GB / 150 GB |
| Kali / HANZO | 10.20.39.14 | 2 / 4 GB / 40 GB |
| pfSense | 10.20.39.15 | 2 / 4 GB / 20 GB |
| Azure AD | Cloud | Separate credentials/connectivity |

Listed VMs allocate 26 GB before AD/host overhead. Use small local models or remote Ollama/cloud; do not blindly start heavy frameworks.

## Risks and open work
Upstream API contains generic command/file/process operations, and many legacy routes construct shell strings. Current release is a **trusted single-operator loopback lab tool**, not a hardened shared service. Origin checks and confirmation UI are not authentication or sandboxing. The smart-scan target guard does not audit every legacy route. See PROJECT_PLAN for argv adapters, server-side scope, authentication, sandboxing and deeper tests.

Catalog fields are statically inferred; conditional actions still need backend validation. Binary detection does not prove compatible versions, credentials, wordlists or successful operation. Some upstream vulnerability counts use output keywords, not validated findings. Evidence exports can retain target information despite credential-field redaction.

Do not claim all tools online, zero flaws or “200% tested.” Record actual measured checks and exact missing prerequisites.

## Deferred website
Existing reference: DrHayabusa/HELPAG-VAPT-Test-Site. User wants a separate CTF-like “test website” repository (likely slug test-website), Windows/IIS guide, full Burp/manual test Markdown, expected OWASP events and Splunk use cases. Inspect existing code first. Do not mark this delivered, rename it or publish it during tool-first work. Keep synthetic data and isolated low-privilege deployment.

## Prompt for Claude
“Read CLAUDE.md, CONTINUATION.md, PROJECT_PLAN.md, docs/PROGRESS.md and docs/VALIDATION_REPORT.md. Inspect git status, run tests, and continue the highest-priority open HANZO work. Preserve existing UI and truthful integration readiness. Website is deferred until requested. Keep code, progress and acceptance evidence committed and pushed.”

## Handoff notes (2026-09-16)

Where things stand, for whoever picks this up next.

### Run it

```bash
cd "/Volumes/shuaibs/Shahid project/hanzo"
bash start_vapt_agent.sh          # worker on :8888, Ollama on :11434
.venv311/bin/python -m unittest discover -s tests
node --test tests/test_*ui.js
```

The project lives on an external volume because the boot disk is full. The path
contains a space, which has already caused two classes of bug — see "Traps" below.

### The four catalogs, and why they matter

Everything is generated from a small number of read-only sources. Change the
source, not the consumers.

| Source | Owns | Consumed by |
| --- | --- | --- |
| `arsenal_catalog.py` | The 90 tool adapters, their fields and readiness | Browser launcher, `arsenal_mcp.py`, preflight, stats |
| `pentest_stages.py` | The 19 engagement stages | Test target menu, preflight, evidence-store phase validation |
| `wordlists.py` | Wordlists that actually exist | Every wordlist field, MCP `list_wordlists` |
| `integrations.lock.json` | Pinned upstream revisions | `redteam_hub.py`, doctor, stats |

Adding a stage means editing `pentest_stages.py` only. Adding an adapter means
adding a route to `hexstrike_server.py`; the catalog picks it up by AST parsing.

### Traps that have already bitten

1. **Spaces in the project path.** Adapters build shell strings for `shell=True`.
   Any new adapter that interpolates a filesystem path must wrap it in `_q()`
   (`hexstrike_server.py`), or the path splits at the space. Guarded by
   `tests/test_command_quoting.py`.
2. **Shebangs cannot contain spaces.** Never symlink a pip console script into
   `tools/bin`; write a `/bin/sh` wrapper. `scripts/install_macos_arsenal.sh`
   does this already.
3. **Homebrew on macOS 13 is Tier 3** and compiles from source, which twice
   exhausted the boot disk. Prefer prebuilt release binaries into `tools/bin`.
   The installer stops at a 1.2 GB floor.
4. **Readiness depends on PATH.** `build_catalog` run from a plain shell reports
   fewer tools than the server, whose PATH includes `tools/bin`. The API is
   authoritative.
5. **Never let the model decide what was found.** `findings.py` extracts; the
   model only narrates, and `/api/reports/narrative` flags any path in the prose
   that is not in the findings.

### Deliberately not done

The autonomous LLM-driven scanning loop. The assistant is advisory, stages are
operator-selected, and every executing stage requires explicit authorization. If
you build it, keep the approval checkpoint and the evidence trail intact.

Also open: the API & token analysis category is 0/4 on macOS (needs `x8`,
which has no macOS release), and Advanced lab simulation is 0/2 (Metasploit).
Both are expected to work on the Kali worker.
