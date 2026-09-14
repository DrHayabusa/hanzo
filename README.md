# HANZO

<img src="static/hanzo-emblem.svg" width="68" alt="HANZO ninja emblem">

A local-first security testing workspace for your Kali worker. Black, gold, and restrained red. Defined scope, visible execution, and persistent evidence.

**Built on HexStrike AI.** HANZO adds a web UI, CVE MCP and Claude-BugHunter bridges, Ollama/cloud analysis, SQLite reports, and fixed HELPAG detection exercises. The upstream license and attribution are preserved in [LICENSE](LICENSE) and [upstream documentation](docs/UPSTREAM_HEXSTRIKE.md).

## Start on Kali

```bash
git clone https://github.com/DrHayabusa/hanzo.git
cd hanzo
bash scripts/setup_kali.sh --all-sources
bash scripts/install_kali_arsenal.sh --core
bash start_vapt_agent.sh
```

Open **http://127.0.0.1:8888** in the Kali browser. The repository is public; cloning requires no GitHub API key.

The bootstrap needs Git, curl, and Python 3.11. If your Kali release has a newer Python only, install `uv` with `pipx`; the script uses it to provision Python 3.11. The current HexStrike proxy dependencies are tested with 3.11, not arbitrary Python releases. See [Kali deployment](docs/LAB_DEPLOYMENT.md).

**Do not run HANZO as root or expose port 8888 to the Internet.** The upstream API can run commands and manage files. It is a trusted single-operator lab control plane, not a hardened multi-tenant service. Keep loopback binding and use an SSH tunnel for remote browser access.

## What works together

| Component | Integration in HANZO |
| --- | --- |
| HexStrike AI | Native API, installed tool inventory, target profiling, selected scan workflow |
| CVE MCP Server | Real stdio initialize/list-tools and CVE triage calls |
| Claude-BugHunter | Isolated CLI, self-test, asset classification/playbooks |
| Ollama | Local model discovery and real chat/inference test |
| Groq, OpenRouter, compatible API | Cloud chat with provider/model/key configuration; live test button |
| SQLite | Local assessment and lab exercise evidence; JSON/Markdown exports |
| HELPAG test site | Fixed, authorized exercise suite for your isolated companion deployment |
| Splunk HEC | Optional correlated event delivery; acceptance does not prove indexing or an alert |
| Optional MCP servers | stdio/SSE/Streamable HTTP discovery and exact allowlisted calls; actual service setup required |
| Larger standalone frameworks | Locked source inventory; separate runtime setup |

`--all-sources` fetches the supplied Git sources at revisions recorded in [integrations.lock.json](integrations.lock.json). It **does not** turn Strix, PentAGI, PentestGPT, CAI, Decepticon, or Shannon into callable HANZO adapters. These are different CLIs/services/MCP clients with their own runtimes, credentials, hardware, and licenses. See [integration readiness](docs/INTEGRATION_READINESS.md).

In **Security tools**, choose a category and command, fill the typed arguments, review the exact request, confirm scope, and run. All **90 bundled tool POST routes** are categorized into **10 groups**, with output, SQLite evidence and download. See [optional MCP setup](docs/OPTIONAL_MCP.md) to connect additional actual servers.

HexStrike's registry is not an installation bundle. Green chips mean executable presence on this worker's PATH, not exhaustive validation. The Kali installer produces a per-package report and does not disguise failures.

## Local or cloud AI

For local AI, install Ollama using its official Linux instructions, then:

```bash
ollama pull qwen3:1.7b
export OLLAMA_URL=http://127.0.0.1:11434
export OLLAMA_MODEL=qwen3:1.7b
bash start_vapt_agent.sh
```

The configured Kali VM has 4 GB RAM: start small, measure memory pressure, or use a separately hosted Ollama server / cloud API. Models are downloaded on the destination machine, not committed to Git.

For cloud AI, open **AI assistant**, select a provider, choose an available model, enter your API key, and press **Test model connectivity**. Or configure `GROQ_API_KEY`, `OPENROUTER_API_KEY`, or `LLM_API_BASE/LLM_API_MODEL/LLM_API_KEY` on the server. No free-tier quota or model availability is guaranteed. Hosted prompts leave your lab. Keys are never intentionally persisted to evidence; do not put secrets into prompts or scan output.

The assistant interprets evidence and suggests next steps. **Chat does not execute tools.** Active tests are launched explicitly from **Test target** or **Lab exercises**, or through the scoped MCP gateway.

## Your lab

HANZO on Kali `10.20.39.14`; HELPAG/IIS `.11`; Splunk `.13`; AD `.10`; Linux `.12`; pfSense `.15`.

```bash
export HANZO_LAB_TARGET=http://10.20.39.11:8080
# Optional; set the real token privately, never in Git:
export HANZO_SPLUNK_HEC_URL=https://10.20.39.13:8088/services/collector/event
export HANZO_SPLUNK_INDEX=vapt_lab
bash start_vapt_agent.sh
```

The existing companion is [HELPAG-VAPT-Test-Site](https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site): Flask/Waitress behind IIS, with synthetic training data, JSON events, Burp guide, IIS deployment instructions, and Splunk sample searches. **Never expose that deliberately vulnerable website publicly.** Validate its IIS service account and network isolation before running it.

Your lab is not deployed or scanned by the bootstrap. Lab exercise requests run only after your authorization and only against the server-configured HELPAG origin. Its legacy `X-Lab-Test-ID` field correlates with HANZO's report ID.

## Verify and operate

```bash
.venv311/bin/python -m unittest discover -s tests -v
node --test tests/test_*ui.js
.venv311/bin/python scripts/validate_integrations.py
.venv311/bin/python scripts/validate_stack.py --inference
.venv311/bin/python scripts/validate_gateway.py
```

The last command requires the local API and configured Ollama model to be running. Cloud connectivity needs your own valid credentials. An unavailable optional service is reported, not treated as online.

- [Page-by-page operator guide](docs/PAGE_GUIDE.md)
- [Kali deployment and lab configuration](docs/LAB_DEPLOYMENT.md)
- [Integration readiness and installation](docs/INTEGRATION_READINESS.md)
- [API and MCP architecture](docs/CENTRAL_REDTEAM_HUB.md)
- [Validation record and remaining checks](docs/VALIDATION_REPORT.md)
- [Continuation notes for another coding agent](CONTINUATION.md)
- [Progress checkpoint](docs/PROGRESS.md) and [remaining plan](PROJECT_PLAN.md)
- [Claude entry point](CLAUDE.md)

## Data and source hygiene

`.env`, keys, virtual environments, models, tool binaries, third-party clones, logs, and `.hanzo-data` are excluded from Git. SQLite is free, local, and requires no separate database server. Back up `.hanzo-data` privately; exported evidence may contain target information.

This is an operator-reviewed lab release, not a claim of zero defects or complete coverage of every upstream HexStrike route. Scope confirmations do not replace written permission or isolation.
