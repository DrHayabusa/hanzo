# Integration readiness

The supplied source list is represented by integrations.lock.json. Sources were cloned and core bridges exercised locally. Do not equate a git clone with runtime integration.

| System | HANZO support | Remaining setup |
| --- | --- | --- |
| HexStrike | Embedded server + scanner API + MCP | Install binaries on Kali; target-specific credentials/options |
| CVE MCP | Isolated Python stdio client; initialize/list/call | Core installer; Internet access for upstream intelligence; optional source API keys |
| Claude-BugHunter | Isolated cbh CLI, classification/skills | Core installer; Claude workflow usage is separate from CLI classification |
| Burp MCP | Optional protocol bridge supports discovery and exact allowlisted GUI calls | Running Burp + PortSwigger extension and private matching configuration; not live-tested here |
| Strix | Locked source inventory | Its sandbox/runtime, provider credentials and separate CLI invocation |
| PentAGI | Locked source + endpoint TCP check | Its Docker services and credentials; TCP reachability is not API integration |
| PentestGPT | Locked source inventory | Its CLI/runtime and model configuration |
| CAI | Locked source inventory | Its agent/MCP-client configuration and dependencies |
| Decepticon | Locked source inventory | Python 3.13, sandbox/management services, its MCP configuration |
| Shannon | Locked source inventory | Its container runtime, target source, and supported model credentials |

Source URLs and exact revisions are in the manifest. To reproduce: bash scripts/install_integrations.sh --all. No optional service is automatically started. Source synchronization refuses conflicting remotes and dirty checkouts before switching revisions.

## Status semantics
- online: native engine or successful core MCP handshake.
- ready: core CLI self-test succeeded.
- executable found: an optional command is on PATH; it has not been invoked/validated.
- TCP reachable: socket connection only, not protocol, authentication, or tool-call verification.
- source cloned: files exist but runtime is not configured.
- needs setup / not installed / error: actionable missing or failing state.

Core readiness is three adapters, not a claim that all registered frameworks are callable. The common facade exports native scope/scan helpers, CVE triage, BugHunter classification, history, lab catalog and configured optional MCP operations. The optional bridge supports stdio, SSE and Streamable HTTP; see [setup and allowlisting](OPTIONAL_MCP.md). Standalone CLIs are not automatically compatible MCP servers.

## Tool inventory
The scanner matrix comes from HexStrike. Several upstream entries name libraries, aliases, vendor GUIs, or specialist utilities rather than a standard Kali command. You should not create fake executables or green statuses to satisfy a count. Use the installer report, official tool instructions, and validate the tools your lab cases actually use.

The script's --full package profile installs available additional packages; it does not license commercial tools, supply cloud credentials, deploy Burp, or provision container services.
