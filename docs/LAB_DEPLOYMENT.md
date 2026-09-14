# Clone and run HANZO on Kali

This guide does not deploy or test IIS/Splunk. Those already exist in your lab; you operate the tests yourself.

## 1. Prerequisites and bootstrap
Use a non-root Kali account. Provide several GB of free disk for the core; larger frameworks/model images can consume much more than your 40 GB Kali allocation. Do not install everything on the laptop.

```bash
sudo apt-get update
sudo apt-get install -y git curl pipx
pipx install uv
export PATH="$HOME/.local/bin:$PATH"
git clone https://github.com/DrHayabusa/hanzo.git
cd hanzo
bash scripts/setup_kali.sh --all-sources
bash scripts/install_kali_arsenal.sh --core
```

The public repository needs no authentication to clone; never paste tokens into remote URLs. If Python 3.11 exists, bootstrap uses it. Otherwise uv creates a Python 3.11 environment. Optional --all-sources clones the locked repositories but only installs core CVE/BugHunter runtimes.

Installer output is authoritative: unsupported packages stay unavailable. Run --full only after reviewing the package list and disk requirements. Package repositories change; the installer must be validated on your exact Kali release. It has not been executed on this macOS laptop.

## 2. Start locally
```bash
export HANZO_LAB_TARGET=http://10.20.39.11:8080
bash start_vapt_agent.sh
```

Open http://127.0.0.1:8888 in Kali. Keep the terminal running. Ctrl-C stops the agent and any Ollama process this launcher itself started, not an existing Ollama system service.

For another machine's browser, tunnel into Kali:
```bash
ssh -N -L 8888:127.0.0.1:8888 kali-user@10.20.39.14
```
Then open http://127.0.0.1:8888 on that machine. Do not expose the raw command/file API on a public or untrusted interface. This is a trusted single-operator service, not an authenticated multi-user portal.

## 3. AI
Follow [Ollama's official Linux setup](https://docs.ollama.com/linux), then run ollama pull qwen3:1.7b. Confirm the Ollama service is active before inference. HANZO uses OLLAMA_URL and OLLAMA_MODEL. An existing separate lab Ollama server is supported; keep its port private.

With 2 vCPU / 4 GB RAM assigned to Kali, a small model or separate AI host is preferable. The listed VM allocations consume 26 GB before AD and host overhead, so the physical 32 GB host is tight. Avoid running all optional agent containers and a larger LLM simultaneously.

Cloud alternatives are configured in AI assistant. [Groq's compatible API](https://console.groq.com/docs/openai) and [OpenRouter's free variants](https://openrouter.ai/docs/guides/routing/model-variants/free) have provider-specific model/usage constraints. No “free forever” guarantee. Use real credentials and press the connectivity test button. HANZO_SKIP_OLLAMA=1 disables automatic local Ollama startup for a cloud-only configuration.

.env.example is documentation: the launcher does not automatically source it. Set variables in the process environment, or use a protected service EnvironmentFile. Never commit credentials.

## 4. Lab mapping
| Role | Address |
| --- | --- |
| AD/DHCP | 10.20.39.10 |
| IIS HELPAG target | 10.20.39.11:8080 |
| Linux services | 10.20.39.12 |
| Splunk | 10.20.39.13 |
| Kali / HANZO | 10.20.39.14 |
| pfSense | 10.20.39.15 |

Physical host: Windows, 16 cores, 32 GB, 1 TB. The Lab network page is optional. Set VAPT_LAB_* variables in lab_topology.py to override defaults.

## 5. Companion website and events
Use the separate [HELPAG repository](https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site). It is Flask + Waitress on loopback:5005 reverse-proxied by IIS on :8080, not ASP.NET. Its WINDOWS_IIS_DEPLOYMENT_GUIDE.md and BURP_SUITE_TEST_GUIDE.md cover deployment and manual exercises.

Before exposing it inside the lab, restrict firewall routes, use synthetic data, snapshots, and a dedicated low-privilege process account. Review the existing installer: it uses a scheduled task and must not run the deliberately vulnerable app as SYSTEM. Some fixture behaviors are intentionally unsafe; never publish that site.

HANZO's fixed exercise runner accepts the companion's current X-Lab-Only health marker or explicit app identity. It sends X-Lab-Test-ID plus X-Hanzo-Correlation-Id. The current companion stores test_id; it may not echo the new header. Reports distinguish sent correlation from confirmed response echo.

## 6. Optional HEC
Set HANZO_SPLUNK_HEC_URL to https://10.20.39.13:8088/services/collector/event, HANZO_SPLUNK_HEC_TOKEN privately, and HANZO_SPLUNK_INDEX=vapt_lab. TLS verification is enabled by default; install/trust the lab CA rather than disabling validation.

HANZO sends its own summary event as hanzo:exercise:json. The companion's application JSONL uses helpag:owasp:json. Configure the companion forwarder/direct HEC independently. Avoid double-ingesting the same application events. IIS W3C, Windows Security, PowerShell, and Sysmon logs require their own Universal Forwarder inputs; HEC from HANZO does not collect them.

Run an exercise in your lab and use its generated search to match correlation_id OR test_id. Confirm event types, timestamps, sourcetypes, index, and saved-search alert firing yourself. HANZO reports delivery acceptance only.

## 7. Validate on your worker
```bash
.venv311/bin/python -m unittest discover -s tests -v
.venv311/bin/python scripts/validate_integrations.py
.venv311/bin/python scripts/validate_stack.py --inference
```

Use Security tools and MCP servers to inspect actual readiness. Test your own target stages during the authorized change window. Keep backups of .hanzo-data outside Git.
