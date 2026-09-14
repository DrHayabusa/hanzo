# HANZO validation record
2026-09-15 (Asia/Dubai). Development host macOS; intended deployment Kali. No remote IIS/Splunk execution claimed.

| Check actually run | Result | Boundary |
| --- | --- | --- |
| Python unittest discovery | PASS — 129 tests | API, evidence, synthetic lab transport, installers, MCP, scope |
| Node UI regressions | PASS — 27 tests | Workflows, provider states, command fields/dropdowns/confirmation/errors |
| pip check | PASS | Existing Python 3.11 core environment |
| JS/shell syntax | PASS | Three UI scripts and startup/bootstrap/installers |
| Tool catalog coverage | PASS — 90/90 POST routes, 10 groups | Metadata coverage, not 90 real scanner executions |
| Optional MCP stdio fixture | PASS | Real temporary initialize/list/schema/allowlisted echo call |
| Optional HTTP transports | PASS with mocks | SSE/Streamable HTTP wiring, not actual Burp/Decepticon |
| Source lock checks | PASS — eight pinned checkouts | Source status, not service deployment |
| MCP adapter onboarding | PASS — 110 tools listed over stdio | 90 generated adapters + 20 control tools; schemas are real, execution still needs the binary |
| MCP authorization gate | PASS | `run_nmap` without `authorization_confirmed` refuses and never calls the worker |
| MCP readiness gate | PASS | An absent binary refuses with an install instruction instead of a confusing tool error |
| Wordlist discovery | PASS — 424 real files grouped | Files found on disk; a wordlist is never invented |

Additional regression coverage: missing/changed config, exact allowlists, confirmation, pagination, timeouts, secret redaction and size limits; HTTP bridge persistence/error handling; automated scan target injection/max_tools guards; clear failure if no suitable executable. This is not a complete audit of all legacy routes.

## Live checks

Independent Linux CI passed on GitHub for release commit `9d5ab5c`: Python 3.11 dependency installation, pip check, the complete Python suite, shell syntax and JavaScript tests. [Verified run](https://github.com/DrHayabusa/hanzo/actions/runs/34891565022). This is Ubuntu CI, not an actual Kali arsenal installation.
- CVE: actual initialize/list discovered **28 tools**; intelligence lookup exercised.
- BugHunter: CLI self-test, **83 skills / 15 commands**, synthetic URL classification. Classification does not scan the URL.
- Ollama: model discovery and real **qwen3:1.7b** generation.
- Central MCP: real initialize/list and catalog call through the running API; the facade exports **110 tools**.
- Browser: real dropdown selection and xxd read of **64 bytes of local README**, exit 0, returned output and persisted evidence.
- MCP stdio: real `initialize`/`list_tools` returning **110 tools**; a real `run_security_tool` xxd call returned exit 0 and actual stdout.
- Tool adapters against an operator-supplied local sample site (127.0.0.1:5005, Docker): **gobuster** with a SecLists
  wordlist returned exit 0 and real findings (.env 200, admin 403, backups 308); **katana** crawled and returned JSON;
  **httpx** returned 200 with title and Flask/Python fingerprint after the adapter fix below.
- Fixed: `/api/tools/httpx` built `httpx -l <target>` (`-l` reads a FILE of targets), so a single URL always failed.
  It now selects `-u` for a host or URL and `-l` only for an existing file.
- Fixed: `hexstrike_mcp.py` defined `httpx_probe` twice; the second definition silently shadowed the first and sent
  parameters the server never reads, so the MCP httpx tool never received a target.
- Report deletion: a throwaway run was created, deleted (`remaining` decremented) and an unknown id returned 404.
- Inventory: **11 of 90 adapters** had their executable present on this Mac during the last check; missing
  dependencies stay visible and readiness updates live when a tool is installed (sqlmap and nikto appeared mid-session).
- UI, assessment, integrations and reports inspected locally; assets served locally.

## Reproduce
```bash
.venv311/bin/python -m unittest discover -s tests -v
node --test tests/test_*ui.js
.venv311/bin/pip check
.venv311/bin/python scripts/doctor.py --json --strict
.venv311/bin/python scripts/sync_integrations.py --check
.venv311/bin/python scripts/validate_integrations.py
# API and configured Ollama must be running for these:
.venv311/bin/python scripts/validate_stack.py --inference
.venv311/bin/python scripts/validate_gateway.py
```

## Known environment limits observed here
The development Mac ran out of disk during the SecLists clone; the checkout was trimmed to 424 usable lists and
`wordlists/` is gitignored. The sample site is a single-threaded container: a 10-thread gobuster run plus a
concurrent sqlmap saturated it and it stopped responding. That is a property of the target, not of HANZO.

## Not certified
Fresh actual Kali installation; all 90 real tool operations; all external frameworks; live Burp/Decepticon; cloud inference without credentials; IIS/Splunk forwarding/indexing/detection; production auth/isolation; exhaustive dependency security or load testing; zero defects.

HEC acceptance is not detection verification. Destination acceptance and hardening are in PROJECT_PLAN.md. CI configuration is included; check the actual GitHub Actions result for independent Linux validation.
