# HANZO validation record
2026-09-15 (Asia/Dubai). Development host macOS; intended deployment Kali. No remote IIS/Splunk execution claimed.

| Check actually run | Result | Boundary |
| --- | --- | --- |
| Python unittest discovery | PASS — 182 tests | API, evidence, synthetic lab transport, installers, MCP, scope |
| Node UI regressions | PASS — 34 tests | Workflows, provider states, command fields/dropdowns/confirmation/errors |
| pip check | PASS | Existing Python 3.11 core environment |
| JS/shell syntax | PASS | Three UI scripts and startup/bootstrap/installers |
| Tool catalog coverage | PASS — 90/90 POST routes, 10 groups | Metadata coverage, not 90 real scanner executions |
| Optional MCP stdio fixture | PASS | Real temporary initialize/list/schema/allowlisted echo call |
| Optional HTTP transports | PASS with mocks | SSE/Streamable HTTP wiring, not actual Burp/Decepticon |
| Source lock checks | PASS — eight pinned checkouts | Source status, not service deployment |
| Target pre-flight | PASS — 15 tests | One TCP connect plus an HTTP HEAD; never a scan |
| Engagement stage catalog | PASS — 15 tests | 19 stages across 8 groups, each reporting this worker's real readiness |
| Finding extraction and narrative | PASS — 18 tests | Findings parsed in Python; the model narrates only those facts and invented paths are flagged |
| Markdown export | PASS — 7 tests | Table escaping verified against the real exporter, not a copy of it |
| Path quoting regression | PASS — 5 tests | Guards the shell=True command strings against paths with spaces |
| macOS arsenal install | PASS — 18 tools verified on PATH | Prebuilt binaries preferred; source builds are opt-in |
| MCP adapter onboarding | PASS — 113 tools listed over stdio | 90 generated adapters + 23 control tools; schemas are real, execution still needs the binary |
| MCP authorization gate | PASS | `run_nmap` without `authorization_confirmed` refuses and never calls the worker |
| MCP readiness gate | PASS | An absent binary refuses with an install instruction instead of a confusing tool error |
| Wordlist discovery | PASS — 429 real files grouped | Files found on disk; a wordlist is never invented |

Additional regression coverage: missing/changed config, exact allowlists, confirmation, pagination, timeouts, secret redaction and size limits; HTTP bridge persistence/error handling; automated scan target injection/max_tools guards; clear failure if no suitable executable. This is not a complete audit of all legacy routes.

## Live checks

Independent Linux CI passed on GitHub for release commit `9d5ab5c`: Python 3.11 dependency installation, pip check, the complete Python suite, shell syntax and JavaScript tests. [Verified run](https://github.com/DrHayabusa/hanzo/actions/runs/34891565022). This is Ubuntu CI, not an actual Kali arsenal installation.
- CVE: actual initialize/list discovered **28 tools**; intelligence lookup exercised.
- BugHunter: CLI self-test, **83 skills / 15 commands**, synthetic URL classification. Classification does not scan the URL.
- Ollama: model discovery and real **qwen3:1.7b** generation.
- Central MCP: real initialize/list and catalog call through the running API; the facade exports **113 tools**.
- Browser: real dropdown selection and xxd read of **64 bytes of local README**, exit 0, returned output and persisted evidence.
- MCP stdio: real `initialize`/`list_tools` returning **113 tools**; a real `run_security_tool` xxd call returned exit 0 and actual stdout.
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

## Session of 2026-09-15: migration and arsenal

The project now runs from an external volume at `/Volumes/shuaibs/Shahid project/hanzo`
because the boot disk was full. The venv, Ollama models, pinned integration sources,
wordlists and `tools/bin` all live there; only Homebrew formulas remain on the boot
volume, since Homebrew always installs into `/opt/homebrew`.

Measured after the move:
- 148 Python tests and 27 JavaScript tests pass from the new location.
- **49 of 90 adapters ready, 48 executables present** (11 at the start of the session).
- Real runs against an authorized local sample site (127.0.0.1:5005, Flask in Docker):
  `httpx` returned 200 with title and `Flask:3.1.8,Python:3.11.16`; `gobuster` with a
  SecLists wordlist returned **14 findings**, including an exposed `.env` (200),
  `admin` (403) and `backups` (308). `katana` and `feroxbuster` also returned real output.
- Local `qwen3:1.7b` inference, CVE MCP, and the BugHunter CLI (83 skills) all work
  from the new location.

Fixed this session:
- `/api/tools/httpx` built `httpx -l <target>`; `-l` reads a FILE of targets, so every
  single-URL probe failed. It now picks `-u` for a host or URL and `-l` only for a file.
- `hexstrike_mcp.py` defined `httpx_probe` twice; the second silently shadowed the first
  and sent parameters the server never reads.
- Adapters interpolated filesystem paths into `shell=True` command strings unquoted, so
  any path containing a space split into separate arguments. 41 command-building lines
  now shell-quote path parameters. This surfaced immediately because the project
  directory itself contains a space.
- The macOS installer linked every console script from its tools venv into `tools/bin`,
  which replaced the real ProjectDiscovery `httpx` binary with the Python httpx library's
  CLI. It now links only the scripts a package declares and never overwrites a real binary.

## Accuracy check against the operator's sample site (2026-09-16)

The site at 127.0.0.1:5005 ("Meridian Freight Solutions") is a deliberately
vulnerable Flask lab target in Docker. Every reported finding was re-fetched
independently with curl and compared on both status code and byte size.

**gobuster, 4,751-word list: 14 findings, 14 exact matches, 0 false positives.**
Status code and response size agreed on every row, including `/.env` (200, 262 B),
`/admin` (403), `/backups` (308 → `/backups/`), `/uploads` (308) and `/portal`
(302 → `/portal/login`).

**False-negative check.** `robots.txt` discloses `/internal/` and `/status/`.
Both words are present in the wordlist and both actually return 404, so gobuster
was right to omit them: they are decoys, not misses. What gobuster genuinely did
not reach were second-level paths (`/portal/login`, `/services/quote`), which a
non-recursive directory scan cannot find by design.

**katana, depth 3: 14 URLs, all genuine.** It recovered exactly the second-level
paths gobuster could not, plus `/api/v1/shipments/`, which is referenced from
JavaScript as `fetch('/api/v1/shipments/' + reference)`. A bare request to that
path returns 404, but the route is real: it answers with
`{"error":"Consignment not found."}` rather than the site's HTML 404 page. A
status-code check alone would have wrongly called it a false positive.

The two tools are complementary: brute force finds unlinked paths, the crawler
finds linked and parameterised ones. Neither is complete alone, and HANZO does not
present either as complete.

**Confirmed real exposures on the lab target:** `/.env` served in plain text with
signing keys and an AWS-style key id; `/backups/` with directory listing including
`meridian-db-export.sql`; `/uploads/` with directory listing including `cv.php`.

## Known environment limits observed here
The boot disk filled twice during this session. Homebrew on macOS 13 is a Tier 3 configuration and compiles
many formulas from source, which is slow and exhausts a full disk; the installer therefore prefers prebuilt
release binaries into `tools/bin` and keeps its download and build caches on the project volume, and it stops
before the boot volume drops below 1.2 GB. The sample site is a single-threaded container: a 10-thread gobuster
run plus a concurrent sqlmap saturated it and Docker itself stopped responding while the disk was full. That is
a property of the target and the host, not of HANZO.

## Not certified
Fresh actual Kali installation; all 90 real tool operations; all external frameworks; live Burp/Decepticon; cloud inference without credentials; IIS/Splunk forwarding/indexing/detection; production auth/isolation; exhaustive dependency security or load testing; zero defects.

HEC acceptance is not detection verification. Destination acceptance and hardening are in PROJECT_PLAN.md. CI configuration is included; check the actual GitHub Actions result for independent Linux validation.
