# HANZO plan and acceptance criteria
Updated 2026-09-15. Tool first; website deferred.

## Delivered source baseline
- [x] Nine-page black/gold/red HANZO workspace.
- [x] All 90 bundled tool POST routes categorized into 10 GUI groups, typed fields, request preview, explicit confirmation, returned/persisted evidence.
- [x] Real CVE stdio and BugHunter CLI bridges; pinned third-party sources.
- [x] Ollama and cloud provider controls with explicit inference checks.
- [x] Optional MCP stdio/SSE/Streamable HTTP discovery and exact allowlisted invocation.
- [x] SQLite reports, truthful failed/partial outcomes, lab configuration and fixed exercises/HEC adapter.
- [x] Kali installers, dirty-source protection, doctor, tests, CI config, operator/Claude handoff.

## Priority 1: user's Kali acceptance
- [ ] Fresh unprivileged Kali bootstrap; retain package, dependency and doctor reports.
- [ ] Install required core/full arsenal and resolve actual missing dependencies, versions, credentials and wordlists.
- [ ] One harmless help/version check plus an appropriate fixture operation per desired adapter.
- [ ] Real model test on destination Ollama or chosen cloud key/model.
- [ ] Real Burp/optional MCP initialize/list and reviewed read-only call.
- [ ] Confirm lab isolation and scope before active testing.
- [ ] User later verifies IIS logs, HEC/indexing and saved-search firing.

A cloned source or green binary indicator does not satisfy runtime acceptance.

## Priority 2: stronger tool coverage/hardening
- [ ] Replace legacy shell strings with reviewed argv adapters by tool family; preserve legitimate advanced options.
- [ ] Per-command schema overrides for conditional actions, enums, sensitive fields, ranges and multi-field requirements.
- [ ] Linux fixture tests for all 90 routes, including invalid input, cancellation and failure.
- [ ] Normalize findings and distinguish output-keyword candidates from confirmed vulnerabilities.
- [ ] Authentication, server-side scope on every execution route and sandboxed workers before non-loopback/shared use.
- [ ] Review dependency security and full transitive locking; update legacy proxy constraints with compatibility tests.
- [ ] Durable job queue, resource budgets, cancellation and restart recovery.
- [ ] Report pagination, retention and redaction review.
- [ ] If requested: bounded LLM tool loop with approvals, scope, exact allowlist, step/time budgets and audit evidence. Current chat is advisory.

## Priority 3: independent frameworks
Use locked source manifest. Deploy Strix/PentAGI/PentestGPT/CAI/Decepticon/Shannon only on suitable hardware following each runtime/license. Add typed bridges only when useful or configure actual MCP services. Never equate a TCP socket or CLI with an MCP server.

## Deferred: test-website
Inspect existing HELPAG site. Prepare synthetic CTF challenges, Windows/IIS deployment, full Burp guide, expected logs/Splunk searches, reset and isolation controls. Publish separately only after tool delivery.

## Done per change
Run relevant Python/JS tests, safe smoke test where feasible, document untested prerequisites, update progress/validation/handoff, scan staged files for secrets, commit and push. Never hide failed evidence or declare every integration ready without protocol/operation proof.
