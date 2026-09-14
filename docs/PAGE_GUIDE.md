# HANZO page guide

## Overview
Live API status, installed executable count, managed jobs, uptime, local integration readiness, and recent SQLite evidence. Empty history is deliberately empty, not sample engagements. Enter an IP/URL/CVE and choose New assessment to move that scope to Test target.

## Test target
Scope is one website URL, hostname, IP, or CVE ID. Profile is the default. Choose Recon, BugHunter classify, CVE intelligence, Validate, or Full workflow. Active scanner stages need the authorization checkbox. The tool limit bounds selected tools, not every request a tool makes. Watch Running jobs, and preserve results in Reports. Full workflow is a fixed adapter sequence, not unrestricted autonomous LLM execution.

## Lab exercises
Select one of seven fixed HELPAG exercises or the suite. The target is read-only in the UI and configured using HANZO_LAB_TARGET. The runner validates a private/loopback origin, confirms the companion's lab identity, refuses redirects, caps response size, and allows one exercise run at a time. The suite contains ten exercise requests plus a health check. Expected vulnerable fixture behavior is labeled Observed—not “secure.” Existing companion logs receive X-Lab-Test-ID; the report includes a matching Splunk search. No lab request is made just by opening this page.

The HEC probe button sends a benign test event only when configured and clicked. An HEC acknowledgement is not proof of event indexing or detection firing.

## Reports
Workflow and lab exercise history persists in SQLite. View evidence, download JSON, or download a lab exercise Markdown report with findings, remediation, correlation ID, and expected event types. The list currently shows up to 30 of each run type. Raw evidence is a technical report; findings are not magically deduplicated or independently verified.

## Lab network
Optional configuration map for 10.20.39.0/24. Initial load is read-only. Probe configured services deliberately performs bounded TCP checks when clicked. Reachability is not authentication or health validation. The Kali node represents the intended worker role, not proof the laptop has address .14.

## MCP servers
Native HexStrike, real CVE MCP, and BugHunter CLI are the connected core. Validate connections performs protocol/CLI checks. Other supplied projects are inventory entries with source paths and links; installed or TCP reachable is not an execution bridge. Those cards explicitly identify external runtimes.

The Your MCP servers panel reads private host configuration. Connect & discover runs a real handshake, exposes schemas, then allows selection of exact server-allowlisted tools. Review JSON arguments, confirm scope and run; evidence is saved locally. No optional server is automatically probed just by viewing the page. Follow OPTIONAL_MCP.md for setup.

## Security tools

The HexStrike command launcher contains all 90 bundled tool POST routes across 10 categories. Select Category → Command, fill the generated arguments, review the exact JSON request and authorize the operation. Missing executables cannot launch from this form. Unknown composite runtime status requires review. Conditional options are still validated by the adapter. Command output is persisted in Reports and downloadable as JSON; failures remain failures.
Filter by command or category. Green means executable present on PATH. Run the Kali installer to install supported packages, then refresh. Some entries are commercial tools, library names, wrappers, or require external services; not every entry can be made runnable by apt. No package installation happens from viewing this page.

## Running jobs
Lists scanner processes managed by HexStrike, not every OS process. Terminate requests confirmation and stops a managed job. This is separate from the fixed HTTP exercise runner.

## AI assistant
Choose Ollama, Groq, OpenRouter, or a compatible API. Enter provider/model/key and use Test model connectivity to generate a real response. Server environment keys are also supported. Browser keys clear on reload and provider change. Chat is advisory: it does not execute scanners. Attach assessment is opt-in because cloud inference transmits that evidence outside the lab.

Keyboard focus is visible, navigation remains accessible on narrower screens, and reduced-motion preference is respected. All visual assets/fonts work without a CDN.
