# HANZO coding-agent entry point
Continue the existing personal authorized lab project; do not rebuild from scratch.

Read CONTINUATION.md, PROJECT_PLAN.md, docs/PROGRESS.md, docs/VALIDATION_REPORT.md and README.md. They contain intent, architecture, source map, setup, lab details, measured results and remaining work.

Priority: HANZO tool first; CTF/IIS website deferred. Preserve compact ninja branding, black/gold/restrained-red UI and upstream LICENSE/attribution. Use a feature branch, preserve user edits, and update progress/test evidence with commits.

Never commit .env, keys, models, third-party checkouts or .hanzo-data. Never fake online status or launch active lab scans during bootstrap. Keep loopback/unprivileged operation.

Checks: Python 3.11 unittest discovery, node --test tests/test_*ui.js, pip check, scripts/doctor.py. Exact commands and external prerequisites are in CONTINUATION.md.
