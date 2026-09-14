"""Bounded HELPAG lab exercises with correlated, persistent detection evidence.

Only the server-configured companion origin can receive requests. Every exercise
uses a fixed request sequence; this module never invokes scanners or a shell.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import requests
from flask import Blueprint, Response, jsonify, request

from hanzo_store import HanzoStore


EXERCISES = [
    {"id": "recon_headers", "name": "Surface & headers", "phase": "recon", "owasp": "A05:2021",
     "description": "Inspect the lab landing page and response security headers.",
     "expected_events": ["http_request"], "request_count": 1},
    {"id": "auth_failures", "name": "Failed sign-ins", "phase": "validate", "owasp": "A07:2021",
     "description": "Send three fixed invalid lab logins to exercise the authentication alert.",
     "expected_events": ["authentication_attempt"], "request_count": 3},
    {"id": "idor", "name": "Object access", "phase": "validate", "owasp": "A01:2021",
     "description": "Request one synthetic user record without a login.",
     "expected_events": ["broken_access_attempt"], "request_count": 1},
    {"id": "sqli", "name": "SQL input validation", "phase": "validate", "owasp": "A03:2021",
     "description": "Compare a normal product search with one fixed SQL injection test input.",
     "expected_events": ["sql_query"], "request_count": 2},
    {"id": "xss", "name": "Reflected input", "phase": "validate", "owasp": "A03:2021",
     "description": "Check reflection of a harmless HTML marker; no script is executed.",
     "expected_events": ["xss_probe"], "request_count": 1},
    {"id": "business_logic", "name": "Checkout rules", "phase": "validate", "owasp": "A04:2021",
     "description": "Submit one negative-quantity synthetic checkout.",
     "expected_events": ["business_logic_abuse"], "request_count": 1},
    {"id": "integrity", "name": "Unsigned preferences", "phase": "validate", "owasp": "A08:2021",
     "description": "Check whether the demo accepts an unsigned synthetic role preference.",
     "expected_events": ["unsigned_data_import"], "request_count": 1},
]
CATALOG = {item["id"]: item for item in EXERCISES}


def configured_target() -> str:
    return os.environ.get("HANZO_LAB_TARGET", "http://10.20.39.11:8080").rstrip("/")


def origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (ValueError, TypeError) as exc:
        raise ValueError("Target must be a valid HTTP(S) origin.") from exc
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        raise ValueError("Use a website origin, with no credentials, path, query or fragment.")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if port and port != (443 if parsed.scheme == "https" else 80):
        host += f":{port}"
    return urlunsplit((parsed.scheme, host, "", "", ""))


def validate_target(value: str) -> str:
    target = origin(value)
    if target != origin(configured_target()):
        raise ValueError("Target must match HANZO_LAB_TARGET configured on the agent server.")
    parsed = urlsplit(target)
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 80, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("The configured lab hostname could not be resolved.") from exc
    if not addresses:
        raise ValueError("The configured lab hostname has no address.")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0].split("%")[0])
        if (not (ip.is_private or ip.is_loopback) or ip.is_link_local or ip.is_multicast
                or ip.is_unspecified or ip.is_reserved):
            raise ValueError("The HELPAG runner requires a private lab or loopback address.")
    return target


class SplunkTelemetry:
    def __init__(self):
        self.last_delivery = None
        self.lock = threading.Lock()

    @staticmethod
    def _settings():
        raw_url = os.getenv("HANZO_SPLUNK_HEC_URL", os.getenv("SPLUNK_HEC_URL", "")).strip()
        token = os.getenv("HANZO_SPLUNK_HEC_TOKEN", os.getenv("SPLUNK_HEC_TOKEN", "")).strip()
        index = os.getenv("HANZO_SPLUNK_INDEX", os.getenv("SPLUNK_INDEX", "vapt_lab"))
        verify = os.getenv("HANZO_SPLUNK_VERIFY_TLS", os.getenv("SPLUNK_VERIFY_TLS", "true")).lower() != "false"
        if not raw_url:
            return "", token, index, verify
        parsed = urlsplit(raw_url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("HEC URL must be HTTP(S) without credentials, query or fragment.")
        path = parsed.path.rstrip("/")
        if path in {"", "/services/collector"}:
            path = "/services/collector/event"
        if path != "/services/collector/event":
            raise ValueError("HEC URL must use /services/collector/event.")
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", "")), token, index, verify

    def status(self):
        try:
            url, token, index, verify = self._settings()
            configured = bool(url and token)
            with self.lock:
                last = self.last_delivery
            return {"configured": configured, "endpoint": url, "index": index,
                    "verify_tls": verify, "token_configured": bool(token),
                    "state": last["status"] if configured and last else ("untested" if configured else "not_configured"),
                    "last_delivery": last, "detection_verified": False,
                    "note": "HEC acceptance confirms delivery only. Validate indexed events and alert firing in Splunk."}
        except ValueError as exc:
            return {"configured": False, "state": "invalid_config", "error": str(exc),
                    "detection_verified": False, "last_delivery": None}

    def send(self, event):
        try:
            url, token, index, verify = self._settings()
        except ValueError as exc:
            return {"status": "invalid_config", "accepted": False, "error": str(exc)}
        if not url or not token:
            return {"status": "not_configured", "accepted": False,
                    "message": "Set HANZO_SPLUNK_HEC_URL and HANZO_SPLUNK_HEC_TOKEN on the agent server."}
        delivery = {"status": "failed", "accepted": False,
                    "correlation_id": event["correlation_id"],
                    "at": datetime.now(timezone.utc).isoformat(), "detection_verified": False}
        try:
            with requests.Session() as client:
                client.trust_env = False
                response = client.post(
                    url, headers={"Authorization": f"Splunk {token}"},
                    json={"time": time.time(), "host": "hanzo", "source": "hanzo-agent",
                          "sourcetype": "hanzo:exercise:json", "index": index, "event": event},
                    timeout=(3, 5), verify=verify, allow_redirects=False,
                )
            response.raise_for_status()
            body = response.json()
            if response.status_code == 200 and body.get("code") == 0:
                delivery.update(status="accepted", accepted=True,
                                message="Splunk HEC accepted the event; indexing and alert firing still require verification.")
            else:
                delivery["error"] = "Splunk HEC did not acknowledge the event with code 0."
        except (requests.RequestException, ValueError, TypeError):
            delivery["error"] = "HEC delivery failed. Check endpoint, token, index and TLS settings on the server."
        with self.lock:
            self.last_delivery = delivery
        return delivery


class LabExerciseRunner:
    def __init__(self, store: HanzoStore, telemetry: SplunkTelemetry):
        self.store = store
        self.telemetry = telemetry
        self.lock = threading.Lock()

    @staticmethod
    def _request(client, target, method, path, **kwargs):
        started = time.monotonic()
        with client.request(method, target + path, timeout=(3, 5), allow_redirects=False,
                            stream=True, **kwargs) as response:
            parts = []
            length = 0
            for part in response.iter_content(chunk_size=4096):
                length += len(part)
                if length > 262144:
                    raise ValueError("The companion returned a response exceeding the evidence limit.")
                parts.append(part)
            text = b"".join(parts).decode("utf-8", errors="replace")
            import json
            try:
                body = json.loads(text)
            except ValueError:
                body = {}
            return {"status_code": response.status_code, "body": body, "text": text,
                    "headers": dict(response.headers), "duration_ms": round((time.monotonic() - started) * 1000),
                    "path": path, "method": method}

    def run(self, exercise_id, target, authorized):
        if authorized is not True:
            raise PermissionError("Confirm authorization for the configured lab before running an exercise.")
        if exercise_id not in CATALOG and exercise_id != "full_suite":
            raise ValueError("Unknown lab exercise.")
        target = validate_target(target)
        if not self.lock.acquire(blocking=False):
            raise RuntimeError("Another lab exercise is running. Wait for it to finish.")
        try:
            return self._run(exercise_id, target)
        finally:
            self.lock.release()

    def _run(self, exercise_id, target):
        run_id = str(uuid.uuid4())
        correlation_id = "hanzo-" + uuid.uuid4().hex
        run = {"id": run_id, "correlation_id": correlation_id,
               "created_at": datetime.now(timezone.utc).isoformat(), "target": target,
               "exercise_id": exercise_id, "authorization_confirmed": True,
               "status": "failed", "checks": [], "findings": [], "request_count": 0,
               "detection_verified": False,
               "splunk_query": f'index={os.getenv("HANZO_SPLUNK_INDEX", "vapt_lab")} (correlation_id="{correlation_id}" OR test_id="{correlation_id}") | stats count by sourcetype event_type',
               "report_url": f"/api/lab/exercises/{run_id}/report"}
        selected = list(CATALOG) if exercise_id == "full_suite" else [exercise_id]
        try:
            with requests.Session() as client:
                client.trust_env = False
                client.headers.update({"User-Agent": "HANZO-Lab-Exercise/1.0",
                                       "X-Hanzo-Correlation-Id": correlation_id,
                                       "X-Lab-Test-ID": correlation_id,
                                       "X-Hanzo-Exercise-Id": exercise_id})
                health = self._request(client, target, "GET", "/health")
                run["request_count"] += 1
                body = health["body"]
                legacy_identity = "OWASP training target" in next(
                    (v for k, v in health["headers"].items() if k.lower() == "x-lab-only"), "")
                if (health["status_code"] != 200 or not isinstance(body, dict)
                        or not (body.get("app") == "helpag-vapt-test-site" or legacy_identity)
                        or body.get("lab_mode") is not True):
                    raise ValueError("Target did not identify as the enabled HELPAG companion. Update/start the lab site first.")
                for item in selected:
                    client.headers["X-Hanzo-Exercise-Id"] = item
                    check, count = self._exercise(client, target, item, correlation_id)
                    run["checks"].append(check)
                    run["request_count"] += count
                    if check.get("finding"):
                        run["findings"].append(check["finding"])
                run["status"] = "completed" if all(c["passed"] for c in run["checks"]) else "needs_review"
        except (requests.RequestException, ValueError, TypeError, KeyError) as exc:
            run["error"] = str(exc) if isinstance(exc, ValueError) else "Companion request failed. Verify the target service and lab network."
        event = {"event_type": "hanzo_exercise", "correlation_id": correlation_id,
                 "exercise_id": exercise_id, "run_id": run_id, "target": target,
                 "status": run["status"], "checks_passed": sum(c["passed"] for c in run["checks"]),
                 "checks_total": len(run["checks"]), "finding_count": len(run["findings"])}
        run["telemetry"] = self.telemetry.send(event)
        run["finished_at"] = datetime.now(timezone.utc).isoformat()
        self.store.record_exercise(run)
        return run

    def _exercise(self, client, target, exercise_id, correlation_id):
        responses = []

        def call(method, path, **kwargs):
            result = self._request(client, target, method, path, **kwargs)
            responses.append(result)
            return result

        catalog = CATALOG[exercise_id]
        check = {"exercise_id": exercise_id, "name": catalog["name"], "passed": False,
                 "owasp": catalog["owasp"], "expected_events": catalog["expected_events"]}
        finding = None
        if exercise_id == "recon_headers":
            response = call("GET", "/")
            headers = {k.lower(): v for k, v in response["headers"].items()}
            missing = [key for key in ("content-security-policy", "x-content-type-options", "x-frame-options") if key not in headers]
            check.update(passed=response["status_code"] == 200, observed={"missing_headers": missing})
            if missing:
                finding = ("Missing response security headers", "medium", ", ".join(missing), "Configure response security headers in the app or IIS.")
        elif exercise_id == "auth_failures":
            for _ in range(3):
                call("POST", "/api/login", json={"username": "hanzo-lab-invalid", "password": "invalid-lab-password"})
            passed = all(r["status_code"] == 401 and r["body"].get("authenticated") is False for r in responses)
            check.update(passed=passed, observed={"rejected_attempts": sum(r["status_code"] == 401 for r in responses)})
        elif exercise_id == "idor":
            response = call("GET", "/api/users/2")
            exposed = response["status_code"] == 200 and response["body"].get("id") == 2
            check.update(passed=exposed, observed={"synthetic_record_accessible": exposed})
            if exposed:
                finding = ("Synthetic user accessible without login", "high", "User 2 was returned to an unauthenticated request.", "Require authentication and enforce per-object ownership.")
        elif exercise_id == "sqli":
            baseline = call("GET", "/api/products/search", params={"q": "Security"})
            probe = call("GET", "/api/products/search", params={"q": "' OR 1=1--"})
            before = len(baseline["body"].get("results", []))
            after = len(probe["body"].get("results", []))
            expanded = baseline["status_code"] == 200 and probe["status_code"] == 200 and after > before
            check.update(passed=expanded, observed={"baseline_rows": before, "probe_rows": after})
            if expanded:
                finding = ("SQL input changes product query results", "high", f"Fixed test input expanded {before} results to {after}.", "Use parameterized SQL and validate search input.")
        elif exercise_id == "xss":
            marker = f'<b data-hanzo="{correlation_id}">HANZO</b>'
            response = call("GET", "/reflect", params={"name": marker})
            reflected = response["status_code"] == 200 and marker in response["text"]
            check.update(passed=reflected, observed={"raw_html_reflected": reflected, "script_executed": False})
            if reflected:
                finding = ("Unescaped HTML reflection", "medium", "The harmless HTML marker was reflected without escaping. Script execution was not tested.", "Apply context-aware output encoding and a restrictive CSP.")
        elif exercise_id == "business_logic":
            response = call("POST", "/api/checkout", json={"quantity": -5, "unit_price": 100})
            accepted = response["status_code"] == 200 and response["body"].get("total") == -500
            check.update(passed=accepted, observed={"negative_total_accepted": accepted})
            if accepted:
                finding = ("Negative checkout total accepted", "medium", "Synthetic checkout accepted a total of -500.", "Validate quantity and calculate trusted prices on the server.")
        elif exercise_id == "integrity":
            response = call("POST", "/api/preferences/import", json={"role": "admin"})
            accepted = response["status_code"] == 200 and response["body"].get("effective_role") == "admin"
            check.update(passed=accepted, observed={"unsigned_role_accepted": accepted})
            if accepted:
                finding = ("Unsigned role preference trusted", "high", "The synthetic import accepted an admin role from request data.", "Never import authorization roles from untrusted preferences.")
        if finding:
            check["finding"] = dict(zip(("title", "severity", "evidence", "remediation"), finding))
        check["requests"] = [{"method": r["method"], "path": r["path"], "status_code": r["status_code"],
                              "duration_ms": r["duration_ms"]} for r in responses]
        check["correlation_sent"] = True
        check["correlation_confirmed"] = all(
            next((v for k, v in r["headers"].items() if k.lower() == "x-hanzo-correlation-id"), "") == correlation_id
            for r in responses)
        return check, len(responses)


def markdown_report(run):
    lines = [f'# HANZO lab exercise — {run["exercise_id"]}', "", f'- Run: `{run["id"]}`',
             f'- Target: `{run["target"]}`', f'- Date: {run["created_at"]}',
             f'- Status: {run["status"]}', f'- Correlation ID: `{run["correlation_id"]}`',
             f'- HEC delivery: {run["telemetry"]["status"]}', "",
             "Exercise completion means the expected training behavior was observed. It does not mean the target is secure.",
             "Splunk indexing and alert firing have not been independently verified by HANZO.", "",
             "## Checks", "", "| Check | Result | Expected event |", "| --- | --- | --- |"]
    for check in run["checks"]:
        lines.append(f'| {check["name"]} | {"Observed" if check["passed"] else "Review"} | {", ".join(check["expected_events"])} |')
    if run.get("error"):
        lines.extend(["", "Error: " + run["error"]])
    lines.extend(["", "## Findings", ""])
    for finding in run["findings"]:
        lines.extend([f'### {finding["title"]} ({finding["severity"]})', "", finding["evidence"], "", finding["remediation"], ""])
    if not run["findings"]:
        lines.extend(["No findings recorded for this exercise.", ""])
    lines.extend(["## Splunk verification", "", "```spl", run["splunk_query"], "```", "",
                  "Compare the companion event types with the expected events above, then confirm the saved-search alert fired in Splunk."])
    return "\n".join(lines) + "\n"


def create_lab_blueprint(store):
    blueprint = Blueprint("hanzo_lab_exercises", __name__)
    telemetry = SplunkTelemetry()
    runner = LabExerciseRunner(store, telemetry)

    @blueprint.get("/api/lab/exercises")
    def catalog():
        suite = {"id": "full_suite", "name": "Detection validation suite", "phase": "validate",
                 "description": "Run all seven bounded exercises with one correlation ID.",
                 "expected_events": sorted({e for item in EXERCISES for e in item["expected_events"]}),
                 "request_count": sum(item["request_count"] for item in EXERCISES)}
        return jsonify({"exercises": [suite] + EXERCISES, "configured_target": configured_target(),
                        "authorization_required": True, "identity_check": "helpag-vapt-test-site"})

    @blueprint.post("/api/lab/exercises/run")
    def run_exercise():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "Request must be a JSON object."}), 400
        try:
            result = runner.run(str(payload.get("exercise_id", "")),
                                str(payload.get("target") or configured_target()),
                                payload.get("authorization_confirmed"))
            return jsonify(result), 201
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409

    @blueprint.get("/api/lab/exercises/history")
    def history():
        try:
            limit = int(request.args.get("limit", "20"))
        except ValueError:
            return jsonify({"error": "limit must be a number"}), 400
        return jsonify({"runs": store.exercise_runs(limit)})

    @blueprint.get("/api/lab/exercises/<run_id>/report")
    def report(run_id):
        run = store.exercise_run(run_id)
        if not run:
            return jsonify({"error": "Exercise report not found."}), 404
        if request.args.get("format") == "md":
            return Response(markdown_report(run), mimetype="text/markdown",
                            headers={"Content-Disposition": f'attachment; filename="hanzo-{run["id"]}.md"'})
        return jsonify(run)

    @blueprint.get("/api/lab/telemetry/status")
    def telemetry_status():
        return jsonify(telemetry.status())

    @blueprint.post("/api/lab/telemetry/test")
    def telemetry_test():
        correlation_id = "hanzo-" + uuid.uuid4().hex
        result = telemetry.send({"event_type": "hanzo_connectivity_test", "correlation_id": correlation_id,
                                 "exercise_id": "telemetry_probe", "message": "HANZO connectivity check"})
        return jsonify({"correlation_id": correlation_id, "delivery": result,
                        "splunk_query": f'index=vapt_lab correlation_id="{correlation_id}"'}), (200 if result["accepted"] else 503)

    return blueprint
