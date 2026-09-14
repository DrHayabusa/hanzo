"""Non-invasive pre-flight for the Test target page.

Answers three questions before any scanner is launched:
  1. Is this a target HANZO can accept, and what kind is it?
  2. Is it actually reachable right now?
  3. Which adapters for the selected stage are installed on this worker?

This performs at most one connection to the target (a TCP connect, plus an HTTP
HEAD for URLs). That is a reachability check, not a scan, and it never runs a
scanner or sends a payload. A target that is down is reported as down rather
than left for a scanner to fail on confusingly.
"""

import re
import socket
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from scan_scope import validate_scan_target

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
DEFAULT_PORTS = {"http": 80, "https": 443}
# Adapters each workflow stage can actually invoke, by catalog id.
STAGE_TOOLS = {
    "recon": ("nmap", "rustscan", "masscan", "subfinder", "amass", "httpx", "katana",
              "gobuster", "ffuf", "feroxbuster", "nuclei"),
    "validate": ("nuclei", "nikto", "sqlmap", "wpscan", "dalfox", "httpx"),
    "full": ("nmap", "httpx", "nuclei", "gobuster", "ffuf", "nikto", "subfinder", "katana"),
}


def classify(target: str) -> str:
    value = str(target or "").strip()
    if CVE_PATTERN.match(value):
        return "cve"
    if "://" in value:
        return "url"
    host = urlsplit("//" + value).hostname or value
    try:
        socket.inet_aton(host)
        return "ip"
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return "ip"
    except OSError:
        return "hostname"


def _endpoint(target: str, kind: str) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Return (host, port, scheme) to probe, without modifying the target."""
    if kind == "cve":
        return None, None, None
    parsed = urlsplit(target if "://" in target else "//" + target)
    host = parsed.hostname
    scheme = parsed.scheme or None
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is None:
        port = DEFAULT_PORTS.get(scheme or "", 443 if scheme == "https" else 80)
    return host, port, scheme


def check_reachable(target: str, kind: str, timeout: float = 4.0) -> Dict[str, Any]:
    """One TCP connect, plus one HTTP HEAD for URLs. Never a scan."""
    if kind == "cve":
        return {"checked": False, "reachable": None,
                "detail": "CVE intelligence does not contact the asset."}
    host, port, scheme = _endpoint(target, kind)
    if not host:
        return {"checked": False, "reachable": None, "detail": "No host to contact."}
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            pass
    except OSError as error:
        return {"checked": True, "reachable": False, "host": host, "port": port,
                "detail": f"No TCP connection to {host}:{port} ({error.strerror or error}). "
                          f"Start the target, or correct the address, before running scanners."}
    result: Dict[str, Any] = {"checked": True, "reachable": True, "host": host, "port": port,
                              "detail": f"TCP connection to {host}:{port} succeeded."}
    if kind == "url" or scheme in {"http", "https"}:
        url = target if "://" in target else f"http://{target}"
        request = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result["http_status"] = response.status
                result["server"] = response.headers.get("Server")
                result["detail"] = f"HTTP {response.status} from {url}."
        except urllib.error.HTTPError as error:
            result["http_status"] = error.code
            result["detail"] = f"HTTP {error.code} from {url}; the host is responding."
        except (urllib.error.URLError, OSError, ValueError) as error:
            result["http_status"] = None
            result["detail"] = (f"TCP connected but no HTTP response from {url} "
                                f"({getattr(error, 'reason', error)}). The service may be "
                                f"overloaded or not speaking HTTP on this port.")
    return result


def stage_readiness(stage: str, catalog: Dict[str, Any]) -> Dict[str, Any]:
    """Report which adapters this stage can use and which are actually installed."""
    wanted = STAGE_TOOLS.get(stage, ())
    if not wanted:
        return {"applicable": False, "ready": [], "missing": [],
                "detail": "This stage does not invoke installed scanners."}
    commands = {str(command.get("id")): command
                for group in catalog.get("categories") or []
                for command in group.get("commands") or []}
    ready = [name for name in wanted if commands.get(name, {}).get("installed") is True]
    missing = [name for name in wanted if commands.get(name, {}).get("installed") is False]
    return {"applicable": True, "ready": ready, "missing": missing,
            "detail": (f"{len(ready)} of {len(wanted)} adapters for this stage are installed."
                       if ready else
                       "No adapter for this stage is installed on this worker. "
                       "Install the arsenal, then refresh the catalog.")}


def preflight(target: str, stage: str, catalog: Dict[str, Any], timeout: float = 4.0) -> Dict[str, Any]:
    """Validate, classify, reach and report readiness without launching anything."""
    raw = str(target or "").strip()
    kind = classify(raw)
    result: Dict[str, Any] = {"target": raw, "kind": kind, "stage": stage}
    if kind == "cve":
        result["valid"] = True
    else:
        try:
            validate_scan_target(raw)
            result["valid"] = True
        except ValueError as error:
            return {**result, "valid": False, "error": str(error),
                    "reachability": {"checked": False, "reachable": None,
                                     "detail": "Not checked: the target is not valid."},
                    "readiness": stage_readiness(stage, catalog),
                    "blockers": [str(error)], "ready_to_run": False,
                    "message": str(error)}
    result["reachability"] = check_reachable(raw, kind, timeout)
    result["readiness"] = stage_readiness(stage, catalog)
    reachable = result["reachability"].get("reachable")
    ready = result["readiness"]
    blockers: List[str] = []
    if reachable is False:
        blockers.append("The target is not reachable from this worker.")
    elif kind in {"url"} and result["reachability"].get("http_status") is None:
        blockers.append("The port accepts connections but returned no HTTP response.")
    if ready.get("applicable") and not ready.get("ready"):
        blockers.append("No adapter for this stage is installed.")
    result["blockers"] = blockers
    result["ready_to_run"] = not blockers
    result["message"] = ("Pre-flight passed. This is a reachability and readiness check, "
                         "not a guarantee that a scanner will succeed."
                         if not blockers else "; ".join(blockers))
    return result
