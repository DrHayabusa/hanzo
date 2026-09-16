"""Turn raw scanner output into structured findings, deterministically.

The language model never reads raw tool output and never decides what was found.
This module parses the evidence in Python; the model is given only the findings
extracted here and is asked to narrate them. That keeps the report readable
without letting it invent a path, a status code, or a vulnerability.
"""

import json
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

# gobuster / feroxbuster / dirsearch style: a path with a status and a size.
GOBUSTER_LINE = re.compile(
    r"^\s*(?P<path>/?\S+)\s+\(Status:\s*(?P<status>\d{3})\)\s*(?:\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?", re.MULTILINE)
FEROX_LINE = re.compile(
    r"^\s*(?P<status>\d{3})\s+(?:GET|POST|HEAD)\s+\S+\s+\S+\s+(?P<size>\d+)c\s+(?P<url>https?://\S+)",
    re.MULTILINE)
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# Paths worth calling out when they answer. Each entry is (pattern, what it means).
SENSITIVE = (
    (re.compile(r"/\.env$|/\.env\.", re.I), "environment file that may hold credentials"),
    (re.compile(r"/\.git(/|$)", re.I), "exposed version control metadata"),
    (re.compile(r"/backups?(/|$)", re.I), "backup location"),
    (re.compile(r"/uploads?(/|$)", re.I), "upload location"),
    (re.compile(r"/admin(/|$)|/portal(/|$)", re.I), "administrative or portal entry point"),
    (re.compile(r"\.sql$|\.bak$|\.old$|\.zip$|\.tar\.gz$", re.I), "downloadable archive or database export"),
    (re.compile(r"/api(/|$)", re.I), "API surface"),
    (re.compile(r"/config|/settings|/credentials", re.I), "configuration path"),
)


def _clean(value: str) -> str:
    return ANSI.sub("", str(value or ""))


def _note_for(path: str) -> Optional[str]:
    for pattern, meaning in SENSITIVE:
        if pattern.search(path):
            return meaning
    return None


def _path_of(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("http://") or text.startswith("https://"):
        split = urlsplit(text)
        return split.path + (f"?{split.query}" if split.query else "") or "/"
    return text if text.startswith("/") else f"/{text}"


def from_gobuster(output: str) -> List[Dict[str, Any]]:
    findings = []
    for match in GOBUSTER_LINE.finditer(_clean(output)):
        path = _path_of(match.group("path"))
        if path in {"/", ""}:
            continue
        findings.append({
            "path": path,
            "status": int(match.group("status")),
            "size": int(match.group("size")) if match.group("size") else None,
            "redirect": (match.group("redirect") or "").strip() or None,
            "note": _note_for(path),
            "source": "gobuster",
        })
    return findings


def from_feroxbuster(output: str) -> List[Dict[str, Any]]:
    findings = []
    for match in FEROX_LINE.finditer(_clean(output)):
        path = _path_of(match.group("url"))
        findings.append({
            "path": path, "status": int(match.group("status")),
            "size": int(match.group("size")), "redirect": None,
            "note": _note_for(path), "source": "feroxbuster",
        })
    return findings


def from_katana(output: str) -> List[Dict[str, Any]]:
    """Katana reports URLs it saw referenced. A reference is not proof it responds."""
    seen, findings = set(), []
    for line in _clean(output).splitlines():
        line = line.strip()
        if not line:
            continue
        url = None
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            url = (record.get("request") or {}).get("endpoint")
            status = ((record.get("response") or {}).get("status_code"))
        elif line.startswith("http"):
            url, status = line.split()[0], None
        else:
            continue
        if not url or url in seen:
            continue
        seen.add(url)
        path = _path_of(url)
        findings.append({
            "path": path, "status": status, "size": None, "redirect": None,
            "note": _note_for(path), "source": "katana",
            "evidence": "referenced by the application",
        })
    return findings


def from_httpx(output: str) -> List[Dict[str, Any]]:
    findings = []
    for line in _clean(output).splitlines():
        line = line.strip()
        if not line.startswith("http"):
            continue
        fields = re.findall(r"\[([^\]]*)\]", line)
        status = next((int(f) for f in fields if f.isdigit() and len(f) == 3), None)
        findings.append({
            "path": _path_of(line.split()[0]), "status": status, "size": None,
            "redirect": None, "note": None, "source": "httpx",
            "evidence": " | ".join(f for f in fields if not f.isdigit()) or None,
        })
    return findings


def from_nuclei(output: str) -> List[Dict[str, Any]]:
    findings = []
    for line in _clean(output).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            info = record.get("info") or {}
            findings.append({
                "path": _path_of(record.get("matched-at") or record.get("host") or ""),
                "status": None, "size": None, "redirect": None,
                "note": info.get("name") or record.get("template-id"),
                "severity": (info.get("severity") or "").lower() or None,
                "source": "nuclei",
            })
        else:
            match = re.match(r"\[(?P<template>[^\]]+)\]\s*\[[^\]]+\]\s*\[(?P<severity>[^\]]+)\]\s*(?P<url>\S+)", line)
            if match:
                findings.append({
                    "path": _path_of(match.group("url")), "status": None, "size": None,
                    "redirect": None, "note": match.group("template"),
                    "severity": match.group("severity").lower(), "source": "nuclei",
                })
    return findings


# --- Non-HTTP tools -------------------------------------------------------
# These do not report paths, so `path` carries the subject of the finding (a
# port, a resource, a parameter) and `note` describes it. That keeps one report
# table usable across every stage.

PORT_LINE = re.compile(
    r"^\s*(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+(?P<state>open|closed|filtered|open\|filtered)"
    r"(?:\s+(?P<service>\S+))?", re.MULTILINE)
FFUF_LINE = re.compile(
    r"^\s*(?P<path>\S+)\s+\[Status:\s*(?P<status>\d{3}),\s*Size:\s*(?P<size>\d+)", re.MULTILINE)
DALFOX_POC = re.compile(r"^\s*\[POC\]\[(?P<kind>[^\]]+)\]\[(?P<method>[^\]]+)\]\[(?P<where>[^\]]+)\]\s*(?P<url>\S+)",
                        re.MULTILINE)
NIKTO_LINE = re.compile(r"^\+\s+(?P<path>/\S*)\s*:\s*(?P<detail>.+)$", re.MULTILINE)


def from_portscan(output: str, source: str = "nmap") -> List[Dict[str, Any]]:
    """nmap, rustscan and masscan all print a PORT/STATE/SERVICE table."""
    findings, seen = [], set()
    for match in PORT_LINE.finditer(_clean(output)):
        if match.group("state") != "open":
            continue
        key = (match.group("port"), match.group("proto"))
        if key in seen:
            continue
        seen.add(key)
        service = (match.group("service") or "").strip() or None
        findings.append({
            "path": f"{match.group('port')}/{match.group('proto')}",
            "status": None, "size": None, "redirect": None,
            "note": f"open port{f' serving {service}' if service else ''}",
            "source": source,
        })
    return findings


def from_ffuf(output: str) -> List[Dict[str, Any]]:
    findings = []
    for match in FFUF_LINE.finditer(_clean(output)):
        path = _path_of(match.group("path"))
        findings.append({
            "path": path, "status": int(match.group("status")),
            "size": int(match.group("size")), "redirect": None,
            "note": _note_for(path), "source": "ffuf",
        })
    return findings


def from_dalfox(output: str) -> List[Dict[str, Any]]:
    """A [POC] line is a payload dalfox saw reflected, not a proven exploit."""
    findings = []
    for match in DALFOX_POC.finditer(_clean(output)):
        findings.append({
            "path": _path_of(match.group("url")), "status": None, "size": None,
            "redirect": None, "severity": "high",
            "note": f"reflected payload ({match.group('where')}, {match.group('method')})",
            "evidence": "dalfox reported a proof-of-concept payload; confirm it manually",
            "source": "dalfox",
        })
    return findings


def from_nikto(output: str) -> List[Dict[str, Any]]:
    findings = []
    for match in NIKTO_LINE.finditer(_clean(output)):
        path = _path_of(match.group("path"))
        findings.append({
            "path": path, "status": None, "size": None, "redirect": None,
            "note": match.group("detail").strip()[:200], "source": "nikto",
        })
    return findings


def from_wafw00f(output: str) -> List[Dict[str, Any]]:
    text = _clean(output)
    detected = re.search(r"is behind\s+(?P<waf>.+?)(?:\s+WAF)?\.?$", text, re.MULTILINE)
    target = re.search(r"Checking\s+(?P<url>\S+)", text)
    path = _path_of(target.group("url")) if target else "/"
    if detected:
        note = f"WAF detected: {detected.group('waf').strip()}"
    elif "No WAF detected" in text:
        note = "no WAF detected by generic fingerprinting"
    else:
        return []
    return [{"path": path, "status": None, "size": None, "redirect": None,
             "note": note, "source": "wafw00f"}]


def from_arjun(output: str) -> List[Dict[str, Any]]:
    """arjun writes "parameter detected: q, based on: body length".

    The rationale after the comma is not a second parameter name.
    """
    text = _clean(output)
    names: List[str] = []
    for match in re.finditer(r"[Pp]arameters? (?:found|detected):\s*(?P<names>[^\n]+)", text):
        for fragment in match.group("names").split(","):
            name = fragment.strip()
            if not name or name.lower().startswith("based on"):
                continue
            name = name.split(" based on")[0].strip()
            if name and name not in names:
                names.append(name)
    return [{"path": f"?{name}", "status": None, "size": None, "redirect": None,
             "note": "hidden parameter accepted by the endpoint", "source": "arjun"}
            for name in names]


# Metadata worth surfacing in a forensics report. Every other EXIF field is noise.
EXIF_NOTABLE = (
    "GPS Position", "GPS Latitude", "GPS Longitude", "Author", "Creator", "Artist",
    "Owner Name", "Software", "Comment", "User Comment", "Camera Model Name",
    "Serial Number", "Create Date", "Producer", "Title", "Company",
)


def from_exiftool(output: str) -> List[Dict[str, Any]]:
    text = _clean(output)
    name = re.search(r"^File Name\s*:\s*(?P<name>.+)$", text, re.MULTILINE)
    subject = (name.group("name").strip() if name else "(file)")
    findings = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        field, value = field.strip(), value.strip()
        if field in EXIF_NOTABLE and value:
            findings.append({
                "path": subject, "status": None, "size": None, "redirect": None,
                "note": f"{field}: {value[:120]}", "source": "exiftool",
            })
    return findings


def _json_documents(output: str) -> List[Any]:
    text = _clean(output).strip()
    if not text:
        return []
    try:
        return [json.loads(text)]
    except ValueError:
        pass
    documents = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                documents.append(json.loads(line))
            except ValueError:
                continue
    return documents


def from_checkov(output: str) -> List[Dict[str, Any]]:
    findings = []
    for document in _json_documents(output):
        for block in (document if isinstance(document, list) else [document]):
            if not isinstance(block, dict):
                continue
            for check in ((block.get("results") or {}).get("failed_checks") or []):
                findings.append({
                    "path": str(check.get("file_path") or check.get("resource") or "")[:200] or "(unknown)",
                    "status": None, "size": None, "redirect": None,
                    "severity": (check.get("severity") or "").lower() or None,
                    "note": f"{check.get('check_id')}: {check.get('check_name')}",
                    "source": "checkov",
                })
    return findings


def from_terrascan(output: str) -> List[Dict[str, Any]]:
    findings = []
    for document in _json_documents(output):
        for violation in (((document or {}).get("results") or {}).get("violations") or []):
            findings.append({
                "path": str(violation.get("file") or violation.get("resource_name") or "(unknown)")[:200],
                "status": None, "size": None, "redirect": None,
                "severity": str(violation.get("severity") or "").lower() or None,
                "note": f"{violation.get('rule_name')}: {violation.get('description') or ''}".strip()[:200],
                "source": "terrascan",
            })
    return findings


def from_trivy(output: str) -> List[Dict[str, Any]]:
    findings = []
    for document in _json_documents(output):
        for result in ((document or {}).get("Results") or []):
            for issue in (result.get("Vulnerabilities") or []):
                findings.append({
                    "path": f"{result.get('Target', '')}:{issue.get('PkgName', '')}"[:200],
                    "status": None, "size": None, "redirect": None,
                    "severity": str(issue.get("Severity") or "").lower() or None,
                    "note": f"{issue.get('VulnerabilityID')}: {issue.get('Title') or ''}".strip()[:200],
                    "source": "trivy",
                })
    return findings


EXTRACTORS = {
    "gobuster": from_gobuster, "feroxbuster": from_feroxbuster, "dirsearch": from_gobuster,
    "dirb": from_gobuster, "katana": from_katana, "httpx": from_httpx, "nuclei": from_nuclei,
    "ffuf": from_ffuf, "dalfox": from_dalfox, "nikto": from_nikto, "wafw00f": from_wafw00f,
    "arjun": from_arjun, "checkov": from_checkov, "terrascan": from_terrascan,
    "trivy": from_trivy, "exiftool": from_exiftool,
    "nmap": lambda out: from_portscan(out, "nmap"),
    "rustscan": lambda out: from_portscan(out, "rustscan"),
    "masscan": lambda out: from_portscan(out, "masscan"),
    "autorecon": lambda out: from_portscan(out, "autorecon"),
}


def extract(tool: str, output: str) -> List[Dict[str, Any]]:
    extractor = EXTRACTORS.get(str(tool or "").lower())
    return extractor(output) if extractor else []


def _walk(node: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def collect(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Pull every finding out of a stored workflow run, without interpreting it."""
    findings: List[Dict[str, Any]] = []
    tools_run: List[Dict[str, Any]] = []
    for node in _walk(evidence):
        tool = node.get("tool") or node.get("adapter") or node.get("command")
        output = node.get("stdout")
        if not isinstance(output, str):
            continue
        name = str(tool or "").lower()
        name = next((key for key in EXTRACTORS if key in name), name)
        extracted = extract(name, output)
        tools_run.append({
            "tool": name or "unknown",
            "return_code": node.get("return_code"),
            "findings": len(extracted),
            "produced_output": bool(output.strip()),
        })
        findings.extend(extracted)

    # Deduplicate on what makes a finding distinct. Keying on path alone collapsed
    # sixteen different checkov failures on one file into a single row.
    merged: Dict[Any, Dict[str, Any]] = {}
    for finding in findings:
        key = (finding["path"], finding.get("source"), finding.get("note"))
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
        elif existing.get("status") is None and finding.get("status") is not None:
            merged[key] = finding
    ordered = sorted(merged.values(),
                     key=lambda item: (item["path"], item.get("source") or "",
                                       str(item.get("note") or "")))
    return {
        "findings": ordered,
        "tools": tools_run,
        "counts": {
            "total": len(ordered),
            "noteworthy": sum(1 for item in ordered if item.get("note")),
            "by_source": {
                source: sum(1 for item in ordered if item.get("source") == source)
                for source in sorted({item.get("source") for item in ordered if item.get("source")})
            },
        },
    }


def as_facts(target: str, collected: Dict[str, Any], limit: int = 60) -> str:
    """The only thing the model is shown. Plain, numbered, and nothing inferred."""
    lines = [f"Target: {target}", ""]
    tools = collected.get("tools") or []
    if tools:
        lines.append("Tools that ran:")
        for entry in tools:
            outcome = ("produced no output" if not entry["produced_output"]
                       else f"{entry['findings']} result(s)")
            lines.append(f"- {entry['tool']} (exit {entry['return_code']}): {outcome}")
        lines.append("")
    findings = collected.get("findings") or []
    if not findings:
        lines.append("No paths or findings were extracted from the tool output.")
        return "\n".join(lines)
    lines.append(f"Observations ({len(findings)} total, showing up to {limit}):")
    for index, item in enumerate(findings[:limit], start=1):
        parts = [f"{index}. {item['path']}"]
        if item.get("status") is not None:
            parts.append(f"HTTP {item['status']}")
        if item.get("size") is not None:
            parts.append(f"{item['size']} bytes")
        if item.get("redirect"):
            parts.append(f"redirects to {item['redirect']}")
        if item.get("severity"):
            parts.append(f"severity {item['severity']}")
        if item.get("note"):
            parts.append(f"category: {item['note']}")
        if item.get("evidence"):
            parts.append(str(item["evidence"]))
        parts.append(f"found by {item.get('source')}")
        lines.append("   ".join([parts[0], " · ".join(parts[1:])]).strip())
    return "\n".join(lines)


REPORT_PROMPT = (
    "You are writing the findings section of an authorized security test report.\n"
    "You are given observations that tools actually produced. Write 2 to 4 short "
    "paragraphs of plain prose for a technical reader.\n\n"
    "Rules you must follow:\n"
    "- Use only the observations given. Never add a path, status code, tool or "
    "vulnerability that is not listed.\n"
    "- Do not claim something is exploitable. Say what was observed and why it is "
    "worth checking.\n"
    "- If a tool produced no output, say so plainly rather than implying coverage.\n"
    "- No bullet lists, no headings, no markdown. Prose only.\n"
    "- Name the most significant observations first.\n"
    "- End with one sentence stating what was not covered by these tools.\n"
)
