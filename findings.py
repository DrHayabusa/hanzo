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
ANSI = re.compile(r"\x1b\[[0-9;]*m")

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


EXTRACTORS = {
    "gobuster": from_gobuster, "feroxbuster": from_feroxbuster, "dirsearch": from_gobuster,
    "dirb": from_gobuster, "katana": from_katana, "httpx": from_httpx, "nuclei": from_nuclei,
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

    merged: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        key = (finding["path"], finding.get("source"))
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
        elif existing.get("status") is None and finding.get("status") is not None:
            merged[key] = finding
    ordered = sorted(merged.values(), key=lambda item: (item["path"], item.get("source") or ""))
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
