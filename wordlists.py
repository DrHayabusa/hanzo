"""Discover wordlists that actually exist on this worker.

Every entry corresponds to a real readable file found on disk. Nothing is
invented: if no wordlist is installed the catalog is empty and says so, rather
than offering a path that would make a scanner fail with a confusing error.

Search roots, in order of preference, plus anything in HANZO_WORDLIST_DIRS
(os.pathsep separated). A project-local clone is supported so the workspace can
carry its own SecLists without touching system directories.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

SUFFIXES = {".txt", ".lst", ".dic", ".words", ".wordlist"}
MAX_FILES = 6000
MAX_DEPTH = 6
SYSTEM_ROOTS = (
    "/usr/share/wordlists",          # Kali default, and apt seclists symlinks
    "/usr/share/seclists",           # apt install seclists
    "/opt/SecLists",                 # documented manual clone
    "/opt/seclists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/usr/share/wfuzz/wordlist",
    "/usr/share/metasploit-framework/data/wordlists",
    "/usr/local/share/wordlists",
)
# Ordered: the first matching keyword wins, so specific groups precede generic ones.
# Keep keywords specific. Broad words such as "discovery" or "common" appear all
# over SecLists and would drag unrelated lists into the wrong group.
GROUPS = (
    ("web", "Web content & directories", ("web-content", "dirb", "dirbuster", "directory-list",
                                          "raft-", "quickhits", "web-extensions")),
    ("dns", "DNS & subdomains", ("dns", "subdomain", "vhost")),
    ("usernames", "Usernames", ("username", "user-name", "/users/", "名前", "names/")),
    ("passwords", "Passwords", ("password", "rockyou", "passwd", "credential", "/leaked")),
    ("api", "API endpoints", ("/api/", "api-", "-api", "swagger", "graphql")),
    ("fuzzing", "Fuzzing & injection", ("fuzz", "payload", "injection", "lfi", "sqli", "xss", "traversal")),
    ("network", "Network & infrastructure", ("infrastructure", "ipv4", "ipv6", "snmp", "ports", "/network")),
)
DEFAULT_GROUP = ("other", "Other wordlists")


def _roots(project_dir: Optional[Path]) -> List[Path]:
    roots: List[Path] = []
    for entry in os.environ.get("HANZO_WORDLIST_DIRS", "").split(os.pathsep):
        if entry.strip():
            roots.append(Path(entry.strip()).expanduser())
    if project_dir:
        roots.append(Path(project_dir) / "wordlists")
    roots.extend(Path(root) for root in SYSTEM_ROOTS)
    seen, unique = set(), []
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if root.is_dir():
            unique.append(root)
    return unique


def classify(path: str) -> tuple[str, str]:
    lowered = path.lower()
    for group_id, label, keywords in GROUPS:
        if any(keyword in lowered for keyword in keywords):
            return group_id, label
    return DEFAULT_GROUP


def _scan(root: Path) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    root_depth = len(root.parts)
    for current, directories, files in os.walk(root, followlinks=False):
        if len(Path(current).parts) - root_depth >= MAX_DEPTH:
            directories[:] = []
        directories[:] = [d for d in sorted(directories) if not d.startswith(".")]
        for name in sorted(files):
            if Path(name).suffix.lower() not in SUFFIXES:
                continue
            candidate = Path(current) / name
            try:
                stat = candidate.stat()
            except OSError:
                continue
            # Empty files are skipped; a short list is still a real list.
            if not stat.st_size or not os.access(candidate, os.R_OK):
                continue
            found.append({"path": str(candidate), "name": name, "bytes": stat.st_size,
                          "relative": str(candidate.relative_to(root))})
            if len(found) >= MAX_FILES:
                return found
    return found


@lru_cache(maxsize=8)
def _cached(root_key: str, stamp: float) -> tuple:
    return tuple(tuple(sorted(item.items())) for item in _scan(Path(root_key)))


def discover(project_dir: Optional[Path] = None, use_cache: bool = True) -> Dict[str, Any]:
    """Return every readable wordlist found under the configured roots."""
    roots, entries, truncated = _roots(project_dir), [], False
    for root in roots:
        try:
            stamp = root.stat().st_mtime if use_cache else 0.0
            items = [dict(item) for item in _cached(str(root), stamp)] if use_cache else _scan(root)
        except OSError:
            continue
        for item in items:
            item["root"] = str(root)
            entries.append(item)
        if len(items) >= MAX_FILES:
            truncated = True
    seen, unique = set(), []
    for entry in entries:
        if entry["path"] in seen:
            continue
        seen.add(entry["path"])
        unique.append(entry)
    grouped: Dict[str, Dict[str, Any]] = {}
    for entry in unique:
        # Classify on the path relative to its root: an absolute path picks up
        # unrelated words from the host layout (/Users/... would match "/users/").
        group_id, label = classify(entry.get("relative") or entry["path"])
        group = grouped.setdefault(group_id, {"id": group_id, "label": label, "wordlists": []})
        group["wordlists"].append(entry)
    order = [group_id for group_id, _, _ in GROUPS] + [DEFAULT_GROUP[0]]
    groups = [grouped[key] for key in order if key in grouped]
    for group in groups:
        group["wordlists"].sort(key=lambda item: item["path"])
    return {
        "roots": [str(root) for root in roots],
        "searched_roots": [str(root) for root in roots],
        "groups": groups,
        "count": len(unique),
        "truncated": truncated,
        "installed": bool(unique),
        "install_hint": ("sudo apt-get install -y seclists  # Kali\n"
                         "git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists\n"
                         "bash scripts/install_wordlists.sh  # project-local clone"),
        "message": ("Every listed wordlist is a readable file found on this worker."
                    if unique else
                    "No wordlist was found on this worker. Install SecLists or set HANZO_WORDLIST_DIRS; "
                    "HANZO will not offer a path that does not exist."),
    }


def resolve(path: str, project_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Check one operator-supplied wordlist path without executing anything."""
    raw = str(path or "").strip()
    if not raw:
        return {"path": raw, "exists": False, "readable": False, "error": "A wordlist path is required."}
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute() and project_dir:
        local = Path(project_dir) / candidate
        if local.exists():
            candidate = local
    if not candidate.exists():
        return {"path": str(candidate), "exists": False, "readable": False,
                "error": f"{candidate} does not exist on this worker."}
    if candidate.is_dir():
        return {"path": str(candidate), "exists": True, "readable": False,
                "error": f"{candidate} is a directory, not a wordlist file."}
    if not os.access(candidate, os.R_OK):
        return {"path": str(candidate), "exists": True, "readable": False,
                "error": f"{candidate} is not readable by this user."}
    return {"path": str(candidate), "exists": True, "readable": True,
            "bytes": candidate.stat().st_size, "error": None}
