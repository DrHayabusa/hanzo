#!/usr/bin/env python3
"""Clone locked integration sources, preserving every modified checkout.

This installs source code only, not third-party services or their dependencies.
Use --check to audit an existing checkout without fetching or modifying it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path


def load_manifest(path: Path) -> list[dict]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or not isinstance(manifest.get("repositories"), list):
        raise ValueError("Unsupported integration lock format")
    seen = set()
    for item in manifest["repositories"]:
        directory = item.get("directory", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", directory) or directory in seen:
            raise ValueError("Integration directories must be unique simple names")
        seen.add(directory)
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", item.get("url", "")):
            raise ValueError(f"{directory}: lock requires an HTTPS GitHub source without credentials")
        if not re.fullmatch(r"[0-9a-f]{40}", item.get("revision", "")):
            raise ValueError(f"{directory}: lock requires a complete commit SHA")
        if item.get("profile") not in {"core", "optional"}:
            raise ValueError(f"{directory}: unknown installation profile")
    return manifest["repositories"]


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True, timeout=180,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    return result.stdout.strip()


def sync_one(item: dict, destination: Path, check_only: bool = False) -> dict:
    path = destination / item["directory"]
    if path.is_symlink() or path.resolve().parent != destination.resolve():
        raise ValueError("Refusing a symlink or path outside the integrations directory")
    exists = path.exists()
    revision = None
    if exists:
        if not path.is_dir() or not (path / ".git").exists():
            raise ValueError("Existing path is not a Git checkout; it was not modified")
        actual = git("-C", str(path), "remote", "get-url", "origin")
        if actual != item["url"]:
            raise ValueError("Unexpected source remote; checkout was not modified")
        # A matching HEAD does not prove that the working files match the lock.
        dirty = git("-C", str(path), "status", "--porcelain", "--untracked-files=normal")
        if dirty:
            raise ValueError("Checkout has local changes; preserve or commit them before installation")
        revision = git("-C", str(path), "rev-parse", "HEAD")
    if revision == item["revision"]:
        return {"directory": item["directory"], "status": "pinned", "revision": revision}
    if check_only:
        return {"directory": item["directory"], "status": "revision_mismatch" if exists else "missing"}
    if not exists:
        git("clone", "--no-checkout", "--filter=blob:none", item["url"], str(path))
    git("-C", str(path), "fetch", "--depth", "1", "origin", item["revision"])
    git("-C", str(path), "checkout", "--detach", item["revision"])
    revision = git("-C", str(path), "rev-parse", "HEAD")
    if revision != item["revision"]:
        raise ValueError("Checkout did not resolve to the locked commit")
    return {"directory": item["directory"], "status": "pinned", "revision": revision}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="Include optional framework sources")
    parser.add_argument("--check", action="store_true", help="Read-only source lock audit; no clone or fetch")
    parser.add_argument("--json", action="store_true", help="Print machine-readable results")
    args = parser.parse_args(argv)
    project = Path(__file__).resolve().parents[1]
    destination = Path(os.environ.get("HANZO_INTEGRATIONS_DIR", project / ".integrations")).expanduser().absolute()
    try:
        repositories = load_manifest(project / "integrations.lock.json")
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    if not args.check:
        destination.mkdir(parents=True, exist_ok=True)
    results = []
    for item in repositories:
        if item["profile"] != "core" and not args.all:
            continue
        try:
            result = sync_one(item, destination, args.check)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            # Do not echo subprocess output: a user's Git transport might contain secrets.
            message = str(exc) if isinstance(exc, ValueError) else f"Git operation failed ({type(exc).__name__}); check connectivity and source access"
            result = {"directory": item["directory"], "status": "error", "message": message}
        results.append(result)
        if not args.json:
            print(f"{result['status'].upper():18} {result['directory']} {result.get('message', result.get('revision', '')[:12])}", flush=True)
    passed = all(item["status"] == "pinned" for item in results)
    if args.json:
        print(json.dumps({"passed": passed, "source_only": True, "repositories": results}, indent=2))
    elif not passed:
        print("Source verification failed. No services have been marked online.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
