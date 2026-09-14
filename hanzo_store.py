"""Small local evidence store for Hanzo workflow history."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List


def redact_evidence(value: Any) -> Any:
    """Remove credential fields before persisting caller-supplied evidence."""
    if isinstance(value, dict):
        return {
            key: "[redacted]" if re.search(
                r"(^|_)(password|passwd|secret|token|api_key|authorization|cookie)($|_)",
                str(key), re.IGNORECASE,
            ) else redact_evidence(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_evidence(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"\b(Bearer|Splunk)\s+[A-Za-z0-9._~+/=-]+", r"\1 [redacted]", value)
    return value


class HanzoStore:
    def __init__(self, project_dir: Path):
        default = Path(project_dir) / ".hanzo-data" / "hanzo.db"
        self.path = Path(os.environ.get("HANZO_DB_PATH", default)).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS workflow_runs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    asset TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    status TEXT NOT NULL,
                    authorized INTEGER NOT NULL DEFAULT 0,
                    result_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_workflow_created ON workflow_runs(created_at DESC)"
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS lab_exercise_runs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )"""
            )

    def record(
        self, asset: str, phase: str, status: str, authorized: bool, result: Dict[str, Any]
    ) -> str:
        run_id = str(uuid.uuid4())
        serialized = json.dumps(redact_evidence(result), default=str)
        if len(serialized) > 500_000:
            serialized = json.dumps({
                "truncated": True,
                "summary": "Result exceeded the 500 KB local evidence limit.",
            })
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO workflow_runs
                    (id, created_at, asset, phase, status, authorized, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id, datetime.now(timezone.utc).isoformat(), asset, phase,
                    status, 1 if authorized else 0, serialized,
                ),
            )
        return run_id

    def recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        safe_limit = min(max(int(limit), 1), 100)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, asset, phase, status, authorized, result_json
                FROM workflow_runs ORDER BY created_at DESC LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["authorized"] = bool(item["authorized"])
            try:
                item["result"] = json.loads(item.pop("result_json"))
            except ValueError:
                item["result"] = {"error": "Stored result could not be decoded"}
                item.pop("result_json", None)
            results.append(item)
        return results

    def delete(self, run_id: str) -> bool:
        """Delete one stored workflow run. Returns False when the id was unknown."""
        identifier = str(run_id or "").strip()
        if not identifier:
            return False
        with self._connect() as connection:
            deleted = connection.execute(
                "DELETE FROM workflow_runs WHERE id = ?", (identifier,)
            ).rowcount
        return bool(deleted)

    def delete_many(self, run_ids: List[str]) -> int:
        """Delete the given workflow runs and return how many rows were removed."""
        identifiers = [str(item).strip() for item in run_ids or [] if str(item).strip()]
        if not identifiers:
            return 0
        placeholders = ",".join("?" for _ in identifiers)
        with self._connect() as connection:
            return connection.execute(
                f"DELETE FROM workflow_runs WHERE id IN ({placeholders})", identifiers
            ).rowcount

    def purge(self, keep_latest: int = 0, older_than_days: int | None = None) -> Dict[str, Any]:
        """Remove old evidence. Deletion is explicit and reports exactly what it removed.

        keep_latest retains the newest N runs; older_than_days removes runs older than
        that age. With neither set, nothing is deleted.
        """
        conditions, parameters = [], []
        if older_than_days is not None:
            if int(older_than_days) < 0:
                raise ValueError("older_than_days cannot be negative")
            cutoff = datetime.now(timezone.utc) - timedelta(days=int(older_than_days))
            conditions.append("created_at < ?")
            parameters.append(cutoff.isoformat())
        if keep_latest:
            if int(keep_latest) < 0:
                raise ValueError("keep_latest cannot be negative")
            conditions.append(
                "id NOT IN (SELECT id FROM workflow_runs ORDER BY created_at DESC LIMIT ?)"
            )
            parameters.append(int(keep_latest))
        if not conditions:
            return {"deleted": 0, "remaining": self.count(),
                    "message": "Nothing deleted: choose runs to delete, a retention count, or an age."}
        with self._connect() as connection:
            deleted = connection.execute(
                f"DELETE FROM workflow_runs WHERE {' AND '.join(conditions)}", parameters
            ).rowcount
        remaining = self.count()
        return {"deleted": int(deleted), "remaining": remaining,
                "message": f"Deleted {int(deleted)} stored run(s); {remaining} remain."}

    def count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) AS total FROM workflow_runs").fetchone()["total"])

    def vacuum(self) -> None:
        """Reclaim file space after deletions."""
        connection = sqlite3.connect(self.path, timeout=15)
        try:
            connection.execute("VACUUM")
        finally:
            connection.close()

    def record_exercise(self, result: Dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO lab_exercise_runs (id, created_at, result_json) VALUES (?, ?, ?)",
                (result["id"], result["created_at"], json.dumps(redact_evidence(result))),
            )

    def exercise_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT result_json FROM lab_exercise_runs ORDER BY created_at DESC LIMIT ?",
                (min(max(int(limit), 1), 100),),
            ).fetchall()
        return [json.loads(row["result_json"]) for row in rows]

    def exercise_run(self, run_id: str) -> Dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM lab_exercise_runs WHERE id = ?", (run_id,),
            ).fetchone()
        return json.loads(row["result_json"]) if row else None
