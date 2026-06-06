"""Append-only hash-chained storage for collector events and state."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def digest(data: Dict[str, Any]) -> str:
    return sha256(canonical_json(data).encode("utf-8")).hexdigest()


class DatabaseManager:
    """Compatibility wrapper around a production-style event store.

    The previous project used SQLite. This class keeps the public methods used by
    the monitor, reports, AI analyzer, and dashboard, but stores events in JSONL
    with a per-event hash chain:

    previous_event_hash -> event body -> event_hash
    """

    def __init__(self, db_path: str = "~/.local/state/evidex/store") -> None:
        base = Path(os.path.expanduser(db_path))
        if base.suffix:
            base = base.with_suffix("")
        self.store_dir = base
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.store_dir / "events.jsonl"
        self.ai_path = self.store_dir / "ai_analysis.jsonl"
        self.baselines_path = self.store_dir / "baselines.json"
        self.offsets_path = self.store_dir / "log_offsets.json"
        self.manifest_path = self.store_dir / "manifest.json"
        self.lock = threading.RLock()
        self._ensure_files()

    def _ensure_files(self) -> None:
        for path in (self.events_path, self.ai_path):
            path.touch(exist_ok=True)
        for path in (self.baselines_path, self.offsets_path):
            if not path.exists():
                path.write_text("{}", encoding="utf-8")
        if not self.manifest_path.exists():
            self._write_json(
                self.manifest_path,
                {
                    "schema": "evidex-store-v1",
                    "created_at": utc_now(),
                    "event_count": 0,
                    "last_event_hash": "",
                },
            )

    def reset_store(self) -> Dict[str, Any]:
        with self.lock:
            self.events_path.write_text("", encoding="utf-8")
            self.ai_path.write_text("", encoding="utf-8")
            self._write_json(self.baselines_path, {})
            self._write_json(self.offsets_path, {})
            self._write_json(
                self.manifest_path,
                {
                    "schema": "evidex-store-v1",
                    "created_at": utc_now(),
                    "event_count": 0,
                    "last_event_hash": "",
                    "reset_at": utc_now(),
                },
            )
        return {"status": "reset", "store_dir": str(self.store_dir)}

    def _read_json(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        content = path.read_text(encoding="utf-8").strip()
        return json.loads(content) if content else {}

    def _write_json(self, path: Path, data: Dict[str, Any]) -> None:
        tmp = path.with_suffix(f"{path.suffix}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)

    def _read_jsonl(self, path: Path) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        if not path.exists():
            return rows
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows

    def _append_jsonl(self, path: Path, row: Dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(row) + "\n")

    def _next_event_id(self) -> int:
        manifest = self._read_json(self.manifest_path)
        return int(manifest.get("event_count", 0)) + 1

    def add_event(
        self,
        event_type: str,
        file_path: str,
        message: str,
        severity: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        with self.lock:
            manifest = self._read_json(self.manifest_path)
            event_id = self._next_event_id()
            row = {
                "id": event_id,
                "timestamp": utc_now(),
                "event_type": event_type,
                "file_path": file_path,
                "message": message,
                "severity": severity,
                "metadata": metadata or {},
                "previous_event_hash": manifest.get("last_event_hash", ""),
            }
            row["event_hash"] = digest(row)
            self._append_jsonl(self.events_path, row)
            manifest["event_count"] = event_id
            manifest["last_event_hash"] = row["event_hash"]
            manifest["updated_at"] = utc_now()
            self._write_json(self.manifest_path, manifest)
            return event_id

    def update_hash(
        self,
        file_path: str,
        file_hash: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self.lock:
            baselines = self._read_json(self.baselines_path)
            baselines[file_path] = {
                "path": file_path,
                "hash": file_hash,
                "last_check": utc_now(),
                **(metadata or {}),
            }
            self._write_json(self.baselines_path, baselines)

    def get_hash(self, file_path: str) -> Optional[str]:
        record = self.get_hash_record(file_path)
        return str(record["hash"]) if record else None

    def get_hash_record(self, file_path: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self._read_json(self.baselines_path).get(file_path)

    def remove_hash(self, file_path: str) -> None:
        with self.lock:
            baselines = self._read_json(self.baselines_path)
            baselines.pop(file_path, None)
            self._write_json(self.baselines_path, baselines)

    def get_hashes_under(self, base_path: str) -> List[Dict[str, Any]]:
        prefix = base_path.rstrip("/") + "/"
        with self.lock:
            return [
                record
                for path, record in self._read_json(self.baselines_path).items()
                if path == base_path or path.startswith(prefix)
            ]

    def update_offset(self, file_path: str, offset: int) -> None:
        with self.lock:
            offsets = self._read_json(self.offsets_path)
            offsets[file_path] = {"offset": offset, "last_check": utc_now()}
            self._write_json(self.offsets_path, offsets)

    def get_offset(self, file_path: str) -> int:
        with self.lock:
            record = self._read_json(self.offsets_path).get(file_path, {})
            return int(record.get("offset", 0))

    def get_events(self, limit: int = 1000) -> List[Tuple]:
        with self.lock:
            rows = self._read_jsonl(self.events_path)
        rows = rows[-limit:][::-1]
        return [
            (
                row["id"],
                row["timestamp"],
                row["event_type"],
                row["file_path"],
                row["message"],
                row["severity"],
                json.dumps(row.get("metadata", {}), sort_keys=True),
                row.get("event_hash", ""),
                row.get("previous_event_hash", ""),
            )
            for row in rows
        ]

    def get_event_records(self, limit: int = 1000) -> List[Dict[str, Any]]:
        with self.lock:
            return self._read_jsonl(self.events_path)[-limit:][::-1]

    def add_ai_analysis(
        self,
        event_id: int,
        provider: str,
        model: str,
        analysis: Dict[str, Any],
    ) -> int:
        with self.lock:
            rows = self._read_jsonl(self.ai_path)
            analysis_id = len(rows) + 1
            row = {
                "id": analysis_id,
                "event_id": event_id,
                "timestamp": utc_now(),
                "provider": provider,
                "model": model,
                "risk_score": int(analysis.get("risk_score", 0)),
                "classification": analysis.get("classification", "unknown"),
                "explanation": analysis.get("explanation", ""),
                "recommended_action": analysis.get("recommended_action", ""),
                "raw_response": analysis,
            }
            row["analysis_hash"] = digest(row)
            self._append_jsonl(self.ai_path, row)
            return analysis_id

    def get_ai_analysis(self, limit: int = 100) -> List[Tuple]:
        with self.lock:
            rows = self._read_jsonl(self.ai_path)
        rows = rows[-limit:][::-1]
        return [
            (
                row["id"],
                row["event_id"],
                row["timestamp"],
                row["provider"],
                row["model"],
                row["risk_score"],
                row["classification"],
                row["explanation"],
                row["recommended_action"],
                json.dumps(row.get("raw_response", {}), sort_keys=True),
            )
            for row in rows
        ]

    def verify_chain(self) -> Dict[str, Any]:
        rows = self._read_jsonl(self.events_path)
        previous_hash = ""
        failures: List[Dict[str, Any]] = []
        for row in rows:
            expected_previous = row.get("previous_event_hash", "")
            if expected_previous != previous_hash:
                failures.append(
                    {
                        "event_id": row.get("id"),
                        "reason": "previous_hash_mismatch",
                        "expected": previous_hash,
                        "actual": expected_previous,
                    }
                )
            row_copy = dict(row)
            event_hash = str(row_copy.pop("event_hash", ""))
            computed = digest(row_copy)
            if computed != event_hash:
                failures.append(
                    {
                        "event_id": row.get("id"),
                        "reason": "event_hash_mismatch",
                        "expected": computed,
                        "actual": event_hash,
                    }
                )
            previous_hash = event_hash
        return {
            "valid": not failures,
            "event_count": len(rows),
            "last_event_hash": previous_hash,
            "failures": failures,
        }
