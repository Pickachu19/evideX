"""Security analysis for log files."""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

from .database import DatabaseManager


class LogTailer:
    def __init__(self, db: DatabaseManager, max_bytes: int) -> None:
        self.db = db
        self.max_bytes = max_bytes

    def read_new(self, path: str) -> str:
        if not os.path.exists(path) or not os.path.isfile(path):
            return ""

        last_offset = self.db.get_offset(path)
        file_size = os.path.getsize(path)
        if file_size < last_offset:
            last_offset = 0

        read_size = min(self.max_bytes, file_size - last_offset)
        if read_size <= 0:
            return ""

        with open(path, "r", errors="ignore") as handle:
            handle.seek(last_offset)
            data = handle.read(read_size)
            new_offset = handle.tell()

        self.db.update_offset(path, new_offset)
        return data


class SecurityAnalyzer:
    def __init__(self, db: DatabaseManager, rules: Dict[str, List[str]], max_bytes: int) -> None:
        self.db = db
        self.rules = rules
        self.tailer = LogTailer(db, max_bytes=max_bytes)

    def analyze(self, path: str) -> List[Tuple[str, str]]:
        """Return a list of (message, severity)."""
        content = self.tailer.read_new(path)
        if not content:
            return []

        lowered = content.lower()
        results: List[Tuple[str, str]] = []

        failed_patterns = self.rules.get("failed_login_patterns", [])
        failed_count = sum(lowered.count(pat) for pat in failed_patterns)
        if failed_count > 0:
            results.append((
                f"SECURITY: {failed_count} failed login attempts in {os.path.basename(path)}",
                "high",
            ))

        sudo_patterns = self.rules.get("sudo_patterns", [])
        sudo_context = self.rules.get("sudo_context", "")
        if sudo_patterns:
            if any(pat in lowered for pat in sudo_patterns) and sudo_context in lowered:
                results.append((
                    f"SECURITY: sudo usage detected in {os.path.basename(path)}",
                    "medium",
                ))

        return results
