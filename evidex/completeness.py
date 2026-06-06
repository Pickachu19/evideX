"""Log completeness verification."""

from __future__ import annotations

import os
from typing import Any, Dict, List

from .database import DatabaseManager


def verify_completeness(config: Dict[str, Any], store: DatabaseManager) -> Dict[str, Any]:
    events = store.get_event_records(100000)
    ids = sorted(int(event["id"]) for event in events)
    missing_ids: List[int] = []
    if ids:
        expected = set(range(ids[0], ids[-1] + 1))
        missing_ids = sorted(expected - set(ids))

    configured_paths = []
    missing_paths = []
    for entry in config.get("paths", []):
        if not entry.get("enabled", True):
            continue
        path = str(entry.get("path", ""))
        configured_paths.append(path)
        if path and not os.path.exists(path):
            missing_paths.append(path)

    chain = store.verify_chain()
    issues = []
    if missing_ids:
        issues.append("event_id_gap")
    if missing_paths:
        issues.append("configured_path_missing")
    if not chain["valid"]:
        issues.append("hash_chain_invalid")

    return {
        "status": "pass" if not issues else "attention",
        "issues": issues,
        "event_count": len(events),
        "missing_event_ids": missing_ids,
        "configured_paths": configured_paths,
        "missing_paths": missing_paths,
        "hash_chain": chain,
    }
