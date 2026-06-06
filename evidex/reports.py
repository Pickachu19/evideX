"""Reporting helpers."""

from __future__ import annotations

import csv
import json
from typing import Dict, List, Optional


def summarize_events(events: List[tuple]) -> Dict[str, int]:
    summary = {
        "total": len(events),
        "file_created": 0,
        "file_modified": 0,
        "file_deleted": 0,
        "file_missing": 0,
        "integrity_drift": 0,
        "security_alert": 0,
    }
    for event in events:
        event_type = event[2]
        if event_type in summary:
            summary[event_type] += 1
    return summary


def _event_to_dict(event: tuple) -> Dict:
    metadata = {}
    if len(event) > 6 and event[6]:
        try:
            metadata = json.loads(event[6])
        except json.JSONDecodeError:
            metadata = {"raw": event[6]}
    return {
        "id": event[0],
        "timestamp": event[1],
        "event_type": event[2],
        "file_path": event[3],
        "message": event[4],
        "severity": event[5],
        "metadata": metadata,
        "event_hash": event[7] if len(event) > 7 else "",
        "previous_event_hash": event[8] if len(event) > 8 else "",
    }


def _analysis_to_dict(row: tuple) -> Dict:
    raw = {}
    if row[9]:
        try:
            raw = json.loads(row[9])
        except json.JSONDecodeError:
            raw = {"raw": row[9]}
    return {
        "id": row[0],
        "event_id": row[1],
        "timestamp": row[2],
        "provider": row[3],
        "model": row[4],
        "risk_score": row[5],
        "classification": row[6],
        "explanation": row[7],
        "recommended_action": row[8],
        "raw_response": raw,
    }


def export_json(
    events: List[tuple],
    path: str,
    ai_analysis: Optional[List[tuple]] = None,
) -> None:
    data = [
        _event_to_dict(e)
        for e in events
    ]
    payload = {
        "events": data,
        "ai_analysis": [_analysis_to_dict(row) for row in ai_analysis or []],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def export_csv(
    events: List[tuple],
    path: str,
    ai_analysis: Optional[List[tuple]] = None,
) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "id",
                "timestamp",
                "event_type",
                "file_path",
                "message",
                "severity",
                "metadata",
                "event_hash",
                "previous_event_hash",
            ]
        )
        for event in events:
            event_dict = _event_to_dict(event)
            writer.writerow(
                [
                    event_dict["id"],
                    event_dict["timestamp"],
                    event_dict["event_type"],
                    event_dict["file_path"],
                    event_dict["message"],
                    event_dict["severity"],
                    json.dumps(event_dict["metadata"], sort_keys=True),
                    event_dict["event_hash"],
                    event_dict["previous_event_hash"],
                ]
            )
        if ai_analysis:
            writer.writerow([])
            writer.writerow(
                [
                    "analysis_id",
                    "event_id",
                    "timestamp",
                    "provider",
                    "model",
                    "risk_score",
                    "classification",
                    "explanation",
                    "recommended_action",
                ]
            )
            for row in ai_analysis:
                writer.writerow(row[:9])
