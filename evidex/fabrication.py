"""AI fabrication and unsupported-claim detection."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .database import DatabaseManager


UNSUPPORTED_CERTAINTY_TERMS = (
    "definitely",
    "guaranteed",
    "confirmed compromise",
    "cryptographically proven by ai",
)


def detect_ai_fabrication(store: DatabaseManager, limit: int = 500) -> Dict[str, Any]:
    events = {event["id"]: event for event in store.get_event_records(limit)}
    findings: List[Dict[str, Any]] = []
    for row in store.get_ai_analysis(limit):
        analysis_id, event_id, _ts, provider, model, score, classification, explanation, action, raw = row
        event = events.get(event_id)
        text = f"{classification} {explanation} {action}".lower()
        raw_response = json.loads(raw) if raw else {}
        if event is None:
            findings.append(
                {
                    "analysis_id": analysis_id,
                    "severity": "high",
                    "reason": "analysis_references_missing_event",
                    "provider": provider,
                    "model": model,
                }
            )
            continue
        if int(score) >= 90 and event.get("severity") not in {"high", "critical"}:
            findings.append(
                {
                    "analysis_id": analysis_id,
                    "event_id": event_id,
                    "severity": "medium",
                    "reason": "high_ai_score_without_high_severity_evidence",
                }
            )
        if any(term in text for term in UNSUPPORTED_CERTAINTY_TERMS):
            findings.append(
                {
                    "analysis_id": analysis_id,
                    "event_id": event_id,
                    "severity": "medium",
                    "reason": "unsupported_certainty_language",
                }
            )
        if raw_response.get("confidence") == "high" and int(score) < 40:
            findings.append(
                {
                    "analysis_id": analysis_id,
                    "event_id": event_id,
                    "severity": "low",
                    "reason": "confidence_score_mismatch",
                }
            )
    return {
        "status": "pass" if not findings else "attention",
        "finding_count": len(findings),
        "findings": findings,
    }
