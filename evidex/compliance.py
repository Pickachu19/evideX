"""Compliance-oriented report generation."""

from __future__ import annotations

from typing import Any, Dict, List

from .database import DatabaseManager
from .completeness import verify_completeness


CONTROL_MAP = [
    {
        "framework": "SOC 2",
        "control": "CC7.2",
        "requirement": "Monitor system components for anomalous activity.",
    },
    {
        "framework": "ISO 27001",
        "control": "A.8.15",
        "requirement": "Logs are protected, reviewed, and monitored.",
    },
    {
        "framework": "PCI DSS",
        "control": "10.3 / 10.5",
        "requirement": "Audit trails are protected from unauthorized modification.",
    },
    {
        "framework": "NIST 800-53",
        "control": "AU-9 / SI-7",
        "requirement": "Audit information and software integrity are protected.",
    },
]


def build_compliance_report(config: Dict[str, Any], store: DatabaseManager) -> Dict[str, Any]:
    events = store.get_event_records(100000)
    chain = store.verify_chain()
    completeness = verify_completeness(config, store)
    high_events = [event for event in events if event.get("severity") == "high"]
    security_events = [
        event
        for event in events
        if event.get("event_type") in {"security_alert", "integrity_drift", "file_missing"}
    ]
    controls: List[Dict[str, Any]] = []
    for control in CONTROL_MAP:
        controls.append(
            {
                **control,
                "status": "pass" if chain["valid"] and completeness["status"] == "pass" else "attention",
                "evidence": {
                    "event_count": len(events),
                    "high_severity_events": len(high_events),
                    "security_relevant_events": len(security_events),
                    "hash_chain_valid": chain["valid"],
                },
            }
        )
    return {
        "summary": {
            "status": "pass" if all(item["status"] == "pass" for item in controls) else "attention",
            "event_count": len(events),
            "hash_chain_valid": chain["valid"],
            "completeness_status": completeness["status"],
        },
        "controls": controls,
        "completeness": completeness,
    }
