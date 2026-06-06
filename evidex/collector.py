"""Collector layer: event intake, persistence, forwarding, and verification."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .database import DatabaseManager
from .siem import forward_event


class Collector:
    def __init__(self, config: Dict[str, Any], store: DatabaseManager) -> None:
        self.config = config
        self.store = store

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store, name)

    def add_event(
        self,
        event_type: str,
        file_path: str,
        message: str,
        severity: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        event_id = self.store.add_event(event_type, file_path, message, severity, metadata)
        records = self.store.get_event_records(1)
        if records:
            try:
                forward_event(self.config, records[0])
            except Exception:
                # SIEM forwarding must not block local evidence capture.
                pass
        return event_id

    def verify_chain(self) -> Dict[str, Any]:
        return self.store.verify_chain()
