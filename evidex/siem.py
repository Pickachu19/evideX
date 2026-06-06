"""SIEM forwarding hooks."""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Dict

from .database import canonical_json, utc_now


def forward_event(config: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    siem = config.get("siem", {})
    if not siem.get("enabled", False):
        return {"status": "disabled"}
    endpoint = siem.get("webhook_url", "")
    if endpoint:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(event).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=int(siem.get("timeout_seconds", 5))) as response:
            return {"status": "sent", "code": response.status}
    outbox_path = Path(os.path.expanduser(siem.get("outbox_path", "~/.local/state/evidex/siem_outbox.jsonl")))
    outbox_path.parent.mkdir(parents=True, exist_ok=True)
    with outbox_path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json({"queued_at": utc_now(), "event": event}) + "\n")
    return {"status": "queued", "path": str(outbox_path)}
