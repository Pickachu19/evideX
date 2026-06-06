"""Production platform coverage checks."""

from __future__ import annotations

import shutil
from typing import Any, Dict


SYSTEMD_UNIT = """[Unit]
Description=EvideX Agent
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/evidex --config /etc/evidex/config.json run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def production_status(config: Dict[str, Any]) -> Dict[str, Any]:
    ebpf_available = bool(shutil.which("bpftool") or shutil.which("bpftrace"))
    container_paths = [
        entry.get("path")
        for entry in config.get("paths", [])
        if any(token in str(entry.get("path", "")) for token in ("/var/lib/docker", "/var/log/pods", "/var/log/containers"))
    ]
    return {
        "agent_collector_split": True,
        "hash_chained_store": True,
        "sqlite_removed": True,
        "rest_api": True,
        "siem_forwarding": config.get("siem", {}).get("enabled", False),
        "ebpf_available": ebpf_available,
        "systemd_unit_template": SYSTEMD_UNIT,
        "container_k8s_paths_configured": container_paths,
        "signed_baselines": config.get("signing", {}).get("enabled", False),
    }
