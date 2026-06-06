"""Configuration loading and defaults."""

from __future__ import annotations

import getpass
import json
import os
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "app": {
        "name": "EvideX",
        "log_dir": "~/.local/state/evidex",
        "db_path": "~/.local/state/evidex/store",
        "log_level": "INFO",
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8765,
        "auto_open": False,
    },
    "monitor": {
        "hash_max_bytes": 50 * 1024 * 1024,
        "log_tail_max_bytes": 256 * 1024,
        "baseline_verify_interval_seconds": 900,
        "debounce_seconds": 0.2,
    },
    "paths": [
        {"path": "/var/log", "recursive": True, "label": "System Logs", "enabled": True},
        {"path": "~/Documents", "recursive": True, "label": "Documents", "enabled": True},
        {"path": "~/Desktop", "recursive": True, "label": "Desktop", "enabled": True},
        {"path": "~/Downloads", "recursive": True, "label": "Downloads", "enabled": True},
        {"path": "~/Pictures", "recursive": True, "label": "Pictures", "enabled": True},
        {"path": "~/Videos", "recursive": True, "label": "Videos", "enabled": True},
        {"path": "/etc", "recursive": True, "label": "System Config", "enabled": True},
        {"path": "/var/www", "recursive": True, "label": "Web Server", "enabled": True},
        {"path": "/var/log/containers", "recursive": True, "label": "Kubernetes Container Logs", "enabled": False},
        {"path": "/var/log/pods", "recursive": True, "label": "Kubernetes Pod Logs", "enabled": False},
        {"path": "/var/lib/docker/containers", "recursive": True, "label": "Docker Container Logs", "enabled": False},
    ],
    "ignore_patterns": [
        "-journal",
        ".xbel",
        "dconf",
        ".goutputstream",
        "~",
        ".swp",
        ".tmp",
        ".cache",
        ".lock",
        "Trash",
        ".thumbnails",
        ".mozilla",
        ".config/pulse",
        "__pycache__",
        ".git/",
        "log_monitor.db",
    ],
    "log_rules": {
        "failed_login_patterns": ["failed password", "authentication failure"],
        "sudo_patterns": ["sudo:"],
        "sudo_context": "command",
    },
    "ai": {
        "enabled": False,
        "provider": "openai",
        "api_key_env": "OPENAI_API_KEY",
        "base_url_env": "OPENAI_BASE_URL",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "timeout_seconds": 20,
        "max_context_lines": 60,
        "minimum_severity": "medium",
    },
    "siem": {
        "enabled": False,
        "webhook_url": "",
        "outbox_path": "~/.local/state/evidex/siem_outbox.jsonl",
        "timeout_seconds": 5,
    },
    "signing": {
        "enabled": True,
        "provider": "local-hmac",
        "secret_env": "LOG_INTEGRITY_SIGNING_KEY",
        "kms_key_id": "",
    },
    "ebpf": {
        "enabled": False,
        "mode": "auto",
    },
}


def _expand_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _default_config_path() -> str:
    env_path = os.environ.get("LOG_INTEGRITY_CONFIG")
    if env_path:
        return env_path
    xdg_path = os.path.join(
        os.path.expanduser("~/.config"), "evidex", "config.json"
    )
    if os.path.exists(xdg_path):
        return xdg_path
    local_path = os.path.abspath("./config.json")
    if os.path.exists(local_path):
        return local_path
    return ""


def _is_wsl() -> bool:
    if not os.path.exists("/proc/version"):
        return False
    try:
        with open("/proc/version", "r", encoding="utf-8") as handle:
            return "microsoft" in handle.read().lower()
    except OSError:
        return False


def _find_windows_profile() -> str:
    users_dir = "/mnt/c/Users"
    if not _is_wsl() or not os.path.isdir(users_dir):
        return ""

    candidates = []
    env_user = os.environ.get("USERNAME") or os.environ.get("USER") or getpass.getuser()
    if env_user:
        candidates.append(env_user)
    candidates.extend(["AJF", "sumaiya"])

    ignored = {"Default", "Default User", "All Users", "Public", "desktop.ini", ".", ".."}
    try:
        candidates.extend(
            name for name in os.listdir(users_dir) if name not in ignored
        )
    except OSError:
        return ""

    for username in dict.fromkeys(candidates):
        profile = os.path.join(users_dir, username)
        if os.path.isdir(profile):
            return profile
    return ""


def _map_wsl_user_path(raw_path: str, expanded_path: str, windows_profile: str) -> str:
    if not windows_profile or not raw_path.startswith("~/"):
        return expanded_path
    home_map = {
        "~/Desktop": "Desktop",
        "~/Documents": "Documents",
        "~/Downloads": "Downloads",
        "~/Pictures": "Pictures",
        "~/Videos": "Videos",
    }
    for prefix, folder in home_map.items():
        if raw_path == prefix or raw_path.startswith(prefix + "/"):
            suffix = raw_path[len(prefix):].lstrip("/")
            return os.path.join(windows_profile, folder, suffix)
    return expanded_path


def load_env_file(path: str = ".env") -> None:
    """Load simple KEY=VALUE pairs without overriding existing environment."""
    env_path = os.path.abspath(path)
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def load_config(path: str | None = None) -> Dict[str, Any]:
    """Load configuration and apply defaults."""
    load_env_file()
    config_path = path or _default_config_path()
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as handle:
            user_config = json.load(handle)
    else:
        user_config = {}

    merged = _deep_merge(DEFAULT_CONFIG, user_config)

    merged["app"]["log_dir"] = _expand_path(merged["app"]["log_dir"])
    merged["app"]["db_path"] = _expand_path(merged["app"]["db_path"])

    windows_profile = _find_windows_profile()

    for entry in merged.get("paths", []):
        raw_path = entry.get("path", "")
        expanded = _expand_path(raw_path)
        expanded = _map_wsl_user_path(raw_path, expanded, windows_profile)
        entry["path"] = expanded
    merged["runtime"] = {
        "is_wsl": _is_wsl(),
        "windows_profile": windows_profile,
    }

    return merged
