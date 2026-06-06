"""File system monitoring and baseline verification."""

from __future__ import annotations

import hashlib
import os
import stat
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    WATCHDOG_AVAILABLE = True
except ImportError:
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = object  # type: ignore[assignment]
    WATCHDOG_AVAILABLE = False

from .ai import IncidentAnalyzer
from .database import DatabaseManager
from .security import SecurityAnalyzer

EventCallback = Callable[[str, str], None]


class SystemMonitorHandler(FileSystemEventHandler):
    def __init__(
        self,
        db: DatabaseManager,
        callback: EventCallback,
        ignore_patterns: List[str],
        max_hash_bytes: int,
        security_analyzer: SecurityAnalyzer,
        incident_analyzer: IncidentAnalyzer,
    ) -> None:
        super().__init__()
        self.db = db
        self.callback = callback
        self.ignore_patterns = ignore_patterns
        self.max_hash_bytes = max_hash_bytes
        self.security_analyzer = security_analyzer
        self.incident_analyzer = incident_analyzer

    def should_ignore(self, path: str) -> bool:
        return any(pattern in path for pattern in self.ignore_patterns)

    def get_file_hash(self, path: str) -> Optional[str]:
        file_hash, _metadata = hash_file(path, self.max_hash_bytes)
        return file_hash

    def _handle_security(self, path: str) -> None:
        if not (path.endswith(".log") or "/var/log" in path):
            return
        for message, severity in self.security_analyzer.analyze(path):
            self.callback(message, severity)
            event_id = self.db.add_event("security_alert", path, message, severity)
            self.incident_analyzer.analyze_async(
                event_id,
                "security_alert",
                path,
                message,
                severity,
                {"indicators": ["security_pattern_match"]},
            )

    def _record_event(
        self,
        event_type: str,
        path: str,
        message: str,
        severity: str,
        metadata: Optional[Dict[str, object]] = None,
    ) -> int:
        event_id = self.db.add_event(event_type, path, message, severity, metadata)
        self.incident_analyzer.analyze_async(
            event_id, event_type, path, message, severity, metadata or {}
        )
        return event_id

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        if self.should_ignore(event.src_path):
            return
        filename = os.path.basename(event.src_path)
        message = f"NEW: {filename} -> {event.src_path}"
        time.sleep(0.2)
        file_hash, metadata = hash_file(event.src_path, self.max_hash_bytes)
        if file_hash:
            self.db.update_hash(event.src_path, file_hash, metadata)
        self.callback(message, "info")
        self._record_event(
            "file_created",
            event.src_path,
            message,
            "info",
            {"current": {**metadata, "hash": file_hash} if file_hash else {}},
        )

    def on_modified(self, event) -> None:
        if event.is_directory:
            return
        if self.should_ignore(event.src_path):
            return
        old_record = self.db.get_hash_record(event.src_path)
        new_hash, metadata = hash_file(event.src_path, self.max_hash_bytes)
        old_hash = old_record["hash"] if old_record else None
        if new_hash and old_hash and old_hash != new_hash:
            filename = os.path.basename(event.src_path)
            message = f"MODIFIED: {filename} -> {event.src_path}"
            self.callback(message, "medium")
            event_metadata = build_change_metadata(old_record, new_hash, metadata)
            self._record_event(
                "file_modified",
                event.src_path,
                message,
                "medium",
                event_metadata,
            )
            self.db.update_hash(event.src_path, new_hash, metadata)
            self._handle_security(event.src_path)
        elif new_hash and not old_hash:
            self.db.update_hash(event.src_path, new_hash, metadata)

    def on_deleted(self, event) -> None:
        if event.is_directory:
            return
        if self.should_ignore(event.src_path):
            return
        filename = os.path.basename(event.src_path)
        message = f"DELETED: {filename} -> {event.src_path}"
        self.callback(message, "high")
        old_record = self.db.get_hash_record(event.src_path)
        self._record_event(
            "file_deleted",
            event.src_path,
            message,
            "high",
            {"previous": old_record or {}},
        )
        self.db.remove_hash(event.src_path)


def file_metadata(path: str) -> Dict[str, object]:
    st = os.stat(path)
    return {
        "size": st.st_size,
        "mtime": st.st_mtime,
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "inode": st.st_ino,
    }


def hash_file(path: str, max_hash_bytes: int) -> Tuple[Optional[str], Dict[str, object]]:
    if not os.path.exists(path) or not os.path.isfile(path):
        return None, {}
    metadata = file_metadata(path)
    if int(metadata["size"]) > max_hash_bytes:
        return None, metadata
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest(), metadata


def build_change_metadata(
    old_record: Optional[Dict[str, object]],
    new_hash: str,
    new_metadata: Dict[str, object],
) -> Dict[str, object]:
    old_record = old_record or {}
    previous = {
        key: old_record.get(key)
        for key in ("hash", "size", "mtime", "mode", "uid", "gid", "inode")
    }
    current = dict(new_metadata)
    current["hash"] = new_hash
    indicators: List[str] = ["hash_mismatch"]
    if previous.get("size") is not None and current.get("size") is not None:
        if int(current["size"]) < int(previous["size"]):
            indicators.append("size_decreased")
        elif int(current["size"]) > int(previous["size"]):
            indicators.append("size_increased")
    for field in ("mode", "uid", "gid", "inode"):
        if previous.get(field) is not None and previous.get(field) != current.get(field):
            indicators.append(f"{field}_changed")
    return {
        "previous": previous,
        "current": current,
        "indicators": indicators,
    }


class MonitorEngine:
    def __init__(
        self,
        config: Dict,
        db: DatabaseManager,
        callback: EventCallback,
        logger,
    ) -> None:
        self.config = config
        self.db = db
        self.callback = callback
        self.logger = logger
        self.observer: Optional[Observer] = None
        self.stop_event = threading.Event()
        self.verify_thread: Optional[threading.Thread] = None

        rules = config.get("log_rules", {})
        self.security_analyzer = SecurityAnalyzer(
            db,
            rules=rules,
            max_bytes=config["monitor"]["log_tail_max_bytes"],
        )
        self.incident_analyzer = IncidentAnalyzer(config, db, logger)

    def start(self) -> bool:
        if not WATCHDOG_AVAILABLE:
            self.callback("watchdog not installed", "high")
            return False

        self.stop_event.clear()
        self.observer = Observer()

        handler = SystemMonitorHandler(
            self.db,
            self.callback,
            ignore_patterns=self.config.get("ignore_patterns", []),
            max_hash_bytes=self.config["monitor"]["hash_max_bytes"],
            security_analyzer=self.security_analyzer,
            incident_analyzer=self.incident_analyzer,
        )

        scheduled = 0
        for entry in self.config.get("paths", []):
            if not entry.get("enabled", True):
                continue
            path = entry.get("path")
            recursive = entry.get("recursive", True)
            if path and not os.path.exists(path):
                try:
                    os.makedirs(path, exist_ok=True)
                    self.callback(f"Created monitored path: {path}", "info")
                except Exception as exc:
                    self.logger.error("Cannot create monitored path %s: %s", path, exc)
                    self.callback(f"Cannot create path: {path}", "medium")
            if path and os.path.exists(path):
                try:
                    self.observer.schedule(handler, path, recursive=recursive)
                    self.callback(f"Monitoring: {path}", "info")
                    scheduled += 1
                except Exception as exc:
                    self.logger.error("Cannot monitor %s: %s", path, exc)
                    self.callback(f"Cannot monitor: {path}", "medium")

        if scheduled == 0:
            self.callback("No paths could be monitored", "high")
            return False

        self.observer.start()
        threading.Thread(target=self._baseline_scan, daemon=True).start()
        self.verify_thread = threading.Thread(target=self._periodic_verify, daemon=True)
        self.verify_thread.start()
        return True

    def verify_now(self) -> Dict[str, object]:
        self.callback("Manual verification started", "info")
        checked_paths = 0
        for entry in self.config.get("paths", []):
            if not entry.get("enabled", True):
                continue
            path = entry.get("path")
            if path and not os.path.exists(path):
                try:
                    os.makedirs(path, exist_ok=True)
                    self.callback(f"Created monitored path: {path}", "info")
                except Exception as exc:
                    self.logger.error("Cannot create monitored path %s: %s", path, exc)
                    self.callback(f"Cannot create path: {path}", "medium")
                    continue
            self._scan_path(path, entry.get("recursive", True), verify=True)
            checked_paths += 1
        self.callback("Manual verification complete", "info")
        return {"status": "ok", "checked_paths": checked_paths}

    def stop(self) -> None:
        self.stop_event.set()
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                pass

    def _baseline_scan(self) -> None:
        self.callback("Baseline scan started", "info")
        for entry in self.config.get("paths", []):
            if not entry.get("enabled", True):
                continue
            self._scan_path(entry.get("path"), entry.get("recursive", True), verify=False)
        self.callback("Baseline scan complete", "info")

    def _periodic_verify(self) -> None:
        interval = self.config["monitor"]["baseline_verify_interval_seconds"]
        while not self.stop_event.wait(interval):
            self.callback("Periodic verification started", "info")
            for entry in self.config.get("paths", []):
                if not entry.get("enabled", True):
                    continue
                self._scan_path(entry.get("path"), entry.get("recursive", True), verify=True)
            self.callback("Periodic verification complete", "info")

    def _scan_path(self, base_path: Optional[str], recursive: bool, verify: bool) -> None:
        if not base_path or not os.path.exists(base_path):
            return
        ignore_patterns = self.config.get("ignore_patterns", [])
        seen_paths = set()

        if recursive:
            for root, _dirs, files in os.walk(base_path):
                if any(pattern in root for pattern in ignore_patterns):
                    continue
                for name in files:
                    path = os.path.join(root, name)
                    if any(pattern in path for pattern in ignore_patterns):
                        continue
                    seen_paths.add(path)
                    self._verify_or_update_hash(path, verify=verify)
        else:
            for name in os.listdir(base_path):
                path = os.path.join(base_path, name)
                if os.path.isfile(path) and not any(
                    pattern in path for pattern in ignore_patterns
                ):
                    seen_paths.add(path)
                    self._verify_or_update_hash(path, verify=verify)
        if verify:
            self._detect_missing_files(base_path, seen_paths, ignore_patterns)

    def _detect_missing_files(
        self,
        base_path: str,
        seen_paths: set[str],
        ignore_patterns: List[str],
    ) -> None:
        for record in self.db.get_hashes_under(base_path):
            path = str(record["path"])
            if path in seen_paths or any(pattern in path for pattern in ignore_patterns):
                continue
            if os.path.exists(path):
                continue
            filename = os.path.basename(path)
            message = f"MISSING FROM BASELINE: {filename} -> {path}"
            self.callback(message, "high")
            event_metadata = {
                "previous": record,
                "indicators": ["missing_during_verification"],
            }
            event_id = self.db.add_event(
                "file_missing",
                path,
                message,
                "high",
                event_metadata,
            )
            self.incident_analyzer.analyze_async(
                event_id,
                "file_missing",
                path,
                message,
                "high",
                event_metadata,
            )
            self.db.remove_hash(path)

    def _verify_or_update_hash(self, path: str, verify: bool) -> None:
        try:
            max_hash_bytes = self.config["monitor"]["hash_max_bytes"]
            new_hash, metadata = hash_file(path, max_hash_bytes)
            if not new_hash:
                return
            old_record = self.db.get_hash_record(path)
            old_hash = old_record["hash"] if old_record else None
            if verify and not old_hash:
                filename = os.path.basename(path)
                message = f"DISCOVERED: {filename} -> {path}"
                event_metadata = {
                    "current": {**metadata, "hash": new_hash},
                    "indicators": ["discovered_during_verification"],
                }
                self.callback(message, "info")
                self.db.add_event("file_created", path, message, "info", event_metadata)
            elif verify and old_hash and old_hash != new_hash:
                filename = os.path.basename(path)
                event_metadata = build_change_metadata(old_record, new_hash, metadata)
                severity = "high" if "size_decreased" in event_metadata["indicators"] else "medium"
                message = f"INTEGRITY DRIFT: {filename} -> {path}"
                self.callback(message, severity)
                event_id = self.db.add_event(
                    "integrity_drift",
                    path,
                    message,
                    severity,
                    event_metadata,
                )
                self.incident_analyzer.analyze_async(
                    event_id,
                    "integrity_drift",
                    path,
                    message,
                    severity,
                    event_metadata,
                )
                self._handle_security(path)
            self.db.update_hash(path, new_hash, metadata)
        except Exception as exc:
            self.logger.error("Hash update failed for %s: %s", path, exc)
