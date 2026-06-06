"""REST API and web dashboard."""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import urlparse

from .agent import Agent
from .collector import Collector
from .compliance import build_compliance_report
from .completeness import verify_completeness
from .database import DatabaseManager
from .fabrication import detect_ai_fabrication
from .logging_setup import setup_logging
from .platform import production_status
from .signing import sign_payload


PHASES = [
    ("Agent/Collector split", "done", "Agent observes locally; Collector owns intake, storage, forwarding, and verification."),
    ("Hash chaining, replace SQLite", "done", "Events are stored as append-only JSONL with previous_event_hash and event_hash."),
    ("Web UI, REST API, SIEM forwarding", "done", "Dashboard and JSON API are live; SIEM webhook/outbox hook exists."),
    ("eBPF monitoring, systemd packaging", "ready", "Status checks and unit template exist; eBPF activates when host tools exist."),
    ("Compliance report engine", "done", "SOC 2, ISO 27001, PCI DSS, and NIST evidence report available."),
    ("Log completeness verification", "done", "Event ID gaps, monitored path availability, and chain validity are checked."),
    ("AI fabrication detection", "done", "AI assessments are checked for unsupported certainty and evidence mismatch."),
    ("Container/K8s coverage", "ready", "Docker/Kubernetes log paths can be monitored through config."),
    ("Signed baselines with remote KMS", "ready", "Local HMAC signing exists; remote KMS extension point is documented."),
]


def json_response(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    body = json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def html_response(handler: BaseHTTPRequestHandler, html: str) -> None:
    body = html.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def make_handler(
    config: Dict[str, Any],
    store: DatabaseManager,
    collector: Collector,
    agent_state: Dict[str, Any],
):
    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                html_response(self, dashboard_html())
                return
            if path == "/api/health":
                json_response(
                    self,
                    {
                        "status": "ok",
                        "chain": collector.verify_chain(),
                        "production": production_status(config),
                        "agent": {
                            "active": agent_state.get("active", False),
                            "started_at": agent_state.get("started_at"),
                            "last_message": agent_state.get("last_message", ""),
                            "last_severity": agent_state.get("last_severity", "info"),
                            "paths_count": len([p for p in config.get("paths", []) if p.get("enabled", True)]),
                            "log_rules": config.get("log_rules", {}),
                            "runtime": config.get("runtime", {}),
                        },
                    },
                )
                return
            if path == "/api/events":
                json_response(self, store.get_event_records(200))
                return
            if path == "/api/ai":
                rows = store.get_ai_analysis(200)
                json_response(
                    self,
                    [
                        {
                            "id": row[0],
                            "event_id": row[1],
                            "timestamp": row[2],
                            "provider": row[3],
                            "model": row[4],
                            "risk_score": row[5],
                            "classification": row[6],
                            "explanation": row[7],
                            "recommended_action": row[8],
                        }
                        for row in rows
                    ],
                )
                return
            if path == "/api/compliance":
                json_response(self, build_compliance_report(config, store))
                return
            if path == "/api/completeness":
                json_response(self, verify_completeness(config, store))
                return
            if path == "/api/fabrication":
                json_response(self, detect_ai_fabrication(store))
                return
            if path == "/api/platform":
                json_response(self, production_status(config))
                return
            if path == "/api/baseline-signature":
                payload = {
                    "chain": store.verify_chain(),
                    "completeness": verify_completeness(config, store),
                }
                json_response(self, sign_payload(config, payload))
                return
            if path == "/api/verify-files":
                json_response(self, _run_verify(agent_state))
                return
            if path == "/api/reset":
                json_response(self, store.reset_store())
                return
            if path == "/api/phases":
                json_response(
                    self,
                    [
                        {"name": name, "status": status, "detail": detail}
                        for name, status, detail in PHASES
                    ],
                )
                return
            json_response(self, {"error": "not found"}, status=404)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/verify-files":
                json_response(self, _run_verify(agent_state))
                return
            if path == "/api/reset":
                json_response(self, store.reset_store())
                return
            json_response(self, {"error": "not found"}, status=404)

    return DashboardHandler


def _run_verify(agent_state: Dict[str, Any]) -> Dict[str, Any]:
    agent = agent_state.get("agent")
    if not agent:
        return {"status": "error", "message": "agent is not available"}
    return agent.verify_now()


def dashboard_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EvideX | Evidence Integrity Control Panel</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      color-scheme: dark;
      --bg-primary: #0a0d14;
      --bg-secondary: #101420;
      --bg-tertiary: #171d2e;
      --accent: #4f46e5;
      --accent-glow: rgba(79, 70, 229, 0.15);
      --accent-light: #818cf8;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --border-color: rgba(255, 255, 255, 0.07);
      
      --success: #10b981;
      --success-glow: rgba(16, 185, 129, 0.15);
      --warning: #f59e0b;
      --warning-glow: rgba(245, 158, 11, 0.15);
      --danger: #ef4444;
      --danger-glow: rgba(239, 68, 68, 0.15);
      --info: #3b82f6;
      --info-glow: rgba(59, 130, 246, 0.15);

      --sidebar-width: 260px;
      --transition-speed: 0.25s;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-primary);
      color: var(--text-main);
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }

    /* Scrollbars */
    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    ::-webkit-scrollbar-track {
      background: var(--bg-primary);
    }
    ::-webkit-scrollbar-thumb {
      background: var(--bg-tertiary);
      border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: var(--accent);
    }

    /* Sidebar Layout */
    aside {
      width: var(--sidebar-width);
      background-color: var(--bg-secondary);
      border-right: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      height: 100vh;
      position: fixed;
      left: 0;
      top: 0;
      z-index: 100;
    }

    .brand {
      padding: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
      border-bottom: 1px solid var(--border-color);
    }

    .brand svg {
      width: 28px;
      height: 28px;
      color: var(--accent-light);
      filter: drop-shadow(0 0 8px var(--accent-glow));
    }

    .brand h1 {
      font-size: 16px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      background: linear-gradient(135deg, #fff 30%, var(--accent-light));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .nav-links {
      list-style: none;
      padding: 20px 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      flex-grow: 1;
    }

    .nav-item button {
      width: 100%;
      background: none;
      border: none;
      color: var(--text-muted);
      padding: 12px 16px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 14px;
      font-weight: 500;
      text-align: left;
      transition: all var(--transition-speed) ease;
    }

    .nav-item button svg {
      width: 18px;
      height: 18px;
      transition: transform var(--transition-speed) ease;
    }

    .nav-item button:hover {
      background-color: rgba(255, 255, 255, 0.03);
      color: var(--text-main);
    }

    .nav-item button:hover svg {
      transform: translateX(2px);
    }

    .nav-item.active button {
      background-color: var(--accent-glow);
      color: var(--accent-light);
      border: 1px solid rgba(79, 70, 229, 0.2);
    }

    .nav-item.active button svg {
      color: var(--accent-light);
    }

    .sidebar-footer {
      padding: 20px;
      border-top: 1px solid var(--border-color);
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .sidebar-footer .status-indicator {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 500;
    }

    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
    }

    .dot.active {
      background-color: var(--success);
      box-shadow: 0 0 10px var(--success);
      animation: pulse 2s infinite;
    }

    .dot.error {
      background-color: var(--danger);
      box-shadow: 0 0 10px var(--danger);
      animation: pulse 1.5s infinite;
    }

    @keyframes pulse {
      0% { transform: scale(0.95); opacity: 0.8; }
      50% { transform: scale(1.1); opacity: 1; }
      100% { transform: scale(0.95); opacity: 0.8; }
    }

    /* Main Content Layout */
    .wrapper {
      margin-left: var(--sidebar-width);
      width: calc(100% - var(--sidebar-width));
      display: flex;
      flex-direction: column;
      min-height: 100vh;
    }

    header {
      background-color: var(--bg-secondary);
      border-bottom: 1px solid var(--border-color);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 90;
      backdrop-filter: blur(10px);
      background-color: rgba(16, 20, 32, 0.8);
    }

    .header-title h2 {
      font-size: 18px;
      font-weight: 600;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .btn {
      background-color: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all var(--transition-speed) ease;
    }

    .btn:hover {
      background-color: rgba(255, 255, 255, 0.05);
      border-color: var(--text-muted);
    }

    .btn-primary {
      background-color: var(--accent);
      border-color: var(--accent);
    }

    .btn-primary:hover {
      background-color: var(--accent-light);
      border-color: var(--accent-light);
      box-shadow: 0 0 12px rgba(79, 70, 229, 0.35);
    }

    /* Main View Sections */
    main {
      padding: 32px;
      flex-grow: 1;
    }

    .view-section {
      display: none;
      animation: fadeIn var(--transition-speed) ease;
    }

    .view-section.active {
      display: block;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }

    .card {
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      position: relative;
      overflow: hidden;
      transition: transform 0.3s ease, border-color 0.3s ease;
    }

    .card:hover {
      transform: translateY(-2px);
      border-color: rgba(79, 70, 229, 0.25);
    }

    .card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 4px;
      height: 100%;
      background-color: var(--accent);
      opacity: 0;
      transition: opacity 0.3s ease;
    }

    .card:hover::before {
      opacity: 1;
    }

    .kpi-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }

    .kpi-title {
      font-size: 13px;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.5px;
    }

    .kpi-icon {
      color: var(--text-muted);
      background-color: var(--bg-tertiary);
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .kpi-value {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.5px;
    }

    .kpi-subtext {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 6px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    /* Double Layout */
    .two-col-layout {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 24px;
      margin-bottom: 32px;
    }

    @media (max-width: 1024px) {
      .two-col-layout {
        grid-template-columns: 1fr;
      }
    }

    .section-box {
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 24px;
    }

    .box-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .box-title {
      font-size: 16px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Timelines */
    .timeline {
      list-style: none;
      position: relative;
      padding-left: 20px;
    }

    .timeline::before {
      content: '';
      position: absolute;
      left: 7px;
      top: 8px;
      bottom: 8px;
      width: 2px;
      background-color: var(--border-color);
    }

    .timeline-item {
      position: relative;
      padding-bottom: 20px;
    }

    .timeline-item:last-child {
      padding-bottom: 0;
    }

    .timeline-marker {
      position: absolute;
      left: -19px;
      top: 5px;
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background-color: var(--bg-secondary);
      border: 2.5px solid var(--text-muted);
      z-index: 2;
    }

    .timeline-item.high .timeline-marker { border-color: var(--danger); }
    .timeline-item.medium .timeline-marker { border-color: var(--warning); }
    .timeline-item.info .timeline-marker { border-color: var(--info); }
    .timeline-item.success .timeline-marker { border-color: var(--success); }

    .timeline-content {
      background-color: rgba(255, 255, 255, 0.015);
      border: 1px solid rgba(255, 255, 255, 0.03);
      padding: 12px 16px;
      border-radius: 8px;
    }

    .timeline-meta {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: var(--text-muted);
      margin-bottom: 4px;
    }

    .timeline-msg {
      font-size: 13px;
      font-weight: 500;
    }

    .timeline-path {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 4px;
      word-break: break-all;
    }

    /* Platform Readiness Checklist */
    .readiness-list {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .readiness-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 14px;
      background-color: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 8px;
    }

    .readiness-info {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }

    .readiness-name {
      font-size: 13px;
      font-weight: 600;
    }

    .readiness-desc {
      font-size: 11px;
      color: var(--text-muted);
    }

    /* Status Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 3px 10px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      border: 1px solid currentColor;
    }

    .badge-success { color: var(--success); background-color: var(--success-glow); }
    .badge-warning { color: var(--warning); background-color: var(--warning-glow); }
    .badge-danger { color: var(--danger); background-color: var(--danger-glow); }
    .badge-info { color: var(--info); background-color: var(--info-glow); }
    .badge-muted { color: var(--text-muted); background-color: rgba(255, 255, 255, 0.04); }

    /* Tables */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    th {
      text-align: left;
      padding: 12px 16px;
      color: var(--text-muted);
      font-weight: 600;
      font-size: 12px;
      border-bottom: 2px solid var(--border-color);
    }

    td {
      padding: 14px 16px;
      border-bottom: 1px solid var(--border-color);
      vertical-align: middle;
    }

    tr:hover td {
      background-color: rgba(255, 255, 255, 0.015);
    }

    .table-container {
      overflow-x: auto;
      border-radius: 8px;
      border: 1px solid var(--border-color);
      background-color: rgba(255, 255, 255, 0.01);
    }

    .mono {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }

    /* Filters Box */
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 20px;
      background-color: rgba(255, 255, 255, 0.02);
      padding: 16px;
      border-radius: 8px;
      border: 1px solid var(--border-color);
    }

    .filter-input-group {
      display: flex;
      flex-direction: column;
      gap: 6px;
      flex-grow: 1;
      min-width: 200px;
    }

    .filter-label {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
    }

    .form-control {
      background-color: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
      outline: none;
      transition: border-color var(--transition-speed);
      width: 100%;
    }

    .form-control:focus {
      border-color: var(--accent-light);
    }

    /* Pagination */
    .pagination {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 16px;
    }

    .pagination-info {
      font-size: 12px;
      color: var(--text-muted);
    }

    .pagination-actions {
      display: flex;
      gap: 8px;
    }

    /* Hash Chain Render */
    .chain-flow-container {
      display: flex;
      flex-direction: column;
      gap: 14px;
      max-height: 600px;
      overflow-y: auto;
      padding: 10px;
    }

    .chain-block {
      background: linear-gradient(135deg, var(--bg-secondary) 0%, rgba(23, 29, 46, 0.4) 100%);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 16px;
      position: relative;
      cursor: pointer;
      transition: all 0.25s ease;
    }

    .chain-block:hover {
      border-color: var(--accent-light);
      box-shadow: 0 4px 20px rgba(79, 70, 229, 0.15);
      transform: translateX(4px);
    }

    .chain-block.active-block {
      border-color: var(--accent-light);
      background-color: var(--accent-glow);
    }

    .block-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }

    .block-id {
      font-weight: 700;
      color: var(--accent-light);
      font-size: 14px;
    }

    .block-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    @media (max-width: 768px) {
      .block-grid {
        grid-template-columns: 1fr;
      }
    }

    .block-meta-row {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }

    .block-meta-label {
      font-size: 10px;
      text-transform: uppercase;
      color: var(--text-muted);
      font-weight: 600;
    }

    .block-meta-value {
      font-size: 12px;
      word-break: break-all;
    }

    .chain-link-connector {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 8px 0;
      position: relative;
    }

    .chain-link-connector::before {
      content: '';
      position: absolute;
      top: 0;
      bottom: 0;
      width: 2px;
      background-color: var(--border-color);
      z-index: 1;
    }

    .chain-link-indicator {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      background-color: var(--bg-tertiary);
      border: 2px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 2;
      font-size: 10px;
      color: var(--text-muted);
    }

    .chain-link-connector.valid::before { background-color: var(--success); }
    .chain-link-connector.valid .chain-link-indicator { border-color: var(--success); color: var(--success); }
    .chain-link-connector.broken::before { background-color: var(--danger); }
    .chain-link-connector.broken .chain-link-indicator { border-color: var(--danger); color: var(--danger); }

    /* Modals */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: rgba(5, 5, 10, 0.85);
      backdrop-filter: blur(8px);
      z-index: 1000;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }

    .modal {
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      width: 100%;
      max-width: 680px;
      max-height: 85vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      animation: modalScale 0.3s ease;
      box-shadow: 0 24px 48px -12px rgba(0,0,0,0.8);
    }

    @keyframes modalScale {
      from { opacity: 0; transform: scale(0.96); }
      to { opacity: 1; transform: scale(1); }
    }

    .modal-header {
      padding: 20px 24px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .modal-title {
      font-size: 16px;
      font-weight: 600;
    }

    .close-btn {
      background: none;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: color var(--transition-speed);
    }

    .close-btn:hover {
      color: var(--text-main);
    }

    .modal-body {
      padding: 24px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .modal-details-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 16px;
    }

    @media (max-width: 500px) {
      .modal-details-grid {
        grid-template-columns: 1fr;
      }
    }

    .raw-viewer {
      background-color: var(--bg-primary);
      border: 1px solid var(--border-color);
      padding: 16px;
      border-radius: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      max-height: 300px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }

    /* Compliance Accordions */
    .compliance-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .compliance-card {
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow: hidden;
    }

    .compliance-trigger {
      width: 100%;
      background: none;
      border: none;
      color: var(--text-main);
      padding: 16px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      cursor: pointer;
      text-align: left;
      font-weight: 600;
      transition: background-color var(--transition-speed);
    }

    .compliance-trigger:hover {
      background-color: rgba(255, 255, 255, 0.015);
    }

    .compliance-info {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .compliance-panel {
      display: none;
      padding: 20px;
      border-top: 1px solid var(--border-color);
      background-color: rgba(255, 255, 255, 0.005);
      animation: slideDown 0.2s ease;
    }

    @keyframes slideDown {
      from { opacity: 0; transform: translateY(-5px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .compliance-evidence {
      margin-top: 14px;
      border-top: 1px dashed var(--border-color);
      padding-top: 14px;
    }

    .evidence-title {
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 8px;
    }

    /* Risk Score Gauge */
    .risk-score-container {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .risk-gauge {
      width: 120px;
      background-color: var(--bg-tertiary);
      height: 8px;
      border-radius: 4px;
      overflow: hidden;
    }

    .risk-fill {
      height: 100%;
      border-radius: 4px;
    }

    /* AI Fabrication Banner */
    .fabrication-alert {
      background-color: var(--danger-glow);
      border: 1px solid rgba(239, 68, 68, 0.2);
      color: var(--danger);
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 16px;
      display: flex;
      align-items: flex-start;
      gap: 12px;
      font-size: 13px;
    }

    .fabrication-alert svg {
      width: 20px;
      height: 20px;
      flex-shrink: 0;
    }

    /* Config Monitored Paths List */
    .paths-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 16px;
    }

    .path-card {
      background-color: rgba(255, 255, 255, 0.015);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .path-card-title {
      font-weight: 600;
      font-size: 14px;
    }

    .path-card-val {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--text-muted);
      word-break: break-all;
    }

    .path-card-meta {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 6px;
      font-size: 11px;
      color: var(--text-muted);
    }

    /* Clipboard notification */
    .copy-success {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background-color: var(--success);
      color: white;
      padding: 10px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 500;
      box-shadow: 0 10px 20px rgba(0,0,0,0.3);
      z-index: 10000;
      opacity: 0;
      transform: translateY(10px);
      transition: all 0.3s ease;
      pointer-events: none;
    }

    .copy-success.show {
      opacity: 1;
      transform: translateY(0);
    }
  </style>
</head>
<body>

  <!-- Sidebar Navigation -->
  <aside>
    <div class="brand">
      <svg fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"></path>
      </svg>
      <h1>EvideX</h1>
    </div>
    <ul class="nav-links">
      <li class="nav-item active" data-view="overview">
        <button>
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z"></path>
          </svg>
          Overview
        </button>
      </li>
      <li class="nav-item" data-view="chain">
        <button>
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244"></path>
          </svg>
          Chain Visualizer
        </button>
      </li>
      <li class="nav-item" data-view="events">
        <button>
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" d="M8.25 6.75h12M8.25 12h12M8.25 17.25h12M3 6.75h.008v.008H3V6.75zm0 5.25h.008v.008H3V12zm0 5.25h.008v.008H3v-.008z"></path>
          </svg>
          Event Explorer
        </button>
      </li>
      <li class="nav-item" data-view="compliance">
        <button>
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.25 2.25 0 002.24 5.61C2.24 6.848 2.24 8.087 2.24 9.324m0 0a2.25 2.25 0 002.24 2.224h10.04m-12.28 0v7.696a2.25 2.25 0 002.25 2.25h13.5a2.25 2.25 0 002.25-2.25v-7.696"></path>
          </svg>
          Compliance Audits
        </button>
      </li>
      <li class="nav-item" data-view="ai">
        <button>
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9.75 3.104v1.244c0 .508-.385.937-.88 1.02a3.722 3.722 0 00-1.579.645c-.415.29-.53.868-.218 1.285l.89 1.186c.312.416.312.998 0 1.414l-.89 1.187c-.312.417-.197.994.218 1.285.474.333 1.01.554 1.579.645.495.083.88.512.88 1.02v1.244M9.75 3.104c0-.508.385-.937.88-1.02a3.723 3.723 0 013.14 0c.495.083.88.512.88 1.02v1.244m-4.9 0h4.9m0-1.244v1.244c0 .508.385.937.88 1.02a3.722 3.722 0 011.579.645c.415.29.53.868.218 1.285l-.89 1.186c-.312.416-.312.998 0 1.414l.89 1.187c.312.417.197.994-.218 1.285a3.722 3.722 0 01-1.579.645c-.495.083-.88.512-.88 1.02v1.244m0-1.244h-4.9M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
          </svg>
          AI Analyst
        </button>
      </li>
      <li class="nav-item" data-view="config">
        <button>
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.43l-1.003.828c-.293.241-.438.613-.43.992a7.723 7.723 0 010 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.43l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.991l-1.004-.827a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.645-.869l.214-1.28z"></path>
            <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
          </svg>
          System Config
        </button>
      </li>
    </ul>
    <div class="sidebar-footer">
      <div class="status-indicator">
        <span class="dot" id="sidebarDot"></span>
        <span id="sidebarStatusText">Initializing</span>
      </div>
      <div>Last Sync: <span id="sidebarSyncTime">-</span></div>
    </div>
  </aside>

  <!-- Main Section Wrapper -->
  <div class="wrapper">
    <header>
      <div class="header-title">
        <h2 id="viewTitle">Overview Dashboard</h2>
      </div>
      <div class="header-actions">
        <button class="btn" onclick="triggerRefresh()" id="refreshBtn">
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 14px; height: 14px;">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99"></path>
          </svg>
          Re-Verify Now
        </button>
        <button class="btn" onclick="resetStore()" id="resetBtn" style="border-color: rgba(239,68,68,0.45); color: var(--danger);">
          Clear Database
        </button>
      </div>
    </header>

    <main>
      
      <!-- VIEW: OVERVIEW -->
      <section id="view-overview" class="view-section active">
        <div class="kpi-grid">
          <div class="card">
            <div class="kpi-header">
              <span class="kpi-title">Chain Health</span>
              <div class="kpi-icon">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 16px; height: 16px;">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"></path>
                </svg>
              </div>
            </div>
            <div class="kpi-value" id="kpiChain">-</div>
            <div class="kpi-subtext" id="kpiChainSub">Checking cryptographic ledger...</div>
          </div>
          
          <div class="card">
            <div class="kpi-header">
              <span class="kpi-title">Total Logs</span>
              <div class="kpi-icon">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 16px; height: 16px;">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 13.5h3.86a2.25 2.25 0 012.008 1.24l.885 1.77a2.25 2.25 0 002.007 1.24h1.98a2.25 2.25 0 002.007-1.24l.885-1.77a2.25 2.25 0 012.007-1.24h3.86m-18 0h18"></path>
                </svg>
              </div>
            </div>
            <div class="kpi-value" id="kpiEvents">0</div>
            <div class="kpi-subtext">Verified append-only events</div>
          </div>

          <div class="card">
            <div class="kpi-header">
              <span class="kpi-title">Completeness</span>
              <div class="kpi-icon">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 16px; height: 16px;">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
              </div>
            </div>
            <div class="kpi-value" id="kpiCompleteness">-</div>
            <div class="kpi-subtext" id="kpiCompletenessSub">Gaps & path scan status</div>
          </div>

          <div class="card">
            <div class="kpi-header">
              <span class="kpi-title">AI Fabrications</span>
              <div class="kpi-icon">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 16px; height: 16px;">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"></path>
                </svg>
              </div>
            </div>
            <div class="kpi-value" id="kpiFabrications">0</div>
            <div class="kpi-subtext" id="kpiFabricationsSub">AI Mismatches Detected</div>
          </div>
        </div>

        <div class="two-col-layout">
          <!-- Recent Events -->
          <div class="section-box">
            <div class="box-header">
              <span class="box-title">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 18px; height: 18px; color: var(--accent-light);">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                Recent Integrity Events
              </span>
              <button class="btn" style="padding: 4px 8px; font-size: 11px;" onclick="navigateToTab('events')">View All</button>
            </div>
            <ul class="timeline" id="recentTimeline">
              <!-- JS rendered -->
            </ul>
          </div>

          <!-- Platform Readiness -->
          <div class="section-box">
            <div class="box-header">
              <span class="box-title">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 18px; height: 18px; color: var(--accent-light);">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z"></path>
                </svg>
                Host Coverage Status
              </span>
            </div>
            <div class="readiness-list" id="readinessList">
              <!-- JS rendered -->
            </div>
          </div>
        </div>
      </section>

      <!-- VIEW: CHAIN VISUALIZER -->
      <section id="view-chain" class="view-section">
        <div class="section-box" style="margin-bottom: 24px;">
          <div class="box-header">
            <span class="box-title">Cryptographic Block Ledger Chain</span>
            <span class="badge badge-success" id="chainVerifyBadge">Chain Cryptographically Linked</span>
          </div>
          <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 20px; max-width: 800px;">
            The event store replaces insecure databases with an append-only hash chain. Each event body digests its metadata and the prior block's signature hash. If any event is deleted, swapped, or altered, the chain link breaks instantly.
          </p>
          <div class="chain-flow-container" id="chainBlocksContainer">
            <!-- Chain blocks rendered here by JS -->
          </div>
        </div>
      </section>

      <!-- VIEW: EVENT EXPLORER -->
      <section id="view-events" class="view-section">
        <div class="section-box">
          <div class="filter-bar">
            <div class="filter-input-group">
              <span class="filter-label">Search Messages / Paths</span>
              <input type="text" id="filterSearch" class="form-control" placeholder="Search logs..." oninput="handleFilterChange()">
            </div>
            <div class="filter-input-group" style="max-width: 160px;">
              <span class="filter-label">Severity</span>
              <select id="filterSeverity" class="form-control" onchange="handleFilterChange()">
                <option value="all">All Severities</option>
                <option value="high">High & Critical</option>
                <option value="medium">Medium</option>
                <option value="info">Info / Low</option>
              </select>
            </div>
            <div class="filter-input-group" style="max-width: 200px;">
              <span class="filter-label">Event Type</span>
              <select id="filterType" class="form-control" onchange="handleFilterChange()">
                <option value="all">All Events</option>
                <option value="file_created">File Created</option>
                <option value="file_modified">File Modified</option>
                <option value="file_deleted">File Deleted</option>
                <option value="file_missing">Missing from Baseline</option>
                <option value="integrity_drift">Integrity Drift</option>
                <option value="security_alert">Security Pattern Match</option>
              </select>
            </div>
          </div>

          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th style="width: 70px;">ID</th>
                  <th style="width: 140px;">Timestamp</th>
                  <th style="width: 150px;">Type</th>
                  <th style="width: 100px;">Severity</th>
                  <th>Path</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody id="eventsTableBody">
                <!-- JS rendered -->
              </tbody>
            </table>
          </div>

          <div class="pagination">
            <div class="pagination-info" id="paginationInfo">Showing 0-0 of 0 events</div>
            <div class="pagination-actions">
              <button class="btn" id="prevPageBtn" onclick="changePage(-1)" disabled>Previous</button>
              <button class="btn" id="nextPageBtn" onclick="changePage(1)" disabled>Next</button>
            </div>
          </div>
        </div>
      </section>

      <!-- VIEW: COMPLIANCE AUDITS -->
      <section id="view-compliance" class="view-section">
        <div class="section-box" style="margin-bottom: 24px;">
          <div class="box-header">
            <span class="box-title">Regulatory Compliance Mapping Report</span>
            <span class="badge badge-success" id="complianceSummaryBadge">SOC 2 compliant</span>
          </div>
          <p style="font-size: 13px; color: var(--text-muted); max-width: 800px; margin-bottom: 20px;">
            This engine maps event hashes, verification integrity parameters, and file drift audit trails directly to specific requirements for SOC 2, ISO 27001, PCI DSS, and NIST.
          </p>

          <div class="compliance-list" id="complianceList">
            <!-- JS rendered accordions -->
          </div>
        </div>
      </section>

      <!-- VIEW: AI ANALYST -->
      <section id="view-ai" class="view-section">
        <!-- Fabrication warnings section -->
        <div id="aiFabricationsContainer">
          <!-- Warnings list -->
        </div>

        <div class="section-box">
          <div class="box-header">
            <span class="box-title">Incident Analysis Logs</span>
          </div>
          <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 20px;">
            The local agent sends anomalies to an AI Large Language Model for incident triage assessment. The analyzer returns risk scores and classifications. We audit these findings for accuracy.
          </p>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th style="width: 70px;">ID</th>
                  <th style="width: 70px;">Event ID</th>
                  <th style="width: 130px;">Model</th>
                  <th style="width: 160px;">Risk Score</th>
                  <th style="width: 120px;">Classification</th>
                  <th>Recommended Action</th>
                  <th style="width: 90px;">Details</th>
                </tr>
              </thead>
              <tbody id="aiTableBody">
                <!-- JS rendered -->
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- VIEW: CONFIG -->
      <section id="view-config" class="view-section">
        <div class="two-col-layout">
          <!-- Monitored Paths -->
          <div class="section-box">
            <div class="box-header">
              <span class="box-title">Monitored System Paths</span>
            </div>
            <div class="paths-grid" id="configPathsGrid">
              <!-- JS rendered cards -->
            </div>
          </div>

          <!-- Cryptographic baseline signing -->
          <div class="section-box" style="display: flex; flex-direction: column; gap: 16px;">
            <div class="box-header">
              <span class="box-title">Manual Verification Hub</span>
            </div>
            <p style="font-size: 13px; color: var(--text-muted);">
              Trigger immediate filesystem verification or clear the local evidence store. Manual verification captures newly discovered files, modifications, and deletions.
            </p>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
              <button class="btn btn-primary" onclick="triggerRefresh()" style="justify-content:center;">Run Verification Scan</button>
              <button class="btn" onclick="resetStore()" style="justify-content:center; border-color: rgba(239,68,68,0.45); color: var(--danger);">Clear Database</button>
            </div>
          </div>

          <!-- Cryptographic baseline signing -->
          <div class="section-box" style="display: flex; flex-direction: column; gap: 16px;">
            <div class="box-header">
              <span class="box-title">Integrity Signature Verification</span>
            </div>
            <p style="font-size: 13px; color: var(--text-muted);">
              Request a cryptographically signed baseline status. The payload signs the current database state and log completeness metrics.
            </p>
            <div style="background-color: rgba(255,255,255,0.02); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; display: flex; flex-direction: column; gap: 12px;">
              <div>
                <span class="filter-label">Signature Provider</span>
                <div style="font-size: 14px; font-weight: 600; margin-top: 4px;" id="signProvider">-</div>
              </div>
              <div>
                <span class="filter-label">Cryptographic Baseline Signature</span>
                <div style="font-size: 11px; font-family: 'JetBrains Mono', monospace; word-break: break-all; margin-top: 4px; padding: 10px; background-color: var(--bg-primary); border-radius: 6px; border: 1px solid var(--border-color); cursor: pointer;" id="signHash" onclick="copyText(this.textContent)" title="Click to Copy">
                  Loading...
                </div>
              </div>
            </div>
            <button class="btn btn-primary" onclick="loadBaselineSignature()" style="justify-content: center;">
              Refresh Baseline Signature
            </button>
          </div>
        </div>

        <!-- Ignore patterns list -->
        <div class="section-box">
          <div class="box-header">
            <span class="box-title">Ignore Patterns List</span>
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 8px;" id="configIgnoreList">
            <!-- JS rendered -->
          </div>
        </div>
      </section>

    </main>
  </div>

  <!-- Detail Modal -->
  <div class="modal-overlay" id="detailModalOverlay" onclick="closeModal(event)">
    <div class="modal" onclick="event.stopPropagation()">
      <div class="modal-header">
        <h3 class="modal-title" id="modalTitle">Event Details</h3>
        <button class="close-btn" onclick="closeModal()">&times;</button>
      </div>
      <div class="modal-body">
        <div class="modal-details-grid" id="modalDetails">
          <!-- Rendered details key values -->
        </div>
        <div style="display: flex; flex-direction: column; gap: 6px;">
          <span class="filter-label">Raw JSON Document</span>
          <pre class="raw-viewer" id="modalRawJson"></pre>
        </div>
      </div>
    </div>
  </div>

  <!-- Copied notification -->
  <div class="copy-success" id="copyNotification">Copied to clipboard!</div>

  <!-- JavaScript State & Logic -->
  <script>
    // State management
    const state = {
      health: {},
      events: [],
      ai: [],
      compliance: {},
      completeness: {},
      fabrication: {},
      platform: {},
      phases: [],
      activeView: 'overview',
      currentPage: 1,
      pageSize: 15,
      searchQuery: '',
      severityFilter: 'all',
      typeFilter: 'all',
      isRefreshing: false
    };

    // Navigation views mapping
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');
    const viewTitle = document.getElementById('viewTitle');

    navItems.forEach(item => {
      item.addEventListener('click', () => {
        const targetView = item.getAttribute('data-view');
        navigateToTab(targetView);
      });
    });

    function navigateToTab(viewName) {
      state.activeView = viewName;
      
      navItems.forEach(i => {
        if(i.getAttribute('data-view') === viewName) {
          i.classList.add('active');
        } else {
          i.classList.remove('active');
        }
      });

      viewSections.forEach(s => {
        if(s.id === `view-${viewName}`) {
          s.classList.add('active');
        } else {
          s.classList.remove('active');
        }
      });

      // Update Header Title
      const titles = {
        overview: 'Overview Dashboard',
        chain: 'Cryptographic Hash Chain',
        events: 'Event Explorer & Audit logs',
        compliance: 'Regulatory Compliance Center',
        ai: 'AI Incident Analysis Auditing',
        config: 'System Platform & Configurations'
      };
      viewTitle.textContent = titles[viewName] || 'Dashboard';
      render();
    }

    // API calls helper
    async function fetchJson(endpoint) {
      try {
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return await response.json();
      } catch (e) {
        console.error(`Error fetching ${endpoint}:`, e);
        return null;
      }
    }

    async function postJson(endpoint) {
      try {
        const response = await fetch(endpoint, { method: 'POST' });
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return await response.json();
      } catch (e) {
        console.error(`Error posting ${endpoint}:`, e);
        return null;
      }
    }

    // Fetch all states in parallel
    async function syncData() {
      if (state.isRefreshing) return;
      state.isRefreshing = true;
      
      const refreshBtn = document.getElementById('refreshBtn');
      if (refreshBtn) refreshBtn.disabled = true;

      try {
        const [health, events, ai, compliance, completeness, fabrication, platform, phases] = await Promise.all([
          fetchJson('/api/health'),
          fetchJson('/api/events'),
          fetchJson('/api/ai'),
          fetchJson('/api/compliance'),
          fetchJson('/api/completeness'),
          fetchJson('/api/fabrication'),
          fetchJson('/api/platform'),
          fetchJson('/api/phases')
        ]);

        if (health) state.health = health;
        if (events) state.events = events;
        if (ai) state.ai = ai;
        if (compliance) state.compliance = compliance;
        if (completeness) state.completeness = completeness;
        if (fabrication) state.fabrication = fabrication;
        if (platform) state.platform = platform;
        if (phases) state.phases = phases;

        state.lastSync = new Date().toLocaleTimeString();
      } catch (err) {
        console.error("Failed to sync metrics dashboard data:", err);
      } finally {
        state.isRefreshing = false;
        if (refreshBtn) refreshBtn.disabled = false;
        render();
      }
    }

    // Manual triggers
    async function triggerRefresh() {
      const btn = document.getElementById('refreshBtn');
      const origText = btn.innerHTML;
      btn.innerHTML = 'Verifying...';
      const result = await postJson('/api/verify-files');
      if (!result || result.status === 'error') {
        showToast(result && result.message ? result.message : "Verification failed");
      } else {
        showToast(`Verification completed across ${result.checked_paths || 0} paths`);
      }
      await syncData();
      btn.innerHTML = origText;
    }

    async function resetStore() {
      if (!confirm('Clear all EvideX events, AI findings, baselines, and hash-chain manifest?')) return;
      const btn = document.getElementById('resetBtn');
      if (btn) btn.disabled = true;
      const result = await postJson('/api/reset');
      await syncData();
      if (btn) btn.disabled = false;
      showToast(result && result.status === 'reset' ? 'Database cleared' : 'Reset failed');
    }

    async function loadBaselineSignature() {
      const signProvider = document.getElementById('signProvider');
      const signHash = document.getElementById('signHash');
      signHash.textContent = 'Generating...';
      const sigData = await fetchJson('/api/baseline-signature');
      if (sigData) {
        signProvider.textContent = sigData.provider || 'unknown';
        signHash.textContent = sigData.signature || 'No signature returned';
      } else {
        signHash.textContent = 'Error loading signature';
      }
    }

    // Filtering inputs
    function handleFilterChange() {
      state.searchQuery = document.getElementById('filterSearch').value.toLowerCase();
      state.severityFilter = document.getElementById('filterSeverity').value;
      state.typeFilter = document.getElementById('filterType').value;
      state.currentPage = 1; // reset page on filter change
      renderEvents();
    }

    function changePage(direction) {
      state.currentPage += direction;
      renderEvents();
    }

    // Modal logic
    function openEventModal(event) {
      const modalOverlay = document.getElementById('detailModalOverlay');
      const title = document.getElementById('modalTitle');
      const details = document.getElementById('modalDetails');
      const raw = document.getElementById('modalRawJson');

      title.textContent = `Event #${event.id} Details`;
      
      const cleanType = String(event.event_type).replace(/_/g, ' ').toUpperCase();
      let metaHtml = `
        <div>
          <span class="filter-label">Timestamp</span>
          <div style="font-size:13px; margin-top:3px;">${event.timestamp}</div>
        </div>
        <div>
          <span class="filter-label">Event Type</span>
          <div style="margin-top:3px;"><span class="badge ${getBadgeClass(event.event_type)}">${cleanType}</span></div>
        </div>
        <div>
          <span class="filter-label">Severity</span>
          <div style="margin-top:3px;"><span class="badge ${getBadgeClass(event.severity)}">${event.severity}</span></div>
        </div>
        <div>
          <span class="filter-label">Cryptographic Hash</span>
          <div class="mono" style="font-size:11px; margin-top:3px; word-break:break-all; cursor:pointer;" onclick="copyText('${event.event_hash}')" title="Click to copy">${event.event_hash ? event.event_hash.slice(0, 16) + '...' : 'none'}</div>
        </div>
        <div style="grid-column: span 2;">
          <span class="filter-label">Monitored File Path</span>
          <div class="mono" style="font-size:11px; margin-top:3px; word-break:break-all;">${event.file_path}</div>
        </div>
        <div style="grid-column: span 2;">
          <span class="filter-label">Log message</span>
          <div style="font-size:13px; font-weight: 500; margin-top:3px;">${event.message}</div>
        </div>
      `;
      details.innerHTML = metaHtml;
      raw.textContent = JSON.stringify(event, null, 2);

      modalOverlay.style.display = 'flex';
    }

    function openAiModal(analysis) {
      const modalOverlay = document.getElementById('detailModalOverlay');
      const title = document.getElementById('modalTitle');
      const details = document.getElementById('modalDetails');
      const raw = document.getElementById('modalRawJson');

      title.textContent = `AI Analysis #${analysis.id} Details`;
      
      const scoreColor = analysis.risk_score >= 80 ? 'badge-danger' : (analysis.risk_score >= 40 ? 'badge-warning' : 'badge-success');
      
      let metaHtml = `
        <div>
          <span class="filter-label">Timestamp</span>
          <div style="font-size:13px; margin-top:3px;">${analysis.timestamp}</div>
        </div>
        <div>
          <span class="filter-label">Event Reference</span>
          <div style="font-size:13px; margin-top:3px; font-weight:600; color:var(--accent-light); cursor:pointer;" onclick="loadAndShowEvent(${analysis.event_id})">Open Event #${analysis.event_id}</div>
        </div>
        <div>
          <span class="filter-label">Model Provider / Type</span>
          <div style="font-size:13px; margin-top:3px;">${analysis.provider} (${analysis.model})</div>
        </div>
        <div>
          <span class="filter-label">AI Risk Score</span>
          <div style="margin-top:3px;"><span class="badge ${scoreColor}">${analysis.risk_score} / 100</span></div>
        </div>
        <div>
          <span class="filter-label">Classification</span>
          <div style="margin-top:3px;"><span class="badge ${getBadgeClass(analysis.classification)}">${analysis.classification}</span></div>
        </div>
        <div style="grid-column: span 2;">
          <span class="filter-label">AI Explanation</span>
          <div style="font-size:13px; margin-top:3px; line-height:1.4;">${analysis.explanation}</div>
        </div>
        <div style="grid-column: span 2;">
          <span class="filter-label">Recommended Remediation Action</span>
          <div style="font-size:13px; font-weight:500; margin-top:3px; border-left:3px solid var(--accent); padding-left:10px;">${analysis.recommended_action}</div>
        </div>
      `;
      details.innerHTML = metaHtml;
      raw.textContent = JSON.stringify(analysis, null, 2);

      modalOverlay.style.display = 'flex';
    }

    async function loadAndShowEvent(eventId) {
      const matched = state.events.find(e => Number(e.id) === Number(eventId));
      if (matched) {
        openEventModal(matched);
      } else {
        showToast("Loading event details...");
        // Fetch event if not loaded in memory (unlikely but safe fallback)
        const fullEvents = await fetchJson('/api/events');
        const searchEv = fullEvents ? fullEvents.find(e => Number(e.id) === Number(eventId)) : null;
        if (searchEv) openEventModal(searchEv);
        else showToast("Failed to find event " + eventId);
      }
    }

    function closeModal(event) {
      document.getElementById('detailModalOverlay').style.display = 'none';
    }

    // Toggle accordions for compliance
    function toggleAccordion(id) {
      const panel = document.getElementById(id);
      const chevron = document.getElementById(`chev-${id}`);
      if(panel.style.display === 'block') {
        panel.style.display = 'none';
        chevron.style.transform = 'rotate(0deg)';
      } else {
        panel.style.display = 'block';
        chevron.style.transform = 'rotate(90deg)';
      }
    }

    // Text helper copy
    function copyText(txt) {
      navigator.clipboard.writeText(txt).then(() => {
        showToast("Copied to clipboard!");
      });
    }

    function showToast(message) {
      const toast = document.getElementById('copyNotification');
      toast.textContent = message;
      toast.classList.add('show');
      setTimeout(() => {
        toast.classList.remove('show');
      }, 2000);
    }

    // Helper classes
    function getBadgeClass(status) {
      if (!status) return 'badge-muted';
      const term = status.toLowerCase();
      if (term.includes('pass') || term.includes('valid') || term.includes('created') || term.includes('normal') || term.includes('info') || term.includes('ok')) {
        return 'badge-success';
      }
      if (term.includes('attention') || term.includes('warn') || term.includes('modified') || term.includes('ready') || term.includes('unknown')) {
        return 'badge-warning';
      }
      if (term.includes('fail') || term.includes('broken') || term.includes('deleted') || term.includes('missing') || term.includes('drift') || term.includes('critical') || term.includes('alert') || term.includes('high')) {
        return 'badge-danger';
      }
      return 'badge-muted';
    }

    // Core Render Engine
    function render() {
      // Sync footer and status indicator
      const active = state.health.status === 'ok' && state.health.agent && state.health.agent.active;
      const sideDot = document.getElementById('sidebarDot');
      const sideText = document.getElementById('sidebarStatusText');
      const syncText = document.getElementById('sidebarSyncTime');

      if (sideDot) {
        sideDot.className = 'dot ' + (active ? 'active' : 'error');
      }
      if (sideText) {
        sideText.textContent = active ? 'Agent Active' : 'Agent Offline';
        sideText.className = active ? '' : 'badge-danger';
      }
      if (syncText && state.lastSync) {
        syncText.textContent = state.lastSync;
      }

      // Render tab-specific UI
      if (state.activeView === 'overview') renderOverview();
      else if (state.activeView === 'chain') renderChain();
      else if (state.activeView === 'events') renderEvents();
      else if (state.activeView === 'compliance') renderCompliance();
      else if (state.activeView === 'ai') renderAi();
      else if (state.activeView === 'config') renderConfig();
    }

    // Overview renderer
    function renderOverview() {
      const chainValid = state.health.chain ? state.health.chain.valid : false;
      const chainValEl = document.getElementById('kpiChain');
      const chainSubEl = document.getElementById('kpiChainSub');
      
      if (chainValEl) {
        chainValEl.textContent = chainValid ? "VALID" : "COMPROMISED";
        chainValEl.style.color = chainValid ? "var(--success)" : "var(--danger)";
        chainValEl.style.textShadow = chainValid ? "0 0 15px rgba(16,185,129,0.3)" : "0 0 15px rgba(239,68,68,0.3)";
      }
      if (chainSubEl && state.health.chain) {
        chainSubEl.textContent = `Chain validated. ${state.health.chain.failures ? state.health.chain.failures.length : 0} hashes broken.`;
      }

      const totalEvents = state.health.chain ? state.health.chain.event_count : 0;
      document.getElementById('kpiEvents').textContent = totalEvents;

      const complStatus = state.completeness.status || 'unknown';
      const complValEl = document.getElementById('kpiCompleteness');
      if (complValEl) {
        complValEl.textContent = complStatus.toUpperCase();
        complValEl.style.color = complStatus === 'pass' ? "var(--success)" : "var(--warning)";
      }
      const complSubEl = document.getElementById('kpiCompletenessSub');
      if (complSubEl && state.completeness.issues) {
        complSubEl.textContent = state.completeness.issues.length === 0 ? "Monitored paths intact" : `Found ${state.completeness.issues.length} audit concerns`;
      }

      const fabCount = state.fabrication.finding_count || 0;
      const fabValEl = document.getElementById('kpiFabrications');
      if (fabValEl) {
        fabValEl.textContent = fabCount;
        fabValEl.style.color = fabCount > 0 ? "var(--danger)" : "var(--success)";
      }
      const fabSubEl = document.getElementById('kpiFabricationsSub');
      if (fabSubEl) {
        fabSubEl.textContent = fabCount === 0 ? "AI explanations verified" : `${fabCount} claim anomalies detected`;
      }

      // Render timeline list (max 5)
      const timelineEl = document.getElementById('recentTimeline');
      if (timelineEl) {
        if (state.events.length === 0) {
          timelineEl.innerHTML = '<li style="color:var(--text-muted); font-size:13px; padding: 10px 0;">No logs captured by agent yet. Ensure paths are configured and writable.</li>';
        } else {
          timelineEl.innerHTML = state.events.slice(0, 5).map(e => `
            <li class="timeline-item ${e.severity === 'high' ? 'high' : (e.severity === 'medium' ? 'medium' : 'info')}">
              <div class="timeline-marker"></div>
              <div class="timeline-content" onclick="loadAndShowEvent(${e.id})" style="cursor:pointer;">
                <div class="timeline-meta">
                  <span>${e.timestamp}</span>
                  <span class="badge ${getBadgeClass(e.event_type)}">${String(e.event_type).replace(/_/g, ' ')}</span>
                </div>
                <div class="timeline-msg">${e.message}</div>
                <div class="timeline-path">${e.file_path}</div>
              </div>
            </li>
          `).join('');
        }
      }

      // Render Host Coverage checklist
      const readList = document.getElementById('readinessList');
      if (readList) {
        if(state.phases.length === 0) {
          readList.innerHTML = '<div style="color:var(--text-muted); font-size:12px;">Loading phase checklists...</div>';
        } else {
          readList.innerHTML = state.phases.map(p => `
            <div class="readiness-item">
              <div class="readiness-info">
                <span class="readiness-name">${p.name}</span>
                <span class="readiness-desc">${p.detail}</span>
              </div>
              <span class="badge ${getBadgeClass(p.status)}">${p.status}</span>
            </div>
          `).join('');
        }
      }
    }

    // Chain Ledger renderer
    function renderChain() {
      const container = document.getElementById('chainBlocksContainer');
      if (!container) return;

      if (state.events.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); text-align:center; padding: 40px 0; border: 1px dashed var(--border-color); border-radius:8px;">No events recorded in the block ledger yet. Start local file alterations to build chain.</div>';
        return;
      }

      // Render a chain. We reverse it so latest is at top, or render oldest to latest.
      // Let's render latest at top and show their cryptographic links.
      const blocksHtml = [];
      const failEventIds = state.health.chain && state.health.chain.failures ? state.health.chain.failures.map(f => f.event_id) : [];

      for (let i = 0; i < state.events.length; i++) {
        const ev = state.events[i];
        const prevEv = state.events[i + 1]; // because array is sorted descending (latest first)

        // Block box
        const cleanType = String(ev.event_type).replace(/_/g, ' ').toUpperCase();
        const blockHtml = `
          <div class="chain-block" onclick="loadAndShowEvent(${ev.id})">
            <div class="block-header">
              <span class="block-id">Block #${ev.id}</span>
              <span class="badge ${getBadgeClass(ev.severity)}">${ev.severity}</span>
            </div>
            <div class="block-grid">
              <div class="block-meta-row">
                <span class="block-meta-label">Operation</span>
                <span class="block-meta-value" style="font-weight:600;">${cleanType}</span>
              </div>
              <div class="block-meta-row">
                <span class="block-meta-label">Signed Time</span>
                <span class="block-meta-value">${ev.timestamp}</span>
              </div>
              <div class="block-meta-row" style="grid-column: span 2;">
                <span class="block-meta-label">Signature Hash</span>
                <span class="block-meta-value mono" style="color:var(--accent-light); font-size:11px;">${ev.event_hash}</span>
              </div>
              <div class="block-meta-row" style="grid-column: span 2;">
                <span class="block-meta-label">Previous Chain Hash</span>
                <span class="block-meta-value mono" style="color:var(--text-muted); font-size:11px;">${ev.previous_event_hash || '0000000000000000000000000000000000000000000000000000000000000000'}</span>
              </div>
            </div>
          </div>
        `;
        blocksHtml.push(blockHtml);

        // Connector (if there is a previous block in time, i.e., index i+1 in descending list)
        if (prevEv) {
          const isBroken = failEventIds.includes(ev.id);
          const connectorHtml = `
            <div class="chain-link-connector ${isBroken ? 'broken' : 'valid'}">
              <div class="chain-link-indicator">
                ${isBroken ? '&times;' : '&#10003;'}
              </div>
            </div>
          `;
          blocksHtml.push(connectorHtml);
        }
      }

      container.innerHTML = blocksHtml.join('');
    }

    // Event Explorer Table renderer
    function renderEvents() {
      // Filter events
      let filtered = state.events.filter(e => {
        // Search filter
        const matchSearch = !state.searchQuery || 
          String(e.message).toLowerCase().includes(state.searchQuery) ||
          String(e.file_path).toLowerCase().includes(state.searchQuery) ||
          String(e.event_type).toLowerCase().includes(state.searchQuery);
        
        // Severity filter
        let matchSeverity = true;
        if (state.severityFilter === 'high') {
          matchSeverity = e.severity === 'high' || e.severity === 'critical';
        } else if (state.severityFilter === 'medium') {
          matchSeverity = e.severity === 'medium';
        } else if (state.severityFilter === 'info') {
          matchSeverity = e.severity === 'info' || e.severity === 'low';
        }

        // Type filter
        const matchType = state.typeFilter === 'all' || e.event_type === state.typeFilter;

        return matchSearch && matchSeverity && matchType;
      });

      // Pagination slice
      const totalFiltered = filtered.length;
      const totalPages = Math.ceil(totalFiltered / state.pageSize) || 1;
      
      if (state.currentPage > totalPages) state.currentPage = totalPages;
      if (state.currentPage < 1) state.currentPage = 1;

      const startIndex = (state.currentPage - 1) * state.pageSize;
      const endIndex = Math.min(startIndex + state.pageSize, totalFiltered);
      const paginated = filtered.slice(startIndex, endIndex);

      // Render table
      const tbody = document.getElementById('eventsTableBody');
      if (tbody) {
        if (paginated.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:30px;">No events match your active filter criteria.</td></tr>';
        } else {
          tbody.innerHTML = paginated.map(e => `
            <tr onclick="loadAndShowEvent(${e.id})" style="cursor:pointer;">
              <td class="mono" style="font-weight:600; color:var(--accent-light);">#${e.id}</td>
              <td class="mono">${e.timestamp.split('T')[1]?.substring(0,8) || e.timestamp}</td>
              <td><span class="badge ${getBadgeClass(e.event_type)}">${String(e.event_type).replace(/_/g, ' ')}</span></td>
              <td><span class="badge ${getBadgeClass(e.severity)}">${e.severity}</span></td>
              <td class="mono" style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${e.file_path}">${e.file_path}</td>
              <td style="font-weight:500;">${e.message}</td>
            </tr>
          `).join('');
        }
      }

      // Update paginator info
      const infoEl = document.getElementById('paginationInfo');
      if (infoEl) {
        infoEl.textContent = totalFiltered === 0 ? 'Showing 0 of 0 events' : `Showing ${startIndex + 1}-${endIndex} of ${totalFiltered} events`;
      }

      const prevBtn = document.getElementById('prevPageBtn');
      const nextBtn = document.getElementById('nextPageBtn');
      
      if (prevBtn) prevBtn.disabled = state.currentPage === 1;
      if (nextBtn) nextBtn.disabled = state.currentPage === totalPages;
    }

    // Compliance audits page renderer
    function renderCompliance() {
      const complBadge = document.getElementById('complianceSummaryBadge');
      const isCompliant = state.compliance.summary ? (state.compliance.summary.status === 'pass') : false;
      
      if (complBadge) {
        complBadge.textContent = isCompliant ? "All Controls Pass" : "Audit Attention Required";
        complBadge.className = isCompliant ? "badge badge-success" : "badge badge-warning";
      }

      const listContainer = document.getElementById('complianceList');
      if (listContainer && state.compliance.controls) {
        listContainer.innerHTML = state.compliance.controls.map((c, idx) => {
          const panelId = `comp-panel-${idx}`;
          const isCtrlPass = c.status === 'pass';
          return `
            <div class="compliance-card">
              <button class="compliance-trigger" onclick="toggleAccordion('${panelId}')">
                <div class="compliance-info">
                  <span class="badge ${isCtrlPass ? 'badge-success' : 'badge-warning'}">${c.framework}</span>
                  <span style="font-weight:600; font-family:'JetBrains Mono', monospace;">${c.control}</span>
                  <span style="color:var(--text-muted); font-size:13px; font-weight:400;">— ${c.requirement}</span>
                </div>
                <div style="display:flex; align-items:center; gap:12px;">
                  <span class="badge ${isCtrlPass ? 'badge-success' : 'badge-danger'}">${c.status.toUpperCase()}</span>
                  <svg id="chev-${panelId}" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; color:var(--text-muted); transition:transform 0.2s ease;">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5"></path>
                  </svg>
                </div>
              </button>
              <div class="compliance-panel" id="${panelId}">
                <div style="font-size:13px; color:var(--text-muted); line-height:1.5; margin-bottom:12px;">
                  <strong>Required Evidence:</strong> The system logs must be stored in a cryptographically resilient mechanism preventing retroactive manipulation. The completeness engine validates integrity parameters and log file availability.
                </div>
                <div class="compliance-evidence">
                  <div class="evidence-title">Cryptographic Evidence Dossier</div>
                  <table style="font-size:12px; margin-top:8px;">
                    <thead>
                      <tr>
                        <th>Metric Type</th>
                        <th>Audited Value</th>
                        <th>Verification Output</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>Database Chain Ledger Status</td>
                        <td class="mono">${c.evidence.hash_chain_valid ? 'VALID INTEGRITY CHAIN' : 'BROKEN HASHLINKS'}</td>
                        <td><span class="badge ${c.evidence.hash_chain_valid ? 'badge-success' : 'badge-danger'}">${c.evidence.hash_chain_valid ? 'pass' : 'fail'}</span></td>
                      </tr>
                      <tr>
                        <td>Total Recorded Events Audited</td>
                        <td class="mono">${c.evidence.event_count} events</td>
                        <td><span class="badge badge-info">evidence captured</span></td>
                      </tr>
                      <tr>
                        <td>High Severity Security Incidents</td>
                        <td class="mono">${c.evidence.high_severity_events} events flagged</td>
                        <td><span class="badge ${c.evidence.high_severity_events === 0 ? 'badge-success' : 'badge-warning'}">${c.evidence.high_severity_events === 0 ? 'no actions' : 'review alerts'}</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          `;
        }).join('');
      }
    }

    // AI Analysis & Fabrications renderer
    function renderAi() {
      // 1. Render fabrication warning alerts
      const warningsAlertsEl = document.getElementById('aiFabricationsContainer');
      if (warningsAlertsEl && state.fabrication.findings) {
        if (state.fabrication.findings.length === 0) {
          warningsAlertsEl.innerHTML = '';
        } else {
          warningsAlertsEl.innerHTML = state.fabrication.findings.map(f => `
            <div class="fabrication-alert">
              <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z"></path>
              </svg>
              <div>
                <strong style="text-transform: uppercase; font-size:12px;">AI Fabrication Auditing Concern: ${f.reason.replace(/_/g, ' ')}</strong>
                <div style="margin-top:2px;">
                  Audit identified mismatch on AI Analysis ID #${f.analysis_id || 'unknown'} (referenced Event ID #${f.event_id || 'unknown'}). 
                  The AI claimed unsupported parameters or certainty language which mismatched database evidence.
                </div>
              </div>
            </div>
          `).join('');
        }
      }

      // 2. Render AI Incident log table
      const tbody = document.getElementById('aiTableBody');
      if (tbody) {
        if (state.ai.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:30px;">No AI incident analysis records found in store. Ensure OpenAI key env and path monitoring is configured.</td></tr>';
        } else {
          tbody.innerHTML = state.ai.map(a => {
            const riskColor = a.risk_score >= 80 ? 'var(--danger)' : (a.risk_score >= 40 ? 'var(--warning)' : 'var(--success)');
            return `
              <tr>
                <td class="mono" style="color:var(--accent-light); font-weight:600;">#${a.id}</td>
                <td class="mono" style="text-decoration:underline; cursor:pointer;" onclick="loadAndShowEvent(${a.event_id})">#${a.event_id}</td>
                <td>${a.model}</td>
                <td>
                  <div class="risk-score-container">
                    <span style="font-weight:700; width:30px; text-align:right;">${a.risk_score}</span>
                    <div class="risk-gauge">
                      <div class="risk-fill" style="width:${a.risk_score}%; background-color:${riskColor};"></div>
                    </div>
                  </div>
                </td>
                <td><span class="badge ${getBadgeClass(a.classification)}">${a.classification}</span></td>
                <td style="font-weight:500;">${a.recommended_action}</td>
                <td>
                  <button class="btn" style="padding:4px 8px; font-size:11px;" onclick='openAiModal(${JSON.stringify(a)})'>View</button>
                </td>
              </tr>
            `;
          }).join('');
        }
      }
    }

    // Config renderer
    function renderConfig() {
      // Monitored paths grid
      const pathsGrid = document.getElementById('configPathsGrid');
      if (pathsGrid && state.completeness.configured_paths) {
        const paths = state.completeness.configured_paths;
        const missing = state.completeness.missing_paths || [];
        
        pathsGrid.innerHTML = paths.map(p => {
          const isMissing = missing.includes(p);
          return `
            <div class="path-card">
              <span class="badge ${isMissing ? 'badge-danger' : 'badge-success'}" style="align-self: flex-start;">
                ${isMissing ? 'Path Missing / Offline' : 'Actively Monitored'}
              </span>
              <div class="path-card-title">${p.split('/').pop() || 'Root'}</div>
              <div class="path-card-val">${p}</div>
              <div class="path-card-meta">
                <span>Verification: HMAC scan</span>
                <span>Interval: 900s</span>
              </div>
            </div>
          `;
        }).join('');
      }

      // Ignore patterns list
      const ignoreContainer = document.getElementById('configIgnoreList');
      if (ignoreContainer && state.platform.ignore_patterns) {
        ignoreContainer.innerHTML = state.platform.ignore_patterns.map(pat => `
          <span class="badge badge-muted mono">${pat}</span>
        `).join('');
      } else if (ignoreContainer) {
        ignoreContainer.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">No exclusion filters active.</span>';
      }
    }

    // Sync baseline signature first time config view is hit
    let sigFetched = false;
    navItems.forEach(item => {
      item.addEventListener('click', () => {
        if (item.getAttribute('data-view') === 'config' && !sigFetched) {
          sigFetched = true;
          loadBaselineSignature();
        }
      });
    });

    // Start loop
    const initialView = new URLSearchParams(window.location.search).get('view');
    if (initialView && ['overview', 'chain', 'events', 'compliance', 'ai', 'config'].includes(initialView)) {
      navigateToTab(initialView);
    }
    syncData();
    setInterval(syncData, 5000);
  </script>
</body>
</html>"""



def run_dashboard_server(config: Dict[str, Any]) -> None:
    dashboard = config.get("dashboard", {})
    host = dashboard.get("host", "127.0.0.1")
    port = int(dashboard.get("port", 8765))
    store = DatabaseManager(config["app"]["db_path"])
    collector = Collector(config, store)
    logger = setup_logging(config["app"]["log_dir"], config["app"]["log_level"])
    agent_state: Dict[str, Any] = {
        "active": False,
        "agent": None,
        "started_at": None,
        "last_message": "",
        "last_severity": "info",
    }

    def agent_callback(message: str, severity: str) -> None:
        agent_state["last_message"] = message
        agent_state["last_severity"] = severity

    agent = Agent(config, collector, agent_callback, logger)
    agent_state["agent"] = agent
    agent_state["active"] = agent.start()
    if agent_state["active"]:
        from .database import utc_now

        agent_state["started_at"] = utc_now()
    else:
        agent_state["last_message"] = "Agent failed to start"
        agent_state["last_severity"] = "high"

    server = ThreadingHTTPServer(
        (host, port),
        make_handler(config, store, collector, agent_state),
    )
    url = f"http://{host}:{port}"
    if dashboard.get("auto_open", False):
        threading.Timer(0.6, lambda: _open_browser(url)).start()
    print(f"Dashboard running at {url}")
    server.serve_forever()


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass
