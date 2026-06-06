"""CLI entrypoint for EvideX."""

from __future__ import annotations

import argparse
import json
import sys
import time

from .agent import Agent
from .collector import Collector
from .compliance import build_compliance_report
from .config import load_config
from .database import DatabaseManager
from .fabrication import detect_ai_fabrication
from .logging_setup import setup_logging
from .api import run_dashboard_server
from .reports import export_csv, export_json, summarize_events


def _console_callback(message: str, severity: str) -> None:
    print(f"[{severity.upper()}] {message}")


def run_headless(config_path: str | None) -> int:
    config = load_config(config_path)
    logger = setup_logging(config["app"]["log_dir"], config["app"]["log_level"])
    collector = Collector(config, DatabaseManager(config["app"]["db_path"]))

    agent = Agent(config, collector, _console_callback, logger)
    if not agent.start():
        return 1

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
        return 0


def generate_report(config_path: str | None, export_path: str | None, fmt: str) -> int:
    config = load_config(config_path)
    db = DatabaseManager(config["app"]["db_path"])
    events = db.get_events(1000)
    ai_analysis = db.get_ai_analysis(1000)
    summary = summarize_events(events)

    if export_path:
        if fmt == "csv":
            export_csv(events, export_path, ai_analysis)
        else:
            export_json(events, export_path, ai_analysis)

    print(f"Total events: {summary['total']}")
    print(f"Integrity drift: {summary['integrity_drift']}")
    print(f"Missing files: {summary['file_missing']}")
    print(f"Security alerts: {summary['security_alert']}")
    print(f"AI/risk assessments: {len(ai_analysis)}")
    return 0


def run_dashboard(config_path: str | None) -> int:
    config = load_config(config_path)
    run_dashboard_server(config)
    return 0


def verify_store(config_path: str | None) -> int:
    config = load_config(config_path)
    store = DatabaseManager(config["app"]["db_path"])
    print(json.dumps(store.verify_chain(), indent=2))
    return 0


def compliance_report(config_path: str | None) -> int:
    config = load_config(config_path)
    store = DatabaseManager(config["app"]["db_path"])
    print(json.dumps(build_compliance_report(config, store), indent=2))
    return 0


def fabrication_report(config_path: str | None) -> int:
    config = load_config(config_path)
    store = DatabaseManager(config["app"]["db_path"])
    print(json.dumps(detect_ai_fabrication(store), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EvideX")
    parser.add_argument("--config", help="Path to config.json")

    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Run headless monitor")
    run_parser.set_defaults(command="run")

    gui_parser = subparsers.add_parser("gui", help="Open web dashboard")
    gui_parser.set_defaults(command="gui")
    gui_parser.add_argument("--host", default=None)
    gui_parser.add_argument("--port", type=int, default=None)

    dashboard_parser = subparsers.add_parser("dashboard", help="Open web dashboard")
    dashboard_parser.set_defaults(command="dashboard")
    dashboard_parser.add_argument("--host", default=None)
    dashboard_parser.add_argument("--port", type=int, default=None)

    report_parser = subparsers.add_parser("report", help="Generate report")
    report_parser.add_argument("--export", help="Export path (json or csv)")
    report_parser.add_argument("--format", choices=["json", "csv"], default="json")

    verify_parser = subparsers.add_parser("verify", help="Verify event hash chain")
    verify_parser.set_defaults(command="verify")

    compliance_parser = subparsers.add_parser("compliance", help="Generate compliance report")
    compliance_parser.set_defaults(command="compliance")

    fabrication_parser = subparsers.add_parser("fabrication", help="Detect unsupported AI analysis claims")
    fabrication_parser.set_defaults(command="fabrication")

    args = parser.parse_args(argv)

    if args.command == "report":
        return generate_report(args.config, args.export, args.format)

    if args.command == "run":
        return run_headless(args.config)

    if args.command in {"gui", "dashboard"}:
        config = load_config(args.config)
        if args.host:
            config["dashboard"]["host"] = args.host
        if args.port:
            config["dashboard"]["port"] = args.port
        run_dashboard_server(config)
        return 0

    if args.command == "verify":
        return verify_store(args.config)

    if args.command == "compliance":
        return compliance_report(args.config)

    if args.command == "fabrication":
        return fabrication_report(args.config)

    if args.command == "gui":
        return run_dashboard(args.config)

    return run_headless(args.config)


if __name__ == "__main__":
    raise SystemExit(main())
