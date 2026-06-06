"""Agent layer: local file/log observation."""

from __future__ import annotations

from typing import Any, Callable, Dict

from .collector import Collector
from .monitor import MonitorEngine


class Agent:
    def __init__(
        self,
        config: Dict[str, Any],
        collector: Collector,
        callback: Callable[[str, str], None],
        logger,
    ) -> None:
        self.engine = MonitorEngine(config, collector, callback, logger)

    def start(self) -> bool:
        return self.engine.start()

    def stop(self) -> None:
        self.engine.stop()

    def verify_now(self):
        return self.engine.verify_now()
