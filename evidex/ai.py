"""Incident analysis helpers.

The deterministic monitor remains the source of truth for integrity. This module
adds investigation support: local risk scoring plus optional structured AI
analysis when an API key is configured.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .database import DatabaseManager


SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}


class IncidentAnalyzer:
    def __init__(self, config: Dict[str, Any], db: DatabaseManager, logger) -> None:
        self.config = config.get("ai", {})
        self.db = db
        self.logger = logger
        self.provider = self.config.get("provider", "openai")
        self.model = self.config.get("model", "gpt-4o-mini")
        self.base_url = os.environ.get(
            self.config.get("base_url_env", "OPENAI_BASE_URL"),
            self.config.get("base_url", "https://api.openai.com/v1"),
        ).rstrip("/")
        self.timeout = int(self.config.get("timeout_seconds", 20))
        self.max_context_lines = int(self.config.get("max_context_lines", 60))
        self.minimum_severity = self.config.get("minimum_severity", "medium")

    def should_analyze(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(
            self.minimum_severity, 1
        )

    def analyze_async(
        self,
        event_id: int,
        event_type: str,
        file_path: str,
        message: str,
        severity: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.should_analyze(severity):
            return
        thread = threading.Thread(
            target=self._analyze,
            args=(event_id, event_type, file_path, message, severity, metadata or {}),
            daemon=True,
        )
        thread.start()

    def _analyze(
        self,
        event_id: int,
        event_type: str,
        file_path: str,
        message: str,
        severity: str,
        metadata: Dict[str, Any],
    ) -> None:
        bundle = {
            "event_type": event_type,
            "file_path": file_path,
            "message": message,
            "severity": severity,
            "metadata": metadata,
            "context_lines": self._read_context_lines(file_path),
        }
        local = self._local_assessment(bundle)
        self.db.add_ai_analysis(event_id, "local-rules", "deterministic-risk-v1", local)

        if not self.config.get("enabled", False):
            return
        if self.provider not in {"openai", "openrouter"}:
            self.logger.warning("Unsupported AI provider configured: %s", self.provider)
            return
        api_key = os.environ.get(self.config.get("api_key_env", "OPENAI_API_KEY"), "")
        if not api_key:
            self.logger.warning("AI analysis enabled, but API key environment variable is missing")
            return
        try:
            analysis = self._remote_assessment(api_key, bundle)
        except Exception as exc:
            self.logger.error("AI analysis failed for event %s: %s", event_id, exc)
            return
        self.db.add_ai_analysis(event_id, self.provider, self.model, analysis)

    def _read_context_lines(self, path: str) -> List[str]:
        if not os.path.exists(path) or not os.path.isfile(path):
            return []
        lines: List[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    lines.append(line.rstrip("\n"))
                    if len(lines) > self.max_context_lines:
                        lines.pop(0)
        except OSError:
            return []
        return lines

    def _local_assessment(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        indicators = set(bundle.get("metadata", {}).get("indicators", []))
        text = "\n".join(bundle.get("context_lines", [])).lower()
        score = 20
        classification = "integrity_event"
        if bundle["severity"] == "high":
            score += 35
        elif bundle["severity"] == "medium":
            score += 20
        if "hash_mismatch" in indicators:
            score += 20
        if "size_decreased" in indicators or "missing_during_verification" in indicators:
            score += 25
            classification = "possible_log_tampering"
        if "failed password" in text or "authentication failure" in text:
            score += 15
            classification = "authentication_attack_context"
        if "sudo:" in text and "command" in text:
            score += 15
            classification = "privilege_activity_context"
        score = min(score, 100)
        if score >= 80:
            action = "Preserve evidence, review authentication history, and inspect privileged shell activity."
        elif score >= 50:
            action = "Review recent changes and confirm whether the file modification was authorized."
        else:
            action = "Track the event and compare it with future changes."
        return {
            "risk_score": score,
            "classification": classification,
            "explanation": (
                "Local risk score based on event severity, integrity indicators, "
                "and nearby authentication or sudo context."
            ),
            "recommended_action": action,
            "confidence": "medium",
        }

    def _remote_assessment(self, api_key: str, bundle: Dict[str, Any]) -> Dict[str, Any]:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
                "classification": {"type": "string"},
                "explanation": {"type": "string"},
                "recommended_action": {"type": "string"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            },
            "required": [
                "risk_score",
                "classification",
                "explanation",
                "recommended_action",
                "confidence",
            ],
        }
        prompt = (
            "You are a security analyst for EvideX, a log evidence integrity product. "
            "Assess whether this event suggests tampering, intrusion activity, or a benign change. "
            "Do not claim cryptographic certainty; hashes and metadata are the source of truth. "
            "Return concise JSON matching the schema.\n\n"
            f"Event bundle:\n{json.dumps(bundle, indent=2, sort_keys=True)}"
        )
        if self.provider == "openrouter" or "openrouter.ai" in self.base_url:
            return self._chat_completions_assessment(api_key, prompt, schema)
        return self._responses_assessment(api_key, prompt, schema)

    def _responses_assessment(
        self,
        api_key: str,
        prompt: str,
        schema: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "input": [{"role": "user", "content": prompt}],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "evidex_incident_assessment",
                    "strict": True,
                    "schema": schema,
                }
            },
        }
        request = urllib.request.Request(
            f"{self.base_url}/responses",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"OpenAI API error {exc.code}: {body}") from exc
        output_text = data.get("output_text") or self._extract_response_text(data)
        if not output_text:
            raise RuntimeError("OpenAI response did not contain output text")
        return json.loads(output_text)

    def _chat_completions_assessment(
        self,
        api_key: str,
        prompt: str,
        schema: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Return only valid JSON matching the requested schema.",
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "evidex_incident_assessment",
                    "strict": True,
                    "schema": schema,
                },
            },
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"AI API error {exc.code}: {body}") from exc
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        if not content:
            raise RuntimeError("AI response did not contain message content")
        return json.loads(content)

    def _extract_response_text(self, data: Dict[str, Any]) -> str:
        chunks: List[str] = []
        for item in data.get("output", []):
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"}:
                    chunks.append(content.get("text", ""))
        return "".join(chunks)
