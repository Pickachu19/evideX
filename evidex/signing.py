"""Signed baseline support with local HMAC and remote KMS extension points."""

from __future__ import annotations

import hmac
import os
from hashlib import sha256
from typing import Any, Dict

from .database import canonical_json


def sign_payload(config: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    signing = config.get("signing", {})
    provider = signing.get("provider", "local-hmac")
    if provider == "remote-kms":
        return {
            "provider": "remote-kms",
            "status": "not_configured",
            "reason": "Configure signing.kms_key_id and implement provider-specific client.",
        }
    secret_env = signing.get("secret_env", "LOG_INTEGRITY_SIGNING_KEY")
    secret = os.environ.get(secret_env, "")
    if not secret:
        secret = "development-only-signing-key"
    signature = hmac.new(
        secret.encode("utf-8"),
        canonical_json(payload).encode("utf-8"),
        sha256,
    ).hexdigest()
    return {"provider": "local-hmac", "signature": signature}
