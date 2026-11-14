"""HMAC-SHA256 signatures used as a stand-in for the channel's role keys."""
from __future__ import annotations

import hmac
import hashlib
from pathlib import Path
from typing import Any

from .util import canonical, load_json


def load_keys(path: Path) -> dict[str, str]:
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError("keys must be a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def sign(payload: dict[str, Any], secret: str) -> str:
    body = canonical(payload).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def check_sig(payload: dict[str, Any], secret: str, sig: str) -> bool:
    if not isinstance(sig, str) or len(sig) != 64:
        return False
    expected = sign(payload, secret)
    return hmac.compare_digest(expected, sig)
