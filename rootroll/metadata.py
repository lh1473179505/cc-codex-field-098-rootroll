"""Signed envelopes.

verify_threshold counts distinct keyids that both verify and belong to the
role; repeating the same key does not meet a threshold. Callers should
treat a missing envelope as a hard failure.
"""
from __future__ import annotations

from typing import Any

from .keys import check_sig


def signed_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    payload = envelope.get("signed")
    if not isinstance(payload, dict):
        raise ValueError("envelope missing signed payload")
    return payload


def verify_threshold(
    envelope: dict[str, Any],
    *,
    keyids: list[str],
    threshold: int,
    keys: dict[str, str],
) -> bool:
    payload = signed_payload(envelope)
    allowed = set(keyids)
    ok: set[str] = set()
    for item in envelope.get("signatures") or []:
        if not isinstance(item, dict):
            continue
        kid = item.get("keyid")
        sig = item.get("sig")
        if kid not in allowed or kid not in keys:
            continue
        if check_sig(payload, keys[kid], sig):
            ok.add(kid)
    return len(ok) >= threshold
