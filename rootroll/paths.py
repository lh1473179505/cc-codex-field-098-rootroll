"""Path confinement for delegated roles.

The current helper uses a prefix startswith check, which is what the
pkg-team escape in docs/incidents.md still relies on.
"""
from __future__ import annotations


def path_allowed(path: str, patterns: list[str]) -> bool:
    if not isinstance(path, str) or not path:
        return False
    for pat in patterns or []:
        if not pat:
            continue
        if path == pat or path.startswith(pat):
            return True
    return False
