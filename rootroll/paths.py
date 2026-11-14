"""Path confinement for delegated roles."""
from __future__ import annotations


def path_allowed(path: str, patterns: list[str]) -> bool:
    if not isinstance(path, str) or not path:
        return False
    for pat in patterns or []:
        if not isinstance(pat, str) or not pat:
            continue
        base = pat.rstrip("/")
        if not base:
            continue
        if path == base or path.startswith(base + "/"):
            return True
    return False


def path_unsafe(path: str) -> bool:
    """Target paths with '..', a leading slash, or a backslash are rejected."""
    if not isinstance(path, str) or not path:
        return True
    if path.startswith("/") or "\\" in path:
        return True
    return any(part == ".." for part in path.split("/"))
