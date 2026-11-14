"""Refresh trusted metadata and install payloads.

The control flow already walks root -> timestamp -> snapshot -> targets ->
payloads and will accept a straightforward newer channel. Several bindings
and confinement checks from docs/channel-protocol.md are missing or loose;
see docs/incidents.md for attacks that still land.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .metadata import signed_payload, verify_threshold
from .paths import path_allowed
from .remote import Remote
from .store import Store
from .util import parse_time, sha256_bytes, sha256_file


@dataclass
class Outcome:
    decision: str
    reason_codes: list[str] = field(default_factory=list)
    installed: dict[str, Any] = field(default_factory=dict)
    trusted_versions: dict[str, int] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "installed": self.installed,
            "trusted_versions": self.trusted_versions,
        }


class ChannelError(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


def _role(root_payload: dict[str, Any], name: str) -> dict[str, Any]:
    roles = root_payload.get("roles") or {}
    role = roles.get(name)
    if not isinstance(role, dict):
        raise ChannelError("bad_root", f"missing role {name}")
    return role


def _verify_role(envelope: dict[str, Any], root_payload: dict[str, Any], role_name: str, keys: dict[str, str]) -> None:
    role = _role(root_payload, role_name)
    keyids = list(role.get("keyids") or [])
    threshold = int(role.get("threshold") or 1)
    if not verify_threshold(envelope, keyids=keyids, threshold=threshold, keys=keys):
        raise ChannelError("bad_signature", f"{role_name} threshold not met")


def _versions(store: Store) -> dict[str, int]:
    out: dict[str, int] = {}
    for name, key in (("root.json", "root"), ("timestamp.json", "timestamp"), ("snapshot.json", "snapshot"), ("targets.json", "targets")):
        if store.has(name):
            out[key] = int(signed_payload(store.load_envelope(name))["version"])
    return out


def refresh(store: Store, remote: Remote, keys: dict[str, str], now: datetime, install_dir: Path) -> Outcome:
    if not store.has("root.json"):
        raise FileNotFoundError("trusted root missing")
    if not remote.exists():
        raise FileNotFoundError("remote metadata missing")

    root_env = store.load_envelope("root.json")
    root_payload = signed_payload(root_env)

    # --- root rotation (loose): accept a newer root.json if it verifies
    # against the keys listed in that same file.
    alias = remote.alias_root()
    if alias is not None:
        new_env, _raw = alias
        new_payload = signed_payload(new_env)
        if int(new_payload.get("version") or 0) >= int(root_payload.get("version") or 0):
            try:
                _verify_role(new_env, new_payload, "root", keys)
                root_env = new_env
                root_payload = new_payload
            except ChannelError:
                # keep the trusted root if the remote file is junk
                pass

    ts_env, ts_raw = remote.timestamp()
    _verify_role(ts_env, root_payload, "timestamp", keys)
    ts = signed_payload(ts_env)

    snap_version = int(ts.get("snapshot_version") or 0)
    snap_env, snap_raw = remote.snapshot(snap_version)
    _verify_role(snap_env, root_payload, "snapshot", keys)
    snap = signed_payload(snap_env)

    meta = snap.get("meta") or {}
    targets_info = meta.get("targets.json") or {}
    targets_version = int(targets_info.get("version") or snap.get("targets_version") or 0)
    targets_env, targets_raw = remote.targets(targets_version)
    _verify_role(targets_env, root_payload, "targets", keys)
    targets = signed_payload(targets_env)

    # Merge top-level targets and any delegated roles that happen to be present.
    files: dict[str, dict[str, Any]] = dict(targets.get("targets") or {})
    delegations = (targets.get("delegations") or {}).get("roles") or []
    for role in delegations:
        name = role.get("name")
        if not name:
            continue
        info = meta.get(f"delegations.{name}.json") or {}
        dver = int(info.get("version") or 0)
        try:
            d_env, _d_raw = remote.delegation(dver, name)
        except FileNotFoundError:
            continue
        d_payload = signed_payload(d_env)
        d_keyids = list(role.get("keyids") or [])
        d_threshold = int(role.get("threshold") or 1)
        if not verify_threshold(d_env, keyids=d_keyids, threshold=d_threshold, keys=keys):
            raise ChannelError("bad_signature", f"delegation {name}")
        # Path confinement is only applied as a soft startswith check, and
        # terminating is ignored — later roles always merge.
        for rel, entry in (d_payload.get("targets") or {}).items():
            patterns = list(role.get("paths") or [])
            if patterns and not path_allowed(rel, patterns):
                continue
            files[rel] = entry

    install_dir = Path(install_dir)
    install_dir.mkdir(parents=True, exist_ok=True)
    manifest = store.load_manifest()
    installed: dict[str, Any] = {}
    for rel, entry in files.items():
        src = remote.payload(rel)
        if not src.is_file():
            raise ChannelError("missing_payload", rel)
        dest = install_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
        rec = {
            "hash": entry.get("hash") or sha256_file(dest),
            "length": entry.get("length") if "length" in (entry or {}) else dest.stat().st_size,
            "version": (entry.get("custom") or {}).get("version"),
        }
        manifest[rel] = rec
        installed[rel] = rec

    store.save_envelope("root.json", root_env)
    store.save_envelope("timestamp.json", ts_env)
    store.save_envelope("snapshot.json", snap_env)
    store.save_envelope("targets.json", targets_env)
    store.save_manifest(manifest)

    return Outcome(
        decision="apply",
        reason_codes=[],
        installed=installed,
        trusted_versions=_versions(store),
    )


def report_refuse(code: str, store: Store) -> Outcome:
    return Outcome(decision="refuse", reason_codes=[code], trusted_versions=_versions(store) if store.has("root.json") else {})
