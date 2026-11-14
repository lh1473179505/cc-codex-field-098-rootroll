"""Refresh trusted metadata and install payloads.

Implements the refresh order from docs/channel-protocol.md: trusted root
expiry, root chain rotation, timestamp, snapshot, top-level targets,
delegations, and only then payload install plus trusted persistence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .metadata import signed_payload, verify_threshold
from .paths import path_allowed, path_unsafe
from .remote import Remote
from .store import Store
from .util import dump_json, parse_time, sha256_bytes


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


def _version(payload: dict[str, Any], label: str) -> int:
    try:
        return int(payload["version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ChannelError("bad_metadata", f"{label} missing version") from exc


def _check_not_expired(payload: dict[str, Any], now: datetime, label: str) -> None:
    expires = payload.get("expires")
    if not isinstance(expires, str):
        raise ChannelError("bad_metadata", f"{label} missing expires")
    try:
        expiry = parse_time(expires)
    except ValueError as exc:
        raise ChannelError("bad_metadata", f"{label} bad expires") from exc
    if expiry <= now:
        raise ChannelError("expired", f"{label} expired at {expires}")


def _check_monotonic(store: Store, name: str, payload: dict[str, Any], raw: bytes, label: str) -> None:
    """Version must not go backwards vs the trusted file; equal version
    requires byte-identical content."""
    if not store.has(name):
        return
    trusted_version = _version(signed_payload(store.load_envelope(name)), label)
    version = _version(payload, label)
    if version < trusted_version:
        raise ChannelError("rollback", f"{label} {version} < trusted {trusted_version}")
    if version == trusted_version and raw != store.path_trusted(name).read_bytes():
        raise ChannelError("version_conflict", f"{label} version {version} differs at equal version")


def _check_binding(info: dict[str, Any], raw: bytes, label: str) -> None:
    """A meta entry binds a metadata file by sha256 and length."""
    want_hash = info.get("hash")
    want_length = info.get("length")
    if not isinstance(want_hash, str) or not isinstance(want_length, int):
        raise ChannelError("bad_metadata", f"{label} meta entry incomplete")
    if len(raw) != want_length or sha256_bytes(raw) != want_hash:
        raise ChannelError("binding_mismatch", f"{label} does not match its meta entry")


def _read_remote(reader, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        return reader()
    except FileNotFoundError as exc:
        raise ChannelError("missing_metadata", label) from exc


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
    _check_not_expired(root_payload, now, "root")

    # --- root chain: walk every version from trusted + 1 through the
    # highest versioned root on the remote; each step must be signed by the
    # currently trusted root's root role and by its own root role.
    highest = remote.latest_root_version()
    if highest is not None:
        trusted_root_version = _version(root_payload, "root")
        if highest == trusted_root_version:
            got = remote.root_at(highest) or remote.alias_root()
            if got is not None:
                _env, raw = got
                if raw != store.path_trusted("root.json").read_bytes():
                    raise ChannelError("version_conflict", "root differs at equal version")
        else:
            for version in range(trusted_root_version + 1, highest + 1):
                got = remote.root_at(version)
                if got is None:
                    raise ChannelError("root_chain_gap", f"missing {version}.root.json")
                new_env, _raw = got
                new_payload = signed_payload(new_env)
                if _version(new_payload, "root") != version:
                    raise ChannelError("bad_metadata", f"root version mismatch at {version}")
                _verify_role(new_env, root_payload, "root", keys)
                _verify_role(new_env, new_payload, "root", keys)
                _check_not_expired(new_payload, now, "root")
                root_env = new_env
                root_payload = new_payload

    # --- timestamp
    ts_env, ts_raw = _read_remote(remote.timestamp, "timestamp.json")
    _verify_role(ts_env, root_payload, "timestamp", keys)
    ts = signed_payload(ts_env)
    _check_not_expired(ts, now, "timestamp")
    _check_monotonic(store, "timestamp.json", ts, ts_raw, "timestamp")

    # --- snapshot, bound by the timestamp
    try:
        snap_version = int(ts["snapshot_version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ChannelError("bad_metadata", "timestamp missing snapshot_version") from exc
    snap_env, snap_raw = _read_remote(lambda: remote.snapshot(snap_version), f"{snap_version}.snapshot.json")
    _check_binding(
        {"hash": ts.get("snapshot_hash"), "length": ts.get("snapshot_length")},
        snap_raw,
        "snapshot",
    )
    _verify_role(snap_env, root_payload, "snapshot", keys)
    snap = signed_payload(snap_env)
    if _version(snap, "snapshot") != snap_version:
        raise ChannelError("bad_metadata", "snapshot version does not match timestamp")
    _check_not_expired(snap, now, "snapshot")
    _check_monotonic(store, "snapshot.json", snap, snap_raw, "snapshot")

    # --- top-level targets, bound by the snapshot
    meta = snap.get("meta") or {}
    targets_info = meta.get("targets.json")
    if not isinstance(targets_info, dict):
        raise ChannelError("bad_metadata", "snapshot meta missing targets.json")
    targets_version = _version(targets_info, "targets meta")
    targets_env, targets_raw = _read_remote(lambda: remote.targets(targets_version), f"{targets_version}.targets.json")
    _check_binding(targets_info, targets_raw, "targets.json")
    _verify_role(targets_env, root_payload, "targets", keys)
    targets = signed_payload(targets_env)
    if _version(targets, "targets") != targets_version:
        raise ChannelError("bad_metadata", "targets version does not match snapshot meta")
    _check_not_expired(targets, now, "targets")
    _check_monotonic(store, "targets.json", targets, targets_raw, "targets")

    # --- delegations, each bound by the snapshot and confined to its paths
    files: dict[str, dict[str, Any]] = {}
    for rel, entry in (targets.get("targets") or {}).items():
        if path_unsafe(rel):
            raise ChannelError("unsafe_path", rel)
        files[rel] = entry
    delegations = (targets.get("delegations") or {}).get("roles") or []
    delegated: list[tuple[dict[str, Any], dict[str, Any]]] = []
    accepted_delegations: list[tuple[str, dict[str, Any]]] = []
    for role in delegations:
        name = role.get("name")
        if not name:
            continue
        info = meta.get(f"delegations.{name}.json")
        if not isinstance(info, dict):
            raise ChannelError("bad_metadata", f"snapshot meta missing delegations.{name}.json")
        dver = _version(info, f"delegations.{name}.json meta")
        d_env, d_raw = _read_remote(lambda: remote.delegation(dver, name), f"{dver}.delegations.{name}.json")
        _check_binding(info, d_raw, f"delegations.{name}.json")
        d_payload = signed_payload(d_env)
        if _version(d_payload, f"delegation {name}") != dver:
            raise ChannelError("bad_metadata", f"delegation {name} version does not match snapshot meta")
        d_keyids = list(role.get("keyids") or [])
        d_threshold = int(role.get("threshold") or 1)
        if not verify_threshold(d_env, keyids=d_keyids, threshold=d_threshold, keys=keys):
            raise ChannelError("bad_signature", f"delegation {name}")
        _check_not_expired(d_payload, now, f"delegation {name}")
        patterns = list(role.get("paths") or [])
        d_targets = d_payload.get("targets") or {}
        for rel in d_targets:
            if path_unsafe(rel):
                raise ChannelError("unsafe_path", rel)
            if not path_allowed(rel, patterns):
                raise ChannelError("path_escape", f"{name} may not sign {rel}")
        delegated.append((role, d_targets))
        accepted_delegations.append((str(name), d_env))

    # Resolve delegated paths in role order: the first role whose paths
    # match decides; a terminating role that does not list the path blocks
    # later siblings, a non-terminating one falls through.
    candidates: list[str] = []
    for _deleg_role, d_targets in delegated:
        for rel in d_targets:
            if rel not in candidates:
                candidates.append(rel)
    for rel in candidates:
        entry: Optional[dict[str, Any]] = None
        for role, d_targets in delegated:
            if not path_allowed(rel, list(role.get("paths") or [])):
                continue
            if rel in d_targets:
                entry = d_targets[rel]
            elif not role.get("terminating"):
                continue
            break
        if entry is not None:
            files[rel] = entry
        else:
            files.pop(rel, None)

    # --- payloads: verify every byte against targets before installing
    # anything, and only then persist the new trusted metadata.
    install_dir = Path(install_dir)
    install_dir.mkdir(parents=True, exist_ok=True)
    staged: list[tuple[str, dict[str, Any], bytes]] = []
    for rel, entry in files.items():
        want_hash = entry.get("hash")
        want_length = entry.get("length")
        if not isinstance(want_hash, str) or not isinstance(want_length, int):
            raise ChannelError("bad_metadata", f"targets entry for {rel} incomplete")
        src = remote.payload(rel)
        if not src.is_file():
            raise ChannelError("missing_payload", rel)
        data = src.read_bytes()
        if len(data) != want_length or sha256_bytes(data) != want_hash:
            raise ChannelError("payload_mismatch", rel)
        staged.append((rel, entry, data))

    manifest = store.load_manifest()
    installed: dict[str, Any] = {}
    for rel, entry, data in staged:
        dest = install_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        rec = {
            "hash": entry.get("hash"),
            "length": entry.get("length"),
            "version": (entry.get("custom") or {}).get("version"),
        }
        manifest[rel] = rec
        installed[rel] = rec

    store.save_envelope("root.json", root_env)
    store.save_envelope("timestamp.json", ts_env)
    store.save_envelope("snapshot.json", snap_env)
    store.save_envelope("targets.json", targets_env)
    for name, d_env in accepted_delegations:
        if "/" in name or ".." in name:
            continue
        dump_json(store.trusted / "delegations" / f"{name}.json", d_env)
    store.save_manifest(manifest)

    return Outcome(
        decision="apply",
        reason_codes=[],
        installed=installed,
        trusted_versions=_versions(store),
    )


def report_refuse(code: str, store: Store) -> Outcome:
    return Outcome(decision="refuse", reason_codes=[code], trusted_versions=_versions(store) if store.has("root.json") else {})
