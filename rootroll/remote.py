"""Read a directory-backed channel mirror. No network I/O."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from .util import load_json, sha256_bytes


class Remote:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.meta = self.root / "metadata"
        self.packages = self.root / "packages"

    def exists(self) -> bool:
        return self.meta.is_dir()

    def read_meta_file(self, filename: str) -> tuple[dict[str, Any], bytes]:
        path = self.meta / filename
        raw = path.read_bytes()
        return load_json(path), raw

    def latest_root_version(self) -> Optional[int]:
        versions = []
        for p in self.meta.glob("*.root.json"):
            name = p.name
            if name.endswith(".root.json") and name[0].isdigit():
                try:
                    versions.append(int(name.split(".", 1)[0]))
                except ValueError:
                    continue
        if versions:
            return max(versions)
        alias = self.meta / "root.json"
        if alias.is_file():
            env = load_json(alias)
            return int(env["signed"]["version"])
        return None

    def root_at(self, version: int) -> Optional[tuple[dict[str, Any], bytes]]:
        path = self.meta / f"{version}.root.json"
        if path.is_file():
            raw = path.read_bytes()
            return load_json(path), raw
        return None

    def alias_root(self) -> Optional[tuple[dict[str, Any], bytes]]:
        path = self.meta / "root.json"
        if not path.is_file():
            return None
        raw = path.read_bytes()
        return load_json(path), raw

    def timestamp(self) -> tuple[dict[str, Any], bytes]:
        return self.read_meta_file("timestamp.json")

    def snapshot(self, version: int) -> tuple[dict[str, Any], bytes]:
        return self.read_meta_file(f"{version}.snapshot.json")

    def targets(self, version: int) -> tuple[dict[str, Any], bytes]:
        return self.read_meta_file(f"{version}.targets.json")

    def delegation(self, version: int, name: str) -> tuple[dict[str, Any], bytes]:
        return self.read_meta_file(f"{version}.delegations.{name}.json")

    def payload(self, relpath: str) -> Path:
        # Target paths are relative to the remote root ("packages/app.bin").
        if relpath.startswith("packages/"):
            return self.root / relpath
        return self.packages / relpath
