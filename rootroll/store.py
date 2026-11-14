"""Trusted local metadata and the installed manifest."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .util import dump_json, load_json, sha256_file


class Store:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.trusted = self.root / "trusted"
        self.installed = self.root / "installed"

    def path_trusted(self, name: str) -> Path:
        return self.trusted / name

    def load_envelope(self, name: str) -> dict[str, Any]:
        return load_json(self.path_trusted(name))

    def has(self, name: str) -> bool:
        return self.path_trusted(name).is_file()

    def save_envelope(self, name: str, envelope: dict[str, Any]) -> None:
        dump_json(self.path_trusted(name), envelope)

    def load_manifest(self) -> dict[str, Any]:
        path = self.installed / "manifest.json"
        if not path.is_file():
            return {}
        data = load_json(path)
        return data if isinstance(data, dict) else {}

    def save_manifest(self, manifest: dict[str, Any]) -> None:
        dump_json(self.installed / "manifest.json", manifest)

    def install_payload(self, relpath: str, source: Path, dest_root: Path) -> None:
        dest = dest_root / relpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
