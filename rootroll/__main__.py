"""CLI for the rootroll channel client."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .keys import load_keys
from .metadata import signed_payload
from .remote import Remote
from .store import Store
from .update import ChannelError, refresh
from .util import dump_json, parse_time


def cmd_status(args: argparse.Namespace) -> int:
    store = Store(Path(args.store))
    if not store.has("root.json"):
        print("missing trusted root", file=sys.stderr)
        return 2
    versions = {}
    for name, key in (("root.json", "root"), ("timestamp.json", "timestamp"), ("snapshot.json", "snapshot"), ("targets.json", "targets")):
        if store.has(name):
            versions[key] = int(signed_payload(store.load_envelope(name))["version"])
    doc = {"trusted_versions": versions, "installed": store.load_manifest()}
    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    store_dir = Path(args.store)
    remote_dir = Path(args.remote)
    keys_path = Path(args.keys)
    report_path = Path(args.report) if args.report else None
    install_dir = Path(args.install_dir) if args.install_dir else store_dir / "installed" / "packages"

    try:
        keys = load_keys(keys_path)
        now = parse_time(args.now)
        store = Store(store_dir)
        remote = Remote(remote_dir)
        outcome = refresh(store, remote, keys, now, install_dir)
    except FileNotFoundError as exc:
        print(f"read error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"read error: {exc}", file=sys.stderr)
        return 2
    except ChannelError as exc:
        from .update import report_refuse
        store = Store(store_dir)
        outcome = report_refuse(exc.code, store)

    if report_path is not None:
        dump_json(report_path, outcome.to_json())
    if outcome.decision == "apply":
        return 0
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rootroll")
    sub = parser.add_subparsers(dest="cmd", required=True)

    st = sub.add_parser("status", help="print trusted versions and the install manifest")
    st.add_argument("--store", required=True)
    st.set_defaults(func=cmd_status)

    ap = sub.add_parser("apply", help="refresh metadata from a remote and install targets")
    ap.add_argument("--store", required=True)
    ap.add_argument("--remote", required=True)
    ap.add_argument("--keys", required=True)
    ap.add_argument("--now", required=True, help="RFC 3339 UTC clock, e.g. 2026-11-14T05:00:00Z")
    ap.add_argument("--report", required=False, default=None)
    ap.add_argument("--install-dir", required=False, default=None)
    ap.set_defaults(func=cmd_apply)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
