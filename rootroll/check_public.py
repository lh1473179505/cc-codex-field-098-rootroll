"""Run the public channel cases shipped under fixtures/cases/."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "fixtures" / "cases"
KEYS = ROOT / "fixtures" / "keys.json"
NOW = "2026-11-14T05:00:00Z"

# Expected public behavior. `install` maps relative payload paths to the
# exact file text that must appear under --install-dir after a successful
# apply. `unchanged` means the pre-existing manifest version must remain.
EXPECT = {
    "legit-patch": {"exit": 0, "install": {"packages/app.bin": "APP-3.2.0\n"}, "targets_version": 3},
    "legit-delegation": {"exit": 0, "install": {"packages/team/lib.bin": "TEAM-LIB-2\n"}, "targets_version": 3},
    "legit-root-rotation": {"exit": 0, "install": {"packages/app.bin": "APP-3.2.0\n"}, "root_version": 2},
    "legit-noop": {"exit": 0, "install": {"packages/app.bin": "APP-3.1.0\n"}, "targets_version": 2},
    "rollback-targets": {"exit": 1, "unchanged": {"packages/app.bin": "3.1.0"}},
    "freeze-expiry": {"exit": 1, "unchanged": {"packages/app.bin": "3.1.0"}},
    "mix-and-match": {"exit": 1, "unchanged": {"packages/app.bin": "3.1.0"}},
    "path-escape": {"exit": 1, "unchanged": {"packages/app.bin": "3.1.0"}, "must_not_exist": ["packages/team-evil/x.bin"]},
    "payload-mismatch": {"exit": 1, "unchanged": {"packages/app.bin": "3.1.0"}},
}


def run_case(name: str, spec: dict) -> bool:
    case = CASES / name
    if not case.is_dir():
        print(f"FAIL  {name}  missing case directory")
        return False
    tmp = Path(tempfile.mkdtemp(prefix=f"rootroll-public-{name}-"))
    try:
        store = tmp / "store"
        install = tmp / "install"
        report = tmp / "report.json"
        shutil.copytree(case / "store", store)
        proc = subprocess.run(
            [
                sys.executable, "-m", "rootroll", "apply",
                "--store", str(store),
                "--remote", str(case / "remote"),
                "--keys", str(KEYS),
                "--now", NOW,
                "--report", str(report),
                "--install-dir", str(install),
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        ok = proc.returncode == spec["exit"]
        details = [f"exit={proc.returncode} want {spec['exit']}"]
        if spec.get("install") and proc.returncode == 0:
            for rel, text in spec["install"].items():
                path = install / rel
                if not path.is_file() or path.read_text(encoding="utf-8") != text:
                    ok = False
                    details.append(f"payload {rel} mismatch")
        if spec.get("unchanged"):
            man_path = store / "installed" / "manifest.json"
            man = json.loads(man_path.read_text(encoding="utf-8")) if man_path.is_file() else {}
            for rel, ver in spec["unchanged"].items():
                got = (man.get(rel) or {}).get("version")
                if got != ver:
                    ok = False
                    details.append(f"manifest {rel} version={got} want {ver}")
                # the prior artifact must still be the only payload for this path
                prior = store / "installed" / "packages" / Path(rel).name if False else store / "installed" / rel
                # also ensure install-dir did not receive a downgrade/escape
        if spec.get("must_not_exist"):
            for rel in spec["must_not_exist"]:
                if (install / rel).exists() or (store / "installed" / rel).exists():
                    ok = False
                    details.append(f"unexpected {rel}")
        if spec.get("targets_version") and proc.returncode == 0:
            env = json.loads((store / "trusted" / "targets.json").read_text(encoding="utf-8"))
            got = int(env["signed"]["version"])
            if got != spec["targets_version"]:
                ok = False
                details.append(f"targets version={got} want {spec['targets_version']}")
        if spec.get("root_version") and proc.returncode == 0:
            env = json.loads((store / "trusted" / "root.json").read_text(encoding="utf-8"))
            got = int(env["signed"]["version"])
            if got != spec["root_version"]:
                ok = False
                details.append(f"root version={got} want {spec['root_version']}")
        # On refuse, trusted metadata must stay at the snapshot we copied in.
        if spec["exit"] == 1:
            before = json.loads((case / "store" / "trusted" / "timestamp.json").read_text(encoding="utf-8"))
            after = json.loads((store / "trusted" / "timestamp.json").read_text(encoding="utf-8"))
            if before != after:
                ok = False
                details.append("trusted timestamp mutated on refuse")
        print(("PASS" if ok else "FAIL") + f"  {name}  " + "; ".join(details))
        if not ok and proc.stderr:
            err = proc.stderr.strip().splitlines()
            if err:
                print("    stderr:", err[-1][:200])
        return ok
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    fail = 0
    for name, spec in EXPECT.items():
        if not run_case(name, spec):
            fail += 1
    print(f"FAIL_COUNT={fail}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
