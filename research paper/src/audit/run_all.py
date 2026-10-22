"""Run audit steps in order, stopping at the first failure (exit code != 0).

Each step is a separate `python -I` process; stdout/stderr go to logs/pipeline_<step>.txt and a
one-line status per step is appended to logs/pipeline_runs.log.

Usage (from the project root)
-----------------------------
    python -I src/audit/run_all.py                 # all steps
    python -I src/audit/run_all.py --from numeric  # resume from a step
    python -I src/audit/run_all.py --only phase2_scan phase2_derive
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PY = [sys.executable, "-I"]
STEPS: list[tuple[str, list[str]]] = [
    ("phase2_scan", ["src/audit/schema_labels.py", "scan", "--overwrite"]),
    ("phase2_derive", ["src/audit/schema_labels.py", "derive", "--overwrite"]),
    ("timeline", ["src/audit/integrity.py", "timeline"]),
    ("numeric", ["src/audit/integrity.py", "numeric", "--overwrite"]),
    ("duplicates", ["src/audit/integrity.py", "duplicates", "--overwrite"]),
    ("timestamps", ["src/audit/integrity.py", "timestamps", "--overwrite"]),
    ("temporal", ["src/audit/temporal.py", "--overwrite"]),
    ("separability", ["src/audit/leakage.py", "separability", "--overwrite"]),
    ("hashes", ["src/audit/leakage.py", "hashes"]),
]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--from", dest="start")
    p.add_argument("--only", nargs="+")
    args = p.parse_args(argv)
    names = [n for n, _ in STEPS]
    steps = STEPS[names.index(args.start):] if args.start else STEPS
    if args.only:
        steps = [s for s in STEPS if s[0] in args.only]
    status_log = ROOT / "logs/pipeline_runs.log"
    for name, cmd in steps:
        t0 = time.perf_counter()
        out = ROOT / f"logs/pipeline_{name}.txt"
        with out.open("w", encoding="utf-8") as fh:
            rc = subprocess.run(PY + cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT).returncode
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} step={name} rc={rc} seconds={time.perf_counter() - t0:.1f} cmd={' '.join(cmd)}"
        with status_log.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(line, flush=True)
        if rc != 0:
            print(f"STOPPED at {name}; see {out.relative_to(ROOT).as_posix()}", flush=True)
            return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
