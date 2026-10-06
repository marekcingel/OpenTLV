# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Retain MSan evidence; retry only pre-main ASLR shadow-map failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    attempts, passed = [], False
    environment = dict(os.environ, MSAN_OPTIONS="halt_on_error=1:exit_code=86")
    for attempt in range(1, 4):
        stdout, stderr = args.output / f"stdout-{attempt}.log", args.output / f"stderr-{attempt}.log"
        with stdout.open("w") as out, stderr.open("w") as err:
            try:
                status = subprocess.run([str(args.native.resolve())], stdout=out, stderr=err,
                                        env=environment, timeout=120).returncode
            except subprocess.TimeoutExpired:
                status = 124
        detail = stderr.read_text(errors="replace")
        shadow_failure = ("MemorySanitizer can not mmap the shadow memory" in detail
                          and "WARNING: MemorySanitizer" not in detail)
        passed = status == 0 and "Persistent Query memory campaign:" in detail
        attempts.append({"attempt": attempt, "returncode": status, "shadow_mapping_failure": shadow_failure,
                         "stdout": stdout.name, "stderr": stderr.name})
        if passed or not shadow_failure:
            break
    report = {"version": 1, "passed": passed, "attempts": attempts,
              "binary_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(),
              "boundary": "instrumented C core and persistent corpus; not uninstrumented C++ dependencies"}
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Query MemorySanitizer: passed={passed}, attempts={len(attempts)}")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
