# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Run bounded Query sanitizer campaigns and retain commands, logs and failures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--targets", nargs="+", default=["parse", "match", "program", "image", "pairs"])
    args = parser.parse_args()
    if not 1 <= args.seconds <= 600 or set(args.targets) - {"parse", "match", "program", "image", "pairs"}:
        parser.error("bounded known Query targets required")
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for target in args.targets:
        binary = (args.build / "tests/fuzz" / f"fuzz_query_{target}").resolve()
        campaign = (args.output / target).resolve()
        (campaign / "corpus").mkdir(parents=True, exist_ok=True)
        seeds = root / "tests/fuzz/query/corpus" / ("match" if target == "pairs" else target)
        command = [str(binary), str(campaign / "corpus"), str(seeds),
                   f"-max_total_time={args.seconds}", "-max_len=4096", "-timeout=10", "-rss_limit_mb=2048",
                   f"-artifact_prefix={campaign}/"]
        if target == "program":
            command += [f"-dict={root / 'tests/fuzz/query/query.dict'}"]
        with (campaign / "run.log").open("w") as log:
            try:
                status = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=args.seconds + 30).returncode
            except subprocess.TimeoutExpired:
                status = 124
        result = {"target": target, "command": command, "returncode": status,
                  "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        if status:
            for failure in sorted(campaign.glob("crash-*")):
                minimized = campaign / (failure.name + ".minimized")
                reduction = [str(binary), "-minimize_crash=1", "-max_total_time=30",
                             f"-exact_artifact_path={minimized}", str(failure)]
                with (campaign / (failure.name + ".minimize.log")).open("w") as log:
                    try:
                        subprocess.run(reduction, stdout=log, stderr=subprocess.STDOUT, timeout=45)
                    except subprocess.TimeoutExpired:
                        pass  # Original crash and log remain the authoritative failure.
        results.append(result)
        (args.output / "report.json").write_text(json.dumps({"version": 1, "seconds_per_target": args.seconds,
            "passed": all(row["returncode"] == 0 for row in results), "results": results}, indent=2) + "\n")
        print(f"Query fuzz {target}: status={status}, budget={args.seconds}s", flush=True)
    if any(row["returncode"] for row in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
