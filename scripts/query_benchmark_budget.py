#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Advisory phase regression budgets; enforce only matching stable platform runs."""
import argparse
import json
import math
from pathlib import Path


def measurements(path):
    data = json.loads(path.read_text())
    rows, variance = {}, {}
    for row in data["benchmarks"]:
        if row.get("error_occurred"):
            raise ValueError(f"failed benchmark: {row['name']}")
        if not row["name"].startswith("query_"):
            continue
        name = row.get("run_name", row["name"].rsplit("_", 1)[0])
        if row.get("aggregate_name") == "median":
            scale = {"ns": 1, "us": 1000, "ms": 1000000, "s": 1000000000}[row["time_unit"]]
            rows[name] = row["real_time"] * scale
        elif row.get("aggregate_name") == "cv":
            variance[name] = row["real_time"]
    return data.get("context", {}), rows, variance


def compare(baseline, latest, threshold=0.25, max_cv=0.10):
    old_context, old, old_cv = baseline
    new_context, new, new_cv = latest
    matching = old_context.get("query_platform") and (
        old_context.get("query_platform") == new_context.get("query_platform"))
    results = []
    for name in sorted(set(old) | set(new)):
        if name not in old or name not in new:
            status, ratio = "missing", None
        else:
            ratio = new[name] / old[name] if old[name] else None
            values = (old[name], new[name], old_cv.get(name, 1), new_cv.get(name, 1))
            if (not all(math.isfinite(value) for value in values) or
                    old[name] <= 0 or new[name] <= 0 or
                    old_cv.get(name, 1) < 0 or new_cv.get(name, 1) < 0):
                status, ratio = "invalid", None
            elif not matching:
                status = "platform-unverified"
            elif max(old_cv.get(name, 1), new_cv.get(name, 1)) > max_cv:
                status = "noisy"
            else:
                status = "regression" if ratio is None or ratio > 1 + threshold else "passed"
        results.append({"name": name, "status": status, "ratio": ratio})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--latest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--threshold", type=float, default=0.25)
    parser.add_argument("--max-cv", type=float, default=0.10)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    if not math.isfinite(args.threshold) or args.threshold < 0 or not 0 <= args.max_cv <= 1:
        parser.error("nonnegative threshold and CV between zero and one required")
    latest = measurements(args.latest)
    results = compare(measurements(args.baseline), latest, args.threshold, args.max_cv) if args.baseline else []
    ready = bool(results) and all(row["status"] == "passed" for row in results)
    report = {"version": 1, "relative_threshold": args.threshold, "max_cv": args.max_cv,
              "ready": ready, "status": "compared" if args.baseline else "baseline-required",
              "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Query budget: {report['status']}, ready={ready}")
    if args.enforce and not ready:
        raise SystemExit("Stable matching-platform baseline and passing measurements required")


if __name__ == "__main__":
    main()
