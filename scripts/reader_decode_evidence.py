# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Collect reproducible #538 decode benchmark evidence from label=Google-JSON pairs.

Example:
  python scripts/reader_decode_evidence.py before=before.json after=after.json \
      --output evidence.json --markdown comparison.md

The first label is the comparison baseline. Google Benchmark context is preserved
verbatim: record the source commit, code variant, compiler, build flags and command
with --benchmark_context when running the executable. Keep raw JSON repetitions
with --benchmark_report_aggregates_only=false; --benchmark_display_aggregates_only=true
may limit terminal output independently. This collector never runs benchmarks.
"""

import argparse
import json
import math
from pathlib import Path
import statistics
import sys


PREFIXES = ("reader_decode/", "tree_decode/", "document_decode/")
NANOSECONDS = {"ns": 1, "us": 1000, "ms": 1000000, "s": 1000000000}
RAW_FIELDS = ("repetition_index", "iterations", "threads", "real_time", "cpu_time",
              "bytes_per_second", "items_per_second")


def positive_number(value, description):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not math.isfinite(value) or value <= 0):
        raise ValueError(f"{description} must be a finite positive number")
    return value


def positive_integer(value, description):
    if not isinstance(value, int):
        raise ValueError(f"{description} must be an integer")
    return positive_number(value, description)


def summarize(values, multiplier):
    return {
        "median_ns": statistics.median(values) * multiplier,
        "cv_percent": (100 * statistics.stdev(values) / statistics.mean(values)
                       if len(values) > 1 else None),
    }


def read_run(label, path):
    source = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(source, dict) or not isinstance(source.get("context"), dict):
        raise ValueError(f"{path}: missing Google Benchmark context")
    rows = source.get("benchmarks")
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{path}: missing benchmark rows")
    grouped = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"{path}: malformed benchmark row")
        if row.get("error_occurred"):
            raise ValueError(f"{path}: benchmark error: {row.get('error_message', row.get('name'))}")
        name = row.get("run_name", row.get("name", ""))
        if not isinstance(name, str):
            raise ValueError(f"{path}: malformed benchmark name")
        if name.startswith(PREFIXES) and row.get("run_type", "iteration") == "iteration":
            grouped.setdefault(name, []).append(row)
    if not grouped:
        raise ValueError(f"{path}: no raw decode repetitions; aggregates alone are insufficient")

    workloads = {}
    for name, repetitions in sorted(grouped.items()):
        description = f"{path}: {name}"
        first = repetitions[0]
        count = positive_integer(first.get("repetitions", 1), f"{description} repetitions")
        if count != len(repetitions):
            raise ValueError(f"{description}: expected {count} repetitions, got {len(repetitions)}")
        unit = first.get("time_unit")
        if unit not in NANOSECONDS:
            raise ValueError(f"{description}: unsupported time unit {unit!r}")
        counters = {key: value for key, value in first.items() if key.endswith("/input")}
        for key in ("elements/input", "wire_bytes/input"):
            positive_number(counters.get(key), f"{description} {key}")
        if name.startswith("document_decode/"):
            for key in ("alloc_calls/input", "free_calls/input", "alloc_bytes/input"):
                positive_number(counters.get(key), f"{description} {key}")
        indices = []
        samples = []
        for row in repetitions:
            if row.get("repetitions", 1) != count or row.get("time_unit") != unit:
                raise ValueError(f"{description}: inconsistent repetition metadata")
            if {key: value for key, value in row.items() if key.endswith("/input")} != counters:
                raise ValueError(f"{description}: input/allocation counters changed between repetitions")
            index = row.get("repetition_index", 0 if count == 1 else None)
            if isinstance(index, bool) or not isinstance(index, int):
                raise ValueError(f"{description}: missing or invalid repetition index")
            indices.append(index)
            positive_integer(row.get("iterations"), f"{description} iterations")
            for field in ("real_time", "cpu_time", "bytes_per_second", "items_per_second"):
                positive_number(row.get(field), f"{description} {field}")
            sample = {key: row[key] for key in RAW_FIELDS if key in row}
            sample["repetition_index"] = index
            samples.append(sample)
        if sorted(indices) != list(range(count)):
            raise ValueError(f"{description}: missing or duplicate repetition indices")
        workloads[name] = {
            "time_unit": unit,
            "counters": counters,
            "samples": sorted(samples, key=lambda item: item["repetition_index"]),
            "cpu": summarize([row["cpu_time"] for row in repetitions], NANOSECONDS[unit]),
            "real": summarize([row["real_time"] for row in repetitions], NANOSECONDS[unit]),
        }
    return {"label": label, "source_file": path.name, "context": source["context"],
            "workloads": workloads}


def collect(runs):
    baseline = runs[0]
    comparisons = []
    for candidate in runs[1:]:
        missing = baseline["workloads"].keys() - candidate["workloads"].keys()
        extra = candidate["workloads"].keys() - baseline["workloads"].keys()
        if missing or extra:
            raise ValueError(f"{candidate['label']}: workload set differs from {baseline['label']}; "
                             f"missing={sorted(missing)}, extra={sorted(extra)}")
        changes = {}
        for name, before in baseline["workloads"].items():
            after = candidate["workloads"][name]
            if before["counters"] != after["counters"]:
                raise ValueError(f"{candidate['label']}: {name}: workload/allocation counters differ")
            changes[name] = {
                f"{clock}_median_change_percent":
                    100 * (after[clock]["median_ns"] / before[clock]["median_ns"] - 1)
                for clock in ("cpu", "real")
            }
        comparisons.append({"label": candidate["label"], "workloads": changes})
    return {
        "schema_version": 1,
        "baseline": baseline["label"],
        "method": "Medians of raw repetitions; CV is sample standard deviation / mean. "
                  "Negative median change means less time. CV is null for one repetition.",
        "runs": runs,
        "comparisons": comparisons,
    }


def markdown(report):
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

    def cv(value):
        return "n/a" if value is None else f"{value:.2f}%"

    lines = [f"Baseline: **{cell(report['baseline'])}**. CPU medians are per complete input; "
             "negative changes mean less time. CV describes repetition variation, not significance.",
             "", "| Run | Workload | CPU median (ns) | CPU CV | Change | Repetitions |",
             "| --- | --- | ---: | ---: | ---: | ---: |"]
    changes = {item["label"]: item["workloads"] for item in report["comparisons"]}
    for run in report["runs"]:
        for name, result in run["workloads"].items():
            change = (f"{changes[run['label']][name]['cpu_median_change_percent']:+.2f}%"
                      if run["label"] in changes else "baseline")
            lines.append(f"| {cell(run['label'])} | {cell(name)} | "
                         f"{result['cpu']['median_ns']:.2f} | {cv(result['cpu']['cv_percent'])} | "
                         f"{change} | {len(result['samples'])} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", metavar="LABEL=PATH")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, help="Optional CPU median comparison table")
    args = parser.parse_args()
    runs = []
    labels = set()
    sources = set()
    for argument in args.runs:
        label, separator, filename = argument.partition("=")
        if not separator or not label.strip() or not filename or label in labels:
            raise ValueError(f"Expected unique nonempty LABEL=PATH, got {argument!r}")
        path = Path(filename)
        labels.add(label)
        sources.add(path.resolve())
        runs.append(read_run(label, path))
    outputs = [args.output] + ([args.markdown] if args.markdown else [])
    if len({path.resolve() for path in outputs}) != len(outputs):
        raise ValueError("JSON and Markdown outputs must be different paths")
    if any(path.resolve() in sources for path in outputs):
        raise ValueError("An output would overwrite an input benchmark JSON")
    report = collect(runs)
    # Validate every input before replacing any prior completed evidence.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown(report), encoding="utf-8")
    print(f"Collected {len(runs)} runs, {len(runs[0]['workloads'])} workloads: {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"Decode evidence failed: {error}", file=sys.stderr)
        sys.exit(1)
