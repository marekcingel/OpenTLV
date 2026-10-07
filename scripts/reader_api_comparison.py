#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

r"""Build and measure identical Reader workloads across C and C++ revisions.

Run on Linux with CMake, Ninja, GCC and Python 3. This intentionally standalone
comparison supports the pre-facade Fixed template API with --legacy-label.
Example (run from the repository root):
  python3 scripts/reader_api_comparison.py --variant main=89991d9f \
      --variant prior=a2d1fd3 --variant candidate=working --legacy-label main \
      --work-dir build/reader-api-comparison --output benchmarks/evidence/reader-api-440

Use --prepare-only, then --run-only to separate compilation from quiet timing.
The output keeps every raw repetition, source identifiers and build settings,
but omits hostnames and absolute paths. Working-tree changes are captured as a
patch; each variant's exact library and benchmark binary are retained locally.
Source/CSV text checksums normalize line endings to LF; binary hashes do not.
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmarks/tools/reader_api_comparison.cpp"
CPP_FLAGS = ["-std=c++11", "-O2", "-DNDEBUG", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
CMAKE_FLAGS = ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
               "-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG", "-DOPENTLV_BUILD_CXX=OFF",
               "-DOPENTLV_BUILD_SHARED_LIBS=OFF", "-DOPENTLV_BUILD_TESTS=OFF",
               "-DOPENTLV_BUILD_EXAMPLES=OFF", "-DOPENTLV_BUILD_CLI=OFF",
               "-DOPENTLV_BUILD_DOCS=OFF", "-DOPENTLV_BUILD_BENCHMARKS=OFF"]


def capture(*command):
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_digest(path):
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def prepare(args):
    variants = []
    labels = set()
    for item in args.variant:
        label, separator, revision = item.partition("=")
        if not separator or not revision or not re.fullmatch(r"[a-zA-Z0-9_-]+", label):
            raise ValueError("variants must be LABEL=REVISION; labels use letters, numbers, '-' or '_'")
        if label in labels:
            raise ValueError(f"duplicate variant: {label}")
        if (args.work_dir / label).exists():
            raise ValueError(f"variant directory already exists: {label}; choose a fresh --work-dir")
        labels.add(label)
        variants.append((label, revision))
    if set(args.legacy_label) - labels:
        raise ValueError("each --legacy-label must name a prepared variant")
    if any(revision == "working" for _, revision in variants):
        untracked = capture("git", "ls-files", "--others", "--exclude-standard", "--",
                            "tlv", "tlv++", "cmake", "CMakeLists.txt")
        if untracked:
            raise ValueError("working-tree provenance cannot capture untracked build inputs: " + untracked)
    metadata = {"schema": 1, "compiler_c": capture(args.cc, "--version").splitlines()[0],
                "compiler_cpp": capture(args.cxx, "--version").splitlines()[0],
                "cmake_flags": CMAKE_FLAGS, "cpp_flags": CPP_FLAGS,
                "benchmark_source_lf_sha256": text_digest(BENCHMARK), "variants": {}}
    for label, revision in variants:
        directory = args.work_dir / label
        directory.mkdir(parents=True, exist_ok=True)
        source_commit = capture("git", "rev-parse", "HEAD" if revision == "working" else revision)
        if revision == "working":
            source = ROOT
            # A Windows checkout measured from WSL must not record CRLF-only
            # differences as changes to every native source file.
            patch = subprocess.check_output(
                ["git", "-c", "core.autocrlf=true", "-c", "core.safecrlf=false",
                 "diff", "--binary", "HEAD", "--",
                 "tlv", "tlv++", "cmake", "CMakeLists.txt"],
                cwd=ROOT, text=True)
        else:
            source = directory / "source"
            archive = subprocess.check_output(["git", "archive", "--format=zip", source_commit], cwd=ROOT)
            with zipfile.ZipFile(io.BytesIO(archive)) as snapshot:
                snapshot.extractall(source)
            patch = ""
        build = directory / "build"
        with (directory / "build.log").open("w") as output:
            subprocess.run(["cmake", "-S", str(source), "-B", str(build), *CMAKE_FLAGS,
                            f"-DCMAKE_C_COMPILER={args.cc}"], check=True, stdout=output, stderr=subprocess.STDOUT)
            subprocess.run(["cmake", "--build", str(build), "--target", "tlv", "--parallel", "2"],
                           check=True, stdout=output, stderr=subprocess.STDOUT)
            flags = CPP_FLAGS + (["-DOPENTLV_LEGACY_FACADE"] if label in args.legacy_label else [])
            subprocess.run([args.cxx, *flags, "-I" + str(source / "tlv++/include"),
                            "-I" + str(source / "tlv/include"), "-I" + str(build / "generated/include"),
                            str(BENCHMARK), str(build / "tlv/libtlv.a"), "-o", str(directory / "benchmark")],
                           check=True, stdout=output, stderr=subprocess.STDOUT)
        metadata["variants"][label] = {"source_commit": source_commit,
                                        "legacy_facade": label in args.legacy_label,
                                        "source_patch": patch,
                                        "generated_config_sha256": digest(build / "generated/include/tlv/config.h"),
                                        "library_sha256": digest(build / "tlv/libtlv.a"),
                                        "executable_sha256": digest(directory / "benchmark")}
        print(f"Prepared {label}: {source_commit[:12]}", flush=True)
    (args.work_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


def measure(args):
    for suffix in (".csv", ".json"):
        output = args.output.with_suffix(suffix)
        if output.exists() and not args.overwrite:
            raise ValueError(f"evidence already exists: {output}; choose another --output or use --overwrite")
    metadata = json.loads((args.work_dir / "metadata.json").read_text())
    if metadata["benchmark_source_lf_sha256"] != text_digest(BENCHMARK):
        raise ValueError("benchmark source changed since preparation; prepare the variants again")
    for label, variant in metadata["variants"].items():
        if variant["executable_sha256"] != digest(args.work_dir / label / "benchmark"):
            raise ValueError(f"benchmark executable changed since preparation: {label}")
        if variant["library_sha256"] != digest(args.work_dir / label / "build/tlv/libtlv.a"):
            raise ValueError(f"native library changed since preparation: {label}")
    allowed_cpus = sorted(os.sched_getaffinity(0))
    cpu = args.cpu if args.cpu is not None else allowed_cpus[0]
    os.sched_setaffinity(0, {cpu})
    metadata["measurement"] = {"started_at_utc": datetime.now(timezone.utc).isoformat(),
                               "repeats": args.repeats, "count": args.count,
                               "warmup_count": 50000, "shuffle_seed": 440, "cpu": cpu,
                               "cpu_model": next((line.split(":", 1)[1].strip() for line in
                                                  Path("/proc/cpuinfo").read_text().splitlines()
                                                  if line.startswith("model name")), "unknown"),
                               "timer": "std::chrono::steady_clock elapsed nanoseconds",
                               "workloads": "Fixture allocation outside timer; Reader construction inside timer. "
                               "range visits exactly count elements; other cases make exactly count calls. "
                               "failed and incremental repeatedly decode a two-byte header missing its Value. "
                               "Failure status is consumed; optional diagnostic fields are not inspected."}
    cases = [(label, framing, work, api)
             for label in metadata["variants"] for framing in ("ber", "fixed")
             for api in ("cpp", "c", "c_diag")
             for work in (("next", "range", "failed", "incremental") if api == "cpp"
                          else ("next", "failed", "incremental"))]

    def run(case, count):
        label, framing, work, api = case
        fields = capture(str(args.work_dir / label / "benchmark"), work, framing, api, str(count)).split(",")
        if len(fields) != 4:
            raise ValueError(f"malformed benchmark output for {case}: {fields}")
        elapsed = float(fields[0])
        if not math.isfinite(elapsed) or elapsed <= 0 or any(int(value) < 0 for value in fields[1:]):
            raise ValueError(f"invalid benchmark measurement for {case}: {fields}")
        return fields

    for case in cases:
        run(case, 50000)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    rng = random.Random(440)
    with args.output.with_suffix(".csv").open("w", newline="") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["variant", "format", "work", "api", "repeat", "count", "ns", "checksum",
                         "error_bytes", "result_bytes"])
        for repeat in range(args.repeats):
            order = list(cases)
            rng.shuffle(order)
            for case in order:
                row = [*case, repeat, args.count, *run(case, args.count)]
                rows.append(row)
                writer.writerow(row)
            output.flush()
            print(f"Completed repeat {repeat + 1}/{args.repeats}", flush=True)
    metadata["summary"] = []
    metadata["raw_csv_lf_sha256"] = text_digest(args.output.with_suffix(".csv"))
    for case in cases:
        values = [float(row[6]) / 1e6 for row in rows if tuple(row[:4]) == case]
        metadata["summary"].append(dict(zip(("variant", "format", "work", "api"), case),
                                        median_ms=round(statistics.median(values), 3),
                                        min_ms=round(min(values), 3), max_ms=round(max(values), 3)))
    args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--variant", action="append", default=[], metavar="LABEL=REVISION")
    parser.add_argument("--legacy-label", action="append", default=[])
    parser.add_argument("--work-dir", type=Path, default=ROOT / "build/reader-api-comparison")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks/evidence/reader-api-440")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--count", type=int, default=2000000)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--overwrite", action="store_true", help="explicitly replace existing evidence")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--run-only", action="store_true")
    args = parser.parse_args()
    args.work_dir = args.work_dir.resolve()
    if args.count <= 0 or args.repeats <= 0:
        parser.error("count and repeats must be positive")
    if not args.run_only:
        if not args.variant:
            parser.error("at least one --variant is required for preparation")
        prepare(args)
    if not args.prepare_only:
        measure(args)


if __name__ == "__main__":
    main()
