#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Compare fixed Callgrind workloads and repeated native timings in two checkouts.

Instruction increases are advisory. Missing, incompatible or incomplete evidence
is an infrastructure error (exit 1), never a successful performance comparison.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from callgrind_report import compare_workload, parse_profile, render_markdown


ROOT = Path(__file__).resolve().parents[1]
WORKLOADS = ("reader", "writer", "document", "query")
BUILD_FLAGS = {"callgrind": ("RelWithDebInfo", "-O2 -g -DNDEBUG"),
               "native": ("Release", "-O3 -DNDEBUG")}


def run(command, log=None, env=None, timeout=600):
    """Execute argv without a shell and retain diagnostics even on failure."""
    try:
        result = subprocess.run([str(part) for part in command], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            partial = [value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
                       for value in (error.stdout, error.stderr)]
            log.write_text(f"Command exceeded {timeout}s: {command}\n" + "\n".join(partial),
                           encoding="utf-8")
        raise RuntimeError(f"Command exceeded {timeout}s: {command[0]}") from error
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(json.dumps([str(part) for part in command]) + "\n\n"
                       + result.stdout + "\n" + result.stderr, encoding="utf-8")
    if result.returncode:
        tail = (result.stderr or result.stdout)[-4000:]
        raise RuntimeError(f"Command failed ({result.returncode}): {command[0]}\n{tail}")
    return result.stdout


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def source_metadata(source):
    """Identify the actual checkout, including local changes used by the build."""
    top = Path(run(["git", "-C", source, "rev-parse", "--show-toplevel"]).strip()).resolve()
    if source != top:
        raise ValueError(f"Source must be a Git checkout root: {source}")
    sha = run(["git", "-C", source, "rev-parse", "HEAD"]).strip()
    status = run(["git", "-C", source, "status", "--porcelain", "--untracked-files=all"])
    paths = run(["git", "-C", source, "ls-files", "-z", "--cached", "--others",
                 "--exclude-standard"]).split("\0")
    manifest = {}
    for name in sorted(set(paths) - {""}):
        path = source / name
        if not path.exists():
            manifest[name] = "deleted"
            continue
        if not path.is_file():
            raise ValueError(f"Unsupported source entry (submodule/directory): {name}")
        path.resolve().relative_to(source)
        manifest[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return {"sha": sha, "dirty": bool(status), "status": status,
            "tree_sha256": digest, "files": manifest}


def configure_command(harness, source, build, mode, compiler):
    configuration, flags = BUILD_FLAGS[mode]
    return ["cmake", "-S", harness, "-B", build, "-G", "Ninja",
            f"-DOPENTLV_SOURCE_DIR={source}", f"-DCMAKE_C_COMPILER={compiler}",
            f"-DCMAKE_BUILD_TYPE={configuration}", "-DCMAKE_C_FLAGS=",
            f"-DCMAKE_C_FLAGS_{configuration.upper()}={flags}",
            "-DCMAKE_EXE_LINKER_FLAGS=", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DOPENTLV_CALLGRIND_INSTRUMENTATION=" + ("ON" if mode == "callgrind" else "OFF")]


def validate_result(text, workload, iterations):
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON result object for {workload}")
    if (value.get("workload") != workload or type(value.get("iterations")) is not int
            or value["iterations"] != iterations):
        raise ValueError(f"Mismatched workload/iteration result: {workload}")
    for key in ("elapsed_ns", "input_bytes"):
        if type(value.get(key)) is not int or value[key] <= 0:
            raise ValueError(f"Invalid {key} for {workload}")
    if type(value.get("checksum")) is not int or value["checksum"] < 0:
        raise ValueError(f"Missing or invalid checksum for {workload}")
    if not isinstance(value.get("input_id"), str) or not value["input_id"]:
        raise ValueError(f"Missing input identity for {workload}")
    return value


def require_equivalent(baseline, candidate, include_checksum=True):
    keys = ("workload", "input_id", "input_bytes")
    if include_checksum:
        keys += ("iterations", "checksum")
    if any(baseline[key] != candidate[key] for key in keys):
        raise ValueError(f"Non-equivalent workload results: {baseline['workload']}")
    if not include_checksum and (baseline["checksum"] * candidate["iterations"] !=
                                 candidate["checksum"] * baseline["iterations"]):
        raise ValueError(f"Different per-iteration checksum: {baseline['workload']}")


def compare(args, output):
    if sys.platform != "linux":
        raise ValueError("Callgrind comparison requires native Linux.")
    compiler = shutil.which(args.cc)
    if not compiler:
        raise ValueError(f"C compiler not found: {args.cc}")
    # Environment flags must not silently turn one of the plain builds into a
    # sanitized or differently optimized benchmark.
    env = os.environ.copy()
    removed_flags = {key: env.pop(key) for key in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS")
                     if key in env}
    sources = {"baseline": args.baseline_source.resolve(),
               "candidate": args.candidate_source.resolve()}
    cpu_info = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    cpu_model = next((line.split(":", 1)[1].strip() for line in cpu_info.splitlines()
                      if line.startswith(("model name", "Hardware", "Processor")) and ":" in line),
                     platform.machine())
    metadata = {"created_at": datetime.now(timezone.utc).isoformat(),
                "platform": platform.platform(), "machine": platform.machine(),
                "cpu_model": cpu_model, "cpu_affinity": sorted(os.sched_getaffinity(0)),
                "compiler": run([compiler, "--version"]).strip(),
                "compiler_target": run([compiler, "-dumpmachine"]).strip(),
                "valgrind": run(["valgrind", "--version"]).strip(),
                "cmake": run(["cmake", "--version"]).splitlines()[0],
                "ninja": run(["ninja", "--version"]).strip(),
                "libc": run(["ldd", "--version"]).splitlines()[0],
                "python": platform.python_version(), "ignored_environment_flags": removed_flags,
                "build_flags": BUILD_FLAGS, "iterations": args.iterations,
                "native_iterations": args.native_iterations,
                "native_repetitions": args.native_repetitions,
                "threshold_percent": args.threshold_percent,
                "threshold_instructions": args.threshold_instructions,
                "native_threshold_percent": args.native_threshold_percent,
                "sources": {side: source_metadata(path) for side, path in sources.items()}}
    harness = output / "harness"
    harness.mkdir()
    metadata["harness_sha256"] = {}
    for name in ("CMakeLists.txt", "workloads.c"):
        source = ROOT / "benchmarks" / "callgrind" / name
        shutil.copyfile(source, harness / name)
        metadata["harness_sha256"][name] = hashlib.sha256(source.read_bytes()).hexdigest()
    write_json(output / "metadata.json", metadata)
    binaries = {}
    for side, source in sources.items():
        binaries[side] = {}
        for mode in BUILD_FLAGS:
            print(f"Building {side} {mode}", flush=True)
            build = output / "builds" / side / mode
            log = output / "logs" / f"{side}-{mode}"
            run(configure_command(harness, source, build, mode, compiler),
                log.with_suffix(".configure.log"), env)
            run(["cmake", "--build", build, "--target", "opentlv-perf-workload",
                 "--parallel", args.jobs], log.with_suffix(".build.log"), env)
            binary = build / "opentlv-perf-workload"
            binaries[side][mode] = binary
            for name in ("CMakeCache.txt", "compile_commands.json"):
                destination = output / "build-metadata" / side / mode / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(build / name, destination)
            metadata.setdefault("binaries_sha256", {}).setdefault(side, {})[mode] = (
                hashlib.sha256(binary.read_bytes()).hexdigest())
    write_json(output / "metadata.json", metadata)

    profiles, profile_results = {}, {}
    for workload in WORKLOADS:
        profiles[workload], profile_results[workload] = {}, {}
        for side in sources:
            print(f"Profiling {side} {workload}", flush=True)
            profile = output / "profiles" / side / f"{workload}.out"
            profile.parent.mkdir(parents=True, exist_ok=True)
            raw = run(["valgrind", "--tool=callgrind", "--instr-atstart=no",
                       "--cache-sim=no", "--branch-sim=no", "--collect-atstart=yes",
                       "--error-exitcode=99", f"--callgrind-out-file={profile}",
                       f"--log-file={profile}.log", binaries[side]["callgrind"],
                       workload, args.iterations],
                      output / "logs" / f"{side}-{workload}-callgrind.log", env)
            result = validate_result(raw, workload, args.iterations)
            profile_results[workload][side] = result
            # Client-request dump .1 is exactly the measured region. The final
            # termination dump contains only the tail and must not be used.
            measured = Path(str(profile) + ".1")
            profiles[workload][side] = parse_profile(measured)
            if profiles[workload][side]["instructions"] <= 0:
                raise ValueError(f"Empty instrumented region: {side} {workload}")
            run(["callgrind_annotate", "--auto=no", "--inclusive=no", "--threshold=100", measured],
                Path(str(profile) + ".functions.txt"), env)
        require_equivalent(profile_results[workload]["baseline"], profile_results[workload]["candidate"])
    write_json(output / "profiles" / "workload-results.json", profile_results)
    metadata["workload_inputs"] = {
        name: {key: values["baseline"][key] for key in ("input_id", "input_bytes")}
        for name, values in profile_results.items()}
    write_json(output / "metadata.json", metadata)

    native = {workload: {side: [] for side in sources} for workload in WORKLOADS}
    for repetition in range(args.native_repetitions):
        # Alternate order to reduce systematic drift; retain every raw sample.
        order = ("baseline", "candidate") if repetition % 2 == 0 else ("candidate", "baseline")
        for workload in WORKLOADS:
            for side in order:
                raw = run([binaries[side]["native"], workload, args.native_iterations],
                          output / "logs" / f"{side}-{workload}-native-{repetition}.log", env, timeout=120)
                result = validate_result(raw, workload, args.native_iterations)
                require_equivalent(profile_results[workload][side], result, include_checksum=False)
                if native[workload][side]:
                    require_equivalent(native[workload][side][0], result)
                native[workload][side].append(result)
            require_equivalent(native[workload]["baseline"][-1], native[workload]["candidate"][-1])
        print(f"Native repetition {repetition + 1}/{args.native_repetitions}", flush=True)
        write_json(output / "native" / "samples.json", native)

    for side, source in sources.items():
        if source_metadata(source)["tree_sha256"] != metadata["sources"][side]["tree_sha256"]:
            raise ValueError(f"{side} source changed during measurement; results are not comparable")
    workloads = [compare_workload(
        name, profiles[name]["baseline"], profiles[name]["candidate"],
        [item["elapsed_ns"] for item in native[name]["baseline"]],
        [item["elapsed_ns"] for item in native[name]["candidate"]],
        threshold_percent=args.threshold_percent, threshold_instructions=args.threshold_instructions,
        native_threshold_percent=args.native_threshold_percent) for name in WORKLOADS]
    for workload in workloads:
        workload.update(metadata["workload_inputs"][workload["name"]])
        for side in sources:
            median = workload["native"][f"{side}_median_ns"]
            workload["native"][f"{side}_ns_per_iteration"] = median / args.native_iterations
            workload["native"][f"{side}_bytes_per_second"] = (
                workload["input_bytes"] * args.native_iterations * 1e9 / median)
    report = {"baseline_sha": metadata["sources"]["baseline"]["sha"],
              "candidate_sha": metadata["sources"]["candidate"]["sha"],
              "metadata": metadata, "workloads": workloads,
              "status": "potential_regression" if any(item["instructions"]["warning"]
                                                       for item in workloads) else "no_instruction_regression"}
    write_json(output / "report.json", report)
    (output / "report.md").write_text(render_markdown(report), encoding="utf-8")
    for item in workloads:
        if item["instructions"]["warning"]:
            message = f"{item['name']}: increased Ir; review report and native timing evidence."
            print(("::warning::" if os.environ.get("GITHUB_ACTIONS") == "true" else "Warning: ") + message)
    print(f"Comparison complete: {output / 'report.md'}", flush=True)


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def nonnegative_float(value):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("must be finite and nonnegative")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-source", type=Path, required=True)
    parser.add_argument("--candidate-source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build" / "callgrind")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--jobs", type=positive_int, default=2)
    parser.add_argument("--iterations", type=positive_int, default=2000)
    parser.add_argument("--native-iterations", type=positive_int, default=20000)
    parser.add_argument("--native-repetitions", type=positive_int, default=5)
    parser.add_argument("--threshold-percent", type=nonnegative_float, default=5.0)
    parser.add_argument("--threshold-instructions", type=int, default=0)
    parser.add_argument("--native-threshold-percent", type=nonnegative_float, default=5.0)
    args = parser.parse_args()
    if args.native_repetitions < 3 or args.threshold_instructions < 0:
        parser.error("at least three native repetitions and a nonnegative instruction threshold are required")
    if max(args.iterations, args.native_iterations) > 100000000:
        parser.error("iteration counts must not exceed 100000000")
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("output directory must be empty; retain previous evidence in a separate directory")
    output.mkdir(parents=True, exist_ok=True)
    try:
        compare(args, output)
    except (OSError, ValueError, RuntimeError) as error:
        write_json(output / "report.json", {"status": "infrastructure_error", "error": str(error)})
        (output / "report.md").write_text(
            "# Callgrind comparison unavailable\n\nInfrastructure or workload validation failed; "
            "this is not a clean performance result. Inspect the retained logs.\n\n"
            + "```text\n" + str(error) + "\n```\n", encoding="utf-8")
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
