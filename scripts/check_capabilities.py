#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Configure, link and execute representative capability profiles."""
import argparse
from pathlib import Path
import subprocess

CAPABILITIES = ("READER", "WRITER", "DOCUMENT", "QUERY", "SCHEMA", "CODEC")
PROFILES = {
    "core": (),
    "read": ("READER",),
    "write": ("WRITER",),
    "read-write": ("READER", "WRITER"),
    "document": ("DOCUMENT",),
    "parse-document": ("READER", "DOCUMENT"),
    "write-document": ("WRITER", "DOCUMENT"),
    "query": ("QUERY",),
    "query-reader": ("QUERY", "READER"),
    "document-query": ("DOCUMENT", "QUERY"),
    "schema": ("SCHEMA",),
    "codec": ("CODEC",),
    "no-reader": tuple(cap for cap in CAPABILITIES if cap != "READER"),
    "no-writer": tuple(cap for cap in CAPABILITIES if cap != "WRITER"),
    "full": CAPABILITIES,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", default="build/capabilities")
    parser.add_argument("--profile", choices=PROFILES, action="append")
    parser.add_argument("--generator")
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--cmake-arg", action="append", default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    for name in args.profile or PROFILES:
        build = Path(args.build_root).resolve() / name
        command = ["cmake", "-S", str(root), "-B", str(build),
                   "-DOPENTLV_BUILD_CXX=OFF", "-DOPENTLV_BUILD_TESTS=ON",
                   "-DOPENTLV_BUILD_UNIT_TESTS=OFF", "-DOPENTLV_BUILD_INTEGRATION_TESTS=OFF",
                   "-DOPENTLV_BUILD_QUERY_TESTS=OFF", "-DOPENTLV_BUILD_EXAMPLES=OFF",
                   "-DOPENTLV_BUILD_CLI=OFF",
                   "-DOPENTLV_BUILD_SHARED_LIBS=" + ("OFF" if args.static else "ON")]
        if args.generator:
            command += ["-G", args.generator]
        command += [f"-DOPENTLV_{cap}={'ON' if cap in PROFILES[name] else 'OFF'}"
                    for cap in CAPABILITIES]
        command += args.cmake_arg
        print(f"Capability profile: {name}", flush=True)
        subprocess.run(command, check=True)
        sources = (build / "capability-sources.txt").read_text().replace("\\", "/").split(";")
        for cap in set(CAPABILITIES) - set(PROFILES[name]):
            if any(f"src/{cap.lower()}/" in source for source in sources):
                raise RuntimeError(f"{name}: disabled {cap} sources are still compiled")
        subprocess.run(["cmake", "--build", str(build), "--config", "Debug",
                        "--parallel", "1"], check=True)
        subprocess.run(["ctest", "--test-dir", str(build), "-C", "Debug",
                        "-L", "capabilities", "--output-on-failure",
                        "--no-tests=error"], check=True)


if __name__ == "__main__":
    main()
