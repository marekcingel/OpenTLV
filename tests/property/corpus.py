#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Generate, enumerate and verify deterministic complete wire cases."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def commit_seed(commit):
    """First eight SHA-256 digest bytes of the lowercase commit, big endian."""
    return int.from_bytes(hashlib.sha256(commit.lower().encode("ascii")).digest()[:8], "big")


def enumerate_cases(root, count):
    cases = sorted(root.glob("*.bin"), key=lambda case: int(case.stem) if case.stem.isdecimal() else -1)
    expected = [root / f"{index:06d}.bin" for index in range(count)]
    if cases != expected or any(case.stat().st_size == 0 for case in cases):
        raise ValueError("corpus must contain exactly the indexed, nonempty complete .bin cases")
    return cases


def write_metadata(path, metadata):
    path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def preserve_failure(root, case, metadata, reason, output=None):
    target = root / case.stem
    target.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(case, target / "input.bin")
    if output is not None and output.exists():
        shutil.copyfile(output, target / "output.bin")
    write_metadata(target / "metadata.json", dict(metadata,
                   case=int(case.stem) if case.stem.isdecimal() else None,
                   filename=case.name, failure=reason))


def run(args):
    seed = int(args.seed) if args.seed else commit_seed(args.commit)
    if not 0 <= seed < 2**64 or args.count < 1:
        raise ValueError("seed must be uint64 and count must be positive")
    version = re.search(r"^#define TLV_GENERATOR_VERSION (\d+)$",
                        args.generator_header.read_text(encoding="utf-8"), re.MULTILINE)
    if not version:
        raise ValueError("cannot identify native generator version")
    nested = args.format in ("ber", "der", "emv")
    depth = args.max_depth if nested else 0
    options = {"count": args.count, "max_depth": depth, "max_elements": args.max_elements,
               "max_value_size": args.max_value_size, "max_case_size": args.max_case_size}
    configuration = {}
    if args.format == "fixed":
        configuration = {"tag_size": args.tag_size, "length_size": args.length_size,
                         "byte_order": args.byte_order, "element_order": "TLV", "length_scope": "value"}
    metadata = {"contract_version": 1, "commit": args.commit, "format": args.format,
                "configuration": configuration, "seed": str(seed),
                "seed_mapping": "explicit-uint64" if args.seed else
                                "sha256-lowercase-ascii-first-8-bytes-big-endian-v1",
                "generator": {"algorithm": "SplitMix64", "version": int(version[1]),
                              "domain": "otlv-generate-v1"}, "options": options}
    metadata["transform"] = "nfc-null-prefix-terminator-suffix-v1" if args.nfc_controls else "none"
    metadata["verification_limits"] = {"max_depth": depth, "max_elements": args.max_elements,
                                       "max_case_size": args.max_case_size}
    if args.nfc_controls and (args.format != "nfc-type2" or args.max_case_size < 4):
        raise ValueError("NFC control framing requires nfc-type2 and at least four case bytes")
    # Reserve two bytes and two elements for explicit domain-owned control framing.
    if args.nfc_controls:
        if args.max_elements < 3:
            raise ValueError("NFC control framing requires at least three elements")
        options["max_case_size"] -= 2
        options["max_elements"] -= 2
    command = [args.cli, "generate", "--format", args.format, "--seed", str(seed),
               "--count", str(args.count), "--output-dir", str(args.root),
               "--max-depth", str(depth), "--max-elements", str(options["max_elements"]),
               "--max-value-size", str(args.max_value_size), "--max-case-size", str(options["max_case_size"])]
    if configuration:
        command += ["--fixed-tag-size", str(args.tag_size), "--fixed-length-size", str(args.length_size),
                    "--fixed-byte-order", args.byte_order]
    metadata["generation_command"] = command
    # Only files owned by this contract are replaced; each configuration has its own directory.
    args.root.mkdir(parents=True, exist_ok=True)
    for case in args.root.glob("*.bin"):
        case.unlink()
    if args.failures.exists():
        for old in args.failures.iterdir():
            if old.is_dir() and old.name.isdecimal():
                shutil.rmtree(old)
        for old in args.failures.glob("*.json"):
            old.unlink()
    write_metadata(args.root / "metadata.json", metadata)
    generated = subprocess.run(command, capture_output=True, text=True, check=False)
    if generated.returncode:
        args.failures.mkdir(parents=True, exist_ok=True)
        write_metadata(args.failures / "generation.json", dict(metadata,
            failure=generated.stdout + generated.stderr, returncode=generated.returncode))
        # A generation failure can leave a useful partial corpus.
        for case in args.root.glob("*.bin"):
            preserve_failure(args.failures, case, metadata, "generation failed")
        raise ValueError(f"generation failed ({generated.returncode}): {generated.stderr}")
    try:
        cases = enumerate_cases(args.root, args.count)
    except ValueError as error:
        args.failures.mkdir(parents=True, exist_ok=True)
        write_metadata(args.failures / "enumeration.json", dict(metadata, failure=str(error)))
        for case in args.root.glob("*.bin"):
            preserve_failure(args.failures, case, metadata, str(error))
        raise
    if args.nfc_controls:
        for case in cases:
            case.write_bytes(b"\x00" + case.read_bytes() + b"\xfe")
    failures = 0
    output = args.root / "actual-output.tmp"
    for case in cases:
        output.unlink(missing_ok=True)
        checked = subprocess.run([args.checker, args.format, str(case), str(output), str(depth),
            str(args.max_elements), str(args.tag_size), str(args.length_size), args.byte_order],
            capture_output=True, text=True, check=False)
        if checked.returncode or not output.exists() or case.read_bytes() != output.read_bytes():
            failures += 1
            reason = f"checker exit {checked.returncode}: {checked.stdout}{checked.stderr}"
            preserve_failure(args.failures, case, metadata, reason, output)
            print(f"{args.format}/{case.name}: {reason}", file=sys.stderr)
    output.unlink(missing_ok=True)
    print(f"{args.format}: {len(cases)} cases, seed {seed}, failures {failures}")
    return 1 if failures else 0


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "checker", "format", "commit"):
        result.add_argument("--" + name, required=True)
    for name in ("root", "failures", "generator-header"):
        result.add_argument("--" + name, type=Path, required=True)
    result.add_argument("--seed", default="")
    result.add_argument("--nfc-controls", action="store_true")
    for name, default in (("count", 128), ("max-depth", 4), ("max-elements", 32),
                          ("max-value-size", 512), ("max-case-size", 4096),
                          ("tag-size", 1), ("length-size", 1)):
        result.add_argument("--" + name, type=int, default=default)
    result.add_argument("--byte-order", choices=("big", "little"), default="big")
    return result


if __name__ == "__main__":
    try:
        sys.exit(run(parser().parse_args()))
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
