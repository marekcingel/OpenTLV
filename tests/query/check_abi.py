# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Compare observed public Query layouts against reviewed architecture snapshots."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--native")
    source.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    actual = json.loads(args.input.read_text() if args.input else
                        subprocess.check_output([args.native], text=True, timeout=30))
    profile = f"{actual['pointer_bits']}-{actual['types']['tlv_query_t']['alignment']}"
    baseline = Path(__file__).with_name("abi") / f"{profile}.json"
    expected = json.loads(baseline.read_text())
    assert actual == expected, ("Query ABI layout changed; review snapshot and compatibility", actual, expected)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(actual, indent=2) + "\n")
    print(f"Public Query ABI snapshot: {profile} layouts match")


if __name__ == "__main__":
    main()
