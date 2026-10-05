# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Check independent expected fixtures, then compare the optional native runner."""
import argparse
import json
from pathlib import Path
import subprocess
from reference import select, v1_baseline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native")
    args = parser.parse_args()
    corpus = json.loads(Path(__file__).with_name("corpus.json").read_text())
    assert corpus["version"] == 1
    for case in corpus["cases"]:
        if "diagnostic" in case:
            if args.native:
                result = subprocess.run([args.native, case["query"], case["wire"]],
                                        capture_output=True, text=True)
                assert result.returncode != 0, case["id"]
                fields = list(map(int, result.stderr.split()))
                expected = case["diagnostic"]
                assert fields[:2] == [expected["code"], expected["kind"]], (case["id"], fields)
                if "begin" in expected:
                    assert fields[2:] == [expected["begin"], expected["end"]], (case["id"], fields)
            continue
        wire = bytes.fromhex(case["wire"])
        actual = select(case["query"], wire)
        assert actual == case["matches"], (case["id"], actual, case["matches"])
        if case.get("v1"):
            assert v1_baseline(case["query"], wire) == actual, case["id"]
        if args.native:
            for mode in ("o", "u", "ro", "ru"):
                result = subprocess.run([args.native, case["query"], case["wire"], mode],
                                        capture_output=True, text=True)
                assert result.returncode == 0, (case["id"], mode, result.stderr)
                native = result.stdout.strip() if isinstance(actual, str) else [int(value) for value in result.stdout.split()]
                assert native == actual, (case["id"], mode, native, actual)
    print(f"{len(corpus['cases'])} Query fixtures passed")


if __name__ == "__main__":
    main()
